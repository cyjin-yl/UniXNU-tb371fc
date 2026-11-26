#!/usr/bin/env python3
"""Conditional, byte-bound MM bootstrap analysis; never an A01 completion gate.

This small abstract interpreter follows the pinned constructor -> init -> cold
call context. It does not execute target instructions. Only explicitly modeled
instruction semantics preserve facts. Unknown calls erase memory facts and
caller-saved values; their ordinary-return continuation is considered only for
the local CFG, while the callee and possible re-entry remain open obligations.

The leaf lookup and syscall models are named assumptions in the output, not
observed XNU behavior. In particular, no report produced here proves runtime
boot, all entries, callback effects, cached-image identity, or all 236 TCHANGE
sites. A conditional local exclusion is not a recursive call-graph closure.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN


SOURCE_SHA256 = 'ab9887ed96c9c08ad68d4c6a5c27e8289fb0c9e55ec3e134547292a1ec579608'
SOURCE_SIZE = 1447088
PINS = {
    'mm_init': (0x6f50, 0x713c, '8622dd85d0b0849624ff75d3d934479ba3dbed7c6b02f740ffc3af199a0edeb6'),
    'mm_constructor': (0x713c, 0x7208, '5b5ff1d3acc76f5376beec745a7b2ef370cf9617dea3c57ba93f5a7691656219'),
    'mm_init_cold': (0x4c988, 0x4cb74, 'd9ee132ccf4c0e89ab5d03b56c9518f6a141b285b68a4f0c8d00119074fdb831'),
    'apple_lookup': (0x6e78, 0x6f20, '2c70b90f21a792aa097f0e186de9f8b44d68b9070d25b797bcdc7d4c065365a0'),
    'strlen': (0x1f00, 0x1f60, '5b4dd36f9820a758339e268e6dcfaa2f4f71a9ecde057eb08ef559aea9aecffa'),
    'crossarch_wrapper': (0xa99c, 0xa9d0, '8ec7f497c6b92b8122106cf58133365625d6722b2800e656035977214db909b6'),
    'crossarch_trap': (0xa9d0, 0xa9dc, '0a93fea11555ed8a905577afd8e8cb1c16f7159d619bee2b0438e622ed0395c8'),
    'lock': (0x99cc, 0x9a44, 'b60fec429ba0519288082d8731091a1980b769d3fa4c4d79a668aa40a1474582'),
}
PRIMARY = ('mm_init', 'mm_constructor', 'mm_init_cold')
PREMISES = {
    'entry_context': 'Entry is the primary MM::init address 0x6f50, without an interior or re-entrant entry.',
    'ordinary_call_returns': 'Local call continuations and RET use the ordinary ARM64 ABI; asynchronous/non-local transfers are outside this context.',
    'fresh_stack': 'The fresh aligned stack is disjoint from input vectors, image memory and external objects; bounds cover these frames.',
    'initial_flag_zero': 'Byte at unslid image address 0xcc080 is zero at this invocation.',
    'apple_hw_absent': 'The complete readable apple vector contains no dyld_hw_tpro key, regardless of string value.',
    'apple_sec_absent': 'The complete readable apple vector contains no has_sec_transition key.',
    'lookup_readonly': 'The pinned apple_lookup/strlen model only reads the supplied vector/strings and preserves non-frame memory; lookup returns null for absent keys.',
    'syscall38_bounded': 'The pinned syscall-38 wrapper returns normally and may write only the one-byte output referenced through x3; it does not retain aliases.',
    'pauth_control': 'PAuth prologue/return instructions preserve the modeled local call/return structure; correspondence to lowered output is a separate proof.',
}
_MASK64 = (1 << 64) - 1
_MEM = re.compile(r'^\[(x\d+|sp)(?:, #(-?(?:0x[0-9a-f]+|[0-9]+)))?\](!)?(?:, #(-?(?:0x[0-9a-f]+|[0-9]+)))?$')
_GPR = re.compile(r'(?:[xw](?:[0-9]|[12][0-9]|30)|[xw]zr|sp)')


def scalar(operand):
    return _GPR.fullmatch(operand) is not None


def require(condition, message):
    if not condition:
        raise ValueError('MM conditional state: ' + message)


@dataclass(frozen=True)
class Pointer:
    region: str
    offset: int

    def add(self, delta):
        result = self.offset + delta
        low, high = (0, 1 << 64) if self.region == 'image' else (-(1 << 63), 1 << 63)
        return Pointer(self.region, result) if low <= result < high else None

    def covers(self, width):
        # These are arithmetic bounds, not a claim that an allocation exists.
        # The fresh-stack and input-readability premises supply allocation bounds.
        low, high = (0, 1 << 64) if self.region == 'image' else (-(1 << 63), 1 << 63)
        return low <= self.offset < high and 0 < width <= high - self.offset


def display(value):
    if isinstance(value, Pointer):
        return {'object': value.region, 'offset': value.offset}
    return hex(value) if isinstance(value, int) else 'unknown'


@dataclass
class State:
    registers: dict = field(default_factory=dict)
    memory: dict = field(default_factory=dict)
    flags: dict | None = None
    frames: tuple = ()

    def clone(self):
        return State(dict(self.registers), dict(self.memory),
                     None if self.flags is None else dict(self.flags), self.frames)

    def get(self, register):
        if register in ('xzr', 'wzr'):
            return 0
        key = 'x' + register[1:] if register.startswith('w') else register
        value = self.registers.get(key)
        if register.startswith('w'):
            return value & 0xffffffff if isinstance(value, int) else None
        return value

    def put(self, register, value):
        if register in ('xzr', 'wzr'):
            return
        if register.startswith('w'):
            value = value & 0xffffffff if isinstance(value, int) else None
            register = 'x' + register[1:]
        elif isinstance(value, int):
            value &= (1 << (128 if register.startswith('q') else 64)) - 1
        self.registers[register] = value

    def load(self, address, width):
        require(width in (1, 2, 4, 8, 16), 'unsupported load width')
        if isinstance(address, int):
            address = Pointer('image', address)
        if not isinstance(address, Pointer) or not address.covers(width):
            return None
        cells = [self.memory.get((address.region, address.offset + i), (None, None))[0]
                 for i in range(width)]
        if all(isinstance(value, int) for value in cells):
            return sum(value << (8 * i) for i, value in enumerate(cells))
        if width == 8 and cells and isinstance(cells[0], tuple):
            pointer = cells[0][0]
            if all(value == (pointer, index) for index, value in enumerate(cells)):
                return pointer
        return None

    def store(self, address, width, value, pc):
        require(width in (1, 2, 4, 8, 16), 'unsupported store width')
        if isinstance(address, int):
            address = Pointer('image', address)
        if not isinstance(address, Pointer):
            self.invalidate(all_registers=True)
            return 'unknown_alias_write'
        if not address.covers(width):
            self.invalidate(all_registers=True)
            return 'invalid_store_interval'
        if isinstance(value, Pointer) and value.region == 'stack' and address.region != 'stack':
            self.invalidate(all_registers=True)
            return 'stack_pointer_escape'
        for index in range(width):
            byte = (value >> (index * 8)) & 255 if isinstance(value, int) else None
            if isinstance(value, Pointer) and width == 8:
                byte = (value, index)
            self.memory[(address.region, address.offset + index)] = (byte, pc)
        return None

    def invalidate(self, all_registers=False):
        self.memory.clear()
        self.flags = None
        for name in tuple(self.registers):
            if name != 'sp' and (all_registers or name.startswith('q') or
                                 name.startswith('x') and int(name[1:]) <= 18):
                self.registers[name] = None

    def call_clobbers(self):
        self.flags = None
        for index in range(19):
            self.put('x' + str(index), None)
        for index in range(32):
            self.put('q' + str(index), None)

    def fact(self, pointer, width):
        value = self.load(pointer, width)
        origins = sorted({self.memory[(pointer.region, pointer.offset + i)][1]
                          for i in range(width) if (pointer.region, pointer.offset + i) in self.memory and
                          self.memory[(pointer.region, pointer.offset + i)][1] is not None})
        return {'value': display(value), 'width': width, 'writes': [hex(pc) for pc in origins]}


@dataclass(frozen=True)
class Instruction:
    pc: int
    word: int
    mnemonic: str
    operands: str
    owner: int


class Program:
    def __init__(self, functions):
        self.instructions, self.functions = {}, {}
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        decoder.skipdata = True
        for name, start, blob in functions:
            require(start % 4 == 0 and len(blob) % 4 == 0 and blob, 'invalid function byte extent')
            end = start + len(blob)
            decoded = list(decoder.disasm(blob, start))
            require(len(decoded) == len(blob) // 4 and
                    all(item.address == start + index * 4 and item.size == 4
                        for index, item in enumerate(decoded)), 'incomplete instruction decoding')
            self.functions[start] = {'name': name, 'start': start, 'end': end,
                                     'sha256': hashlib.sha256(blob).hexdigest()}
            for item in decoded:
                require(item.address not in self.instructions, 'overlapping function bytes')
                word = struct.unpack('<I', item.bytes)[0]
                self.instructions[item.address] = Instruction(item.address, word, item.mnemonic,
                                                              item.op_str, start)


def pinned_program(source):
    require(source.identity.get('sha256') == SOURCE_SHA256 and
            source.identity.get('size') == SOURCE_SIZE, 'wrong standalone input identity')
    functions = []
    for name, (start, end, expected) in PINS.items():
        blob = source.read(start, end - start)
        require(len(blob) == end - start and hashlib.sha256(blob).hexdigest() == expected,
                name + ' bytes differ from the reviewed function')
        functions.append((name, start, blob))
    require(source.read(0xa62f7, 13) == b'dyld_hw_tpro\0' and
            source.read(0xa5e36, 19) == b'has_sec_transition\0', 'lookup key identity changed')
    return Program(functions)


def hazard(word):
    return word in (0xd5900040, 0xd5940000) or word & 0xffffffe0 in (
        0xd53b4060, 0xd53ef1a0, 0xd51ef1a0)


def number(operand):
    return int(operand.removeprefix('#'), 0)


def plus(left, right, subtract=False, width=64):
    if isinstance(right, int):
        delta = -right if subtract else right
        if isinstance(left, Pointer):
            return left.add(delta)
        if isinstance(left, int):
            return (left + delta) & ((1 << width) - 1)
    if subtract and isinstance(left, Pointer) and isinstance(right, Pointer) and left.region == right.region:
        return (left.offset - right.offset) & ((1 << width) - 1)
    return None


def compare(left, right, width, add=False):
    if not isinstance(left, int) or not isinstance(right, int):
        return None
    mask, sign = (1 << width) - 1, 1 << (width - 1)
    left, right = left & mask, right & mask
    full = left + right if add else left - right
    result = full & mask
    overflow = (~(left ^ right) & (left ^ result) & sign) if add else ((left ^ right) & (left ^ result) & sign)
    return {'z': result == 0, 'n': bool(result & sign),
            'c': full > mask if add else left >= right, 'v': bool(overflow)}


def condition(flags, code):
    if flags is None:
        return None
    z, n, c, v = (flags[key] for key in ('z', 'n', 'c', 'v'))
    values = {'eq': z, 'ne': not z, 'hs': c, 'lo': not c, 'hi': c and not z,
              'ls': not c or z, 'ge': n == v, 'lt': n != v,
              'gt': not z and n == v, 'le': z or n != v, 'mi': n,
              'pl': not n, 'vs': v, 'vc': not v, 'al': True}
    return values.get(code)


class Analyzer:
    def __init__(self, program, assumptions, *, max_steps=50000, max_states=1024):
        self.program, self.assumptions = program, assumptions
        self.max_steps, self.max_states = max_steps, max_states
        self.events, self.branches, self.checkpoints = [], [], []
        self.visited, self.reached_hazards, self.unmodeled = set(), set(), []
        self.returned, self.steps = 0, 0
        self.bootstrap = Pointer('stack', -0xf0 + 0x20)

    def event(self, kind, pc, **extra):
        self.events.append({'kind': kind, 'pc': hex(pc), **extra})

    def opaque_call(self, state, insn, target):
        self.event('unresolved_callee', insn.pc, target=hex(target),
                   arguments={f'x{i}': display(state.get(f'x{i}')) for i in range(8)},
                   effects='all memory facts killed; ordinary-return continuation only')
        state.invalidate()

    def lookup(self, state, insn):
        if not self.assumptions.get('lookup_readonly') or state.get('x0') != Pointer('apple', 0):
            return False
        key = state.get('x1')
        name = {0xa62f7: 'apple_hw_absent', 0xa5e36: 'apple_sec_absent'}.get(key)
        if name is None:
            return False
        result = 0 if self.assumptions.get(name) else None
        state.call_clobbers()
        state.put('x0', result)
        self.event('conditional_lookup_model', insn.pc, key=hex(key), premise=name,
                   result=display(result), dependency_hashes={name: PINS[name][2] for name in ('apple_lookup', 'strlen')})
        return True

    def syscall(self, state, insn):
        output = state.load(state.get('x3'), 8)
        allowed = (self.assumptions.get('syscall38_bounded') and insn.pc == 0xa9d4 and
                   insn.word == 0xd4001001 and state.get('x16') == 38 and
                   all(state.get('x' + str(index)) == 0 for index in range(3)) and
                   isinstance(output, Pointer) and output.region == 'stack' and
                   not self.bootstrap.offset <= output.offset < self.bootstrap.offset + 0x58)
        if not allowed:
            self.event('unresolved_syscall', insn.pc, effects='all memory facts killed')
            state.invalidate()
        else:
            state.store(output, 1, None, insn.pc)
            state.call_clobbers()
            self.event('conditional_syscall38_model', insn.pc, output=display(output), width=1,
                       result='unknown', premise='syscall38_bounded')

    def checkpoint(self, state, insn):
        if insn.pc in (0x7204, 0x6fa8, 0x4c9a8):
            self.checkpoints.append({'pc': hex(insn.pc),
                                     'hardware': state.fact(self.bootstrap.add(0x20), 1),
                                     'protected_stack': state.fact(self.bootstrap.add(0x30), 8),
                                     'security_transition': state.fact(self.bootstrap.add(0x22), 1)})

    def memory(self, state, insn):
        split = insn.operands.find('[')
        if split < 0:
            return False
        match = _MEM.fullmatch(insn.operands[split:])
        if match is None:
            return False
        registers = [item.strip() for item in insn.operands[:split].rstrip(', ').split(',')]
        if not all(re.fullmatch(r'(?:[xw](?:[0-9]|[12][0-9]|30)|[xw]zr|q(?:[0-9]|[12][0-9]|3[01]))', item)
                   for item in registers):
            return False
        base, displacement, pre, post = match.groups()
        offset = int(displacement, 0) if displacement else 0
        original = state.get(base)
        address = plus(original, offset)
        if pre:
            state.put(base, address)
        mnemonic = insn.mnemonic
        pair = mnemonic in ('stp', 'ldp')
        require(len(registers) == (2 if pair else 1), 'unsupported memory operand count')
        width = (16 if registers[0].startswith('q') else
                 8 if registers[0].startswith(('x', 'd')) else 4)
        if mnemonic.endswith('b'):
            width = 1
        elif mnemonic.endswith('h'):
            width = 2
        for index, register in enumerate(registers):
            at = plus(address, index * width)
            if mnemonic.startswith('ld'):
                state.put(register, state.load(at, width))
            else:
                invalidation = state.store(at, width, state.get(register), insn.pc)
                if invalidation:
                    self.event(invalidation, insn.pc)
                    if invalidation == 'invalid_store_interval':
                        return False
        if post:
            state.put(base, plus(original, int(post, 0)))
        return True

    def run(self, entry, state):
        queue = [(entry, state)]
        while queue:
            require(len(queue) <= self.max_states, 'path-state budget exceeded')
            pc, current = queue.pop()
            while pc is not None:
                require(len(queue) <= self.max_states, 'path-state budget exceeded')
                self.steps += 1
                require(self.steps <= self.max_steps, 'instruction-step budget exceeded')
                insn = self.program.instructions.get(pc)
                if insn is None:
                    self.unmodeled.append({'pc': hex(pc), 'reason': 'edge outside supplied function bytes'})
                    break
                self.visited.add(pc)
                self.checkpoint(current, insn)
                if hazard(insn.word):
                    self.reached_hazards.add(pc)
                    break
                mnemonic, operands = insn.mnemonic, insn.operands
                args = [item.strip() for item in operands.split(',')]
                next_pc = pc + 4
                handled = True
                if mnemonic in ('nop', 'dmb', 'isb'):
                    pass
                elif mnemonic in ('pacibsp', 'autibsp'):
                    handled = bool(self.assumptions.get('pauth_control'))
                elif mnemonic in ('ret', 'retab', 'retaa'):
                    handled = (bool(self.assumptions.get('ordinary_call_returns')) and operands in ('', 'x30') and
                               (mnemonic == 'ret' or bool(self.assumptions.get('pauth_control'))))
                    if handled:
                        if current.frames:
                            next_pc = current.frames[-1]
                            current.frames = current.frames[:-1]
                        else:
                            self.returned += 1
                            next_pc = None
                elif mnemonic in ('stp', 'ldp', 'str', 'ldr', 'stur', 'ldur',
                                  'strb', 'ldrb', 'sturb', 'ldurb', 'strh', 'ldrh'):
                    handled = self.memory(current, insn)
                elif (mnemonic in ('adr', 'adrp') and len(args) == 2 and
                      re.fullmatch(r'x(?:[0-9]|[12][0-9]|30)', args[0]) and args[1].startswith('#')):
                    current.put(args[0], number(args[1]))
                elif (mnemonic == 'movi' and len(args) == 2 and re.fullmatch(r'v(?:[0-9]|[12][0-9]|3[01])\.2d', args[0]) and
                      args[1].startswith('#') and number(args[1]) == 0):
                    current.put('q' + args[0][1:].split('.')[0], 0)
                elif (mnemonic == 'mov' and len(args) == 2 and scalar(args[0]) and
                      (args[1].startswith('#') or scalar(args[1]))):
                    value = number(args[1]) if args[1].startswith('#') else current.get(args[1])
                    current.put(args[0], value)
                elif (mnemonic == 'movk' and len(args) in (2, 3) and scalar(args[0]) and args[0] != 'sp' and
                      args[1].startswith('#') and (len(args) == 2 or re.fullmatch(r'lsl #[0-9]+', args[2]))):
                    old = current.get(args[0])
                    shift = number(args[2].removeprefix('lsl ')) if len(args) == 3 else 0
                    require(shift in ((0, 16) if args[0].startswith('w') else (0, 16, 32, 48)) and
                            0 <= number(args[1]) <= 0xffff, 'unsupported MOVK immediate/shift')
                    current.put(args[0], ((old & ~(0xffff << shift)) | (number(args[1]) << shift))
                                if isinstance(old, int) else None)
                elif (mnemonic in ('add', 'sub', 'adds', 'subs') and len(args) == 3 and
                      scalar(args[0]) and scalar(args[1]) and (args[2].startswith('#') or scalar(args[2]))):
                    left = current.get(args[1])
                    right = number(args[2]) if args[2].startswith('#') else current.get(args[2])
                    width = 32 if args[0].startswith('w') else 64
                    if mnemonic.endswith('s'):
                        current.flags = compare(left, right, width, add=mnemonic.startswith('add'))
                    current.put(args[0], plus(left, right, mnemonic.startswith('sub'), width))
                elif (mnemonic == 'and' and len(args) == 3 and scalar(args[0]) and scalar(args[1]) and
                      args[2].startswith('#')):
                    value = current.get(args[1])
                    current.put(args[0], value & number(args[2]) if isinstance(value, int) else None)
                elif (mnemonic in ('cmp', 'cmn') and len(args) == 2 and scalar(args[0]) and
                      (args[1].startswith('#') or scalar(args[1]))):
                    right = number(args[1]) if args[1].startswith('#') else current.get(args[1])
                    current.flags = compare(current.get(args[0]), right, 32 if args[0].startswith('w') else 64,
                                            add=mnemonic == 'cmn')
                elif mnemonic == 'b':
                    next_pc = number(operands)
                elif mnemonic.startswith('b.') or mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                    target = number(args[-1])
                    if mnemonic.startswith('b.'):
                        take = condition(current.flags, mnemonic[2:])
                    else:
                        value = current.get(args[0])
                        if mnemonic.startswith('tb'):
                            take = not bool(value & (1 << number(args[1]))) if isinstance(value, int) else None
                        else:
                            take = value == 0 if isinstance(value, int) else False if isinstance(value, Pointer) else None
                        if mnemonic in ('cbnz', 'tbnz') and take is not None:
                            take = not take
                    self.branches.append({'pc': hex(pc), 'word': hex(insn.word), 'target': hex(target),
                                          'taken': take})
                    if take is None:
                        queue.append((target, current.clone()))
                    elif take:
                        next_pc = target
                elif mnemonic == 'bl':
                    target = number(operands)
                    if target == 0x6e78 and self.lookup(current, insn):
                        pass
                    elif target in (0x713c, 0x4c988, 0xa99c, 0xa9d0) or (
                            target == 0x99cc and current.load(plus(current.get('x0'), 8), 8) == 0):
                        if target in self.program.functions:
                            current.put('x30', pc + 4)
                            current.frames += (pc + 4,)
                            next_pc = target
                        else:
                            self.opaque_call(current, insn, target)
                    else:
                        self.opaque_call(current, insn, target)
                elif mnemonic == 'svc':
                    self.syscall(current, insn)
                elif mnemonic in ('brk', 'udf', 'hlt'):
                    self.event('terminating_exception', pc, instruction=mnemonic)
                    next_pc = None
                else:
                    handled = False
                if not handled:
                    current.invalidate(all_registers=True)
                    self.unmodeled.append({'pc': hex(pc), 'word': hex(insn.word),
                                           'instruction': mnemonic + ' ' + operands,
                                           'reason': 'unmodeled effect; all facts killed'})
                    break
                pc = next_pc
        return self


def analyze_mm_init(source, assumptions=None):
    """Analyze one explicitly assumed bootstrap context, preserving open gates."""
    assumptions = {} if assumptions is None else dict(assumptions)
    require(set(assumptions) <= set(PREMISES) and all(type(value) is bool for value in assumptions.values()),
            'unknown or non-boolean premise')
    program = pinned_program(source)
    initial = State(registers={'sp': Pointer('stack', 0), 'x0': Pointer('env', 0),
                               'x1': Pointer('apple', 0), 'x2': Pointer('cache_input', 0)})
    if assumptions.get('initial_flag_zero'):
        initial.store(0xcc080, 1, 0, None)
    analysis = Analyzer(program, assumptions)
    context_ready = all(assumptions.get(key) for key in
                        ('entry_context', 'ordinary_call_returns', 'fresh_stack', 'pauth_control'))
    if context_ready:
        analysis.run(0x6f50, initial)
    else:
        analysis.unmodeled.append({'reason': 'primary entry/stack/ABI context premises are incomplete'})
    sites = sorted(pc for pc, insn in program.instructions.items()
                   if program.functions[insn.owner]['name'] in PRIMARY and hazard(insn.word))
    require(len(sites) == 16, 'pinned primary-function hazard census changed')
    cutpoints = {}
    for pc, expected in ((0x6fa8, 0x70f8), (0x4c9a8, 0x4cb04)):
        observations = [item for item in analysis.branches if item['pc'] == hex(pc)]
        cutpoints[hex(pc)] = {'target': hex(expected), 'observations': len(observations),
                              'all_taken': bool(observations) and
                              all(item['taken'] is True and item['target'] == hex(expected) for item in observations)}
    conditional = (context_ready and not analysis.unmodeled and not analysis.reached_hazards and
                   analysis.returned > 0 and all(item['all_taken'] for item in cutpoints.values()))
    unresolved = [event for event in analysis.events
                  if event['kind'] in ('unresolved_callee', 'unresolved_syscall',
                                       'unknown_alias_write', 'stack_pointer_escape', 'invalid_store_interval')]
    return {
        'schema': 'route-a-nontpro-mm-conditional-v1',
        'input': dict(source.identity),
        'scope': 'one primary standalone MM::init invocation and its constructor/cold frames; ordinary-return continuations',
        'status': 'conditional_local_exclusion' if conditional else 'unresolved',
        'assumptions': [{'id': name, 'statement': statement, 'assumed': bool(assumptions.get(name)),
                         'discharged_by_runtime': False} for name, statement in PREMISES.items()],
        'functions': [{**value, 'start': hex(value['start']), 'end': hex(value['end'])}
                      for value in program.functions.values()],
        'object': {'id': 'bootstrap_mm', 'address': display(analysis.bootstrap), 'extent': 0x58,
                   'hardware_offset': 0x20, 'protected_stack_offset': 0x30, 'security_offset': 0x22},
        'cutpoints': cutpoints, 'state_observations': analysis.checkpoints,
        'local_hazards': [{'pc': hex(pc), 'word': hex(program.instructions[pc].word),
                           'verdict': 'unreachable_in_this_frame_under_premises' if conditional else 'unresolved'}
                          for pc in sites],
        'conditional_excluded_count': len(sites) if conditional else 0,
        'abstract_hazard_paths': [hex(pc) for pc in sorted(analysis.reached_hazards)],
        'unmodeled': analysis.unmodeled,
        'events': analysis.events, 'open_effect_obligations': unresolved,
        'analysis': {'steps': analysis.steps, 'ordinary_return_paths': analysis.returned,
                     'capstone': capstone.__version__, 'checker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        'entry_coverage_complete': False, 'nested_callees_closed': False,
        'cached_handoff_verified': False, 'all_a01_hazards_closed': False,
        'runtime_execution_observed': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--conditional-bootstrap', action='store_true',
                        help='explicitly assume the listed bootstrap/leaf/ABI premises; does not discharge them')
    arguments = parser.parse_args()
    from audit_route_a_nontpro import Standalone
    source = Standalone(arguments.input)
    report = analyze_mm_init(source, {name: True for name in PREMISES} if arguments.conditional_bootstrap else {})
    require(source.recheck(), 'standalone input changed during analysis')
    with arguments.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
