#!/usr/bin/env python3
"""Byte-bound conditional ProtectedStack construction and MM publication.

This composes complete, pinned function bodies and one exact policy store under
an explicitly assumed caller sequence. It does not assert that the runtime constructor or
startup CFG actually supplies that sequence, object identity or apple vector.
Unknown effects prevent a contract from being composed. No output from this
module is an A01, shared-cache, syscall, lowering or runtime completion gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import audit_route_a_nontpro_state as core
from audit_route_a_nontpro_state import Analyzer, Pointer, Program, State, display, require


STACK_PINS = {
    'process_constructor': (0x1fd80, 0x202d4, '50f8129456d70d57cef0a2c697cd8038b212ef201df892a20a2f6df0266e8924'),
    'default_stack_policy': (0x21264, 0x212f0, '93cd58dc4e10f24e483d8fed5de03c75ad64f58353923d2c1b47c7aff50c1528'),
    'runtime_constructor': (0x3c4a8, 0x3c7e8, '1d56fb39ab8ea22aaa6183aa48880bf4b4bf013f8b7c550fbff1cc6532085b3c'),
    'stack_constructor': (0x3cb2c, 0x3cb68, 'f607cbc8636cdcdac013f7cda0eb4f2602aa9453cee79b8c0c7cbac83c3e052b'),
    'install_stack': (0x3ccf0, 0x3ccf8, '6215e1bbd3c8ac0311d5a5d6e67e46e033efc47a193976238e4ff03101d8acf6'),
    'stack_query': (0x32020, 0x320c8, '512e1c27d321b270c47635608054c49a1658babe10526652d8d49f76eddd21b5'),
    'apple_lookup': core.PINS['apple_lookup'],
    'strlen': core.PINS['strlen'],
}
STACK_PREMISES = {
    'entry_context': 'The caller reaches Process 0x1ffdc with x19 naming its Process subobject, then follows the reported policy/store/runtime-constructor/setter/query sequence without an alternate entry.',
    'ordinary_call_returns': core.PREMISES['ordinary_call_returns'],
    'fresh_stack': 'A fresh writable stack covers relative bytes [-0x1000,0), is aligned, and is disjoint from the input/config, MM, runtime and external objects.',
    'pauth_control': core.PREMISES['pauth_control'],
    'apple_hw_absent': core.PREMISES['apple_hw_absent'],
    'lookup_readonly': core.PREMISES['lookup_readonly'],
    'policy_config_binding': 'A live writable ProcessConfig spans at least 0x340 bytes; Process is its +0x10 subobject and Process +0xd0 contains the complete apple-vector pointer.',
    'runtime_stack_binding': 'A fresh live runtime object spans at least 0x538 bytes and is disjoint from the policy/config object, MM and caller stack; its ProtectedStack subobject is exactly [0x4f8,0x538).',
    'runtime_auxiliary_inputs': 'Runtime constructor x2/x3 are scalar or external-object values, not aliases to the modeled live caller stack.',
    'data_signing_effects': 'The two exact PACDA/PACDB forms return normally and affect only their scalar destination; traps and correspondence to lowered output remain separate obligations.',
    'published_mm_binding': 'The live, writable global MM object is the object at unslid image coordinate 0xcc088, distinct from the policy and runtime objects.',
    'published_mm_hardware_zero': 'That same global MM object has hardware flag byte +0x20 equal to zero before this sequence.',
    'sequence_preserves_objects': 'No intervening writer, callback, syscall, escape, lifetime end or concurrent access mutates these objects or inputs between the modeled phases, including after Process +0x101 is written.',
}
CONFIG = Pointer('process_config', 0)
POLICY = CONFIG.add(0x10)
RUNTIME = Pointer('runtime_state', 0)
PROTECTED_STACK = RUNTIME.add(0x4f8)
MM = Pointer('image', 0xcc088)
INITIAL_SP = Pointer('stack', 0)
OBJECT_BOUNDS = {'stack': (-0x1000, 0), 'process_config': (0, 0x340),
                 'runtime_state': (0, 0x538), 'image': (0xcc088, 0xcc0e0)}
OPEN_GATES = ('caller_trace_bound', 'entry_coverage_complete', 'all_writers_covered',
              'cached_handoff_verified', 'all_a01_hazards_closed', 'runtime_execution_observed')


def pinned_stack_program(source):
    require(source.identity.get('sha256') == core.SOURCE_SHA256 and
            source.identity.get('size') == core.SOURCE_SIZE, 'wrong standalone input identity')
    functions = []
    for name, (start, end, expected) in STACK_PINS.items():
        blob = source.read(start, end - start)
        require(len(blob) == end - start and hashlib.sha256(blob).hexdigest() == expected,
                name + ' bytes differ from the reviewed function')
        functions.append((name, start, blob))
    require(source.read(0xa62f7, 13) == b'dyld_hw_tpro\0', 'lookup key identity changed')
    return Program(functions)


class ReturnStates(Analyzer):
    """Observe candidate returns; successful decoding/ABI handling is checked too."""

    def __init__(self, program, assumptions):
        super().__init__(program, assumptions, max_steps=8192, max_states=64)
        self.return_states = []

    def checkpoint(self, state, insn):
        if not state.frames and insn.mnemonic in ('ret', 'retab', 'retaa'):
            require(len(self.return_states) < 64, 'leaf return-state budget exceeded')
            self.return_states.append(state.clone())

    def memory(self, state, insn):
        split = insn.operands.find('[')
        match = core._MEM.fullmatch(insn.operands[split:]) if split >= 0 else None
        if match is None:
            return super().memory(state, insn)
        registers = [item.strip() for item in insn.operands[:split].rstrip(', ').split(',')]
        base, displacement, _, _ = match.groups()
        address = core.plus(state.get(base), int(displacement, 0) if displacement else 0)
        if isinstance(address, int):
            address = Pointer('image', address)
        width = 16 if registers[0].startswith('q') else 8 if registers[0].startswith('x') else 4
        if insn.mnemonic.endswith('b'):
            width = 1
        elif insn.mnemonic.endswith('h'):
            width = 2
        total = width * len(registers)
        interval = OBJECT_BOUNDS.get(address.region) if isinstance(address, Pointer) else None
        if interval is None or not interval[0] <= address.offset <= interval[1] - total:
            # Preserve the core's explicit unknown-alias/escape diagnostics for
            # an unknown store, then stop even for an otherwise unused load.
            if not isinstance(address, Pointer) and insn.mnemonic.startswith('st'):
                super().memory(state, insn)
            self.event('unresolved_object_access', insn.pc, address=display(address), width=total,
                       reason='access is not contained in a named live object')
            state.invalidate(all_registers=True)
            return False
        return super().memory(state, insn)

    def inline_target(self, state, insn, target):
        # The sole call in the complete RuntimeState constructor. No other
        # inherited caller is implicitly granted an effect contract here.
        return (insn.owner == 0x3c4a8 and insn.pc == 0x3c7d4 and
                insn.word == 0x940000d6 and target == 0x3cb2c)

    def modeled_effect(self, state, insn):
        forms = {0xdac10a30: ('pacda', 'x16, x17'),
                 0xdac10e11: ('pacdb', 'x17, x16')}
        if (insn.owner != 0x3c4a8 or not self.assumptions.get('data_signing_effects') or
                forms.get(insn.word) != (insn.mnemonic, insn.operands)):
            return False
        # Overapproximate the scalar effects: retaining neither input/output
        # scratch register nor NZCV is needed for the field-initialization proof.
        # Memory preservation depends on the explicit normal-execution premise.
        state.put('x16', None)
        state.put('x17', None)
        state.flags = None
        self.event('conditional_data_signing_model', insn.pc, word=hex(insn.word),
                   killed=['x16', 'x17', 'NZCV'], premise='data_signing_effects')
        return True


def object_observation(state):
    return {
        'return_x0': display(state.get('x0')),
        'stack_pointer': display(state.get('sp')),
        'hardware': state.fact(MM.add(0x20), 1),
        'installed_pointer': state.fact(MM.add(0x30), 8),
        'stack_top': state.fact(PROTECTED_STACK, 8),
        'next_protected_stack': state.fact(PROTECTED_STACK.add(0x18), 8),
        'process_policy_byte': state.fact(POLICY.add(0x101), 1),
        'all_64_stack_bytes_zero': all(state.load(PROTECTED_STACK.add(i), 1) == 0
                                       for i in range(64)),
    }


def phase(program, assumptions, name, incoming, bind):
    """Compose only total local return paths with no unresolved nested effects."""
    address = STACK_PINS[name][0]
    observations, outgoing, reasons = [], [], []
    events, branches, unmodeled, hazards, steps = [], [], [], set(), 0
    for prior in incoming:
        state = prior.clone()
        bind(state)
        analysis = ReturnStates(program, assumptions).run(address, state)
        events.extend(analysis.events)
        branches.extend(analysis.branches)
        unmodeled.extend(analysis.unmodeled)
        hazards.update(analysis.reached_hazards)
        steps += analysis.steps
        if analysis.returned != len(analysis.return_states) or not analysis.returned:
            reasons.append('not every observed terminal is a supported ordinary return')
        if analysis.unmodeled or analysis.reached_hazards:
            reasons.append('unmodeled instruction, outgoing edge or tracked hazard')
        if any(item['kind'] not in ('conditional_lookup_model', 'conditional_data_signing_model')
               for item in analysis.events):
            # Even a later store that restores a field cannot close an opaque
            # callee, exception, syscall or unknown alias effect.
            reasons.append('nested or memory effect remains unresolved')
        for returned in analysis.return_states:
            if returned.get('sp') != INITIAL_SP or returned.frames:
                reasons.append('caller stack/frame identity was not restored')
            observations.append(object_observation(returned))
            outgoing.append(returned)
            require(len(outgoing) <= 64, 'composed return-state budget exceeded')
    report = {'name': name, 'entry': hex(address), 'steps': steps,
              'return_paths': len(outgoing), 'branches': branches, 'events': events,
              'unmodeled': unmodeled, 'hazards': [hex(pc) for pc in sorted(hazards)],
              'post_states': observations, 'unresolved': sorted(set(reasons)),
              'local_effects_closed_under_premises': not reasons}
    return report, outgoing


def publish_policy(program, assumptions, incoming):
    """Bind the exact three-instruction local call/store edge, not all callers."""
    for pc, expected in ((0x1ffdc, 0xaa1303e0), (0x1ffe0, 0x940004a1), (0x1ffe4, 0x39040660)):
        require(pc in program.instructions and program.instructions[pc].word == expected,
                'Process policy call/store edge bytes changed')
    writer = program.instructions[0x1ffe4]
    require(writer.mnemonic == 'strb' and writer.operands == 'w0, [x19, #0x101]',
            'unsupported Process policy writer decoding')
    outgoing, reasons = [], []
    for prior in incoming:
        state = prior.clone()
        if state.get('x19') != POLICY or state.get('w0') != 0:
            reasons.append('policy return or preserved Process pointer is unknown')
            continue
        model = ReturnStates(program, assumptions)
        if not model.memory(state, writer) or model.events:
            reasons.append('Process writer has unresolved effects')
            continue
        if state.load(CONFIG.add(0x111), 1) != 0:
            reasons.append('Process +0x101 is not the same zero byte as config +0x111')
        outgoing.append(state)
    return {'name': 'process_policy_publication', 'call_pc': '0x1ffe0', 'store_pc': '0x1ffe4',
            'callee': '0x21264', 'byte_coordinate': display(CONFIG.add(0x111)),
            'scope': 'only the explicitly assumed local call/store edge; intervening caller effects remain open',
            'post_states': [object_observation(state) for state in outgoing],
            'unresolved': reasons, 'local_effects_closed_under_premises': bool(outgoing) and not reasons}, outgoing


def compose_stack_contract(program, assumptions):
    """Internal composition engine; callers of this API must bind program bytes.

    The CLI obtains a validated Standalone input, and analyze_stack_contract()
    checks its reported identity and every function byte extent. Programmatic
    callers must supply that validated source interface. Synthetic tests call
    this engine directly and do not produce a production input identity.
    """
    require(set(assumptions) <= set(STACK_PREMISES) and
            all(type(value) is bool for value in assumptions.values()),
            'unknown or non-boolean stack premise')
    result = {'status': 'unresolved', 'phases': [], 'postconditions': {},
              'unresolved': [], **dict.fromkeys(OPEN_GATES, False)}
    missing = [name for name in STACK_PREMISES if not assumptions.get(name)]
    if missing:
        result['unresolved'].append({'reason': 'composition premises are incomplete', 'premises': missing})
        return result
    initial = State(registers={'sp': INITIAL_SP})
    initial.store(POLICY.add(0xd0), 8, Pointer('apple', 0), None)
    initial.store(MM.add(0x20), 1, 0, None)
    frontier = [initial]

    def policy(state):
        state.put('x0', POLICY)
        state.put('x19', POLICY)

    def construct(state):
        state.put('x0', RUNTIME)
        state.put('x1', CONFIG)
        state.put('x2', None)
        state.put('x3', None)

    def install(state):
        state.put('x0', MM)
        state.put('x1', PROTECTED_STACK)

    def query(state):
        state.put('x0', state.load(MM.add(0x30), 8))

    stages = (
        ('default_stack_policy', policy, lambda state: state.get('w0') == 0,
         'default policy must return disabled'),
        ('runtime_constructor', construct,
         lambda state: state.get('x0') == RUNTIME and
         state.load(RUNTIME.add(8), 8) == CONFIG and
         state.load(CONFIG.add(0x111), 1) == 0 and
         all(state.load(PROTECTED_STACK.add(i), 1) == 0 for i in range(64)),
         'runtime constructor must return the same object, retain the config pointer, and zero its complete stack subobject'),
        ('install_stack', install,
         lambda state: state.load(MM.add(0x30), 8) == PROTECTED_STACK and
         state.load(MM.add(0x20), 1) == 0 and
         all(state.load(PROTECTED_STACK.add(i), 1) == 0 for i in range(64)),
         'publication must preserve hardware zero and the same disabled stack object'),
        ('stack_query', query,
         lambda state: state.get('w0') == 0 and
         state.load(MM.add(0x30), 8) == PROTECTED_STACK and
         state.load(MM.add(0x20), 1) == 0 and
         all(state.load(PROTECTED_STACK.add(i), 1) == 0 for i in range(64)),
         'query of the installed object must return false without changing the invariant'),
    )
    for name, bind, postcondition, description in stages:
        record, frontier = phase(program, assumptions, name, frontier, bind)
        result['phases'].append(record)
        if not record['local_effects_closed_under_premises']:
            result['unresolved'].append({'phase': name, 'reason': 'local effects or return paths are unresolved'})
            return result
        if not frontier or not all(postcondition(state) for state in frontier):
            result['unresolved'].append({'phase': name, 'reason': description})
            return result
        if name == 'default_stack_policy':
            publication, frontier = publish_policy(program, assumptions, frontier)
            result['phases'].append(publication)
            if not publication['local_effects_closed_under_premises']:
                result['unresolved'].append({'phase': 'process_policy_publication',
                                             'reason': 'exact policy call/store binding is unresolved'})
                return result
    result.update(status='conditional_disabled_stack_binding', postconditions={
        'published_mm_hardware_zero': True,
        'published_mm_protected_stack_nonnull': True,
        'same_runtime_subobject': True,
        'all_64_stack_bytes_zero': True,
        'query_returns_false': True,
        'scope': 'only this assumed sequence; no later writer or caller coverage is asserted',
    })
    return result


def analyze_stack_contract(source, assumptions=None):
    assumptions = {} if assumptions is None else dict(assumptions)
    program = pinned_stack_program(source)
    result = compose_stack_contract(program, assumptions)
    return {
        'schema': 'route-a-nontpro-disabled-stack-conditional-v1',
        'input': dict(source.identity),
        'scope': 'conditional local sequence: Process policy/store -> RuntimeState constructor with nested ProtectedStack constructor -> global MM publication -> query',
        'assumptions': [{'id': name, 'statement': statement, 'assumed': bool(assumptions.get(name)),
                         'discharged_by_runtime': False} for name, statement in STACK_PREMISES.items()],
        'objects': {'process_config': {'address': display(CONFIG), 'extent': 0x340},
                    'process_subobject': display(POLICY),
                    'runtime': {'address': display(RUNTIME), 'extent': 0x538},
                    'protected_stack': {'address': display(PROTECTED_STACK), 'extent': 64},
                    'published_mm': {'address': display(MM), 'extent': 0x58}},
        'object_access_bounds': {name: list(bounds) for name, bounds in OBJECT_BOUNDS.items()},
        'functions': [{**value, 'start': hex(value['start']), 'end': hex(value['end'])}
                      for value in program.functions.values()],
        'checker': {'module_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    'interpreter_sha256': hashlib.sha256(Path(core.__file__).read_bytes()).hexdigest(),
                    'capstone': core.capstone.__version__},
        **result,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--conditional-sequence', action='store_true',
                        help='explicitly assume the reported caller/input/object premises; does not discharge them')
    args = parser.parse_args()
    from audit_route_a_nontpro import Standalone
    source = Standalone(args.input)
    report = analyze_stack_contract(source, {name: True for name in STACK_PREMISES} if args.conditional_sequence else {})
    require(source.recheck(), 'standalone input changed during stack analysis')
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
