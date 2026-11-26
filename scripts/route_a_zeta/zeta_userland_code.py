"""Prove which words of a userland image's instruction sections are code.

Apple's current linker leaves LC_DATA_IN_CODE empty, while clang places
arm64e jump tables and hand-written decoder tables inside __text. A linear
sweep therefore cannot tell a table entry from an instruction. This walks
control flow from every declared function start, the entry point and the
defined symbols, and decodes the hardened arm64e jump-table dispatch exactly.
Words it never reaches are not proven code. Anything unusual is reported,
not guessed.

The linker records a function start for every __text atom, jump tables and
constant tables included, so function starts are only strong roots when a
nonzero __unwind_info encoding covers them. Every other root is accepted
only if a tentative walk from it stays on decodable, non-UDF instructions
outside every decoded table. Those roots come in two grades: code pointers
(chained-fixup rebase targets and adr/adrp+add addresses formed by proven
code) and bare function starts or symbols. Each proven word records the
grade of the root that reached it first. A sequential walk never crosses into another
function start, since calls to noreturn functions are followed directly by
the next atom, which may be a table; that start is judged as its own root.
A tentative walk that runs into a start other than after a call fails.
"""
import bisect
from functools import lru_cache
import re
import struct
from sys import intern

from capstone import (Cs, CsError, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN,
                      CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET,
                      CS_GRP_PRIVILEGE, CS_GRP_BRANCH_RELATIVE)
from capstone.arm64 import ARM64_OP_REG

LC_UNIXTHREAD, LC_FUNCTION_STARTS, LC_MAIN, LC_SYMTAB = 0x5, 0x26, 0x80000028, 0x2
LC_DYLD_CHAINED_FIXUPS = 0x80000034
# DYLD_CHAINED_PTR_ARM64E rebases hold an absolute address; USERLAND and USERLAND24 an offset from __TEXT.
DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 1, 9, 12
# Standalone kexts: the arm64e bit layout with a vm offset from the image header.
DYLD_CHAINED_PTR_ARM64E_KERNEL = 7
CONDITIONAL = ('cbz', 'cbnz', 'tbz', 'tbnz')
STOPS = ('ret', 'retab', 'retaa', 'eret', 'brk', 'udf', 'hlt')
INDIRECT = ('br', 'braa', 'braaz', 'brab', 'brabz')
CALLS = ('bl', 'blr', 'blraa', 'blraaz', 'blrab', 'blrabz')
# Transaction aborts can restore PC/register state at TSTART. No transaction
# context is modeled by this CFG walker, even if Capstone knows the mnemonic.
UNMODELED_FLOW = ('tstart', 'tcommit', 'tcancel', 'ttest')
TARGET = re.compile(r'#(-?0x[0-9a-f]+|-?[0-9]+)$')
# The hardened dispatch clang emits for arm64e, newest instruction last.
# Capstone prints immediates below ten in decimal.
DISPATCH = (('adrp', r'x17, #(0x[0-9a-f]+)'), ('add', r'x17, x17, #(0x[0-9a-f]+|[0-9])'),
            ('ldrsw', r'x16, \[x17, x16, lsl #2\]'), ('adr', r'x17, #(0x[0-9a-f]+)'),
            ('add', r'x16, x17, x16'), ('br', r'x16'))


def uleb128(data, at, end):
    value = shift = 0
    while True:
        if at >= end:
            raise ValueError('truncated ULEB128')
        byte = data[at]
        at += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            return value, at


def seeds(data, info):
    """(strong, weak) roots: entry point and unwind-covered starts, then other starts and symbols."""
    text = next(s for s in info['segments'] if s['name'] == '__TEXT')
    starts, strong, symbols, at = set(), set(), set(), 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        if command == LC_FUNCTION_STARTS:
            offset, length = struct.unpack_from('<II', data, at + 8)
            cursor, address = offset, text['vmaddr']
            while cursor < offset + length and data[cursor]:
                delta, cursor = uleb128(data, cursor, offset + length)
                address += delta
                starts.add(address)
        elif command == LC_MAIN:
            strong.add(text['vmaddr'] + struct.unpack_from('<Q', data, at + 8)[0])
        elif command == LC_UNIXTHREAD:
            flavor, count = struct.unpack_from('<II', data, at + 8)
            if flavor != 6 or count != 68:
                raise ValueError('unsupported LC_UNIXTHREAD state')
            strong.add(struct.unpack_from('<Q', data, at + 16 + 32 * 8)[0])
        elif command == LC_SYMTAB:
            symoff, nsyms = struct.unpack_from('<II', data, at + 8)
            for index in range(nsyms):
                kind = data[symoff + 16 * index + 4]
                if not kind & 0xe0 and kind & 0xe == 0xe:
                    symbols.add(struct.unpack_from('<Q', data, symoff + 16 * index + 8)[0])
        at += size
    covering = unwind_encodings(data, info, text['vmaddr'])
    keys = sorted(covering)
    for address in starts:
        index = bisect.bisect_right(keys, address) - 1
        if index >= 0 and covering[keys[index]]:
            strong.add(address)
    return strong, (starts | symbols) - strong, starts


def unwind_encodings(data, info, text_base):
    """Function address -> compact unwind encoding, from __TEXT,__unwind_info."""
    section = next((s for g in info['segments'] for s in g['sections'] if s['name'] == '__unwind_info'), None)
    if section is None:
        return {}
    blob = data[section['offset']:section['offset'] + section['size']]
    version, common_off, common_count, _, _, index_off, index_count = struct.unpack_from('<7I', blob)
    if version != 1:
        raise ValueError('unsupported __unwind_info version')
    common = struct.unpack_from(f'<{common_count}I', blob, common_off)
    result = {}
    for i in range(index_count - 1):
        function, second, _ = struct.unpack_from('<III', blob, index_off + 12 * i)
        kind = struct.unpack_from('<I', blob, second)[0]
        if kind == 2:
            _, entries_off, count = struct.unpack_from('<IHH', blob, second)
            for j in range(count):
                offset, encoding = struct.unpack_from('<II', blob, second + entries_off + 8 * j)
                result[text_base + offset] = encoding
        elif kind == 3:
            _, entries_off, count, local_off, local_count = struct.unpack_from('<IHHHH', blob, second)
            local = struct.unpack_from(f'<{local_count}I', blob, second + local_off)
            for j in range(count):
                entry = struct.unpack_from('<I', blob, second + entries_off + 4 * j)[0]
                result[text_base + function + (entry & 0xffffff)] = (common + local)[entry >> 24]
        else:
            raise ValueError('unsupported __unwind_info page kind')
    return result


def unwind_lsdas(blob, text_base):
    """Function address -> LSDA address, from the LSDA index of an __unwind_info blob."""
    version, _, _, _, _, index_off, index_count = struct.unpack_from('<7I', blob)
    if version != 1:
        raise ValueError('unsupported __unwind_info version')
    result = {}
    if index_count < 2:
        return result
    first = struct.unpack_from('<I', blob, index_off + 8)[0]
    last = struct.unpack_from('<I', blob, index_off + 12 * (index_count - 1) + 8)[0]
    for at in range(first, last, 8):
        function, lsda = struct.unpack_from('<II', blob, at)
        result[text_base + function] = text_base + lsda
    return result


def encoded(data, at, encoding):
    """One call-site table value: (value, next offset)."""
    if encoding == 0x01:
        return uleb128(data, at, len(data))
    if encoding == 0x03:
        return struct.unpack_from('<I', data, at)[0], at + 4
    if encoding == 0x0b:
        return struct.unpack_from('<i', data, at)[0], at + 4
    raise ValueError(f'unsupported LSDA call-site encoding {encoding:#x}')


def landing_pads(read, function, lsda):
    """Landing pads of one LSDA (the Itanium C++ ABI exception table), with LPStart at the function."""
    header = read(lsda, 32)
    if header[0] != 0xff:
        raise ValueError(f'LSDA at {lsda:#x} has an explicit LPStart')
    at = 1
    if header[at] != 0xff:
        _, at = uleb128(header, at + 1, len(header))
    else:
        at += 1
    call_site_encoding = header[at]
    length, at = uleb128(header, at + 1, len(header))
    table = read(lsda, at + length)
    pads = set()
    while at < len(table):
        _, at = encoded(table, at, call_site_encoding)
        _, at = encoded(table, at, call_site_encoding)
        pad, at = encoded(table, at, call_site_encoding)
        _, at = uleb128(table, at, len(table))
        if pad:
            pads.add(function + pad)
    return pads


def pointer_targets(data, info):
    """Rebase targets of LC_DYLD_CHAINED_FIXUPS (arm64e, kernel, userland and userland24 chains)."""
    base = next(s for s in info['segments'] if s['name'] == '__TEXT')['vmaddr']
    targets, at = set(), 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        at += size
        if command != LC_DYLD_CHAINED_FIXUPS:
            continue
        offset = struct.unpack_from('<I', data, at - size + 8)[0]
        version, starts_offset = struct.unpack_from('<II', data, offset)
        if version != 0:
            raise ValueError('unsupported chained fixups version')
        image = offset + starts_offset
        for index in range(struct.unpack_from('<I', data, image)[0]):
            info_offset = struct.unpack_from('<I', data, image + 4 + 4 * index)[0]
            if not info_offset:
                continue
            seg = image + info_offset
            _, page_size, pointer_format, segment_offset, _, page_count = struct.unpack_from('<IHHQIH', data, seg)
            if pointer_format not in (DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_ARM64E_KERNEL,
                                      DYLD_CHAINED_PTR_ARM64E_USERLAND, DYLD_CHAINED_PTR_ARM64E_USERLAND24):
                raise ValueError(f'unsupported chained pointer format {pointer_format}')
            absolute = pointer_format == DYLD_CHAINED_PTR_ARM64E
            segment = next(s for s in info['segments'] if s['vmaddr'] - base == segment_offset)
            for page in range(page_count):
                start = struct.unpack_from('<H', data, seg + 22 + 2 * page)[0]
                if start == 0xffff:
                    continue
                cursor = segment['fileoff'] + page * page_size + start
                while True:
                    value = struct.unpack_from('<Q', data, cursor)[0]
                    if not value >> 62 & 1:
                        if value >> 63:
                            targets.add(base + (value & 0xffffffff))
                        else:
                            targets.add((0 if absolute else base) + (value & 0x7ffffffffff))
                    step = value >> 51 & 0x7ff
                    if not step:
                        break
                    cursor += 8 * step
    return targets


def materialized(insns, code):
    """Addresses formed by adr, or adrp then add on the same register, in proven code."""
    found = set()
    for pc in code:
        mnemonic, operands = insns[pc]
        if mnemonic == 'adr':
            found.add(int(operands.split('#')[1], 0))
        elif mnemonic == 'adrp' and pc + 4 in code:
            register, page = operands.split(', #')
            following = insns[pc + 4]
            prefix = f'{register}, {register}, #'
            if following[0] == 'add' and following[1].startswith(prefix):
                immediate = re.fullmatch(r'(0x[0-9a-f]+|[0-9]+)(?:, lsl #(12))?',
                                         following[1][len(prefix):])
                if immediate:
                    found.add(int(page, 0) + (int(immediate[1], 0) << int(immediate[2] or 0)))
    return found


def poe2_instruction(word):
    """Decode TCHANGE{F,B} for CFG discovery, without lowering or emulation.

    These FEAT_S1POE2 instructions change permission-overlay TIndex state and
    have a register result; no A77 execution semantics are supplied here.
    LLVM models their normal control flow as fall-through. Traps remain runtime
    behavior, as for other potentially faulting instructions in this walk.

    Encoding reference: LLVM llvm/test/MC/AArch64/arm-poe2.s,
    blob dbed9ba599067923194b15c63e365c8a4f2d38e6 (the eight TCHANGE vectors).
    https://github.com/llvm/llvm-project/blob/main/llvm/test/MC/AArch64/arm-poe2.s
    Flow evidence: TCHANGERegInst/TCHANGEImmInst inherit I -> EncodedI ->
    AArch64Inst -> Instruction without branch/call/return/terminator overrides;
    Instruction's flow flags default to false. The four defm declarations only
    add HasS1POE2. Checked against LLVM commit
    8ac298779c251819b6bab7739464547ee014aabd on 2026-11-23:
    https://github.com/llvm/llvm-project/blob/8ac298779c251819b6bab7739464547ee014aabd/llvm/lib/Target/AArch64/AArch64InstrFormats.td
    https://github.com/llvm/llvm-project/blob/8ac298779c251819b6bab7739464547ee014aabd/llvm/lib/Target/AArch64/AArch64InstrInfo.td
    https://github.com/llvm/llvm-project/blob/8ac298779c251819b6bab7739464547ee014aabd/llvm/include/llvm/Target/Target.td
    Fixed bits are checked separately for register and 7-bit-immediate forms;
    bit 17 is NB, bit 18 selects the backward transition. Unknown neighbors
    remain undecoded. This function grants no root or reachability evidence.
    """
    forms = ((0xFFFDFC00, 0xD5800000, 'tchangef', False),
             (0xFFFDFC00, 0xD5840000, 'tchangeb', False),
             (0xFFFDF000, 0xD5900000, 'tchangef', True),
             (0xFFFDF000, 0xD5940000, 'tchangeb', True))
    for mask, opcode, mnemonic, immediate in forms:
        if word & mask != opcode:
            continue
        register = lambda index: 'xzr' if index == 31 else f'x{index}'
        operand = f'#{(word >> 5) & 127}' if immediate else register((word >> 5) & 31)
        operands = f'{register(word & 31)}, {operand}'
        if word & (1 << 17):
            operands += ', nb'
        return mnemonic, operands
    return None


def section_instructions(decoder, data, section):
    # disasm_lite keeps the native instruction array until its iterator ends.
    # AArch64 instructions have fixed width, so an aligned cut preserves decoding.
    batch_bytes = 64 * 1024
    for relative in range(0, section['size'], batch_bytes):
        start = section['offset'] + relative
        length = min(batch_bytes, section['size'] - relative)
        yield from decoder.disasm_lite(data[start:start + length], section['addr'] + relative)


def decode(data, sections, oracle=None):
    """{address: (mnemonic, operands)}; a word Capstone cannot decode has a '.'-prefixed mnemonic.

    oracle, when given, maps a set of such words to {word: (mnemonic, operands)} for those it
    knows to be straight-line instructions (llvm_oracle)."""
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.skipdata = True
    table = {}
    for section in sections:
        start = section['offset']
        for address, size, mnemonic, operands in section_instructions(decoder, data, section):
            if mnemonic.startswith('.') and size == 4:
                word = struct.unpack_from('<I', data, start + address - section['addr'])[0]
                explicit = poe2_instruction(word)
                if explicit:
                    mnemonic, operands = explicit
            if mnemonic in UNMODELED_FLOW:
                mnemonic = '.unmodeled-' + mnemonic
            table[address] = (intern(mnemonic), operands)
    if oracle:
        unknown = {}
        for section in sections:
            low, high = section['addr'], section['addr'] + section['size']
            for address, (mnemonic, _) in table.items():
                if mnemonic.startswith('.') and low <= address < high:
                    unknown[address] = struct.unpack_from('<I', data, section['offset'] + address - low)[0]
        known = oracle(set(unknown.values()))
        for address, word in unknown.items():
            if word in known:
                mnemonic, operands = known[word]
                table[address] = ('.unmodeled-' + mnemonic if mnemonic in UNMODELED_FLOW else mnemonic,
                                  operands)
    return table


AMX_MASK, AMX_BASE = 0xfffff000, 0x00201000
LLVM_FEATURES = ('+v9.5a,+sve2,+sve2-aes,+sve2-sha3,+sve2-sm4,+sve2-bitperm,+sve2p1,+sme2p1,+sme-f64f64,'
                 '+sme-i16i64,+sme-f16f16,+sme-lutv2,+bf16,+i8mm,+mops,+cssc,+sha3,+sm4,+fp16fml,+rcpc3,+lse128,'
                 '+the,+d128,+gcs,+ite,+lut,+faminmax,+fp8,+jsconv,+complxnum,+rand,+mte,+ls64,+wfxt,+hbc,+flagm,'
                 '+altnzcv,+pauth,+predres,+sb,+specrestrict,+ssbs,+tme')
# Anything that can change the flow of control stays undecodable, so a walk never steps over it.
LLVM_CONTROL = re.compile(r'(b|bl|br|blr|b\..*|bc\..*|cb.*|tbn?z|ret.*|eret.*|bra.*|blra.*|brk|hlt|udf|svc|hvc|smc|'
                          r'tstart|tcommit|tcancel|ttest)')


def llvm_oracle(words):
    """Straight-line instructions among words Capstone cannot decode: Apple AMX words
    (0x00201000-0x00201fff, which do not branch) and whatever llvm-mc decodes with every A-profile
    feature (SME2, newer SVE) unless it is a branch, return, trap or exception."""
    import subprocess
    known = {word: ('amx', f'{(word >> 5) & 0x7f}, {word & 0x1f}') for word in words
             if word & AMX_MASK == AMX_BASE}
    rest = sorted(word for word in words if word not in known)
    if not rest:
        return known
    text = ''.join(f'0x{w & 0xff:02x} 0x{(w >> 8) & 0xff:02x} 0x{(w >> 16) & 0xff:02x} 0x{w >> 24:02x}\n'
                   for w in rest)
    result = subprocess.run(['llvm-mc', '--disassemble', '-triple=aarch64', f'-mattr={LLVM_FEATURES}'],
                            input=text, capture_output=True, text=True, check=False)
    invalid = {int(m.group(1)) for m in re.finditer(r'<stdin>:(\d+):\d+: warning: invalid instruction encoding',
                                                   result.stderr)}
    lines = iter(line.strip() for line in result.stdout.splitlines()
                 if line.startswith('\t') and not line.lstrip().startswith('.'))
    for number, word in enumerate(rest, 1):
        if number in invalid:
            continue
        mnemonic, _, operands = next(lines).partition('\t')
        if not LLVM_CONTROL.fullmatch(mnemonic):
            known[word] = (mnemonic, operands.strip())
    return known


def register_alias(name):
    """Use one name for each general register, including writes to its W view."""
    aliases = {'fp': 'x29', 'lr': 'x30', 'wsp': 'sp', 'wzr': 'xzr'}
    if name in aliases:
        return aliases[name]
    if re.fullmatch(r'w(?:[0-9]|[12][0-9]|30)', name):
        return 'x' + name[1:]
    return name


@lru_cache(maxsize=1)
def effect_decoder():
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    return decoder


@lru_cache(maxsize=4096)
def word_writes(word):
    """Register writes of one straight-line word, or None for unknown effects.

    Cache only address-independent effects, not a decoded branch destination or
    an instruction object retaining Capstone's native allocation. The bounded
    cache is per worker. LLVM-only/explicit decoder extensions do not supply
    register-effect evidence and therefore cannot be crossed by this search.
    """
    try:
        instruction = next(effect_decoder().disasm(struct.pack('<I', word), 0, count=1), None)
        if instruction is None or instruction.size != 4 or not instruction.id:
            return None
        control = {CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET,
                   CS_GRP_PRIVILEGE, CS_GRP_BRANCH_RELATIVE}
        if control.intersection(instruction.groups) or LLVM_CONTROL.fullmatch(instruction.mnemonic):
            return None
        # AArch64 regs_access in the pinned Capstone reports explicit REG/MEM
        # accesses. An MSR system-register operand is not an ordinary REG;
        # do not mistake a missing NZCV/PSTATE write for preservation.
        if instruction.mnemonic in ('msr', 'sys', 'sysl', 'dcps1', 'dcps2', 'dcps3', 'drps'):
            return None
        if any(operand.type == ARM64_OP_REG and operand.access not in (1, 2, 3)
               for operand in instruction.operands):
            return None
        _, registers = instruction.regs_access()
        names = [instruction.reg_name(register) for register in registers]
        if any(not name for name in names):
            return None
        writes = {register_alias(name) for name in names}
        # Capstone 5.0.6 omits the implicit NZCV write for these operand-free
        # FlagM instructions (including update_flags, derived from that same
        # metadata). Their only register result is architectural NZCV.
        if instruction.update_flags or instruction.mnemonic in ('cfinv', 'axflag', 'xaflag'):
            writes.add('nzcv')
        return frozenset(writes)
    except CsError:
        return None


def preserves_registers(insns, data, va_to_off, at, protected):
    """One actual four-byte instruction preserves the search's reaching values."""
    if at not in insns:
        return False
    try:
        offset = va_to_off(at, 4)
        if offset < 0 or offset + 4 > len(data):
            return False
        writes = word_writes(struct.unpack_from('<I', data, offset)[0])
    except (ValueError, IndexError, struct.error):
        return False
    return writes is not None and not protected.intersection(writes)


def jump_table(insns, data, va_to_off, pc):
    """Decode a hardened dispatch with an intact local clamp, or return None.

    Every crossed word must preserve the reaching index, flags, or register
    bound. This local data-flow check does not by itself prove that every
    incoming CFG path executes the clamp; callers must not treat it as a
    general dominance proof.
    """
    values = []
    for index, (mnemonic, pattern) in enumerate(DISPATCH):
        at = pc - 4 * (len(DISPATCH) - 1 - index)
        found = insns.get(at)
        match = found and found[0] == mnemonic and re.fullmatch(pattern, found[1])
        if not match:
            return None
        values += [int(group, 0) for group in match.groups()]
    page, low, anchor = values
    # The clamp: cmp x16, #N (or a register holding N) then csel x16, x16, xzr, ls. Kernel code
    # has csneg x16, x16, xzr, ls, the same selection (the negated zero register is zero).
    limit = guard_start = None
    for at in range(pc - 24, pc - 24 - 4 * 8, -4):
        found = insns.get(at)
        if not found:
            return None
        if found in (('csel', 'x16, x16, xzr, ls'), ('csneg', 'x16, x16, xzr, ls')):
            for before in range(at - 4, at - 4 * 6, -4):
                compare = insns.get(before)
                if not compare:
                    return None
                if compare[0] == 'cmp':
                    immediate = re.fullmatch(r'x16, #(0x[0-9a-f]+|[0-9]+)(?:, lsl #(12))?', compare[1])
                    register = re.fullmatch(r'x16, (x(?:[0-9]|[12][0-9]|30)|fp|lr|xzr)', compare[1])
                    if immediate:
                        limit = int(immediate[1], 0) << int(immediate[2] or 0)
                        guard_start = before
                        break
                    if register:
                        bound = register_alias(register[1])
                        if bound == 'xzr':
                            limit = 0
                            guard_start = before
                            break
                        for setter in range(before - 4, before - 4 * 6, -4):
                            move = insns.get(setter)
                            if not move:
                                return None
                            constant = (re.fullmatch(r'([wx](?:[0-9]|[12][0-9]|30)|fp|lr), '
                                                     r'#(0x[0-9a-f]+|[0-9]+)', move[1])
                                        if move[0] == 'mov' else None)
                            if constant and register_alias(constant[1]) == bound:
                                limit = int(constant[2], 0)
                                guard_start = setter
                                if limit >= 1 << (32 if constant[1].startswith('w') else 64):
                                    return None
                                break
                            if not preserves_registers(insns, data, va_to_off, setter, {bound}):
                                return None
                        break
                if not preserves_registers(insns, data, va_to_off, before, {'x16', 'nzcv'}):
                    return None
            break
        if not preserves_registers(insns, data, va_to_off, at, {'x16'}):
            return None
    if limit is None:
        return None
    base = page + low
    start = va_to_off(base, 4 * (limit + 1))
    entries = struct.unpack_from(f'<{limit + 1}i', data, start)
    return dict(dispatch=pc, guard_start=guard_start, table=base, entries=limit + 1, anchor=anchor,
                targets=sorted({anchor + entry for entry in entries}))


def table_entry_context(insns, data, va_to_off, roots=()):
    """Conservative static entry superset, computed before any visited filtering.

    Every decoded direct branch/call, every materialized code address, and
    every locally recognized table contributes potential entries, even when
    its source is not admitted as code or its own clamp can be bypassed.
    These addresses only disqualify table bounds; they never grant code roots.
    The caller supplies all declared roots, including weak roots and incoming
    cross-owner roots, without filtering them through previously proven code.
    """
    entries = set(roots)
    entries.update(materialized(insns, insns))
    candidates = {}
    for pc, (mnemonic, operands) in insns.items():
        if mnemonic in ('b', 'bl') or mnemonic.startswith(('b.', 'bc.')) or mnemonic in CONDITIONAL:
            target = TARGET.search(operands)
            if target is None:
                raise ValueError(f'direct control flow has no decoded target at {pc:#x}')
            entries.add(int(target[1], 0))
        if mnemonic == 'br' and operands == 'x16':
            table = jump_table(insns, data, va_to_off, pc)
            if table is not None:
                candidates[pc] = table
                entries.update(table['targets'])
    ordered = sorted(entries)
    rejected = {}
    for pc, table in candidates.items():
        at = bisect.bisect_right(ordered, table['guard_start'])
        if at < len(ordered) and ordered[at] <= pc:
            rejected[pc] = ordered[at]
    return dict(candidates=candidates, entries=ordered, rejected=rejected)


def walk(insns, data, va_to_off, roots, code, data_words, strict, boundaries, external=None,
         external_pending=None, table_context=None):
    """Follow control flow; a strict walk returns None instead of stopping at a doubtful word.

    external, when given, covers code outside these sections that another proof owns (an image
    calling another directly inside a shared cache); reaching it is recorded in external.reached
    and ends that path without counting against the walk."""
    roots = tuple(roots)
    if table_context is None:
        table_context = table_entry_context(insns, data, va_to_off, set(roots) | set(boundaries))
    # This also covers a new caller entering a dispatch already present in code.
    for pc, entry in table_context['rejected'].items():
        if pc in code:
            raise ValueError(f'jump-table clamp at {pc:#x} can be bypassed by entry {entry:#x}')
    found_code, tables, anomalies, work = set(), [], [], list(roots)
    while work:
        pc, after_call = work.pop(), False
        while pc not in code and pc not in found_code:
            found = insns.get(pc)
            if found is None and external is not None and pc in external:
                (external.reached if external_pending is None else external_pending).add(pc)
                break
            if strict and found and found[0] == 'udf' and after_call:
                break  # the trap clang places after a call to a noreturn function
            if found is None or found[0].startswith('.') or pc in data_words or (strict and found[0] == 'udf'):
                if strict:
                    return None
                kind = ('leaves_instruction_sections' if found is None else 'reaches_table' if pc in data_words
                        else 'reaches_undecodable_word')
                anomalies.append(dict(kind=kind, address=hex(pc)))
                break
            mnemonic, operands = found
            # A call's stack-argument cleanup still counts as following the call.
            after_call = mnemonic in CALLS or (after_call and mnemonic == 'add' and operands.startswith('sp, sp, #'))
            found_code.add(pc)
            target = TARGET.search(operands)
            if mnemonic == 'b':
                work.append(int(target.group(1), 0))
                break
            if mnemonic == 'bl' or mnemonic.startswith(('b.', 'bc.')) or mnemonic in CONDITIONAL:
                work.append(int(target.group(1), 0))
            elif mnemonic in STOPS:
                break
            elif mnemonic in INDIRECT:
                if pc in table_context['rejected']:
                    entry = table_context['rejected'][pc]
                    raise ValueError(f'jump-table clamp at {pc:#x} can be bypassed by entry {entry:#x}')
                table = table_context['candidates'].get(pc) if mnemonic == 'br' else None
                if table:
                    tables.append(table)
                    work += table['targets']
                break
            pc += 4
            if pc in boundaries:
                # Only a call to a noreturn function may run into the next atom, unless that atom
                # is already proven code (offlineasm places a global label every few instructions).
                if strict and not after_call and pc not in code and pc not in found_code:
                    return None
                break
    return found_code, tables, anomalies


def table_words(tables):
    words = set()
    for table in tables:
        words.update(range(table['table'], table['table'] + 4 * table['entries'], 4))
    return words


def image_landing_pads(data, info, va_to_off):
    """Exception landing pads named by the LSDAs that a standalone image's __unwind_info lists."""
    section = next((s for g in info['segments'] for s in g['sections'] if s['name'] == '__unwind_info'), None)
    if section is None:
        return set()
    text = next(s for s in info['segments'] if s['name'] == '__TEXT')

    def read(address, length):
        offset = va_to_off(address, 1)
        return data[offset:offset + length]
    pads = set()
    for function, lsda in unwind_lsdas(data[section['offset']:section['offset'] + section['size']],
                                       text['vmaddr']).items():
        pads |= landing_pads(read, function, lsda)
    return pads


def prove(data, info, sections, va_to_off, oracle=None, gaps=False):
    """Returns (insns, code, table words, tables, anomalies, roots); code maps address to root grade.

    Exception landing pads are a root grade between code pointers and bare starts."""
    insns = decode(data, sections, oracle)
    strong, weak, starts = seeds(data, info)
    ordered = [('landing', image_landing_pads(data, info, va_to_off))]
    return prove_roots(insns, data, va_to_off, strong, weak, starts, pointer_targets(data, info), ordered,
                       gaps=gaps)


def prove_roots(insns, data, va_to_off, strong, weak, starts, pointers, ordered=(), external=None, gaps=False):
    """The proof from supplied roots. Strong roots are walked first. Then come code pointers and
    adr/adrp addresses, then each (grade, roots) of ordered in turn (exception landing pads, stub
    entries, calls from other images), then bare starts. Each root after the strong ones is accepted
    only after a strict tentative walk.

    gaps, when set, adds a last grade: code left inside a proven atom after a proven terminator
    (a dead epilogue or error exit nothing branches to), accepted only by the same strict walk,
    which may not run into another atom."""
    ordered = tuple((grade, tuple(extra)) for grade, extra in ordered)
    potential_entries = set(strong) | set(weak) | set(starts) | set(pointers)
    for _, extra in ordered:
        potential_entries.update(extra)
    table_context = table_entry_context(insns, data, va_to_off, potential_entries)
    del table_context['entries'], potential_entries
    found, tables, anomalies = walk(insns, data, va_to_off, sorted(a for a in strong if a in insns), set(), set(),
                                    False, starts, external, table_context=table_context)
    code = dict.fromkeys(found, 'unwind')
    del found
    data_words = table_words(tables)
    tried, rejected = set(), []

    def attempt(root, grade):
        tried.add(root)
        # Do not publish cross-image edges until this tentative proof commits.
        pending = set()
        result = walk(insns, data, va_to_off, [root], code, data_words, True, starts, external, pending,
                      table_context)
        if result is None or any(word in code or word in result[0] for word in table_words(result[1])):
            rejected.append(dict(address=hex(root), grade=grade))
            return False
        if external is not None:
            external.reached.update(pending)
        code.update(dict.fromkeys(result[0], grade))
        tables.extend(result[1])
        data_words.update(table_words(result[1]))
        return True

    accepted = dict(pointer=0, start=0)
    while True:
        candidates = sorted(a for a in pointers | materialized(insns, code)
                            if a in insns and a not in code and a not in data_words and a not in tried)
        if not candidates:
            break
        accepted['pointer'] += sum(attempt(root, 'pointer') for root in candidates)
    for grade, extra in ordered:
        accepted.setdefault(grade, 0)
        for root in sorted(extra):
            if root in insns and root not in code and root not in data_words and root not in tried:
                accepted[grade] += attempt(root, grade)
    for root in sorted(weak):
        if root in insns and root not in code and root not in data_words and root not in tried:
            accepted['start'] += attempt(root, 'start')
    # A root that ran into a start proven only later is tried again until nothing changes.
    while True:
        retry, rejected[:] = rejected[:], []
        progress = False
        for entry in retry:
            root = int(entry['address'], 16)
            if root in code or root in data_words:
                continue
            if attempt(root, entry['grade']):
                accepted[entry['grade']] = accepted.get(entry['grade'], 0) + 1
                progress = True
        if not progress:
            break
    if gaps:
        accepted['gap'] = 0
        atoms = sorted(starts)
        while True:
            progress = False
            for index, start in enumerate(atoms):
                if start not in code:
                    continue
                end = atoms[index + 1] if index + 1 < len(atoms) else max(insns) + 4
                for pc in range(start, end - 4, 4):
                    after = pc + 4
                    if (pc in code and (insns[pc][0] in STOPS or insns[pc][0] in INDIRECT or insns[pc][0] == 'b')
                            and after in insns and after not in code and after not in data_words
                            and after not in tried and attempt(after, 'gap')):
                        accepted['gap'] += 1
                        progress = True
            if not progress:
                break
    conflicts = sorted(code.keys() & data_words)
    if conflicts:
        raise ValueError(f'jump table overlaps proven code at {conflicts[0]:#x}')
    roots = dict(unwind=len(strong), pointer_accepted=accepted['pointer'], start_accepted=accepted['start'],
                 rejected=rejected)
    for grade, _ in ordered:
        roots[f'{grade}_accepted'] = accepted[grade]
    if gaps:
        roots['gap_accepted'] = accepted['gap']
    return insns, code, data_words, tables, anomalies, roots
