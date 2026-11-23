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
