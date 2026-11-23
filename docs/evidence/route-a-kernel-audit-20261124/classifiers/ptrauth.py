"""Auditable, equal-width lowering of the original AArch64 PAuth instructions.

This implements a *plain-pointer compatibility ABI*, not pointer authentication.
It is valid only when loaders, fixups, the kernel and all participating code agree
to produce raw pointers.  In particular, replacing XPAC by NOP does not strip an
arbitrary signed pointer, and replacing AUT by NOP does not validate anything.
The caller must assert that ABI explicitly with ``plain_pointers=True``.

Encoding reference: LLVM's original, accepted PAuth assembler/disassembler patch
https://reviews.llvm.org/D36517 (AuthBase, BaseAuthLoad, SignAuth* and MC vectors).
Semantic reference: https://clang.llvm.org/docs/PointerAuthentication.html .

The decoder is deliberately limited to the original Armv8.3 PAuth families. A
``None`` result means "not recognized here", not "compatible with Cortex-A77".
An independent target-feature scan is still required for an entire executable.
"""

from __future__ import annotations

from typing import Any


NOP = 0xD503201F
RET = 0xD65F03C0


class LoweringError(ValueError):
    """A recognized instruction cannot be lowered under the requested contract."""

    def __init__(self, word: int, mnemonic: str, reason: str) -> None:
        self.word = word
        self.mnemonic = mnemonic
        self.reason = reason
        super().__init__(f"{mnemonic} (0x{word:08x}): {reason}")


_REGISTER_FORMS = {
    0xDAC10000: "PACIA", 0xDAC10400: "PACIB",
    0xDAC10800: "PACDA", 0xDAC10C00: "PACDB",
    0xDAC11000: "AUTIA", 0xDAC11400: "AUTIB",
    0xDAC11800: "AUTDA", 0xDAC11C00: "AUTDB",
}
_ZERO_FORMS = {
    0xDAC123E0: "PACIZA", 0xDAC127E0: "PACIZB",
    0xDAC12BE0: "PACDZA", 0xDAC12FE0: "PACDZB",
    0xDAC133E0: "AUTIZA", 0xDAC137E0: "AUTIZB",
    0xDAC13BE0: "AUTDZA", 0xDAC13FE0: "AUTDZB",
    0xDAC143E0: "XPACI", 0xDAC147E0: "XPACD",
}
_HINT_FORMS = {
    0xD503211F: "PACIA1716", 0xD503215F: "PACIB1716",
    0xD503219F: "AUTIA1716", 0xD50321DF: "AUTIB1716",
    0xD503231F: "PACIAZ", 0xD503235F: "PACIBZ",
    0xD503239F: "AUTIAZ", 0xD50323DF: "AUTIBZ",
    0xD503233F: "PACIASP", 0xD503237F: "PACIBSP",
    0xD50323BF: "AUTIASP", 0xD50323FF: "AUTIBSP",
    0xD50320FF: "XPACLRI",
}
_BRANCH_REGISTER_FORMS = {
    0xD71F0800: "BRAA", 0xD71F0C00: "BRAB",
    0xD73F0800: "BLRAA", 0xD73F0C00: "BLRAB",
}
_BRANCH_ZERO_FORMS = {
    0xD61F081F: "BRAAZ", 0xD61F0C1F: "BRABZ",
    0xD63F081F: "BLRAAZ", 0xD63F0C1F: "BLRABZ",
}
_RETURNS = {0xD65F0BFF: "RETAA", 0xD65F0FFF: "RETAB"}
_EXCEPTION_RETURNS = {0xD69F0BFF: "ERETAA", 0xD69F0FFF: "ERETAB"}


def _check_word(word: int) -> None:
    if isinstance(word, bool) or not isinstance(word, int):
        raise TypeError("instruction word must be an unsigned 32-bit integer")
    if not 0 <= word <= 0xFFFFFFFF:
        raise ValueError("instruction word must be an unsigned 32-bit integer")


def _record(word: int, mnemonic: str, family: str, replacement: int | None,
            action: str, operands: dict[str, Any] | None = None,
            reason: str | None = None) -> dict[str, Any]:
    return {
        "word": word,
        "mnemonic": mnemonic,
        "family": family,
        "operands": operands or {},
        "requires_plain_pointers": True,
        "authentication_preserved": False,
        "supported": replacement is not None,
        "action": action,
        "replacement": replacement,
        "reason": reason,
    }


def describe(word: int) -> dict[str, Any] | None:
    """Return JSON-serializable PAuth audit information, or ``None``.

    ``supported`` means an equal-width replacement exists under the explicit
    plain-pointer ABI, not that it preserves PAC checks or that an image is safe
    to run. ``operands`` records register numbers, with SP/ZR distinctions where
    they matter. Unsupported instructions retain a machine-readable ``reason``.
    """
    _check_word(word)

    if word in _HINT_FORMS:
        # These exact hints already execute as NOP on the non-PAuth A77 target.
        # Keep their encodings rather than treating *all* HINT space as PAuth.
        return _record(word, _HINT_FORMS[word], "hint", word, "preserve_hint")

    opcode = word & 0xFFFFFC00
    if opcode in _REGISTER_FORMS:
        mnemonic = _REGISTER_FORMS[opcode]
        return _record(word, mnemonic, "auth" if mnemonic.startswith("AUT") else "sign",
                       NOP, "nop", {
                           "destination": word & 31,
                           "modifier": (word >> 5) & 31,
                           "modifier_is_sp": ((word >> 5) & 31) == 31,
                       })

    opcode = word & 0xFFFFFFE0
    if opcode in _ZERO_FORMS:
        mnemonic = _ZERO_FORMS[opcode]
        family = ("strip" if mnemonic.startswith("XPAC") else
                  "auth" if mnemonic.startswith("AUT") else "sign")
        return _record(word, mnemonic, family, NOP, "nop",
                       {"destination": word & 31})

    opcode = word & 0xFFFFFC00
    mnemonic = _BRANCH_REGISTER_FORMS.get(opcode)
    modifier = word & 31
    zero_modifier = False
    if mnemonic is None:
        # Zero-modifier forms require *all* low five bits to be one. Do not
        # convert neighboring unallocated words into newly executable branches.
        mnemonic = _BRANCH_ZERO_FORMS.get(word & 0xFFFFFC1F)
        modifier = 0
        zero_modifier = True
    if mnemonic is not None:
        is_call = mnemonic.startswith("BLR")
        replacement = (0xD63F0000 if is_call else 0xD61F0000) | (word & 0x3E0)
        return _record(word, mnemonic, "call" if is_call else "branch",
                       replacement, "plain_branch", {
                           "target": (word >> 5) & 31,
                           "modifier": modifier,
                           "modifier_is_sp": not zero_modifier and modifier == 31,
                           "zero_modifier": zero_modifier,
                       })

    if word in _RETURNS:
        return _record(word, _RETURNS[word], "return", RET, "plain_return",
                       {"target": 30, "modifier_is_sp": True})
    if word in _EXCEPTION_RETURNS:
        return _record(word, _EXCEPTION_RETURNS[word], "exception_return", None,
                       "reject", reason="privileged_exception_return_not_supported")

    if word & 0xFF200400 == 0xF8200400:
        key_b = bool(word & (1 << 23))
        writeback = bool(word & (1 << 11))
        base, destination = (word >> 5) & 31, word & 31
        immediate = ((word >> 12) & 0x1FF) | (((word >> 22) & 1) << 9)
        if immediate & 0x200:
            immediate -= 0x400
        offset = immediate * 8
        operands = {
            "base": base, "base_is_sp": base == 31,
            "destination": destination, "destination_is_zero": destination == 31,
            "offset": offset, "writeback": writeback,
        }
        mnemonic = "LDRAB" if key_b else "LDRAA"
        # The original authenticates the *base*, then adds offset, then loads.
        # Ordinary loads are equivalent only when that base is already raw.
        if writeback and base == destination and base != 31:
            return _record(word, mnemonic, "load", None, "reject", operands,
                           "constrained_unpredictable_writeback_overlap")
        registers = (base << 5) | destination
        if writeback:
            if not -256 <= offset <= 255:
                return _record(word, mnemonic, "load", None, "reject", operands,
                               "writeback_offset_needs_expansion")
            replacement = 0xF8400C00 | ((offset & 0x1FF) << 12) | registers
            action = "ldr_pre_index"
        elif offset >= 0:
            replacement = 0xF9400000 | ((offset // 8) << 10) | registers
            action = "ldr_unsigned_offset"
        elif offset >= -256:
            replacement = 0xF8400000 | ((offset & 0x1FF) << 12) | registers
            action = "ldur_signed_offset"
        else:
            return _record(word, mnemonic, "load", None, "reject", operands,
                           "negative_offset_needs_expansion")
        return _record(word, mnemonic, "load", replacement, action, operands)

    if word & 0xFFE0FC00 == 0x9AC03000:
        # PACGA computes a generic data signature; it is neither a pointer nor
        # an identity operation. In particular, Rm==31 denotes SP, not XZR.
        return _record(word, "PACGA", "generic_signature", None, "reject", {
            "destination": word & 31,
            "source": (word >> 5) & 31,
            "source_is_zero": ((word >> 5) & 31) == 31,
            "modifier": (word >> 16) & 31,
            "modifier_is_sp": ((word >> 16) & 31) == 31,
        }, "generic_signature_requires_a_separate_abi")

    return None


def lower(word: int, *, plain_pointers: bool = False,
          pacga_policy: str = "reject") -> tuple[str, int] | None:
    """Return ``(mnemonic, replacement_word)`` under the requested ABI.

    Reject by exception rather than truncating load offsets or inventing a PACGA
    result. The only currently supported ``pacga_policy`` is ``'reject'``.
    Hints retain their bytes, but still require the plain-pointer contract: on
    this target they do not authenticate or normalize signed pointers.
    """
    if not isinstance(plain_pointers, bool):
        raise TypeError("plain_pointers must be a bool")
    if pacga_policy != "reject":
        raise ValueError("unsupported pacga_policy; only 'reject' is implemented")
    info = describe(word)
    if info is None:
        return None
    if not info["supported"]:
        raise LoweringError(word, info["mnemonic"], info["reason"])
    if not plain_pointers:
        raise LoweringError(word, info["mnemonic"], "plain_pointer_abi_not_asserted")
    return info["mnemonic"], info["replacement"]
