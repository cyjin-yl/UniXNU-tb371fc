"""Adapt the shared, fail-closed Route A instruction policy for zeta's CFG walker.

This deliberately selects the plain-pointer ABI contract. Authentication is
not preserved; pointer representation must be plain throughout the process.
PACGA has no admitted substitution. Hint-space instructions retain their
original encoding, so they require no patch and are omitted from edits.
The pinned upstream source and license are recorded in route-a-sources.json.
"""
from arm64_lowering.instructions import lower as _lower
import numpy as np

PAC_MASKS = ((0xffff0000, 0xdac10000), (0xffe0fc00, 0x9ac03000), (0xfffff81f, 0xd61f081f),
             (0xfffff81f, 0xd63f081f), (0xfffff800, 0xd71f0800), (0xfffff800, 0xd73f0800),
             (0xfffffbff, 0xd65f0bff), (0xfffffbff, 0xd69f0bff), (0xff200400, 0xf8200400))


def candidate_indices(words):
    """Vectorized non-hint PAuth class census, including rejected encodings."""
    hit = np.zeros(words.shape, dtype=bool)
    for mask, value in PAC_MASKS:
        match = (words & np.uint32(mask)) == np.uint32(value)
        if value == 0xdac10000:
            match &= ((words >> np.uint32(10)) & np.uint32(0x3f)) <= np.uint32(0x11)
        hit |= match
    return np.nonzero(hit)[0]


def lower(word):
    """Return (lowercase mnemonic, replacement), None, or raise ValueError."""
    result = _lower(word, plain_pointers=True, pacga_policy="reject")
    if result is None or result[1] == word:
        return None
    mnemonic, replacement = result
    return mnemonic.lower(), replacement
