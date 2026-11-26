"""Synthetic declaration metadata vetoes are exact, bounded, and never roots."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from route_a_zeta.zeta_macho_entries import (cache_declared_entries,
                                           standalone_declared_entries)


BASE = 0xffff000000100000  # Deliberately beyond exact IEEE-754 integer range.
LINK = BASE + 0x2000


def uleb(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def segment(name, address, size, fileoff, filesize, *, executable=False, section=False):
    body = struct.pack('<II16sQQQQIIII', 0x19, 152 if section else 72, name,
                       address, size, fileoff, filesize, 5 if executable else 1,
                       5 if executable else 1, int(section), 0)
    if section:
        body += struct.pack('<16s16sQQIIIIIIII', b'__text', name,
                            address + 0x800, 0x800, fileoff + 0x800, 2,
                            0, 0, 0x80000400, 0, 0, 0)
    return body


def image(commands=(), payload=b'', *, text_fileoff=0, link_fileoff=0x1000,
          extra_segments=(), base=BASE):
    link_size = max(0x1000, (len(payload) + 0xfff) & ~0xfff)
    segments = [segment(b'__TEXT', base, 0x1000, text_fileoff, 0x1000,
                        executable=True, section=True),
                segment(b'__LINKEDIT', base + 0x2000, link_size, link_fileoff, link_size)]
    all_commands = segments + list(extra_segments) + list(commands)
    encoded = b''.join(all_commands)
    header = struct.pack('<8I', 0xfeedfacf, 0x0100000c, 2, 6, len(all_commands),
                         len(encoded), 0, 0)
    data = bytearray(max(0x1000, link_fileoff + link_size))
    data[:len(header + encoded)] = header + encoded
    data[link_fileoff:link_fileoff + len(payload)] = payload
    return data


def main(entryoff=0x800):
    return struct.pack('<IIQQ', 0x80000028, 24, entryoff, 0)


def thread(pc=BASE + 0x804):
    result = bytearray(struct.pack('<IIII', 5, 288, 6, 68) + bytes(272))
    struct.pack_into('<Q', result, 16 + 32 * 8, pc)
    return bytes(result)


def exports(offset, size, kind=0x80000033):
    if kind == 0x80000033:
        return struct.pack('<4I', kind, 16, offset, size)
    return struct.pack('<12I', kind, 48, 0, 0, 0, 0, 0, 0, 0, 0, offset, size)


def trie(payload):
    # One named edge to one terminal. The child offset fits in one byte.
    prefix = b'\0\1_entry\0'
    return prefix + bytes((len(prefix) + 1,)) + uleb(len(payload)) + payload + b'\0'


def exported(payload, *, command=0x80000033, extra_commands=(), base=BASE):
    blob = trie(payload)
    return image([exports(0x1000, len(blob), command), *extra_commands], blob, base=base)


def symbols(records, names=b'\0sym\0alias\0'):
    table = b''.join(struct.pack('<IBBHQ', *record) for record in records)
    command = struct.pack('<6I', 2, 24, 0x1000, len(records),
                          0x1000 + len(table), len(names))
    return image([command], table + names)


def dependency():
    name = b'/usr/lib/example.dylib\0'
    size = (24 + len(name) + 7) & ~7
    return struct.pack('<6I', 0xc, size, 24, 0, 0, 0) + name.ljust(size - 24, b'\0')


class FakeCache:
    """Actual member offsets differ from all image logical file offsets."""
    def __init__(self, data, *, logical_link=0x1000, split=None, gap=False):
        text = bytes(data[:0x1000])
        link = bytes(data[logical_link:logical_link + 0x1000])
        pieces = [(BASE, text)]
        if split is None:
            pieces.append((LINK, link))
        else:
            pieces += [(LINK, link[:split]),
                       (LINK + split + int(gap), link[split + int(gap):])]
        self.members, self.maps, self.reads = [], [], []
        for index, (address, chunk) in enumerate(pieces):
            prefix = 0x80 + index * 0x20
            self.members.append(b'X' * prefix + chunk)
            self.maps.append((address, len(chunk), index, prefix))

    def locate(self, address):
        for start, length, index, fileoff in self.maps:
            if start <= address < start + length:
                return index, fileoff + address - start, start + length - address
        raise KeyError(address)

    def read(self, address, length):
        index, offset, room = self.locate(address)
        if length > room:
            raise ValueError('read crosses cache mapping')
        self.reads.append((address, length))
        return self.members[index][offset:offset + length]


class DeclaredEntryTests(unittest.TestCase):
    def test_no_declarations_returns_empty_immutable_set(self):
        result = standalone_declared_entries(image())
        self.assertEqual(result, frozenset())
        self.assertIsInstance(result, frozenset)

    def test_main_and_thread_preserve_high_integer_addresses(self):
        for command, target in ((main(), BASE + 0x800), (thread(), BASE + 0x804)):
            with self.subTest(target=target):
                entries = standalone_declared_entries(image([command]))
                self.assertEqual(entries, frozenset((target,)))
                self.assertTrue(all(type(address) is int for address in entries))

    def test_routines_initializer_is_a_veto_address(self):
        routine = struct.pack('<II8Q', 0x1a, 72, BASE + 0x808, 0, 0, 0, 0, 0, 0, 0)
        self.assertEqual(standalone_declared_entries(image([routine])), {BASE + 0x808})

    def test_lc_thread_has_the_same_pc_layout_without_unix_stack_semantics(self):
        command = bytearray(thread())
        struct.pack_into('<I', command, 0, 4)
        self.assertEqual(standalone_declared_entries(image([command])), {BASE + 0x804})

    def test_conflicting_or_duplicate_entry_commands_fail_closed(self):
        for commands in ([main(), main()], [thread(), thread()], [main(), thread()]):
            with self.subTest(commands=commands), self.assertRaises(ValueError):
                standalone_declared_entries(image(commands))

    def test_thread_wrong_flavor_count_and_size_fail_closed(self):
        for offset, value in ((8, 1), (12, 67), (4, 280)):
            bad = bytearray(thread())
            struct.pack_into('<I', bad, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                standalone_declared_entries(image([bad]))

    def test_entry_must_be_aligned_file_backed_executable(self):
        for command in (main(0x801), main(0x2000), main((1 << 64) - 1),
                        thread(BASE + 0x2000)):
            with self.subTest(command=command), self.assertRaises(ValueError):
                standalone_declared_entries(image([command]))

    def test_defined_and_absolute_symbols_but_not_common_debug_or_alias_values(self):
        records = [(1, 0xf, 1, 0, BASE + 0x80c),
                   (1, 3, 0, 0, BASE + 0x810),
                   (1, 1, 0, 0, BASE + 0x814),
                   (1, 0xe0, 0, 0, BASE + 0x818),
                   (1, 0xb, 0, 0, 5),
                   (1, 0xd, 0, 0, BASE + 0x81c)]
        self.assertEqual(standalone_declared_entries(symbols(records)),
                         {BASE + 0x80c, BASE + 0x810})

    def test_symbol_at_section_end_is_still_a_conservative_veto(self):
        self.assertEqual(standalone_declared_entries(symbols([(1, 0xf, 1, 0, BASE + 0x1000)])),
                         {BASE + 0x1000})

    def test_invalid_symbol_section_address_or_string_fails_closed(self):
        for record in ((1, 0xf, 0, 0, BASE + 0x800), (1, 0xf, 2, 0, BASE + 0x800),
                       (1, 0xf, 1, 0, BASE + 0x700), (99, 0xf, 1, 0, BASE + 0x800),
                       (1, 0xb, 0, 0, 99), (1, 5, 0, 0, 0),
                       (1, 3, 1, 0, BASE + 0x800)):
            with self.subTest(record=record), self.assertRaises(ValueError):
                standalone_declared_entries(symbols([record]))
        with self.assertRaises(ValueError):
            standalone_declared_entries(symbols([(1, 0xf, 1, 0, BASE + 0x800)], b'\0name'))

    def test_regular_weak_threadlocal_and_absolute_exports(self):
        for flags, value, expected in ((0, 0x820, BASE + 0x820),
                                       (4, 0x824, BASE + 0x824),
                                       (1, 0x828, BASE + 0x828),
                                       (2, BASE + 0x82c, BASE + 0x82c)):
            with self.subTest(flags=flags):
                self.assertEqual(standalone_declared_entries(exported(uleb(flags) + uleb(value))),
                                 {expected})

    def test_absolute_export_can_name_an_address_in_another_owner(self):
        value = (1 << 64) - 1
        self.assertEqual(standalone_declared_entries(exported(b'\2' + uleb(value))), {value})

    def test_resolver_stub_and_resolver_are_both_collected(self):
        self.assertEqual(standalone_declared_entries(exported(b'\x10' + uleb(0x830) + uleb(0x834))),
                         {BASE + 0x830, BASE + 0x834})

    def test_reexport_ordinals_and_import_names_are_not_addresses(self):
        for name in (b'\0', b'_renamed\0'):
            with self.subTest(name=name):
                data = exported(b'\x08\1' + name, extra_commands=[dependency()])
                self.assertEqual(standalone_declared_entries(data), frozenset())
        for payload in (b'\x08\0\0', b'\x08\2\0', b'\x08\1name'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                standalone_declared_entries(exported(payload, extra_commands=[dependency()]))

    def test_both_dyld_info_forms_and_exports_trie_command_are_read(self):
        for command in (0x22, 0x80000022, 0x80000033):
            with self.subTest(command=command):
                self.assertEqual(standalone_declared_entries(exported(b'\0' + uleb(0x838), command=command)),
                                 {BASE + 0x838})

    def test_two_distinct_export_commands_collect_both_payloads(self):
        first, second = trie(b'\0' + uleb(0x840)), trie(b'\0' + uleb(0x844))
        commands = [exports(0x1000, len(first), 0x80000022),
                    exports(0x1000 + len(first), len(second))]
        self.assertEqual(standalone_declared_entries(image(commands, first + second)),
                         {BASE + 0x840, BASE + 0x844})

    def test_empty_exports_placeholder_is_supported(self):
        self.assertEqual(standalone_declared_entries(image([exports(0, 0)])), frozenset())

    def test_unsupported_or_inconsistent_export_semantics_fail_closed(self):
        for payload in (b'\x20' + uleb(0x800) + b'\0', b'\x40\0', b'\3\0',
                        b'\x18\1\0', b'\x11\0\0', b'\0' + uleb(0x800) + b'\0',
                        b'\x10' + uleb(0x801) + uleb(0x804), b'\0' + uleb(0x1800)):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                standalone_declared_entries(exported(payload))

    def test_relative_export_can_reference_a_segment_below_text(self):
        lower = segment(b'__LOW', BASE - 0x1000, 0x1000, 0x2000, 0x1000)
        blob = trie(b'\0' + uleb((1 << 64) - 0x800))
        data = image([exports(0x1000, len(blob))], blob, extra_segments=[lower]) + bytes(0x1000)
        self.assertEqual(standalone_declared_entries(data), {BASE - 0x800})

    def test_truncated_overflowing_and_overlong_ulebs_fail_closed(self):
        for blob in (b'\x80', b'\xff' * 9 + b'\2', b'\x80' * 10 + b'\0',
                     trie(b'\0\x80'), trie(b'\0' + b'\xff' * 9 + b'\2')):
            with self.subTest(blob=blob), self.assertRaises(ValueError):
                standalone_declared_entries(image([exports(0x1000, len(blob))], blob))

    def test_trie_child_cycle_bad_offset_and_overlapping_nodes_fail_closed(self):
        bad = [b'\0\1a\0\5\0\1b\0\5',  # child node points to itself
               b'\0\1a\0\0', b'\0\1a\0\x7f',
               b'\0\2a\0\x08b\0\x09\0\0\0',
               b'\0\1unterminated', b'\0\1\0\4', b'\0']
        for blob in bad:
            with self.subTest(blob=blob), self.assertRaises(ValueError):
                standalone_declared_entries(image([exports(0x1000, len(blob))], blob))

    def test_trie_shared_leaf_is_parsed_without_exponential_paths(self):
        leaf = b'\3\0\x80\x11\0'  # value 0x880
        blob = b'\0\2a\0\x08b\0\x08' + leaf
        self.assertEqual(standalone_declared_entries(image([exports(0x1000, len(blob))], blob)),
                         {BASE + 0x880})

    def test_deep_trie_uses_a_bounded_iterative_walk(self):
        records = []
        for index in range(1500):
            target = 14 * (index + 1)
            encoded = uleb(target)
            # Bounded, non-minimal ULEB encodings are accepted by dyld.
            fixed = encoded[:-1] + bytes((encoded[-1] | 128,))
            fixed += b'\x80' * (9 - len(encoded)) + b'\0'
            records.append(b'\0\1a\0' + fixed)
        records.append(b'\3\0\x80\x10\0')  # value 0x800
        blob = b''.join(records)
        self.assertEqual(standalone_declared_entries(image([exports(0x1000, len(blob))], blob)),
                         {BASE + 0x800})

    def test_metadata_must_be_inside_file_backed_linkedit(self):
        for command in (exports(0x800, 8), exports(0x1ffc, 8),
                        struct.pack('<6I', 2, 24, 0x1ff8, 1, 0x1000, 1),
                        struct.pack('<6I', 2, 24, 0x1000, 1, 0x2000, 1)):
            with self.subTest(command=command), self.assertRaises(ValueError):
                standalone_declared_entries(image([command]))

    def test_command_geometry_duplicates_and_allocation_budgets_fail_closed(self):
        data = image()
        mutations = ((16, 0xffffffff), (20, 0xffffffff), (20, 16 * 1024 * 1024 + 8),
                     (32 + 4, 0), (32 + 4, 73))
        for offset, value in mutations:
            bad = bytearray(data)
            struct.pack_into('<I', bad, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(ValueError):
                standalone_declared_entries(bad)
        for commands in ([exports(0, 0), exports(0, 0)],
                         [exports(0, 0, 0x22), exports(0, 0, 0x80000022)],
                         [struct.pack('<6I', 2, 24, 0x1000, 0xffffffff, 0, 0)]):
            with self.subTest(commands=commands), self.assertRaises(ValueError):
                standalone_declared_entries(image(commands))

    def test_segment_overflow_and_wrong_header_identity_fail_closed(self):
        for offset, encoding, value in ((0, '<I', 0xcffaedfe), (4, '<I', 7),
                                         (32 + 24, '<Q', (1 << 64) - 0x800),
                                         (32 + 40, '<Q', 0x1000)):
            data = image()
            struct.pack_into(encoding, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                standalone_declared_entries(data)


class CacheDeclaredEntryTests(unittest.TestCase):
    def test_cache_logical_offsets_are_translated_through_linkedit(self):
        offset = 0xa000
        blob = trie(b'\0' + uleb(0x900))
        data = image([exports(offset, len(blob)), main()], blob,
                     text_fileoff=0x6000, link_fileoff=offset)
        cache = FakeCache(data, logical_link=offset)
        self.assertEqual(cache_declared_entries(cache, BASE), {BASE + 0x900, BASE + 0x800})
        self.assertIn((LINK, len(blob)), cache.reads)
        self.assertTrue(all(address >= BASE for address, _ in cache.reads))

    def test_all_sources_match_standalone_and_cross_cache_mapping_boundaries(self):
        table = struct.pack('<IBBHQ', 1, 0xf, 1, 0, BASE + 0x904)
        names = b'\0symbol\0'
        blob = trie(b'\x10' + uleb(0x908) + uleb(0x90c))
        payload = table + names + blob
        commands = [struct.pack('<6I', 2, 24, 0x1000, 1, 0x1010, len(names)),
                    exports(0x1010 + len(names), len(blob)), thread()]
        data = image(commands, payload)
        expected = {BASE + 0x804, BASE + 0x904, BASE + 0x908, BASE + 0x90c}
        self.assertEqual(standalone_declared_entries(data), expected)
        for split in (3, 15, 18, 27):
            with self.subTest(split=split):
                self.assertEqual(cache_declared_entries(FakeCache(data, split=split), BASE), expected)

    def test_cache_hole_short_read_or_header_address_mismatch_fails_closed(self):
        data = exported(b'\0' + uleb(0x900))
        with self.assertRaises(ValueError):
            cache_declared_entries(FakeCache(data, split=12, gap=True), BASE)
        cache = FakeCache(data)
        original = cache.read
        cache.read = lambda address, length: original(address, length)[:-1]
        with self.assertRaises(ValueError):
            cache_declared_entries(cache, BASE)
        bad = bytearray(data)
        struct.pack_into('<Q', bad, 32 + 24, BASE + 0x10000)
        struct.pack_into('<Q', bad, 32 + 72 + 32, BASE + 0x10800)
        with self.assertRaises(ValueError):
            cache_declared_entries(FakeCache(bad), BASE)

    def test_cache_does_not_accept_file_offset_as_vm_address(self):
        with self.assertRaises(ValueError):
            cache_declared_entries(FakeCache(image()), 0x80)


if __name__ == '__main__':
    unittest.main()
