"""Actual declaration bytes cannot grant roots or bypass a jump-table clamp."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm64_lowering.proof import _validate_table_entry_guards
from route_a_zeta import zeta_dyld_cache as dc
from route_a_zeta import zeta_userland_code as code
from test_route_a_macho_entries import exports, main, segment, thread, trie, uleb

BASE, CODE, TABLE, ANCHOR = 0x10000, 0x10800, 0x11000, 0x11800
DISPATCH = CODE + 28


def image(declaration=None, target=CODE + 8, *, base=BASE, roots=True, executable=True):
    data = bytearray(0x3000)
    text = bytearray(segment(b'__TEXT', base, 0x2000, 0, 0x2000,
                             executable=True, section=executable))
    if executable:
        struct.pack_into('<QQ', text, 72 + 32, base + 0x800, 0x1008)
    commands = [bytes(text), segment(b'__LINKEDIT', base + 0x2000, 0x1000, 0x2000, 0x1000)]
    if roots and executable:
        starts = uleb(0x800) + b'\0'
        data[0x2000:0x2000 + len(starts)] = starts
        commands.append(struct.pack('<4I', 0x26, 16, 0x2000, len(starts)))
    if declaration == 'main':
        commands.append(main(target - base))
    elif declaration in ('thread', 'unixthread'):
        command = bytearray(thread(target))
        struct.pack_into('<I', command, 0, 4 if declaration == 'thread' else 5)
        commands.append(bytes(command))
    elif declaration == 'routines':
        commands.append(struct.pack('<II8Q', 0x1a, 72, target, 0, 0, 0, 0, 0, 0, 0))
    elif declaration in ('symbol', 'absolute-symbol'):
        kind, section = (0xf, 1) if declaration == 'symbol' else (3, 0)
        symbol = struct.pack('<IBBHQ', 1, kind, section, 0, target)
        data[0x2100:0x2110] = symbol
        data[0x2110:0x2117] = b'\0entry\0'
        commands.append(struct.pack('<6I', 2, 24, 0x2100, 1, 0x2110, 7))
    elif declaration:
        if declaration == 'absolute-export':
            terminal = b'\2' + uleb(target)
        elif declaration == 'resolver':
            terminal = b'\x10' + uleb(0x800) + uleb(target - base)
        else:
            terminal = b'\0' + uleb(target - base)
        blob = trie(terminal)
        data[0x2100:0x2100 + len(blob)] = blob
        kind = {'legacy-export': 0x22, 'dyld-export': 0x80000022}.get(declaration, 0x80000033)
        commands.append(exports(0x2100, len(blob), kind))
    encoded = b''.join(commands)
    struct.pack_into('<8I', data, 0, 0xfeedfacf, 0x0100000c, 2, 2,
                     len(commands), len(encoded), 0, 0)
    data[32:32 + len(encoded)] = encoded
    if executable:
        # CMP/CSEL followed by the exact six real AArch64 dispatch words.
        anchor = base + 0x1800
        delta = anchor - (base + 0x800 + 20)
        adr = 0x10000011 | ((delta & 3) << 29) | (((delta >> 2) & 0x7ffff) << 5)
        struct.pack_into('<8I', data, 0x800, 0xf100061f, 0x9a9f9210,
                         0xb0000011, 0x91000231, 0xb8b07a30, adr, 0x8b100230, 0xd61f0200)
        struct.pack_into('<2i', data, 0x1000, 0, 4)
        struct.pack_into('<2I', data, 0x1800, 0xd65f03c0, 0xd65f03c0)
    return data


def cache_for(primary, extra=None):
    data = bytearray(primary)
    images = [(BASE, '/usr/lib/guard.dylib')]
    if extra is not None:
        data.extend(bytes(0x4000 - len(data)))
        data.extend(extra)
        images.append((BASE + 0x4000, '/usr/lib/declarations.dylib'))

    def locate(address):
        offset = address - BASE
        if not 0 <= offset < len(data):
            raise ValueError('outside synthetic cache mapping')
        return 0, offset, len(data) - offset

    def read(address, length):
        _, offset, room = locate(address)
        if length > room:
            raise ValueError('synthetic cache read leaves mapping')
        return data[offset:offset + length]

    return SimpleNamespace(images=images, files=[SimpleNamespace(data=data)],
                           regions=[(BASE, len(data), 0, 0, 5)], locate=locate, read=read,
                           slide_targets=lambda: np.zeros(0, dtype=np.uint64))


def standalone(data):
    cache = cache_for(data)
    parsed = dc.Image(cache, BASE, 'standalone-fixture')
    sections = parsed.instruction_sections()
    info = dict(segments=[dict(name='__TEXT', vmaddr=BASE, sections=sections)])
    return code.prove(data, info, sections, lambda address, size: address - BASE)


def cache_claim(cache):
    sections = dc.Image(cache, BASE, 'cache-fixture').instruction_sections()
    geometry = dict(address=hex(BASE), file=0, size=sum(s['size'] for s in sections),
                    regions=[dict(address=s['addr'], offset=s['offset'], size=s['size']) for s in sections])
    return [(dict(kept={}, tables=1, table_dispatches=[DISPATCH]), geometry)]


def driver():
    spec = importlib.util.spec_from_file_location(
        'route_a_declared_guard_driver', ROOT / 'scripts/route_a_zeta/prove-zeta-dyld-cache.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class DeclaredGuardIntegrationTests(unittest.TestCase):
    def test_complete_byte_backed_fixture_accepts_entry_at_the_clamp(self):
        result = standalone(image('export', CODE))
        self.assertEqual([table['dispatch'] for table in result[3]], [DISPATCH])
        self.assertIn(ANCHOR, result[1])

    def test_standalone_exports_resolver_and_absolute_symbol_cannot_bypass(self):
        for declaration in ('export', 'legacy-export', 'dyld-export', 'resolver', 'absolute-symbol'):
            with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
                standalone(image(declaration))

    def test_standalone_declaration_only_address_does_not_become_code(self):
        result = standalone(image('export', ANCHOR, roots=False))
        self.assertEqual(result[1], {})
        self.assertEqual(result[3], [])

    def test_standalone_malformed_symbols_fail_in_bounded_declaration_parser(self):
        data = image('symbol')
        cursor = 32
        while struct.unpack_from('<I', data, cursor)[0] != 2:
            cursor += struct.unpack_from('<I', data, cursor + 4)[0]
        struct.pack_into('<I', data, cursor + 12, 0xffffffff)
        with self.assertRaisesRegex(ValueError, 'Mach-O declared entries:.*budget'):
            standalone(data)

    def test_consumer_checks_all_kinds_of_declared_entries(self):
        for declaration in ('main', 'thread', 'unixthread', 'routines', 'symbol',
                            'absolute-symbol', 'export', 'legacy-export', 'dyld-export', 'resolver'):
            cache = cache_for(image(declaration))
            with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, 'static-entry bypass'):
                _validate_table_entry_guards(cache, cache_claim(cache), {})

    def test_consumer_checks_declarations_in_non_code_images(self):
        for declaration in ('absolute-symbol', 'absolute-export'):
            extra = image(declaration, base=BASE + 0x4000, roots=False, executable=False)
            cache = cache_for(image(), extra)
            with self.subTest(declaration=declaration), self.assertRaisesRegex(ValueError, 'static-entry bypass'):
                _validate_table_entry_guards(cache, cache_claim(cache), {})

    def worker(self, cache, work):
        module = driver()
        sections = dc.Image(cache, BASE, 'worker-fixture').instruction_sections()
        ranges = [(s['addr'], s['addr'] + s['size']) for s in sections]
        module.init(cache, ranges, cache.slide_targets(), work)
        module.STATE.update(islands=[], input_sha256='fixture-input', rules_sha256='fixture-rules')
        return module

    def test_worker_vetoes_own_main_and_export_entries(self):
        for declaration in ('main', 'export'):
            with self.subTest(declaration=declaration), tempfile.TemporaryDirectory() as directory:
                module = self.worker(cache_for(image(declaration)), Path(directory))
                with self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
                    module.prove_image((0, ()))

    def test_worker_vetoes_cross_owner_declarations_before_publishing_a_table(self):
        extra = image('absolute-export', base=BASE + 0x4000, roots=False, executable=False)
        with tempfile.TemporaryDirectory() as directory:
            module = self.worker(cache_for(image(), extra), Path(directory))
            self.assertFalse(module.STATE['guard_targets'].flags.writeable)
            with self.assertRaisesRegex(ValueError, 'clamp.*bypassed'):
                module.prove_image((0, ()))
            self.assertFalse(list(Path(directory).glob('*.done.json')))
            self.assertFalse(list(Path(directory).glob('*.npz')))

    def test_worker_declaration_address_never_grants_a_root(self):
        with tempfile.TemporaryDirectory() as directory:
            module = self.worker(cache_for(image('export', ANCHOR, roots=False)), Path(directory))
            _, result, reached = module.prove_image((0, ()))
            self.assertEqual(result['proven_instructions'], 0)
            self.assertEqual(result['tables'], 0)
            self.assertEqual(reached, [])

    def test_declaration_address_budget_fails_closed(self):
        cache = cache_for(image('export', CODE))
        module = driver()
        module.MAX_DECLARATION_TARGETS = 0
        with self.assertRaisesRegex(ValueError, 'address budget'):
            module.declaration_targets(cache, [(CODE, ANCHOR + 8)])


if __name__ == '__main__':
    unittest.main()
