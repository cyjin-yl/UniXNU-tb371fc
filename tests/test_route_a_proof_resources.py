"""Resource ownership and partial receipts for the actual proof driver."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import json
from test_route_a_proof import cache_bytes, BASE, module
from route_a_zeta import zeta_dyld_cache as dc

def member(uuid, address):
    data=cache_bytes(images=0)
    data[0x58:0x68]=uuid
    struct.pack_into('<Q',data,0x200,address)
    return data

def fixture(root, case):
    root.mkdir()
    main=root/'cache'
    primary=cache_bytes(images=0)
    uid=b'1234567890123456'
    if case=='short':
        main.write_bytes(b'bad')
    elif case=='magic':
        primary[:16]=b'x'*16
        main.write_bytes(primary)
    elif case=='badmap':
        struct.pack_into('<Q',primary,0x208,0)
        main.write_bytes(primary)
    elif case=='badimage':
        struct.pack_into('<II',primary,0x1c0,len(primary),1)
        main.write_bytes(primary)
    else:
        count=2 if case=='missing' else 1
        struct.pack_into('<II',primary,0x188,0x600,count)
        for index in range(count):
            off=0x600+56*index
            primary[off:off+16]=uid
            struct.pack_into('<Q',primary,off+16,(index+1)*0x10000)
            suffix=f'.{index+1}'.encode()
            primary[off+24:off+56]=suffix.ljust(32,b'\0')
        main.write_bytes(primary)
        child=member(b'0'*16 if case=='uuid' else uid, BASE if case=='overlap' else BASE+0x10000)
        (root/'cache.1').write_bytes(child)
    return main

def observe(mod, case, root):
    files=[]; maps=[]; error=None; cache=None
    main=fixture(root,case)
    op=Path.open
    mm=mod.mmap.mmap
    def opened(path,*a,**kw):
        result=op(path,*a,**kw)
        files.append(result)
        return result
    def mapped(*a,**kw):
        result=mm(*a,**kw)
        maps.append(result)
        return result
    try:
        with patch.object(Path,'open',opened), patch.object(mod.mmap,'mmap',mapped):
            try:
                cache=mod.Cache(main)
            except Exception as e:
                error=e # deliberately retain traceback / partially built objects
        result=(type(error).__name__ if error else None, sum(not f.closed for f in files), sum(not m.closed for m in maps),len(files),len(maps))
        return result
    finally:
        # Never leave the baseline leak alive beyond the observation.
        for m in maps:
            if not m.closed: m.close()
        for f in files:
            if not f.closed: f.close()

class ResourceTests(unittest.TestCase):
    def test_constructor_cleanup(self):
        for case in ('short','magic','badmap','badimage','uuid','missing','overlap'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                error,f,m,_,_=observe(dc,case,Path(tmp)/'fixture')
                self.assertIsNotNone(error)
                self.assertEqual((f,m),(0,0))

    def test_success_transfers_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            error,f,m,nfiles,nmaps=observe(dc,'valid',Path(tmp)/'fixture')
            self.assertIsNone(error)
            self.assertEqual((f,m,nfiles,nmaps),(2,2,2,2))

    def test_partial_receipts(self):
        for phase in ('initial-rules','cache-open','attempt','precise'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                driver=module('prove-zeta-dyld-cache')
                cache=fixture(root/'fixture','magic' if phase=='cache-open' else 'valid')
                work=root/'work'
                argv=['--cache',str(cache),'--work',str(work),'--jobs','1']
                def fail_attempt(*args):
                    if phase=='precise':
                        driver.publish_record(work/'partial.json',dict(phase='worker',complete=False,missing=[4]))
                    raise RuntimeError('synthetic attempt failure')
                def fail_rules():
                    raise RuntimeError('synthetic rules failure')
                rules=fail_rules if phase=='initial-rules' else lambda: {'fixture':True}
                with patch.object(driver,'rules_manifest',rules), patch.object(driver,'run_attempt',fail_attempt):
                    with self.assertRaises((RuntimeError,ValueError)):
                        driver.main(argv)
                partial=json.loads((work/'partial.json').read_text())
                self.assertFalse(partial['complete'])
                self.assertEqual(partial['phase'],'worker' if phase=='precise' else phase)
                self.assertFalse((work/'summary.json').exists())
                self.assertEqual(driver.STATE,{})
                if phase=='precise':
                    self.assertEqual(partial['missing'],[4])

if __name__=='__main__':
    unittest.main(verbosity=2)
