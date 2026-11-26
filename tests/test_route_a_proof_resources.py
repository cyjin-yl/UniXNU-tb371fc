"""Resource ownership and partial receipts for the actual proof driver."""
from pathlib import Path
from concurrent.futures import Future
from contextlib import redirect_stderr
import errno
import hashlib
import io
import struct
import tempfile
import unittest
from unittest.mock import patch
import json
from test_route_a_proof import cache_bytes, BASE, module
from route_a_zeta import zeta_dyld_cache as dc
from route_a_zeta.zeta_closure import ClosureError, close


class InlinePool:
    """Exercise driver receipts with deterministic futures, without worker forks."""
    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def submit(self, fn, job):
        future = Future()
        try:
            future.set_result(fn(job))
        except BaseException as error:
            future.set_exception(error)
        return future

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

    def check_partial_write_failure(self, phase, transient):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / 'cache'
            cache.write_bytes(cache_bytes())
            work = root / 'work'
            driver = module('prove-zeta-dyld-cache')
            original = ValueError('sentinel primary proof failure')
            real_publish = driver.publish_record
            partial_calls = []

            class InlinePool:
                def __init__(self, **kwargs):
                    pass

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def submit(self, fn, job):
                    future = Future()
                    if phase == 'worker' or (phase == 'closure-worker' and job[1]):
                        future.set_exception(original)
                    else:
                        try:
                            future.set_result(fn(job))
                        except BaseException as error:
                            future.set_exception(error)
                    return future

            def publish(path, record):
                if path.name == 'partial.json':
                    partial_calls.append(dict(record))
                    if not transient or len(partial_calls) == 1:
                        raise OSError(errno.ENOSPC, 'injected receipt write failure')
                return real_publish(path, record)

            def fail_closure(ownership, reached, prove_batch, **kwargs):
                if phase == 'closure-worker':
                    return prove_batch([(0, (BASE + 0x100,))])
                raise original

            stderr = io.StringIO()
            with patch.object(driver, 'ProcessPoolExecutor', InlinePool), \
                 patch.object(driver, 'publish_record', publish), \
                 patch.object(driver, 'close', side_effect=fail_closure), \
                 redirect_stderr(stderr):
                with self.assertRaises(ValueError) as caught:
                    driver.main(['--cache', str(cache), '--work', str(work), '--jobs', '1'])
            self.assertIs(caught.exception, original)
            expected_calls = 3 if phase == 'closure-worker' and not transient else 2
            self.assertEqual(len(partial_calls), expected_calls)
            self.assertTrue(all(record == partial_calls[0] for record in partial_calls))
            expected_phase = {'worker': 'own roots', 'closure': 'closure',
                              'closure-worker': 'closure-001'}[phase]
            self.assertEqual(partial_calls[0]['phase'], expected_phase)
            self.assertEqual(partial_calls[0]['error'], 'ValueError')
            self.assertEqual(partial_calls[0]['error_message'], str(original))
            self.assertFalse(partial_calls[0]['error_message_truncated'])
            self.assertFalse(partial_calls[0]['error_message_unavailable'])
            if phase in ('worker', 'closure-worker'):
                self.assertEqual(partial_calls[0]['missing'], [0])
                self.assertEqual(partial_calls[0]['acknowledged'], [])
                failed = partial_calls[0]['failed_job']
                self.assertEqual((failed['index'], failed['path'], failed['address']),
                                 (0, '/usr/lib/test0.dylib', BASE))
                self.assertFalse(failed['island'])
                self.assertEqual(failed['operation'], 'result')
                roots = (BASE + 0x100,) if phase == 'closure-worker' else ()
                self.assertEqual(failed['phase'], 'calls' if roots else 'own')
                self.assertEqual(failed['called_roots_count'], len(roots))
                self.assertEqual(failed['called_roots_sample'], list(roots))
                self.assertEqual(failed['called_roots_sha256'],
                                 driver.json_digest(roots) if roots else None)
            if transient:
                self.assertEqual(json.loads((work / 'partial.json').read_text()), partial_calls[0])
            else:
                self.assertFalse((work / 'partial.json').exists())
            self.assertIn('partial receipt write failed during ' + expected_phase, stderr.getvalue())
            self.assertFalse((work / 'summary.json').exists())
            self.assertEqual(driver.STATE, {})

    def test_transient_partial_write_failure_preserves_primary_and_exact_phase(self):
        for phase in ('worker', 'closure', 'closure-worker'):
            with self.subTest(phase=phase):
                self.check_partial_write_failure(phase, transient=True)

    def test_persistent_partial_write_failure_preserves_primary(self):
        for phase in ('worker', 'closure', 'closure-worker'):
            with self.subTest(phase=phase):
                self.check_partial_write_failure(phase, transient=False)

    def test_island_failure_records_its_owner_without_claiming_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, work = root / 'cache', root / 'work'
            cache.write_bytes(cache_bytes(images=0, island=True))
            driver = module('prove-zeta-dyld-cache')
            original = ValueError('synthetic island proof failure')
            with patch.object(driver, 'ProcessPoolExecutor', InlinePool), \
                 patch.object(driver, 'prove_image', side_effect=original):
                with self.assertRaises(ValueError) as caught:
                    driver.main(['--cache', str(cache), '--work', str(work), '--jobs', '1'])
            self.assertIs(caught.exception, original)
            record = json.loads((work / 'partial.json').read_text())
            self.assertEqual(record['phase'], 'own roots')
            self.assertEqual(record['failed_job']['index'], 0)
            self.assertEqual(record['failed_job']['address'], BASE + 0x2000)
            self.assertEqual(record['failed_job']['path'], f'island-{BASE + 0x2000:x}')
            self.assertTrue(record['failed_job']['island'])
            self.assertFalse(record['complete'])
            self.assertFalse((work / 'summary.json').exists())

    def test_wait_failure_does_not_blame_the_previous_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, work = root / 'cache', root / 'work'
            cache.write_bytes(cache_bytes(images=2))
            driver = module('prove-zeta-dyld-cache')
            original = RuntimeError('synthetic wait failure')
            actual_wait = driver.wait
            calls = []

            def wait(pending, **kwargs):
                calls.append(None)
                if len(calls) == 2:
                    raise original
                return actual_wait(pending, **kwargs)

            with patch.object(driver, 'ProcessPoolExecutor', InlinePool), \
                 patch.object(driver, 'wait', side_effect=wait):
                with self.assertRaises(RuntimeError) as caught:
                    driver.main(['--cache', str(cache), '--work', str(work), '--jobs', '1'])
            self.assertIs(caught.exception, original)
            record = json.loads((work / 'partial.json').read_text())
            self.assertEqual(record['acknowledged'], [0])
            self.assertEqual(record['missing'], [1])
            self.assertEqual(record['operation'], 'wait')
            self.assertIsNone(record['failed_job'])
            self.assertFalse(record['complete'])
            self.assertFalse((work / 'summary.json').exists())

    def test_actual_closure_failure_retains_context_after_receipt_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache, work = root / 'cache', root / 'work'
            cache.write_bytes(cache_bytes())
            driver = module('prove-zeta-dyld-cache')
            errors, receipts = [], []
            actual_publish = driver.publish_record

            def missing_owner(ownership, initial, prove_batch, **kwargs):
                try:
                    return close(ownership, {}, prove_batch, **kwargs)
                except ClosureError as error:
                    errors.append(error)
                    raise

            def publish(path, record):
                if path.name == 'partial.json':
                    receipts.append(dict(record))
                    if len(receipts) == 1:
                        raise OSError(errno.ENOSPC, 'synthetic receipt failure')
                return actual_publish(path, record)

            with patch.object(driver, 'ProcessPoolExecutor', InlinePool), \
                 patch.object(driver, 'close', side_effect=missing_owner), \
                 patch.object(driver, 'publish_record', side_effect=publish), \
                 redirect_stderr(io.StringIO()):
                with self.assertRaises(ClosureError) as caught:
                    driver.main(['--cache', str(cache), '--work', str(work), '--jobs', '1'])
            self.assertIs(caught.exception, errors[0])
            self.assertEqual(len(receipts), 2)
            self.assertEqual(receipts[0], receipts[1])
            record = json.loads((work / 'partial.json').read_text())
            self.assertEqual(record['phase'], 'closure')
            self.assertEqual(record['error_message'], 'initial executable owner inventory mismatch')
            self.assertEqual(record['closure_context']['missing_owners'],
                             dict(count=1, sample=[0]))
            self.assertEqual(record['closure_context']['unexpected_owners'],
                             dict(count=0, sample=[]))
            self.assertFalse(record['complete'])
            self.assertFalse((work / 'summary.json').exists())

    def test_error_text_is_bounded_and_unrenderable_errors_stay_primary(self):
        class Unrenderable(ValueError):
            def __str__(self):
                raise RuntimeError('synthetic formatting failure')

        for original in (ValueError('x' * 5000), Unrenderable()):
            with self.subTest(error=type(original).__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                work = root / 'work'
                driver = module('prove-zeta-dyld-cache')
                with patch.object(driver, 'rules_manifest', side_effect=original):
                    with self.assertRaises(ValueError) as caught:
                        driver.main(['--cache', str(root / 'unused-cache'),
                                     '--work', str(work), '--jobs', '1'])
                self.assertIs(caught.exception, original)
                record = json.loads((work / 'partial.json').read_text())
                if isinstance(original, Unrenderable):
                    self.assertEqual(record['error_message'], '<exception text unavailable>')
                    self.assertTrue(record['error_message_unavailable'])
                    self.assertFalse(record['error_message_truncated'])
                else:
                    self.assertEqual(record['error_message'], 'x' * 2048)
                    self.assertTrue(record['error_message_truncated'])
                    self.assertFalse(record['error_message_unavailable'])
                self.assertFalse(record['complete'])
                self.assertFalse((work / 'summary.json').exists())

    def test_owner_diagnostic_bounds_path_and_roots_but_hashes_full_identity(self):
        driver = module('prove-zeta-dyld-cache')
        path = '/synthetic/' + 'a' * 2000
        cache = type('CacheFixture', (), dict(images=[(BASE, path)]))()
        roots = tuple(BASE + 4 * i for i in range(32))
        record = driver.failed_job_context(cache, [], (0, roots), 'submit')
        self.assertEqual(record['path'], path[:1024])
        self.assertTrue(record['path_truncated'])
        self.assertEqual(record['path_sha256'], hashlib.sha256(path.encode()).hexdigest())
        self.assertEqual(record['called_roots_count'], 32)
        self.assertEqual(record['called_roots_sample'], list(roots[:8]))
        self.assertEqual(record['called_roots_sha256'], driver.json_digest(roots))
        self.assertEqual(record['operation'], 'submit')


if __name__=='__main__':
    unittest.main(verbosity=2)
