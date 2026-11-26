#!/usr/bin/env python3
"""Prove which PAC-shaped words of an arm64e dyld shared cache are code.

Each image is proven on its own with zeta_userland_code: its unwind-covered
function starts are strong roots. Slide-info rebase targets inside its
instruction sections and adr/adrp+add addresses formed by its proven code
are pointer roots. Exception landing pads from its LSDAs and the entries of
its stub sections are structural roots, and its other function starts are
bare roots. Words Capstone cannot decode are given to llvm-mc with every
A-profile feature: Apple AMX words and SME2 or newer SVE instructions are
straight-line code a walk steps over; branches stay undecodable. Last, code
left inside a proven atom after a proven terminator (dead epilogues and
error exits) is proven by the same strict walk. Images in
a cache call each other directly, so a walk that reaches another image's
code or a stub island records the target and stops there (Coverage).
Accepted external edges propagate through images and islands to a fixed point,
including intermediate owners without residual PAC. Every PAC word in proven
code gets its ordinary lowering (zeta_userland_pauth). Unproven PAC words
are left as they are and reported: they are either data or code no proof
reaches, and rewriting data would corrupt it.

Results go to --work, one compressed numpy file per image plus a JSON
summary. Reads the cache only.
"""
import argparse
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from route_a_zeta.zeta_closure import close
from route_a_zeta import zeta_dyld_cache as dc
from route_a_zeta import zeta_userland_code as code
from route_a_zeta import zeta_userland_pauth as pauth
from arm64_lowering.proof import rules_manifest, seal_summary, source_manifest
from arm64_lowering.closure_receipts import receipt_set_digest

GRADES = ('unwind', 'pointer', 'landing', 'stub', 'call', 'start', 'gap')
STATE = {}


def pac_candidates(words):
    """Indexes of words whose encoding is a non-hint PAC instruction class."""
    return pauth.candidate_indices(words)


def init(cache, ranges, targets, work):
    STATE['cache'] = cache
    STATE['coverage'] = dc.Coverage(ranges)
    STATE['targets'] = targets
    STATE['work'] = work


def section_va_to_off(cache, file_index):
    def va_to_off(address, length):
        index, offset, room = cache.locate(address)
        if index != file_index or room < length:
            raise ValueError(f'{address:#x} is not in the image file')
        return offset
    return va_to_off


def prove_code(cache, sections, strong, weak, starts, ordered, label):
    """Proof plus the lowered PAC words of the given sections."""
    file_index = sections[0]['file']
    data = cache.files[file_index].data
    va_to_off = section_va_to_off(cache, file_index)
    insns = code.decode(data, sections, code.llvm_oracle)
    targets = STATE['targets']
    pointers = set()
    for section in sections:
        low, high = np.searchsorted(targets, [section['addr'], section['addr'] + section['size']])
        pointers.update(int(t) for t in targets[low:high] if not int(t) & 3)
    # The image's own sections are decoded word for word, so only other code counts as external.
    coverage = STATE['coverage']
    coverage.reached = set()
    _, proven, data_words, tables, anomalies, roots = code.prove_roots(
        insns, data, va_to_off, strong, weak, starts, pointers, ordered, coverage, gaps=True)
    edits, unproven, unlowerable, kept, kept_data = [], [], [], Counter(), []
    for section in sections:
        words = np.frombuffer(data, dtype='<u4', count=section['size'] // 4, offset=section['offset'])
        for index in pac_candidates(words):
            address = section['addr'] + 4 * int(index)
            word = int(words[index])
            if address in proven:
                try:
                    lowered = pauth.lower(word)
                except ValueError as error:
                    unlowerable.append(dict(va=hex(address), word=hex(word), reason=str(error)))
                    continue
                if lowered is None:
                    unlowerable.append(dict(va=hex(address), word=hex(word), reason='unrecognized PAuth candidate'))
                    continue
                name, ordinary = lowered
                if insns[address][0] != name:
                    raise ValueError(f'{label}: decoder says {insns[address][0]} for {name} at {address:#x}')
                edits.append((address, section['offset'] + 4 * int(index), word, ordinary,
                              GRADES.index(proven[address])))
            elif address in data_words:
                kept['table'] += 1
                kept_data.append((address, section['offset'] + 4 * int(index), word))
            else:
                unproven.append((address, word))
    return dict(edits=edits, unproven=unproven, unlowerable=unlowerable, kept=dict(kept), kept_data=kept_data,
                table_dispatches=sorted({table['dispatch'] for table in tables}),
                reached=sorted(coverage.reached), file=file_index, proven_instructions=len(proven),
                tables=len(tables), roots=roots, anomalies=dict(Counter(a['kind'] for a in anomalies)))


def result_name(path):
    return hashlib.sha256(path.encode()).hexdigest()[:16]


def json_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def publish_record(path, record):
    temporary = path.with_suffix('.tmp')
    with temporary.open('x') as stream:
        json.dump(record, stream, sort_keys=True)
        stream.write('\n')
    temporary.replace(path)


def publish_partial(path, record):
    """Keep a receipt I/O failure from replacing the proof's primary error."""
    try:
        publish_record(path, record)
    except OSError as receipt_error:
        print(f"partial receipt write failed during {record['phase']}: {receipt_error}",
              file=sys.stderr)


def prove_image(job):
    """Prove one image, save its arrays, and return its summary and the external code it reached."""
    index, called = job
    cache = STATE['cache']
    island = index >= len(cache.images)
    if island:
        address, end, file_index, fileoff = STATE['islands'][index-len(cache.images)]
        path = f'island-{address:x}'
    else:
        address, path = cache.images[index]
    work = STATE['work']
    phase = 'calls' if called else 'own'
    roots_digest = json_digest(called) if called else None
    name = f'{path if island else result_name(path)}.{phase}' + (f'-{roots_digest}' if called else '')
    identity = dict(index=index, path=path, address=address, phase=phase,
                    input_sha256=STATE['input_sha256'], rules_sha256=STATE['rules_sha256'],
                    called_roots_sha256=roots_digest, pid=os.getpid(), start_ns=time.time_ns())
    publish_record(work / f'{name}.started.json', identity)
    if island:
        sections = [dict(name='island', addr=address, size=end-address, offset=fileoff, file=file_index)]
        strong, weak, starts = set(), set(), set()
        ordered = []
    else:
        image = dc.Image(cache, address, path)
        sections = image.instruction_sections()
        strong, weak, starts = image.roots() if sections else (set(), set(), set())
        ordered = [('landing', image.landing_pads()), ('stub', image.stub_entries())] if sections else []
    if not sections:
        publish_record(work / f'{name}.done.json', dict(identity, result=None, artifact=None))
        return index, None, []
    if called:
        ordered.append(('call', set(called)))
    started = time.time()
    result = prove_code(cache, sections, strong, weak, starts, ordered, path)
    result['seconds'] = round(time.time() - started, 2)
    reached = result['reached']
    result = save(work, name, result)
    result.update(result_file=f'{name}.npz', reproven_with_calls=bool(called))
    artifact = work / result['result_file']
    with artifact.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    publish_record(work / f'{name}.done.json', dict(identity, result=result,
                   artifact=dict(name=artifact.name, bytes=artifact.stat().st_size, sha256=digest)))
    return index, result, reached


def save(work, name, result):
    edits = np.array(result.pop('edits'), dtype=np.uint64).reshape(-1, 5)
    unproven = np.array(result.pop('unproven'), dtype=np.uint64).reshape(-1, 2)
    kept_data = np.array(result.pop('kept_data'), dtype=np.uint64).reshape(-1, 3)
    reached = np.array(result.pop('reached', []), dtype=np.uint64)
    temporary = work / f'{name}.npz.tmp'
    with temporary.open('xb') as stream:
        np.savez_compressed(stream, edits=edits, unproven=unproven, kept_data=kept_data, reached=reached)
    temporary.replace(work / f'{name}.npz')
    result.update(edit_count=len(edits), unproven_count=len(unproven),
                  edits_by_evidence=dict(Counter(GRADES[int(g)] for g in edits[:, 4])) if len(edits) else {})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--cache', required=True, type=Path, help='main cache file (subcaches beside it)')
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=8)
    parser.add_argument('--only', action='append', help='prove only images whose path ends with this')
    args = parser.parse_args(argv)
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    args.work.mkdir(parents=True, exist_ok=True)
    if any(args.work.iterdir()):
        parser.error('--work must be empty to bind artifacts to this attempt')
    cache = None
    stage = 'initial-rules'
    pending_partial = {}
    try:
        initial_rules = rules_manifest()
        with (args.work / 'initial-rules.json').open('x') as stream:
            json.dump(initial_rules, stream, sort_keys=True)
        stage = 'cache-open'
        cache = dc.Cache(args.cache)
        stage = 'attempt'
        return run_attempt(args, cache, initial_rules, pending_partial)
    except BaseException as error:
        partial = args.work / 'partial.json'
        # Preserve more precise worker or closure failure evidence.
        if not partial.exists() and not (args.work / 'summary.json').exists():
            record = pending_partial or dict(schema='zeta-proof-partial-v1',
                                             phase=stage, error=type(error).__name__,
                                             complete=False)
            publish_partial(partial, record)
        raise
    finally:
        STATE.clear()
        if cache is not None:
            for member in cache.files:
                member.data.close()
                member.handle.close()


def run_attempt(args, cache, initial_rules, pending_partial):
    partial = args.work / 'partial.json'
    completed_phases = {}
    cache.check_opened_generations()
    with (args.work / 'opened-generations.json').open('x') as stream:
        json.dump([dict(name=m.path.name, **m.opened_generation) for m in cache.files], stream)
    initial_input = source_manifest(cache)
    cache.check_opened_generations()
    with (args.work / 'initial-input.json').open('x') as stream:
        json.dump(initial_input, stream, sort_keys=True)
    images = [dc.Image(cache, address, path) for address, path in cache.images]
    ranges = [(s['addr'], s['addr'] + s['size']) for image in images for s in image.sections
              if s['flags'] & dc.INSTRUCTIONS and s['size']]
    islands = [(start, start + size, index, fileoff)
               for index, cache_file in enumerate(cache.files)
               for start, size, fileoff, _, _, flags, maxprot, _ in cache_file.slid if flags & 8]
    ranges += [(start, end) for start, end, _, _ in islands]
    ranges.sort()
    targets = cache.slide_targets()
    order = sorted(range(len(images)), key=lambda i: -sum(s['size'] for s in images[i].sections
                                                           if s['flags'] & dc.INSTRUCTIONS))
    if args.only:
        order = [i for i in order if any(images[i].path.endswith(o) for o in args.only)]
    summary = dict(schema='zeta-dyld-cache-proof-v1', cache=str(args.cache), images={})
    init(cache, ranges, targets, args.work)
    STATE['islands'] = islands
    STATE['input_sha256'] = json_digest(initial_input)
    STATE['rules_sha256'] = json_digest(initial_rules)

    def run(jobs, label):
        results, reached = {}, {}
        expected = [i for i, _ in jobs]
        acknowledged = set()
        pending = {}
        backlog = iter(jobs)
        # A fork takes its own copy of STATE while retaining exactly the mappings
        # from which the parent computed the ranges and slide targets.
        with ProcessPoolExecutor(max_workers=args.jobs, mp_context=multiprocessing.get_context('fork')) as pool:
            def submit_next():
                job = next(backlog, None)
                if job is not None:
                    pending[pool.submit(prove_image, job)] = job[0]

            try:
                for _ in range(min(len(jobs), args.jobs)):
                    submit_next()
                while pending:
                    ready, _ = wait(pending, return_when=FIRST_COMPLETED)
                    for future in ready:
                        requested = pending.pop(future)
                        index, result, found = future.result()
                        if index != requested or index in acknowledged:
                            raise ValueError(f'unexpected result {index} for job {requested}')
                        if result is not None:
                            results[index], reached[index] = result, found
                        acknowledged.add(index)
                        count = len(acknowledged)
                        if count % 200 == 0 or count == len(jobs):
                            print(f'{label}: {count}/{len(jobs)}', file=sys.stderr, flush=True)
                    for _ in ready:
                        submit_next()
            except BaseException as error:
                record = dict(schema='zeta-proof-partial-v1', phase=label,
                              error=type(error).__name__, expected=expected,
                              acknowledged=sorted(acknowledged),
                              missing=[i for i in expected if i not in acknowledged],
                              completed_phases=completed_phases,
                              artifacts_observed=sorted(p.name for p in args.work.glob('*.npz')),
                              complete=False)
                pending_partial.update(record)
                publish_partial(partial, record)
                raise
        completed_phases[label] = sorted(acknowledged)
        return results, reached

    island_ids = list(range(len(images), len(images)+len(islands)))
    ownership = [(s['addr'], s['addr'] + s['size'], i) for i, image in enumerate(images)
                 for s in image.instruction_sections()]
    ownership.extend((a,b,i) for i,(a,b,_,_) in zip(island_ids,islands))
    results, reached = run([(i, ()) for i in order + island_ids], 'own roots')
    rounds = []
    def batch(jobs):
        label = f'closure-{len(rounds)+1:03d}'
        receipt = dict(round=label, input_sha256=STATE['input_sha256'],
                       rules_sha256=STATE['rules_sha256'],
                       jobs=[dict(index=i, roots_sha256=json_digest(roots), roots_count=len(roots))
                             for i,roots in jobs])
        publish_record(args.work / f'{label}.started.json', receipt)
        fresh, edges = run(jobs, label)
        if set(fresh) != {i for i,_ in jobs}:
            raise ValueError('closure lost code-bearing owner')
        results.update(fresh)
        receipt['results'] = {str(i):r['result_file'] for i,r in fresh.items()}
        publish_record(args.work / f'{label}.done.json', receipt)
        rounds.append(receipt)
        return edges
    try:
        closure = close(ownership, reached, batch, partial=bool(args.only))
    except BaseException as error:
        if not partial.exists():
            record = pending_partial or dict(
                schema='zeta-proof-partial-v1', phase='closure',
                error=type(error).__name__, complete=False,
                completed_phases=completed_phases)
            pending_partial.update(record)
            publish_partial(partial, record)
        raise
    summary['closure'] = dict(converged=True, partial=bool(args.only),
                             round_count=len(rounds), rounds_sha256=json_digest(rounds),
                             receipt_set_sha256=receipt_set_digest(args.work)[0],
                             final_roots_sha256=json_digest({str(i):sorted(r) for i,r in closure['roots'].items()}))
    for index, result in results.items():
        if index < len(images):
            summary['images'][images[index].path] = result
    island_results = []
    for index, (start,end,_,_) in zip(island_ids,islands):
        island_results.append(dict(results[index], address=hex(start), size=end-start))
    summary['islands'] = island_results
    totals = Counter()
    for entry in list(summary['images'].values()) + island_results:
        totals['edits'] += entry['edit_count']
        totals['unproven'] += entry['unproven_count']
        totals['unlowerable'] += len(entry['unlowerable'])
        for grade, count in entry['edits_by_evidence'].items():
            totals['edits:' + grade] += count
    summary['totals'] = dict(totals)
    cache.check_opened_generations()
    summary = seal_summary(cache, summary, args.work, partial=bool(args.only))
    if summary['rules'] != initial_rules:
        raise ValueError('proof rules changed during this attempt')
    if summary['source_manifest'] != initial_input:
        raise ValueError('proof input bytes or inventory changed during this attempt')
    pending_summary = args.work / 'summary.tmp'
    pending_summary.write_text(json.dumps(summary, indent=1) + '\n')
    # seal_summary has finished its last mmap read. Only the final rename
    # publishes a consumable summary.
    cache.check_opened_generations()
    pending_summary.replace(args.work / 'summary.json')
    print(json.dumps(summary['totals'], indent=1))
    return 1 if args.only or totals['unproven'] or totals['unlowerable'] else 0


if __name__ == '__main__':
    sys.exit(main())
