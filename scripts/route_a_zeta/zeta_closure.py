
"""Independent prototype: finite worklist closure of committed external CFG edges."""
import bisect
from collections import defaultdict

def close(ranges, initial, prove_batch, max_rounds=128, *, partial=False):
    """ranges: disjoint aligned (begin,end,owner); initial: owner->accepted edges.
    prove_batch receives (owner, sorted inbound roots) and returns owner->edges.
    A disappearing edge invalidates the entire attempt, not just its producer.
    The caller must keep source/input frozen and retain results per roots digest.
    """
    ranges = sorted(ranges)
    begins = [a for a, _, _ in ranges]
    for i, (a,b,k) in enumerate(ranges):
        if a >= b or a % 4 or b % 4 or (i and ranges[i-1][1] > a):
            raise ValueError("ambiguous executable ownership")
    owners = {k for _,_,k in ranges}
    if not set(initial) <= owners or (not partial and set(initial) != owners):
        raise ValueError("initial executable owner inventory mismatch")
    edges = {k:set(v) for k,v in initial.items()}
    roots = defaultdict(set)
    frontier = set().union(*edges.values()) if edges else set()
    rounds = []
    while frontier:
        dirty = set()
        for t in sorted(frontier):
            i = bisect.bisect_right(begins,t)-1
            if t % 4 or i < 0 or t >= ranges[i][1]:
                raise ValueError("edge outside aligned executable ownership")
            k = ranges[i][2]
            if k not in edges:
                if partial:
                    continue # caller cannot seal full proof
                raise ValueError("missing executable owner")
            if t not in roots[k]:
                roots[k].add(t)
                dirty.add(k)
        if not dirty:
            break
        if len(rounds) >= max_rounds:
            raise ValueError("closure bound reached; incomplete")
        jobs = [(k, tuple(sorted(roots[k]))) for k in sorted(dirty)]
        returned = prove_batch(jobs)
        if set(returned) != dirty:
            raise ValueError("missing or unexpected proof result")
        frontier = set()
        for k in dirty:
            new = set(returned[k])
            if not edges[k] <= new:
                raise ValueError("nonmonotone accepted external edges")
            frontier.update(new - edges[k])
            edges[k] = new
        rounds.append(jobs)
    return dict(edges=edges, roots=dict(roots), rounds=rounds)
