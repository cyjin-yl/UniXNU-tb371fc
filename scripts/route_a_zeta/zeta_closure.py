
"""Independent prototype: finite worklist closure of committed external CFG edges."""
import bisect
from collections import defaultdict


class ClosureError(ValueError):
    """A failed closure gate with bounded, diagnostic-only owner/edge context."""
    def __init__(self, message, **context):
        super().__init__(message)
        self.context = context


def difference_context(left, right):
    """Count every missing value while retaining only the eight smallest values."""
    count, sample = 0, []
    for value in left:
        if value in right:
            continue
        count += 1
        if len(sample) < 8 or value < sample[-1]:
            bisect.insort(sample, value)
            if len(sample) > 8:
                sample.pop()
    return dict(count=count, sample=sample)

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
            raise ClosureError("ambiguous executable ownership",
                               owner=k, range_start=a, range_end=b)
    owners = {k for _,_,k in ranges}
    if not set(initial) <= owners or (not partial and set(initial) != owners):
        raise ClosureError("initial executable owner inventory mismatch",
                           missing_owners=difference_context(owners, initial),
                           unexpected_owners=difference_context(initial, owners))
    edges = {k:set(v) for k,v in initial.items()}
    roots = defaultdict(set)
    frontier = set().union(*edges.values()) if edges else set()
    rounds = []
    while frontier:
        dirty = set()
        for t in sorted(frontier):
            i = bisect.bisect_right(begins,t)-1
            if t % 4 or i < 0 or t >= ranges[i][1]:
                raise ClosureError("edge outside aligned executable ownership",
                                   target=t, round=len(rounds) + 1)
            k = ranges[i][2]
            if k not in edges:
                if partial:
                    continue # caller cannot seal full proof
                raise ClosureError("missing executable owner",
                                   owner=k, target=t, round=len(rounds) + 1)
            if t not in roots[k]:
                roots[k].add(t)
                dirty.add(k)
        if not dirty:
            break
        if len(rounds) >= max_rounds:
            raise ClosureError("closure bound reached; incomplete",
                               completed_rounds=len(rounds), max_rounds=max_rounds,
                               pending_owners=difference_context(dirty, ()))
        jobs = [(k, tuple(sorted(roots[k]))) for k in sorted(dirty)]
        returned = prove_batch(jobs)
        if set(returned) != dirty:
            raise ClosureError("missing or unexpected proof result",
                               round=len(rounds) + 1,
                               missing_owners=difference_context(dirty, returned),
                               unexpected_owners=difference_context(returned, dirty))
        frontier = set()
        for k in dirty:
            new = set(returned[k])
            if not edges[k] <= new:
                raise ClosureError("nonmonotone accepted external edges",
                                   owner=k, round=len(rounds) + 1,
                                   removed_edges=difference_context(edges[k], new))
            frontier.update(new - edges[k])
            edges[k] = new
        rounds.append(jobs)
    return dict(edges=edges, roots=dict(roots), rounds=rounds)
