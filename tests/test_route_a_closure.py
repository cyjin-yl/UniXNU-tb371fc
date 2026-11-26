
import json, pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
from route_a_zeta.zeta_closure import ClosureError, close
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import struct
from route_a_zeta import zeta_userland_code as code

A,B,I,C = 0x1000,0x2000,0x3000,0x4000
ranges = [(x,x+4,k) for k,x in enumerate((A,B,I,C))]
def branch(pc,t):
    return 0x14000000 | (((t-pc)//4)&0x03ffffff)
words = {A:branch(A,B), B:branch(B,I), I:branch(I,C), C:0xd65f0fff}
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
class Coverage:
    def __init__(self): self.reached=set()
    def __contains__(self,a): return a in words
def proof(k,roots):
    pc=ranges[k][0]
    insns={i.address:(i.mnemonic,i.op_str) for i in md.disasm(struct.pack('<I',words[pc]),pc)}
    ext=Coverage()
    _,proven,_,_,_,_=code.prove_roots(insns,b'',lambda *args:0,{A} if k==0 else set(),set(),set(),set(),[('call',set(roots))],ext)
    return set(ext.reached),set(proven)
class Tests(unittest.TestCase):
    def test_chain_through_no_pac_image_and_island(self):
        initial={k:proof(k,())[0] for k in range(4)}
        self.assertEqual(initial,{0:{B},1:set(),2:set(),3:set()})
        self.assertEqual(proof(3,())[1],set())
        seen={}
        def batch(jobs):
            result={}
            for k,r in jobs:
                result[k],seen[k]=proof(k,r)
            return result
        report=close(ranges,initial,batch)
        self.assertEqual(report['rounds'],[[(1,(B,))],[(2,(I,))],[(3,(C,))]])
        self.assertEqual(seen[3],{C})
    def test_retracted_edge(self):
        with self.assertRaisesRegex(ValueError,'nonmonotone'):
            close(ranges,{0:{B},1:{C},2:set(),3:set()},lambda jobs:{k:set() for k,r in jobs})
    def test_missing_ack(self):
        with self.assertRaisesRegex(ValueError,'missing'):
            close(ranges,{0:{B},1:set(),2:set(),3:set()},lambda jobs:{})
    def test_bound(self):
        with self.assertRaisesRegex(ValueError,'bound'):
            close(ranges,{0:{B},1:set(),2:set(),3:set()},lambda jobs:{k:proof(k,r)[0] for k,r in jobs},max_rounds=1)
    def test_overlapping_owners(self):
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            close(ranges+[(A,A+4,9)],{},lambda jobs:{})
    def test_unaligned(self):
        with self.assertRaisesRegex(ValueError,'aligned'):
            close(ranges,{0:{B+1},1:set(),2:set(),3:set()},lambda jobs:{})
    def test_missing_initial_owner(self):
        with self.assertRaisesRegex(ValueError,'inventory'):
            close(ranges,{0:{B},1:set()},lambda jobs:{})
    def test_explicit_partial_scope(self):
        r=close(ranges,{0:{B},1:set()},lambda jobs:{1:{I}},partial=True)
        self.assertEqual(r['rounds'],[[(1,(B,))]])
    def test_cycle_terminates(self):
        r=close(ranges,{0:{B},1:set(),2:set(),3:set()},lambda jobs:{k:({A} if k==1 else {B}) for k,_ in jobs})
        self.assertEqual(len(r['rounds']),2)
    def test_closure_failure_identifies_bad_target_and_result_owner(self):
        with self.assertRaises(ClosureError) as caught:
            close(ranges,{0:{B+1},1:set(),2:set(),3:set()},lambda jobs:{})
        self.assertEqual(str(caught.exception),'edge outside aligned executable ownership')
        self.assertEqual(caught.exception.context,dict(target=B+1,round=1))
        with self.assertRaises(ClosureError) as caught:
            close(ranges,{0:{B},1:set(),2:set(),3:set()},lambda jobs:{99:set()})
        self.assertEqual(caught.exception.context,
                         dict(round=1,missing_owners=dict(count=1,sample=[1]),
                              unexpected_owners=dict(count=1,sample=[99])))

    def test_nonmonotone_failure_identifies_removed_edges(self):
        with self.assertRaises(ClosureError) as caught:
            close(ranges,{0:{B},1:{C},2:set(),3:set()},
                  lambda jobs:{k:set() for k,_ in jobs})
        self.assertEqual(caught.exception.context,
                         dict(owner=1,round=1,removed_edges=dict(count=1,sample=[C])))

    def test_missing_owner_context_counts_all_but_bounds_samples(self):
        many=[(A+4*k,A+4*k+4,k) for k in range(32)]
        with self.assertRaises(ClosureError) as caught:
            close(many,{0:set()},lambda jobs:{})
        self.assertEqual(caught.exception.context['missing_owners'],
                         dict(count=31,sample=list(range(1,9))))
        self.assertEqual(caught.exception.context['unexpected_owners'],
                         dict(count=0,sample=[]))

if __name__=='__main__': unittest.main(verbosity=2)
