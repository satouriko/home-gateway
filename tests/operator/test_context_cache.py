import concurrent.futures
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import context_cache


class ContextCacheTests(unittest.TestCase):
    def setUp(self):
        context_cache.invalidate()
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'patrol.json';self.state.write_text('initial')
        self.addCleanup(context_cache.invalidate)

    def test_ttl_stabilizes_volatile_snapshot_until_sixty_seconds_from_collection(self):
        calls=[]
        def collect():
            calls.append(1)
            return {'checked_at':1000+len(calls),'memory_available':4000-len(calls)}
        first=context_cache.get(collect,[self.state],now=10)
        self.assertEqual(context_cache.get(collect,[self.state],now=69),first)
        refreshed=context_cache.get(collect,[self.state],now=70)
        self.assertEqual(refreshed['checked_at'],1002)
        self.assertEqual(len(calls),2)

    def test_default_ttl_uses_monotonic_clock_and_never_extends_on_cache_hit(self):
        count=[]
        def collect():count.append(1);return {'generation':len(count)}
        with patch.object(context_cache.time,'monotonic',side_effect=[100,110,161]):
            self.assertEqual(context_cache.get(collect,[])['generation'],1)
            self.assertEqual(context_cache.get(collect,[])['generation'],1)
            self.assertEqual(context_cache.get(collect,[])['generation'],2)

    def test_atomic_state_replacement_and_missing_file_creation_invalidate_before_ttl(self):
        calls=[];missing=self.root/'incidents.json'
        def collect():calls.append(1);return {'generation':len(calls)}
        watch=[self.state,missing]
        self.assertEqual(context_cache.get(collect,watch,now=10)['generation'],1)
        replacement=self.root/'replacement';replacement.write_text('initial');os.replace(replacement,self.state)
        self.assertEqual(context_cache.get(collect,watch,now=11)['generation'],2)
        missing.write_text('{}')
        self.assertEqual(context_cache.get(collect,watch,now=12)['generation'],3)
        missing.unlink()
        self.assertEqual(context_cache.get(collect,watch,now=13)['generation'],4)

    def test_inplace_timestamp_change_is_seen_even_when_inode_and_size_stay_equal(self):
        calls=[]
        def collect():calls.append(1);return len(calls)
        self.assertEqual(context_cache.get(collect,[self.state],now=10),1)
        info=self.state.stat();self.state.write_text('changed')
        os.utime(self.state,ns=(info.st_atime_ns,info.st_mtime_ns+1000000))
        self.assertEqual(context_cache.get(collect,[self.state],now=11),2)

    def test_watch_set_and_factory_identity_are_part_of_the_one_entry_key(self):
        a=self.root/'policy.json';b=self.root/'workflow.json';calls=[]
        def collect():calls.append(1);return len(calls)
        self.assertEqual(context_cache.get(collect,[a,b],now=10),1)
        self.assertEqual(context_cache.get(collect,[b,a,a],now=11),1)
        self.assertEqual(context_cache.get(collect,[a],now=12),2)
        self.assertEqual(context_cache.get(collect,[b],now=13),3)
        def other():return 'separate factory'
        self.assertEqual(context_cache.get(other,[a],now=14),'separate factory')
        self.assertEqual(context_cache.get(collect,[a],now=15),4)

    def test_return_and_factory_aliases_cannot_mutate_cached_snapshot(self):
        raw={'services':{'gateway':{'healthy':False}},'rows':[{'at':10}]}
        def collect():return raw
        first=context_cache.get(collect,[self.state],now=10)
        first['services']['gateway']['healthy']=True;first['rows'].append({'at':20})
        raw['rows'][0]['at']=999
        cached=context_cache.get(collect,[self.state],now=11)
        self.assertFalse(cached['services']['gateway']['healthy'])
        self.assertEqual(cached['rows'],[{'at':10}])

    def test_refresh_errors_raise_instead_of_falling_back_to_old_healthy_context(self):
        mode={'fail':False};calls=[]
        def collect():
            calls.append(1)
            if mode['fail']:raise RuntimeError('collection unavailable')
            return {'healthy':len(calls)==1}
        self.assertTrue(context_cache.get(collect,[self.state],now=10)['healthy'])
        mode['fail']=True
        with self.assertRaisesRegex(RuntimeError,'collection unavailable'):
            context_cache.get(collect,[self.state],now=70)
        mode['fail']=False
        self.assertFalse(context_cache.get(collect,[self.state],now=71)['healthy'])
        self.assertEqual(len(calls),3)

    def test_two_concurrent_readers_collect_once_and_receive_independent_snapshots(self):
        entered=threading.Event();release=threading.Event();calls=[]
        def collect():
            calls.append(1);entered.set()
            if not release.wait(2):raise TimeoutError('test release not reached')
            return {'rows':[]}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first=pool.submit(context_cache.get,collect,[self.state],10)
            self.assertTrue(entered.wait(1))
            second=pool.submit(context_cache.get,collect,[self.state],10)
            release.set();a=first.result(timeout=2);b=second.result(timeout=2)
        self.assertEqual(len(calls),1);self.assertEqual(a,b)
        a['rows'].append('mutation');self.assertEqual(b['rows'],[])

    def test_source_change_during_collection_prevents_caching_mixed_snapshot(self):
        calls=[]
        def collect():
            calls.append(1)
            if len(calls)==1:
                replacement=self.root/'next';replacement.write_text('new version');os.replace(replacement,self.state)
            return {'generation':len(calls)}
        self.assertEqual(context_cache.get(collect,[self.state],now=10)['generation'],1)
        self.assertEqual(context_cache.get(collect,[self.state],now=11)['generation'],2)
        self.assertEqual(context_cache.get(collect,[self.state],now=12)['generation'],2)

    def test_metadata_permission_errors_force_fresh_collection_without_reusing_any_snapshot(self):
        calls=[]
        def collect():calls.append(1);return {'generation':len(calls)}
        self.assertEqual(context_cache.get(collect,[self.state],now=10)['generation'],1)
        with patch.object(Path,'stat',side_effect=PermissionError('metadata unavailable')):
            self.assertEqual(context_cache.get(collect,[self.state],now=11)['generation'],2)
            self.assertEqual(context_cache.get(collect,[self.state],now=12)['generation'],3)
        self.assertEqual(context_cache.get(collect,[self.state],now=13)['generation'],4)

    def test_size_change_invalidates_even_when_inode_and_timestamp_are_preserved(self):
        calls=[]
        def collect():calls.append(1);return len(calls)
        self.assertEqual(context_cache.get(collect,[self.state],now=10),1)
        info=self.state.stat();self.state.write_text('longer new state')
        os.utime(self.state,ns=(info.st_atime_ns,info.st_mtime_ns))
        self.assertEqual(context_cache.get(collect,[self.state],now=11),2)

    def test_explicit_invalidation_and_invalidation_inside_factory_force_next_refresh(self):
        calls=[]
        def collect():
            calls.append(1)
            if len(calls)==1:context_cache.invalidate()
            return len(calls)
        self.assertEqual(context_cache.get(collect,[],now=10),1)
        self.assertEqual(context_cache.get(collect,[],now=11),2)
        context_cache.invalidate()
        self.assertEqual(context_cache.get(collect,[],now=12),3)


if __name__=='__main__':unittest.main()
