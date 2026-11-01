import unittest
import patrol


class PatrolBoundsTests(unittest.TestCase):
    def test_dynamic_domains_are_bounded_and_expire_before_model_context(self):
        now=1800000000
        state={'tracked_probes':{f'host{i}.example.com':{'observed_at':now-i} for i in range(300)},
               'audit_rollup':{'fault_counts':{f'client_business:host{i}.example.com':1 for i in range(300)},'fault_last_seen':{f'client_business:host{i}.example.com':now-i for i in range(300)}},
               'business_observations':{'checks':{'old.example.com':{'at':now-300000},'new.example.com':{'at':now}}}}
        patrol.bound_observations(state,now)
        self.assertLessEqual(len(state['tracked_probes']),24)
        self.assertLessEqual(len(state['audit_rollup']['fault_counts']),64)
        self.assertNotIn('old.example.com',state['business_observations']['checks'])
        patrol.bound_observations(state,now+3*86400+1)
        self.assertEqual(state['tracked_probes'],{})
        self.assertEqual(state['audit_rollup']['fault_counts'],{})


if __name__=='__main__':unittest.main()
