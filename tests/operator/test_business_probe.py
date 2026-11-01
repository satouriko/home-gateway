import unittest

import business_probe


def sample(status=200, elapsed=100, content=True, verified=True):
    result = {'transport_ok': True, 'http_status': status, 'elapsed_ms': elapsed, 'path_verified': verified}
    if content is not None:
        result['content_ok'] = content
    return result


class ProbeSequence:
    def __init__(self, direct, proxy):
        self.results = {'direct': iter(direct), 'proxy': iter(proxy)}
        self.calls = []

    def __call__(self, target, path):
        self.calls.append((target, path))
        result = next(self.results[path])
        if isinstance(result, Exception):
            raise result
        return result


class BusinessProbeTests(unittest.TestCase):
    def test_bounded_repeated_path_samples_and_layered_acceptance(self):
        runner = ProbeSequence([sample()] * 3, [sample()] * 3)
        result = business_probe.compare('Video.Example.com', runner, 1000)
        self.assertEqual(result['target'], 'video.example.com')
        self.assertEqual(len(runner.calls), 6)
        self.assertEqual(set(path for _, path in runner.calls), {'direct', 'proxy'})
        for path in result['paths'].values():
            self.assertTrue(path['transport_ok'])
            self.assertTrue(path['http_ok'])
            self.assertTrue(path['business_ok'])
            self.assertTrue(path['usable'])
            self.assertEqual(path['application_state'], 'healthy')
        self.assertFalse(result['policy_changed'])

    def test_403_is_rejected_429_limited_and_5xx_server_error(self):
        for status, state in ((403, 'rejected'), (429, 'rate_limited'), (503, 'server_error')):
            with self.subTest(status=status):
                result = business_probe.compare('video.example.com', lambda target, path: sample(status), 1000)
                direct = result['paths']['direct']
                self.assertTrue(direct['transport_ok'])
                self.assertFalse(direct['http_ok'])
                self.assertFalse(direct['usable'])
                self.assertEqual(direct['application_state'], state)
                self.assertGreaterEqual(result['counters']['failed_samples'], 6)

    def test_generic_http_success_is_not_proof_of_application_usability(self):
        result = business_probe.compare('video.example.com', lambda target, path: sample(content=None), 1000)
        direct = result['paths']['direct']
        self.assertTrue(direct['http_ok'])
        self.assertIsNone(direct['business_ok'])
        self.assertFalse(direct['usable'])
        self.assertEqual(direct['application_state'], 'unverified')
        self.assertEqual(result['issue_candidates'], [])

    def test_wrong_content_and_redirect_are_not_success(self):
        for response in (sample(content=False), sample(302)):
            result = business_probe.compare('video.example.com', lambda target, path: response, 1000)
            self.assertFalse(result['paths']['direct']['usable'])
            self.assertFalse(result['paths']['direct']['business_ok'])

    def test_transient_failure_and_single_latency_outlier_do_not_recommend_policy(self):
        runner = ProbeSequence([TimeoutError(), sample(elapsed=100), sample(elapsed=110)],
                               [sample(elapsed=1000), sample(elapsed=90), sample(elapsed=100)])
        result = business_probe.compare('video.example.com', runner, 1000)
        self.assertEqual(result['issue_candidates'], [])
        self.assertEqual(result['counters']['transient_paths'], 1)
        self.assertEqual(result['paths']['direct']['median_elapsed_ms'], 105)

    def test_recurring_failure_is_actionable_only_with_verified_paths(self):
        for verified in (True, False):
            runner = ProbeSequence([sample(403, verified=verified)] * 3, [sample(verified=verified)] * 3)
            result = business_probe.compare('video.example.com', runner, 1000)
            self.assertEqual(result['issue_candidates'][0]['kind'], 'recurring_path_failure')
            self.assertEqual(result['issue_candidates'][0].get('preferred_path'), 'proxy' if verified else None)
            self.assertFalse(result['policy_changed'])

    def test_repeated_latency_gap_is_only_a_review_signal(self):
        runner = ProbeSequence([sample(elapsed=1000), sample(elapsed=1100), sample(elapsed=1200)],
                               [sample(elapsed=90), sample(elapsed=100), sample(elapsed=110)])
        result = business_probe.compare('video.example.com', runner, 1000)
        self.assertEqual(result['issue_candidates'][0]['kind'], 'repeated_latency_gap')
        self.assertEqual(result['issue_candidates'][0]['action'], 'review_only')
        self.assertFalse(result['policy_changed'])

    def test_invalid_targets_never_reach_probe_transport(self):
        calls = []
        def runner(target, path):
            calls.append((target, path))
            return sample()
        for target in ('127.0.0.1', '192.168.1.1', 'localhost', 'router.lan', 'foo.local',
                       'https://' + 'user:pass@public.example.com/', 'https://public.example.com/private',
                       'https://public.example.com:8443/', 'https://public.example.com/?token=x',
                       'http://public.example.com/', 'http://[::1]', 'a.example.com\nHeader: x'):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    business_probe.compare(target, runner, 1000)
        self.assertEqual(calls, [])

    def test_exception_details_and_unknown_payloads_are_bounded_and_sanitized(self):
        runner = ProbeSequence([RuntimeError('SECRET credentials')] * 3, [{'unexpected': 'SECRET'}] * 3)
        result = business_probe.compare('video.example.com', runner, 1000)
        self.assertFalse(result['paths']['direct']['transport_ok'])
        self.assertFalse(result['paths']['proxy']['usable'])
        self.assertNotIn('SECRET', str(result))

    def test_malformed_latency_cannot_abort_a_successful_probe(self):
        result = business_probe.compare('video.example.com', lambda target, path: sample(elapsed=10 ** 1000), 1000)
        self.assertTrue(result['paths']['direct']['usable'])
        self.assertIsNone(result['paths']['direct']['median_elapsed_ms'])
        self.assertEqual(result['issue_candidates'], [])


if __name__ == '__main__':
    unittest.main()
