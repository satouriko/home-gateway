import json
import unittest

import traffic


def connection(identifier='a', host='video.example.com', source='192.168.1.20', upload=100, download=1000, **extra):
    return {'id': identifier, 'start': '2026-11-01T00:00:00Z', 'upload': upload, 'download': download,
            'metadata': {'sourceIP': source, 'host': host}, 'rule': 'DomainSuffix',
            'chains': ['Hong Kong', 'proxy'], **extra}


class TrafficTests(unittest.TestCase):
    def test_only_real_client_domains_become_candidates(self):
        rows = [connection(), connection('pi', 'control.example.com', '192.168.1.2'),
                connection('loop', 'loop.example.com', '127.0.0.1'),
                connection('probe', 'probe.example.com', synthetic=True),
                connection('private', 'router.lan'), connection('ip', '192.168.1.1'),
                connection('empty', '')]
        state = traffic.update({}, {'connections': rows}, 1000, {'192.168.1.2'})
        self.assertEqual(traffic.candidates(state, 1000), ['video.example.com'])
        result = traffic.summary(state, 1000)
        self.assertEqual(result['scope'], 'household_clients')
        self.assertFalse(result['coverage']['complete'])
        self.assertIn('short_or_failed_connections_may_be_absent', result['coverage']['gaps'])

    def test_bytes_are_monotonic_deltas_and_counter_reset_is_not_new_traffic(self):
        state = traffic.update({}, [connection()], 1000, set())
        self.assertEqual(traffic.summary(state, 1000)['observed_bytes_lower_bound'], 0)
        state = traffic.update(state, [connection(upload=160, download=1100)], 1001, set())
        state = traffic.update(state, [connection(upload=160, download=1100)], 1002, set())
        self.assertEqual(traffic.summary(state, 1002)['observed_bytes_lower_bound'], 160)
        state = traffic.update(state, [connection(upload=2, download=3)], 1003, set())
        self.assertEqual(traffic.summary(state, 1003)['observed_bytes_lower_bound'], 160)
        state = traffic.update(state, [connection(upload=12, download=23)], 1004, set())
        result = traffic.summary(state, 1004)
        self.assertEqual(result['observed_bytes_lower_bound'], 190)
        self.assertEqual(result['domains'][0]['observed_upload_bytes'], 70)
        self.assertEqual(result['domains'][0]['observed_download_bytes'], 120)

    def test_missing_snapshots_do_not_recount_a_returning_connection(self):
        state = traffic.update({}, [connection()], 1000, set())
        state = traffic.update(state, [connection(download=1100)], 1001, set())
        state = traffic.update(state, [], 1002, set())
        state = traffic.update(state, [connection(download=1100)], 1003, set())
        self.assertEqual(traffic.summary(state, 1003)['observed_bytes_lower_bound'], 100)

    def test_reused_id_or_expired_baseline_does_not_count_unknown_bytes(self):
        state = traffic.update({}, [connection()], 1000, set())
        state = traffic.update(state, [connection(start='2026-11-01T01:00:00Z', download=5000)], 1010, set())
        self.assertEqual(traffic.summary(state, 1010)['observed_bytes_lower_bound'], 0)
        state = traffic.update(state, [connection(download=9000)], 1000 + 73 * 3600, set())
        self.assertEqual(traffic.summary(state, 1000 + 73 * 3600)['observed_bytes_lower_bound'], 0)

    def test_empty_and_stale_data_are_unknown_not_healthy(self):
        result = traffic.summary({}, 1000)
        self.assertEqual(result['domains'], [])
        self.assertEqual(result['status'], 'insufficient_evidence')
        self.assertFalse(result['coverage']['complete'])
        state = traffic.update({}, [connection()], 1000, set())
        self.assertEqual(traffic.candidates(state, 1000 + 73 * 3600), [])
        self.assertEqual(traffic.summary(state, 1000 + 73 * 3600)['domains'], [])

    def test_client_failures_persist_and_are_deduplicated_without_raw_logs(self):
        fail = {'domain': 'chat.example.com', 'sourceIP': '192.168.1.20', 'error_category': 'timeout',
                'origin': 'client', 'id': 'warning-1', 'at': 1000,
                'raw_log': 'SECRET https://' + 'user:pass@example.com/private'}
        state = traffic.record_failures({}, [fail, fail], 1000, set())
        self.assertEqual(traffic.summary(state, 1000)['domains'][0]['failure_count'], 1)
        self.assertEqual(traffic.summary(state, 1000)['issues'], [])
        for at in (1060, 1120):
            state = traffic.record_failures(state, [{**fail, 'id': str(at), 'at': at}], at, set())
        state = traffic.update(state, [], 1200, set())
        result = traffic.summary(state, 1200)
        self.assertEqual(result['issues'][0]['kind'], 'recurring_client_failure')
        self.assertEqual(result['domains'][0]['failure_count'], 3)
        self.assertEqual(traffic.candidates(state, 1200), ['chat.example.com'])
        self.assertNotIn('SECRET', json.dumps(state))

    def test_control_failures_and_arbitrary_error_text_do_not_create_client_usage(self):
        failures = [{'domain': 'control.example.com', 'sourceIP': '192.168.1.2', 'origin': 'client', 'error_category': 'timeout'},
                    {'domain': 'probe.example.com', 'sourceIP': '192.168.1.20', 'origin': 'probe', 'error_category': 'timeout'},
                    {'domain': 'missing.example.com', 'origin': 'client', 'error_category': 'timeout'}]
        state = traffic.record_failures({}, failures, 1000, {'192.168.1.2'})
        self.assertEqual(traffic.candidates(state, 1000), [])

    def test_cardinality_and_serialized_state_are_finite_even_with_oversized_input(self):
        rows = [connection(str(i), 'd%s.example.com' % i, chains=['x' * 10000]) for i in range(2000)]
        state = traffic.update({}, rows, 1000, set())
        self.assertLessEqual(len(state['domains']), 256)
        self.assertLess(len(json.dumps(state).encode()), 32 * 1024 * 1024)
        self.assertLess(len(json.dumps(traffic.summary(state, 1000)).encode()), 65536)
        self.assertLessEqual(len(traffic.candidates(state, 1000, limit=1000)), 3)

    def test_changed_host_same_id_does_not_transfer_bytes_between_domains(self):
        state = traffic.update({}, [connection()], 1000, set())
        state = traffic.update(state, [connection(host='new.example.com', download=5000)], 1001, set())
        self.assertEqual(traffic.summary(state, 1001)['observed_bytes_lower_bound'], 0)

    def test_malformed_telemetry_does_not_interrupt_client_collection(self):
        rows = [None, {'metadata': None}, connection(upload=10 ** 1000),
                {**connection('invalid'), 'metadata': {'sourceIP': '192.168.1.20', 'host': 'bad.example.com', 'origin': []}},
                connection('valid', 'good.example.com')]
        state = traffic.update({}, rows, 1000, set(), failures=[
            {'domain': 'fail.example.com', 'sourceIP': '192.168.1.20', 'origin': 'client', 'error_category': []}])
        self.assertIn('good.example.com', traffic.candidates(state, 1000))
        self.assertEqual(traffic.summary(state, 1000)['failure_count'], 1)

    def test_old_warning_cannot_move_observed_domain_backwards_in_time(self):
        state = traffic.update({}, [connection()], 2000, set())
        state = traffic.record_failures(state, [{'domain': 'video.example.com', 'sourceIP': '192.168.1.20',
                                               'origin': 'client', 'error_category': 'timeout', 'at': 1000}], 2000, set())
        self.assertEqual(traffic.summary(state, 2000)['domains'][0]['last_seen'], 2000)

    def test_many_devices_and_connection_ids_do_not_create_unbounded_state(self):
        rows = [connection(str(i), source='192.168.%s.%s' % (i // 250, i % 250 + 1)) for i in range(5000)]
        state = traffic.update({}, rows, 1000, set())
        state = traffic.update(state, [dict(row, download=2000) for row in rows], 1001, set())
        result = traffic.summary(state, 1001)
        self.assertLessEqual(len(state['connections']), 4096)
        self.assertLessEqual(len(state['devices']), 128)
        self.assertLess(len(json.dumps(state).encode()), 32 * 1024 * 1024)
        self.assertEqual(result['observed_bytes_lower_bound'], 4096000)
        self.assertGreater(result['coverage']['dropped_observations'], 0)

    def test_old_busy_domain_does_not_displace_recent_household_candidates(self):
        state = traffic.update({}, [connection(host='old.example.com')], 1000, set())
        state = traffic.update(state, [connection(host='old.example.com', download=9000000)], 1100, set())
        state = traffic.update(state, [connection('new', 'recent.example.com')], 1100 + 7 * 3600, set())
        self.assertEqual(traffic.candidates(state, 1100 + 7 * 3600), ['recent.example.com'])

    def test_zero_byte_or_stuck_connection_is_candidate_but_not_proven_failure(self):
        state = traffic.update({}, [connection(upload=0, download=0)], 1000, set())
        state = traffic.update(state, [connection(upload=0, download=0)], 1060, set())
        self.assertEqual(traffic.candidates(state, 1060), ['video.example.com'])
        self.assertEqual(traffic.summary(state, 1060)['issues'], [])

    def test_saturated_hourly_history_serializes_within_two_mebibytes(self):
        rows = [connection(str(i), 'd%s.example.com' % (i % 256),
                           '192.168.%s.%s' % (i // 250, i % 250 + 1)) for i in range(4096)]
        state = traffic.update({}, rows, 1000, set())
        for hour in range(1, 72):
            state = traffic.update(state, [dict(row, upload=hour * 10000, download=hour * 1000000)
                                          for row in rows[:256]], 1000 + hour * 3600, set())
        self.assertLess(len(json.dumps(state).encode()), 2 * 1024 * 1024)

    def test_old_failures_remain_history_without_permanent_urgent_recurrence(self):
        state = {}
        for at in (1000, 1060, 1120):
            state = traffic.record_failures(state, [{'domain': 'video.example.com', 'sourceIP': '192.168.1.20',
                                                     'origin': 'client', 'error_category': 'timeout', 'at': at}], at, set())
        self.assertEqual(traffic.summary(state, 1200)['issues'][0]['kind'], 'recurring_client_failure')
        result = traffic.summary(state, 5000)
        self.assertEqual(result['issues'], [])
        self.assertEqual(result['domains'][0]['failure_count'], 3)
        self.assertEqual(result['domains'][0]['device_addresses'], ['192.168.1.20'])

    def test_completed_connection_baselines_do_not_block_new_traffic_for_days(self):
        old = [connection(str(i)) for i in range(4096)]
        state = traffic.update({}, old, 1000, set())
        state = traffic.update(state, [connection('new')], 1400, set())
        state = traffic.update(state, [connection('new', download=1500)], 1402, set())
        self.assertEqual(traffic.summary(state, 1402)['observed_bytes_lower_bound'], 500)

    def test_failure_event_capacity_does_not_hide_all_future_failures(self):
        events = [{'domain': 'video.example.com', 'sourceIP': '192.168.1.20', 'origin': 'client',
                   'error_category': 'timeout', 'id': str(i), 'at': 1000} for i in range(1024)]
        state = traffic.record_failures({}, events, 1000, set())
        for at in (1060, 1120):
            state = traffic.record_failures(state, [{**events[0], 'id': str(at), 'at': at}], at, set())
        result = traffic.summary(state, 1200)
        self.assertEqual(result['failure_count'], 1026)
        self.assertEqual(result['issues'][0]['kind'], 'recurring_client_failure')
        self.assertLessEqual(len(state['failure_events']), 1024)

    def test_full_domain_history_admits_new_recent_domain_without_waiting_for_age(self):
        state = traffic.update({}, [connection(str(i), 'd%s.example.com' % i) for i in range(256)], 1000, set())
        state = traffic.update(state, [connection('new', 'new.example.com')], 1010, set())
        result = traffic.summary(state, 1010)
        self.assertEqual(len(state['domains']), 256)
        self.assertIn('new.example.com', traffic.candidates(state, 1010))
        self.assertEqual(result['coverage']['domain_evictions'], 1)
        self.assertEqual(result['coverage']['failure_domain_evictions'], 0)

    def test_new_failure_survives_snapshot_domain_churn_until_recurrence_is_observable(self):
        state = traffic.update({}, [connection(str(i), 'd%s.example.com' % i) for i in range(256)], 1000, set())
        for index, at in enumerate((1060, 1120, 1180)):
            state = traffic.record_failures(state, [{'domain': 'failed.example.com', 'sourceIP': '192.168.1.20',
                                                     'origin': 'client', 'error_category': 'timeout', 'at': at}], at, set())
            rows = [connection('%s-%s' % (index, i), 'churn%s-%s.example.com' % (index, i)) for i in range(300)]
            state = traffic.update(state, rows, at + 1, set())
        result = traffic.summary(state, 1200)
        self.assertEqual(result['issues'][0]['domain'], 'failed.example.com')
        self.assertEqual(result['issues'][0]['failure_count'], 3)
        self.assertIn('failed.example.com', traffic.candidates(state, 1200))
        self.assertGreaterEqual(result['coverage']['domain_evictions'], 901)
        self.assertEqual(result['coverage']['failure_domain_evictions'], 0)
        self.assertLessEqual(len(state['domains']), 256)

    def test_new_failure_at_all_failure_capacity_evicts_oneoff_before_recurring_issue(self):
        state = traffic.record_failures({}, [{'domain': 'd%s.example.com' % i, 'sourceIP': '192.168.1.20',
                                             'origin': 'client', 'error_category': 'timeout', 'at': 1000} for i in range(256)], 1000, set())
        for at in (1060, 1120):
            state = traffic.record_failures(state, [{'domain': 'd0.example.com', 'sourceIP': '192.168.1.20',
                                                     'origin': 'client', 'error_category': 'timeout', 'at': at}], at, set())
        state = traffic.record_failures(state, [{'domain': 'new-failure.example.com', 'sourceIP': '192.168.1.20',
                                                 'origin': 'client', 'error_category': 'timeout', 'at': 1180}], 1180, set())
        result = traffic.summary(state, 1200)
        self.assertIn('new-failure.example.com', state['domains'])
        self.assertEqual(result['issues'][0]['domain'], 'd0.example.com')
        self.assertEqual(result['coverage']['failure_domain_evictions'], 1)
        self.assertEqual(result['coverage']['recurring_issue_evictions'], 0)
        self.assertEqual(len(state['domains']), 256)

    def test_ordinary_domain_capacity_drop_is_visible_when_all_records_have_recent_failures(self):
        state = traffic.record_failures({}, [{'domain': 'd%s.example.com' % i, 'sourceIP': '192.168.1.20',
                                             'origin': 'client', 'error_category': 'timeout', 'at': 1000} for i in range(256)], 1000, set())
        state = traffic.update(state, [connection('ordinary', 'ordinary.example.com')], 1010, set())
        result = traffic.summary(state, 1010)
        self.assertEqual(result['coverage']['domain_capacity_drops'], 1)
        self.assertEqual(result['coverage']['dropped_observations'], 1)
        self.assertEqual(len(state['domains']), 256)


if __name__ == '__main__':
    unittest.main()
