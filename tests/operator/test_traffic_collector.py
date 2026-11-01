import json
import os
from pathlib import Path
import tempfile
import unittest
import io
from collections import namedtuple

import traffic
import traffic_collector


Usage = namedtuple('Usage', 'total used free')


class CollectorTests(unittest.TestCase):
    def test_mihomo_warning_yields_only_sanitized_client_failure(self):
        raw = {'type': 'warning', 'time': '2026-11-01T01:02:03Z',
               'payload': '[TCP] dial PROXY (match Match/) 192.168.2.2:1234 --> video.example.com:443 error: timeout password=PRIVATE'}
        event = traffic_collector.parse_warning(raw, 1000, {'192.168.2.1'})
        self.assertEqual(event['domain'], 'video.example.com')
        self.assertEqual(event['sourceIP'], '192.168.2.2')
        self.assertEqual(event['error_category'], 'timeout')
        self.assertEqual(event['origin'], 'client')
        self.assertEqual(event['id'], traffic_collector.parse_warning(raw, 1010, {'192.168.2.1'})['id'])
        self.assertNotIn('PRIVATE', json.dumps(event))
        self.assertNotIn('payload', event)

    def test_control_public_sources_and_private_targets_are_excluded(self):
        for source, target in (('192.168.2.1', 'video.example.com'), ('127.0.0.1', 'video.example.com'),
                               ('8.8.8.8', 'video.example.com'), ('192.168.2.2', 'router.lan'),
                               ('192.168.2.2', '192.168.2.1')):
            line = {'type': 'warning', 'payload': '[TCP] dial DIRECT (match Match/) %s:123 --> %s:443 error: timeout' % (source, target)}
            self.assertIsNone(traffic_collector.parse_warning(line, 1000, {'192.168.2.1'}))

    def test_unknown_or_over_budget_log_events_never_become_records(self):
        for line in ('raw credentials', {'type': 'info', 'payload': 'timeout'},
                     {'type': 'warning', 'payload': 'x' * 20000}, {'payload': []}):
            self.assertIsNone(traffic_collector.parse_warning(line, 1000, {'192.168.2.1'}))

    def test_missing_log_timestamp_deduplicates_within_bounded_minute(self):
        line = {'type': 'warning', 'payload': '[TCP] dial PROXY (match Match/) 192.168.2.2:123 --> video.example.com:443 error: connection refused'}
        first = traffic_collector.parse_warning(line, 1000, set())
        same = traffic_collector.parse_warning(json.dumps(line), 1001, set())
        later = traffic_collector.parse_warning(line, 1061, set())
        self.assertEqual(first['id'], same['id'])
        self.assertNotEqual(first['id'], later['id'])
        self.assertEqual(first['error_category'], 'refused')

    def test_local_address_discovery_uses_only_interface_addresses(self):
        addresses = traffic_collector.interface_addresses([{'ifname': 'eth0', 'addr_info': [
            {'local': '192.168.2.1', 'family': 'inet'}, {'local': 'fd00::1', 'family': 'inet6'}]}])
        self.assertIn('192.168.2.1', addresses)
        self.assertIn('fd00::1', addresses)
        self.assertNotIn('192.168.2.2', addresses)

    def test_disk_writes_are_atomic_private_and_throttled_to_two_minutes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'traffic.json'
            collector = traffic_collector.Collector(target, {'192.168.2.1'}, disk_usage=lambda path: Usage(0, 0, 10 * 1024 ** 3))
            collector.observe({'connections': []}, 1000)
            self.assertTrue(collector.persist(1000))
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            collector.observe({'connections': []}, 1002)
            self.assertFalse(collector.persist(1002))
            self.assertEqual(json.loads(target.read_text())['collector']['last_success'], 1000)
            self.assertTrue(collector.persist(1120))
            self.assertFalse(collector.persist(1240))
            self.assertLessEqual(target.stat().st_size, 2 * 1024 ** 2)

    def test_low_disk_preserves_previous_file_without_dropping_failure_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'traffic.json'
            collector = traffic_collector.Collector(target, set(), disk_usage=lambda path: Usage(0, 0, 3 * 1024 ** 3))
            collector.observe({'connections': []}, 1000)
            self.assertFalse(collector.persist(1000))
            self.assertFalse(target.exists())
            self.assertTrue(collector.state['collector']['disk_write_deferred'])

    def test_sampling_stoppage_is_visible_even_when_old_domains_exist(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = traffic_collector.Collector(Path(directory) / 'traffic.json', {'192.168.2.1'})
            collector.observe({'connections': [{'id': 'a', 'metadata': {'sourceIP': '192.168.2.2', 'host': 'video.example.com'},
                                                'upload': 0, 'download': 0}]}, 1000)
            collector.snapshot_failed(1010)
            result = traffic.summary(collector.state, 1200)
            self.assertEqual(result['status'], 'collection_stale')
            self.assertFalse(result['coverage']['sampling_active'])
            self.assertEqual(result['coverage']['last_success'], 1000)
            self.assertFalse(result['coverage']['failure_stream_available'])

    def test_polling_excludes_gateway_and_nonhousehold_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = traffic_collector.Collector(Path(directory) / 'traffic.json', {'192.168.2.1'})
            rows = [{'id': str(i), 'metadata': {'sourceIP': address, 'host': '%s.example.com' % name}, 'upload': 0, 'download': 0}
                    for i, (address, name) in enumerate((('192.168.2.1', 'control'), ('8.8.8.8', 'public'), ('192.168.2.2', 'real')))]
            collector.observe({'connections': rows}, 1000)
            self.assertEqual(traffic.candidates(collector.state, 1000), ['real.example.com'])

    def test_unattributed_logs_do_not_invent_household_use_when_discovery_failed(self):
        line = {'type': 'warning', 'payload': '[TCP] dial PROXY (match Match/) 192.168.2.2:123 --> video.example.com:443 error: timeout'}
        self.assertIsNone(traffic_collector.parse_warning(line, 1000, None))

    def test_malformed_controller_snapshot_does_not_refresh_collection_health(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = traffic_collector.Collector(Path(directory) / 'traffic.json', set())
            collector.observe({'connections': []}, 1000)
            with self.assertRaises(ValueError):
                collector.observe({'unexpected': []}, 1100)
            self.assertEqual(collector.state['collector']['last_success_at'], 1000)

    def test_warning_queue_is_bounded_and_contains_no_original_messages(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = traffic_collector.Collector(Path(directory) / 'traffic.json', set())
            for port in range(600):
                collector.warning({'type': 'warning', 'payload': '[TCP] dial PROXY (match Match/) 192.168.2.2:%s --> video.example.com:443 error: timeout PRIVATE' % port}, 1000)
            self.assertEqual(len(collector.events), 512)
            self.assertEqual(collector.stream['failure_events_dropped'], 88)
            self.assertNotIn('PRIVATE', str(collector.events))

    def test_crash_temporaries_are_removed_without_deleting_current_private_state(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'traffic.json'
            target.write_text('private')
            stale = Path(directory) / '.traffic.json.old'
            stale.write_text('old partial observation')
            os.utime(stale, (1, 1))
            fresh = Path(directory) / '.traffic.json.current'
            fresh.write_text('new')
            traffic_collector.cleanup_stale_temporaries(target, 1000)
            self.assertFalse(stale.exists())
            self.assertTrue(fresh.exists())
            self.assertEqual(target.read_text(), 'private')

    def test_byte_budget_skips_write_without_creating_an_oversized_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'traffic.json'
            collector = traffic_collector.Collector(target, set(), disk_usage=lambda path: Usage(0, 0, 10 * 1024 ** 3))
            collector.state['oversized_fixture'] = 'x' * (2 * 1024 ** 2)
            self.assertFalse(collector.persist(1000))
            self.assertFalse(target.exists())
            self.assertEqual(collector.metadata['persist_error_category'], 'state_byte_budget')


class WarningSocketTests(unittest.TestCase):
    def test_bounded_native_frame_preserves_timestamp_for_failure_dedup(self):
        body=b'{"level":"warn","time":"17:05:01","message":"fixture"}'
        self.assertEqual(traffic_collector.read_log_frame(io.BytesIO(bytes([129,len(body)])+body))[1],body)

    def test_unbounded_masked_fragmented_and_truncated_frames_are_rejected(self):
        for raw in [bytes([129,127])+b'\x00\x00\x00\x00\x00\x01\x00\x00',bytes([129,255]),bytes([1,0]),bytes([129,3])+b'x']:
            with self.assertRaises(ValueError):traffic_collector.read_log_frame(io.BytesIO(raw))


if __name__ == '__main__':
    unittest.main()
