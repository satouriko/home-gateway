import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import runtime_facts

START='39f53479d3a045ac8e11786248231fbf'
STOP='9d1aaa27d60140bd96365438aad20286b'


class RuntimeFactsTests(unittest.TestCase):
    def setUp(self):
        runtime_facts._cache=None
        self.commands=[]
        self.fail=set()
        self.events=[{'_PID':'1','_COMM':'systemd','UNIT':'dsh.service','MESSAGE_ID':kind,
                      '__REALTIME_TIMESTAMP':str((190000+i)*1000000),'MESSAGE':'SECRET token sk-abcdef '+str(i)}
                     for i,kind in enumerate([STOP,START,STOP,START])]
        self.files={'/proc/uptime':'12345.67 23456.78',
                    '/proc/meminfo':'MemTotal: 2000000 kB\nMemAvailable: 1000000 kB\n',
                    '/sys/class/thermal/thermal_zone0/temp':'45000',
                    '/sys/class/net/wlan0/carrier':'1'}

    def run_command(self,args,**kwargs):
        self.commands.append((args,kwargs))
        self.assertLessEqual(kwargs['timeout'],3)
        self.assertLessEqual(kwargs['stdout_limit'],128*1024)
        if args[0] in self.fail:raise FileNotFoundError('SECRET path sk-abcdef')
        if args[0]=='systemctl':
            output='MainPID=1234\nActiveState=active\nSubState=running\nNRestarts=0\nInvocationID='+('a'*32)+'\nExecMainStartTimestampMonotonic=1000000\nActiveEnterTimestampMonotonic=1000200\n'
        elif args[0]=='journalctl':output='\n'.join(json.dumps(row) for row in self.events)
        elif args[0]=='ip':output=json.dumps([{'dev':'wlan0','gateway':'192.168.2.1','prefsrc':'192.168.2.4'}])
        elif args[0]=='iw':output='Connected to aa:bb:cc:dd:ee:ff (on wlan0)\n\tSSID: SECRET WIFI\n\tsignal: -42 dBm\n\trx bitrate: 144.4 MBit/s\n\ttx bitrate: 72.2 MBit/s\n'
        elif args[0]=='vcgencmd':output='throttled=0x50000\n'
        else:raise AssertionError(args)
        return subprocess.CompletedProcess(args,0,output,'')

    def read_file(self,path,*args,**kwargs):
        name=str(path)
        if name not in self.files:raise FileNotFoundError(name)
        return self.files[name]

    def collect(self,now=200000):
        with patch.object(runtime_facts,'bounded_run',self.run_command),patch.object(Path,'read_text',lambda path,*a,**kw:self.read_file(path,*a,**kw)):
            return runtime_facts.collect(now)

    def test_manager_lifecycle_is_distinct_from_zero_automatic_restarts_and_private_logs_are_removed(self):
        result=self.collect();service=result['services']['dsh.service']
        self.assertEqual(service['automatic_restart_count'],0)
        self.assertEqual(service['main_pid'],1234)
        self.assertEqual(service['invocation_id'],'a'*32)
        self.assertEqual(service['process_start_monotonic_usec'],1000000)
        self.assertEqual(service['lifecycle']['observed_start_count'],2)
        self.assertEqual(service['lifecycle']['observed_stop_count'],2)
        self.assertEqual(service['lifecycle']['events'][0]['kind'],'stopped')
        self.assertFalse(service['lifecycle']['coverage']['complete'])
        self.assertIsNone(service['lifecycle']['coverage']['retention_start_at'])
        encoded=json.dumps(result)
        for secret in ['SECRET','sk-abcdef','SSID','aa:bb:cc:dd:ee:ff','192.168.2.1']:
            self.assertNotIn(secret,encoded)

    def test_hardware_and_active_uplink_are_samples_without_bandwidth_or_cause_inference(self):
        result=self.collect()
        self.assertEqual(result['host']['uptime_seconds'],12345.67)
        self.assertEqual(result['host']['memory_available_bytes'],1024000000)
        self.assertEqual(result['host']['temperature_celsius'],45.0)
        self.assertEqual(result['host']['throttled_flags'],0x50000)
        self.assertEqual(result['uplink']['interface'],'wlan0')
        self.assertEqual(result['uplink']['signal_dbm'],-42)
        self.assertEqual(result['uplink']['tx_phy_mbit_s'],72.2)
        self.assertNotIn('bandwidth_mbit_s',result['uplink'])
        self.assertIn('single_sample',result['uplink']['evidence_limits'])

    def test_unavailable_commands_and_empty_journal_are_unknown_not_never_restarted(self):
        self.fail={'systemctl','journalctl','ip','vcgencmd'}
        result=self.collect(); service=result['services']['dsh.service']
        self.assertIsNone(service['automatic_restart_count'])
        self.assertIsNone(service['lifecycle']['observed_start_count'])
        self.assertFalse(service['lifecycle']['coverage']['query_succeeded'])
        self.assertEqual(result['uplink']['status'],'unknown')
        self.assertNotIn('SECRET',json.dumps(result))
        runtime_facts._cache=None;self.fail.clear();self.events=[]
        empty=self.collect()['services']['dsh.service']['lifecycle']
        self.assertEqual(empty['observed_start_count'],0)
        self.assertFalse(empty['coverage']['complete'])
        self.assertIn('retention_unknown',empty['coverage']['gaps'])

    def test_untrusted_process_messages_and_partial_json_never_supply_lifecycle_events(self):
        self.events += [{'_PID':'55','UNIT':'dsh.service','MESSAGE_ID':START,'__REALTIME_TIMESTAMP':'190009000000'},
                        {'_PID':'1','UNIT':'dsh.service','MESSAGE_ID':'not-a-systemd-event','MESSAGE':'Started dsh.service SECRET'}]
        result=self.collect()['services']['dsh.service']['lifecycle']
        self.assertEqual(result['observed_start_count'],2)
        self.assertEqual(len(result['events']),4)
        runtime_facts._cache=None
        self.events=[{'_PID':'1','UNIT':'dsh.service','MESSAGE_ID':START,'__REALTIME_TIMESTAMP':'malformed'}]
        partial=self.collect()['services']['dsh.service']['lifecycle']
        self.assertEqual(partial['coverage']['invalid_event_count'],1)
        self.assertFalse(partial['coverage']['complete'])

    def test_cache_bounds_frequency_and_returns_independent_results(self):
        first=self.collect();first['services']['dsh.service']['main_pid']=999
        count=len(self.commands)
        second=self.collect(200020)
        self.assertEqual(second['services']['dsh.service']['main_pid'],1234)
        self.assertEqual(len(self.commands),count)
        self.assertEqual(second['observed_at'],200000)
        self.collect(200061)
        self.assertGreater(len(self.commands),count)


if __name__=='__main__':unittest.main()
