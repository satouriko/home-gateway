import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import control_route

class RouteTests(unittest.TestCase):
    def test_iproute2_uid_start_end_format_is_idempotent(self):
        calls=[]
        def run(*args):
            calls.append(args)
            if args==('ip','-j','route','get','192.168.2.1'):
                return SimpleNamespace(stdout=json.dumps([{'dev':'wlan0','prefsrc':'192.168.2.4'}]))
            if args==('ip','-j','rule','show'):
                return SimpleNamespace(stdout=json.dumps([{'priority':100,'uid_start':999,'uid_end':999,'table':'51889'}]))
            return SimpleNamespace(stdout='')
        with patch.object(control_route,'run',side_effect=run),patch.object(control_route.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=999)):
            self.assertEqual(control_route.apply()['uid'],999)
        self.assertFalse(any(call[:3]==('ip','rule','add') for call in calls))

if __name__=='__main__':unittest.main()
