import copy
import io
import json
import time
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
from types import SimpleNamespace
import patrol
from test_broker import healthy_result

class DispatchTests(unittest.TestCase):
    def run_patrol(self,failure,recovered=False,job='inactive'):
        calls=[];commands=[];broken=healthy_result();broken['checks'][failure]={'ok':False,'error':'TimeoutError'}
        def call(request):
            calls.append(request['operation'])
            if request['operation']=='diagnose':return copy.deepcopy(broken)
            if request['operation'] in ['recheck_nodes','restore_gateway']:return {'verified_healthy':recovered,'verification':healthy_result() if recovered else copy.deepcopy(broken)}
            if request['operation']=='quality':return {}
            raise AssertionError(request)
        def command(args,**_kwargs):
            commands.append(args)
            return SimpleNamespace(stdout=job if args[1]=='is-active' else 'success',returncode=0)
        with tempfile.TemporaryDirectory() as folder:
            context=Path(folder)/'context.json';context.write_text('{"urgent":false}')
            with patch.object(patrol,'STATE',Path(folder)),patch.object(patrol,'CONTEXT',context),patch.object(patrol,'call',side_effect=call),patch.object(patrol,'inspect_active',return_value={'active':True,'version':'v','result':{'action':'none','probe_domains':[]}}),patch.object(patrol.subprocess,'run',side_effect=command),patch.object(patrol,'save',side_effect=lambda p,data,group=None:p.write_text(json.dumps(data))),patch.object(patrol,'routine_allowed',return_value=True),redirect_stdout(io.StringIO()):
                patrol.main()
            return calls,commands,json.loads(context.read_text())
    def test_successful_conventional_repair_does_not_purchase_ai_analysis(self):
        calls,commands,_context=self.run_patrol('proxy_https',recovered=True)
        self.assertIn('recheck_nodes',calls)
        self.assertFalse(any(command[1]=='start' for command in commands))
    def test_false_healthy_program_cannot_hide_a_new_unresolved_fault(self):
        _calls,commands,context=self.run_patrol('proxy_https')
        self.assertTrue(any(command[1]=='start' for command in commands));self.assertTrue(context['urgent'])
    def test_new_fault_stops_an_active_routine_before_urgent_dispatch(self):
        for job in ['active','activating']:
            with self.subTest(job=job):
                _calls,commands,context=self.run_patrol('bootstrap_dns_api',job=job)
                verbs=[command[1] for command in commands]
                self.assertLess(verbs.index('stop'),verbs.index('start'));self.assertTrue(context['urgent'])

if __name__=='__main__':unittest.main()
