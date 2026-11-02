import errno
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack, redirect_stdout
from unittest.mock import patch

import bounded
import native_jobs
import patrol
import pricing

SOURCE=Path(__file__).resolve().parents[2]/'src/operator/ai_job.py'


class WorkerTests(unittest.TestCase):
    def execute(self,context,runner=None):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);reports=root/'reports';context_path=root/'context.json'
            context_path.write_text(json.dumps(context,ensure_ascii=False))
            prompt=root/'prompt';prompt.write_text('Inspect the network.\n')
            ledger=root/'native.json';ledger.write_text(json.dumps({'session_id':'source','runs':[{
                'id':'job','kind':'independent_audit','state':'running','at':time.time(),'deadline':time.time()+540}]}))
            paths={'/run/net-gateway-agent/patrol-context.json':context_path,
                   '/usr/local/share/net-gateway-agent/maintenance-prompt.txt':prompt,
                   '/var/lib/dsh/workspace/maintenance-runs':reports}
            def path(value):return paths.get(str(value),Path(value))
            original_run=bounded.run
            def worker(args,**kwargs):
                # Real pipes and OS argv limits; only replace the external model
                # executable with a child that reports what reached its stdin.
                stub='import json,sys; s=sys.stdin.read(); print(json.dumps({"type":"final","text":"received-tail" if s.count("TAIL-EVIDENCE")==1 else "missing-or-duplicated-input"}))'
                return original_run([sys.executable,'-c',stub,*args[1:]],**kwargs)
            def call(request):
                return native_jobs.finish(request['session_id'],request['job_id'],request['outcome'],
                    execution_session_id=request.get('execution_session_id'),summary=request.get('summary'))
            error=None;exit_code=None
            with ExitStack() as stack:
                stack.enter_context(patch('pathlib.Path',side_effect=path))
                stack.enter_context(patch('os.chdir'))
                stack.enter_context(patch('shutil.disk_usage',return_value=type('Disk',(),{'free':8*1024**3})()))
                stack.enter_context(patch('os.statvfs',return_value=type('FS',(),{'f_favail':100000})()))
                stack.enter_context(patch.object(pricing,'pricing_state',return_value={'off_peak_seconds_remaining':3600}))
                stack.enter_context(patch.object(pricing,'routine_allowed',return_value=True))
                stack.enter_context(patch.object(bounded,'run',side_effect=runner or worker))
                stack.enter_context(patch.object(patrol,'call',side_effect=call))
                stack.enter_context(patch.object(native_jobs,'PATH',ledger))
                stack.enter_context(patch.object(native_jobs,'STATE',root))
                stack.enter_context(redirect_stdout(io.StringIO()))
                try:runpy.run_path(str(SOURCE),run_name='__main__')
                except SystemExit as result:exit_code=result.code
                except Exception as result:error=result
            records=[json.loads(p.read_text()) for p in reports.glob('*.json')] if reports.exists() else []
            return {'error':error,'exit':exit_code,'reports':records,'job':json.loads(ledger.read_text())['runs'][-1]}

    def context(self,**extra):
        return {'native_job_id':'job','native_session_id':'source','maintenance_trigger':'independent_audit',**extra}

    def test_large_utf8_observations_reach_the_worker_and_finish_the_native_lease(self):
        diagnosis={'evidence':'证据'*70000+'TAIL-EVIDENCE'}
        result=self.execute(self.context(diagnosis=diagnosis,last_diagnosis=diagnosis))
        self.assertIsNone(result['error'])
        self.assertEqual(result['exit'],0)
        self.assertEqual(result['reports'][0]['summary'],'received-tail')
        self.assertEqual(result['job']['state'],'completed')

    def test_spawn_failure_is_durable_and_finishes_without_waiting_for_lease_expiry(self):
        def failed(*args,**kwargs):raise OSError(errno.E2BIG,'Argument list too long')
        result=self.execute(self.context(),failed)
        self.assertIsNone(result['error'])
        self.assertNotEqual(result['exit'],0)
        self.assertEqual(result['job']['state'],'failed')
        self.assertTrue(result['job'].get('summary'))
        self.assertEqual(result['reports'][0]['failure']['kind'],'spawn_error')
        self.assertEqual(result['reports'][0]['failure']['errno'],errno.E2BIG)

    def test_timeout_records_visible_failure_without_exposing_raw_stderr(self):
        def timeout(*args,**kwargs):
            raise bounded.LimitError('process execution timed out',{'stdout':bytearray(), 'stderr':bytearray(b'private provider diagnostic')})
        result=self.execute(self.context(),timeout)
        self.assertIsNone(result['error'])
        self.assertEqual(result['job']['state'],'failed')
        self.assertTrue(result['job'].get('summary'))
        self.assertEqual(result['reports'][0]['failure']['kind'],'timeout')
        self.assertNotIn('private provider diagnostic',json.dumps(result['reports']))

    def test_zero_exit_without_final_output_is_not_reported_as_a_completed_review(self):
        result=self.execute(self.context(),lambda *a,**k:subprocess.CompletedProcess([],0,'',''))
        self.assertIsNone(result['error'])
        self.assertNotEqual(result['exit'],0)
        self.assertEqual(result['job']['state'],'failed')
        self.assertEqual(result['reports'][0]['failure']['kind'],'missing_final')

    def test_nonzero_worker_exit_keeps_its_partial_output_but_cannot_claim_completion(self):
        output=json.dumps({'type':'final','text':'Partial observations only'})+'\n'
        result=self.execute(self.context(),lambda *a,**k:subprocess.CompletedProcess([],1,output,''))
        self.assertEqual(result['exit'],1)
        self.assertEqual(result['job']['state'],'failed')
        self.assertIn('Partial observations only',result['reports'][0]['summary'])
        self.assertEqual(result['reports'][0]['failure']['kind'],'worker_exit')

    def test_unrelated_json_lines_do_not_crash_result_reporting(self):
        output='null\n[]\n'+json.dumps({'type':'final','text':'Review completed'})+'\n'
        result=self.execute(self.context(),lambda *a,**k:subprocess.CompletedProcess([],0,output,''))
        self.assertIsNone(result['error'])
        self.assertEqual(result['exit'],0)
        self.assertEqual(result['job']['state'],'completed')


if __name__=='__main__':unittest.main()
