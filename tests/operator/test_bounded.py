import sys
import unittest
from bounded import run

class BoundedOutputTests(unittest.TestCase):
    def test_stdout_and_stderr_are_limited_during_read(self):
        for descriptor in [1,2]:
            with self.subTest(descriptor=descriptor),self.assertRaisesRegex(ValueError,'output budget'):
                run([sys.executable,'-c',f'import os\nwhile True: os.write({descriptor}, b"x"*4096)'],stdout_limit=8192,stderr_limit=8192,timeout=2)
    def test_normal_result_and_input_are_preserved(self):
        result=run([sys.executable,'-c','import sys; print(sys.stdin.read())'],input='hello')
        self.assertEqual(result.stdout,'hello\n');self.assertEqual(result.returncode,0)
    def test_cancelled_owner_stops_a_child_without_waiting_for_its_work(self):
        with self.assertRaisesRegex(ValueError,'cancelled'):
            run([sys.executable,'-c','import time;time.sleep(10)'],cancelled=lambda:True)

if __name__=='__main__':unittest.main()
