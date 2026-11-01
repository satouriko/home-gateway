import unittest
import sandbox_runner


class SandboxRunnerTests(unittest.TestCase):
    def test_drops_web_bind_capability_before_confined_execution(self):
        command = sandbox_runner.command(['--ro-bind','/','/','--bind','/var/lib/dsh/workspace','/var/lib/dsh/workspace','--','bash','-c','true'])
        self.assertEqual(command[:4], ['/usr/bin/setpriv','--ambient-caps=-all','--inh-caps=-all','/usr/bin/bwrap'])
        split = command.index('--')
        self.assertEqual(command[split+1:], ['bash','-c','true'])
        for path in ['/var/lib/dsh/state','/var/lib/dsh-login','/run/net-gateway-agent']:
            self.assertIn(path, command[:split])
            self.assertEqual(command[command.index(path)-1], '--tmpfs')

    def test_invalid_runner_profile_never_falls_back_to_unconfined(self):
        for arguments in [[], ['bash','-c','true'], ['--ro-bind','/','/','--']]:
            with self.assertRaises(ValueError): sandbox_runner.command(arguments)


if __name__ == '__main__': unittest.main()
