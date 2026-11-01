from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import skills

class SkillReleaseTests(unittest.TestCase):
    def test_routine_canary_is_bounded_by_parent_deadline(self):
        self.assertEqual(skills.canary_budget(150,100),50)
        with self.assertRaises(ValueError):skills.canary_budget(115,100)
    def test_three_complete_stages_are_accepted_without_arbitrary_list_length(self):
        self.assertTrue(skills.valid_method_contract({'user_preferences_changeable':True,'can_maintain_tools':True,
            'workflow':['测试并复现','发布且保留回退','观测实际结果']}))
        self.assertFalse(skills.valid_method_contract({'user_preferences_changeable':False,'can_maintain_tools':True,
            'workflow':['测试并复现','发布且保留回退','观测实际结果']}))
    def test_failed_behavior_test_keeps_published_skill(self):
        with tempfile.TemporaryDirectory() as folder:
            active=Path(folder)/'SKILL.md';active.write_text('working skill')
            with patch.object(skills,'ACTIVE',active),patch.object(skills,'behavior_tests',side_effect=ValueError('bad behavior')):
                with self.assertRaises(ValueError):skills.action('skill_publish','candidate')
            self.assertEqual(active.read_text(),'working skill')
    def test_method_skill_cannot_embed_deployment_addresses(self):
        source='---\nname: home-network-operator\ndescription: Use when maintaining networks\n---\n'+('方法 '*100)+'192.168.2.4'
        with self.assertRaises(ValueError):skills.validate(source)

if __name__=='__main__':unittest.main()
