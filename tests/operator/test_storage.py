from pathlib import Path
import json
import fcntl
import os
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from types import SimpleNamespace
import io
import storage
from storage import prune_background,trim_files

class StorageTests(unittest.TestCase):
    def test_checkpoint_rotation_preserves_current_recovery_pointer(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder);(p/'checkpoints').mkdir()
            for number in range(8):
                child=p/'checkpoints'/str(number);child.mkdir();os.utime(child,(number+1,number+1))
            (p/'known-good').symlink_to(p/'checkpoints/0')
            storage.trim_checkpoints(p,keep=4)
            self.assertTrue((p/'known-good').exists());self.assertEqual(len(list((p/'checkpoints').iterdir())),5)
    def test_low_space_releases_reserve_and_defers_routine_without_a_model(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);state=base/'state';state.mkdir();home=base/'home';home.mkdir();work=base/'work';work.mkdir()
            reserve=state/'emergency.reserve';reserve.write_bytes(b'x'*100)
            with patch.object(storage,'STATE',state),patch.object(storage,'HOME',home),patch.object(storage,'WORK',work),patch.object(storage,'CONFIG',base/'missing'),patch.object(storage.shutil,'disk_usage',return_value=SimpleNamespace(free=1024**3)),redirect_stdout(io.StringIO()):storage.main()
            result=json.loads((state/'storage.json').read_text())
            self.assertFalse(reserve.exists());self.assertTrue(result['pause_routine']);self.assertTrue(result['critical'])
    def test_background_rotation_preserves_user_chats_and_live_leases(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder);workspace=base/'workspace';workspace.mkdir();registry={};dirs=[]
            for number in range(4):
                name='session-'+str(number).zfill(36);p=workspace/name;p.mkdir();(p/'session.lock').touch();(p/'log').write_bytes(b'x'*100)
                registry[name]={'kind':'patrol','user_chat':number==0};os.utime(p,(number+1,number+1));dirs.append(p)
            with (dirs[1]/'session.lock').open('r+b') as handle:
                fcntl.flock(handle,fcntl.LOCK_EX)
                result=prune_background(base,registry,0,1)
            self.assertTrue(dirs[0].exists());self.assertTrue(dirs[1].exists());self.assertFalse(dirs[2].exists());self.assertTrue(dirs[3].exists())
    def test_duplicate_reports_have_a_count_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            for index in range(8):(p/str(index)).write_bytes(b'x'*10)
            self.assertEqual(trim_files(p,keep=3),50);self.assertEqual(len(list(p.iterdir())),3)

if __name__=='__main__':unittest.main()
