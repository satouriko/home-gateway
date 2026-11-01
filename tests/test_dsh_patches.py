import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
spec=importlib.util.spec_from_file_location('dsh_patches',Path(__file__).parents[1]/'tools/apply_dsh_patches.py')
patcher=importlib.util.module_from_spec(spec);spec.loader.exec_module(patcher)
sha=lambda value:hashlib.sha256(value.encode()).hexdigest()

class PatchTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.runtime=self.root/'runtime';self.folder=self.runtime/'node_modules/@vendor/sdk';self.folder.mkdir(parents=True)
        self.patches=self.root/'patches';self.patches.mkdir()
        (self.folder/'package.json').write_text('{"version":"1.0"}');(self.folder/'LICENSE').write_text('MIT')
        patch=''
        changes=[]
        for name in ['first.js','second.js']:
            (self.folder/name).write_text('old\n')
            patch+=f'diff --git a/node_modules/@vendor/sdk/{name} b/node_modules/@vendor/sdk/{name}\n--- a/node_modules/@vendor/sdk/{name}\n+++ b/node_modules/@vendor/sdk/{name}\n@@ -1 +1 @@\n-old\n+new\n'
            changes.append({'path':name,'upstreamSha256':sha('old\n'),'patchedSha256':sha('new\n')})
        (self.patches/'sdk.patch').write_text(patch)
        self.manifest={'format':1,'patches':[{'package':'@vendor/sdk','version':'1.0','licenseSha256':sha('MIT'),'file':'sdk.patch','sha256':sha(patch),'changes':changes}]}
        (self.patches/'manifest.json').write_text(json.dumps(self.manifest))
    def test_verified_idempotent_and_resumes_known_partial_install(self):
        (self.folder/'first.js').write_text('new\n')
        self.assertEqual(patcher.apply(self.runtime,self.patches),1)
        self.assertEqual(patcher.apply(self.runtime,self.patches),0)
        self.assertEqual((self.folder/'second.js').read_text(),'new\n')
    def test_unknown_source_or_tampering_fails_before_any_runtime_write(self):
        (self.folder/'second.js').write_text('unreviewed\n')
        with self.assertRaises(ValueError):patcher.apply(self.runtime,self.patches)
        self.assertEqual((self.folder/'first.js').read_text(),'old\n')
        (self.folder/'second.js').write_text('old\n');(self.patches/'sdk.patch').write_text('tampered')
        with self.assertRaises(ValueError):patcher.apply(self.runtime,self.patches)
    def test_symlink_escape_is_rejected(self):
        outside=self.root/'outside';outside.write_text('old\n')
        (self.folder/'first.js').unlink();(self.folder/'first.js').symlink_to(outside)
        with self.assertRaises(ValueError):patcher.apply(self.runtime,self.patches)
        self.assertEqual(outside.read_text(),'old\n')
    def test_new_module_is_created_and_partial_install_can_resume(self):
        patch=(self.patches/'sdk.patch').read_text()
        patch+='--- /dev/null\n+++ b/node_modules/@vendor/sdk/lib/new.js\n@@ -0,0 +1 @@\n+new module\n'
        (self.patches/'sdk.patch').write_text(patch)
        package=self.manifest['patches'][0];package['sha256']=sha(patch)
        package['changes'].append({'path':'lib/new.js','upstreamSha256':None,'patchedSha256':sha('new module\n')})
        (self.patches/'manifest.json').write_text(json.dumps(self.manifest))
        self.assertEqual(patcher.apply(self.runtime,self.patches),3)
        self.assertEqual((self.folder/'lib/new.js').read_text(),'new module\n')
        self.assertEqual(patcher.apply(self.runtime,self.patches),0)
