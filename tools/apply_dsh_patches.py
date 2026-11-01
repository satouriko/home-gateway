#!/usr/bin/env python3
"""Apply the reviewed SDK extension only to exact, pinned npm artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def apply(runtime,patches):
    runtime=Path(runtime).resolve();patches=Path(patches).resolve()
    manifest=json.loads((patches/'manifest.json').read_text())
    if manifest.get('format')!=1:raise ValueError('unsupported patch manifest')
    targets=[]
    for package in manifest['patches']:
        relative=PurePosixPath(package['package'])
        if relative.is_absolute() or '..' in relative.parts or len(relative.parts)!=2 or not relative.parts[0].startswith('@'):
            raise ValueError('invalid SDK package path')
        folder=runtime/'node_modules'/str(relative)
        if json.loads((folder/'package.json').read_text())['version']!=package['version']:raise ValueError('SDK version requires patch review')
        patchfile=patches/package['file']
        if patchfile.parent!=patches or digest(patchfile)!=package['sha256']:raise ValueError('patch integrity mismatch')
        if digest(folder/'LICENSE')!=package['licenseSha256']:raise ValueError('upstream license changed')
        for change in package['changes']:
            name=PurePosixPath(change['path'])
            if name.is_absolute() or '..' in name.parts:raise ValueError('invalid SDK target path')
            target=folder/str(name)
            for parent in [target,*target.parents]:
                if parent==runtime.parent:break
                if parent.is_symlink():raise ValueError('SDK target symlink rejected')
            current=digest(target) if target.exists() else None
            if current not in [change['upstreamSha256'],change['patchedSha256']]:raise ValueError('SDK source changed; review before patching: '+str(relative/name))
            targets.append((target,Path('node_modules')/str(relative)/str(name),change,current,package))
    with tempfile.TemporaryDirectory(prefix='dsh-extension-') as tmp:
        stage=Path(tmp)
        for source,relative,_,_,_ in targets:
            destination=stage/relative;destination.parent.mkdir(parents=True,exist_ok=True)
            if source.exists():shutil.copy2(source,destination)
        for package in manifest['patches']:
            include=[str(relative) for _,relative,change,current,owner in targets if owner is package and current!=change['patchedSha256']]
            if not include:continue
            arguments=['git','apply',*[f'--include={name}' for name in include],str(patches/package['file'])]
            subprocess.run(arguments,cwd=stage,check=True,capture_output=True)
        for _,relative,change,_,_ in targets:
            if digest(stage/relative)!=change['patchedSha256']:raise ValueError('patched SDK verification failed')
        changed=0
        for target,relative,change,current,_ in targets:
            if current==change['patchedSha256']:continue
            target.parent.mkdir(parents=True,exist_ok=True)
            temporary=target.with_name(target.name+'.home-gateway-next')
            try:
                with temporary.open('xb') as stream:
                    os.chmod(temporary,(target.stat().st_mode&0o777) if target.exists() else 0o644);stream.write((stage/relative).read_bytes());stream.flush();os.fsync(stream.fileno())
                temporary.replace(target);changed+=1
            finally:temporary.unlink(missing_ok=True)
    return changed


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--patches',type=Path,default=Path(__file__).resolve().parents[1]/'runtime/dsh/patches')
    args=parser.parse_args();print(json.dumps({'verified':True,'patched_files':apply(args.runtime,args.patches)}))

if __name__=='__main__':main()
