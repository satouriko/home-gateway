"""Bound subprocess pipes during reads; output limits do not depend on child memory."""
import os
import selectors
import subprocess
import time

class LimitError(ValueError):
    def __init__(self,message,data):
        super().__init__(message)
        self.stdout=data['stdout'].decode(errors='replace');self.stderr=data['stderr'].decode(errors='replace')

def run(args, *, input='', timeout=20, stdout_limit=32768, stderr_limit=8192, env=None, cancelled=None):
    process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    selector=selectors.DefaultSelector();payload=input.encode();sent=0;data={'stdout':bytearray(),'stderr':bytearray()}
    limits={'stdout':stdout_limit,'stderr':stderr_limit};deadline=time.monotonic()+timeout
    for stream,name in [(process.stdout,'stdout'),(process.stderr,'stderr')]:
        os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
    if payload:
        os.set_blocking(process.stdin.fileno(),False);selector.register(process.stdin,selectors.EVENT_WRITE,'stdin')
    else:process.stdin.close()
    try:
        while selector.get_map():
            if cancelled and cancelled():raise LimitError('process operation cancelled',data)
            remaining=deadline-time.monotonic()
            if remaining<=0:raise LimitError('process execution timed out',data)
            for key,_events in selector.select(min(remaining,.2)):
                stream=key.fileobj;name=key.data
                if name=='stdin':
                    try:sent+=os.write(stream.fileno(),payload[sent:sent+4096])
                    except BrokenPipeError:sent=len(payload)
                    if sent>=len(payload):selector.unregister(stream);stream.close()
                else:
                    chunk=os.read(stream.fileno(),4096)
                    if not chunk:selector.unregister(stream);stream.close();continue
                    if len(data[name])+len(chunk)>limits[name]:raise LimitError('process output budget exceeded',data)
                    data[name].extend(chunk)
        code=process.wait(timeout=max(.1,deadline-time.monotonic()))
        return subprocess.CompletedProcess(args,code,data['stdout'].decode(errors='replace'),data['stderr'].decode(errors='replace'))
    finally:
        selector.close()
        for stream in [process.stdin,process.stdout,process.stderr]:
            if not stream.closed:stream.close()
        if process.poll() is None:
            process.terminate()
            try:process.wait(timeout=2)
            except subprocess.TimeoutExpired:process.kill()
        process.wait(timeout=3)
