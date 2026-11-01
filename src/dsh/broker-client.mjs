import net from 'node:net';

export function callBroker(request, signal, timeout = 300000) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('gateway operation cancelled'));
    const socket = net.createConnection('/run/net-gateway-agent/control.sock');
    let body = '';
    let received=false;
    const abort = () => socket.destroy(new Error('gateway operation cancelled'));
    signal?.addEventListener('abort', abort, { once: true });
    socket.setTimeout(timeout, () => socket.destroy(new Error('gateway tool timed out; protected recovery may still be running')));
    socket.on('connect', () => socket.write(JSON.stringify(request) + '\n'));
    socket.on('error', reject);
    socket.on('data', chunk => {
      body += chunk.toString('utf8');
      if (body.length > 1048576) return socket.destroy(new Error('gateway response too large'));
      if (body.includes('\n')) {
        received=true;
        try { resolve(JSON.parse(body.slice(0, body.indexOf('\n')))); } catch (error) { reject(error); }
        socket.end();
      }
    });
    socket.on('end',()=>{if(!received) reject(new Error('gateway closed without a response'));});
    socket.on('close', () => signal?.removeEventListener('abort', abort));
  });
}
