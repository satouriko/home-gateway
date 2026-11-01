import { callBroker } from '../broker-client.mjs';

export const name = 'home-network-overview';
export const inject = ['webServer', 'connection'];
export function apply(ctx) { installOverview(ctx, callBroker); }

export function installOverview(ctx, broker) {
  ctx.effect(() => ctx.webServer.register({
    kind: 'exact', path: '/api/home-network/overview',
    handler: async (req, res) => {
      const reply = (status, value) => {
        const body = JSON.stringify(value);
        res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body), 'X-Content-Type-Options': 'nosniff' });
        res.end(body);
      };
      const admission = ctx.connection.admit(req);
      if ('rejection' in admission) return reply(admission.rejection, {error:'access_denied'});
      if (req.method !== 'GET') return reply(405, {error:'GET_required'});
      try {
        const expected = `${req.socket?.encrypted ? 'https' : 'http'}://${req.headers.host}`;
        if (req.headers.origin && new URL(req.headers.origin).origin !== expected) return reply(403, {error:'cross_origin'});
      } catch { return reply(403, {error:'invalid_origin'}); }
      try {
        const result = await broker({operation:'overview'}, undefined, 8000);
        if (!result.ok) return reply(503, {error:'overview_unavailable'});
        reply(200, result.result);
      } catch { reply(503, {error:'overview_unavailable'}); }
    },
  }));
}
