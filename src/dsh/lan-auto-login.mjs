import { installMobileViewport, installInspectionRecords, MOBILE_LAYOUT_CSS } from './mobile-layout.mjs';

export const name = 'lan-auto-login';
export const inject = ['connection', 'webServer'];

export function apply(ctx) {
  // Seed the supported locale bridge before client plugins mount.
  if (ctx.webServer.tapIndex) {
    const bootstrap = '<style>'+MOBILE_LAYOUT_CSS+'</style><script>window.__DSH_LOCALE__=window.__DSH_LOCALE__||{read:function(){return Promise.resolve({languages:["zh-CN"],preference:"zh"})},onChange:function(){}};(' + installMobileViewport.toString() + ')();(' + installInspectionRecords.toString() + ')();</script>';
    ctx.effect(() => ctx.webServer.tapIndex(html => html.replace('<head>', '<head>' + bootstrap).replace('lang="en"', 'lang="zh-CN"')));
  }
  const connection = ctx.connection;
  ctx.effect(() => {
    const originalAdmit = connection.admit;
    const originalIndex = connection.authorizeIndex;
    const isLan = request => {
      const address = (request.socket?.remoteAddress ?? '').replace(/^::ffff:/, '');
      return address.startsWith('192.168.2.');
    };
    const admit = function (request) {
      const result = originalAdmit.call(this, request);
      if (result.rejection === 401 && isLan(request) && !connection.browserPeer.signal.aborted) {
        return { peer: connection.browserPeer };
      }
      return result;
    };
    const index = function (request, response) {
      if (!isLan(request)) return originalIndex.call(this, request, response);
      const result = admit.call(this, request);
      if (!('rejection' in result)) return true;
      response.writeHead(result.rejection, { 'cache-control': 'no-store' });
      response.end(result.rejection === 403 ? 'forbidden' : 'unauthorized');
      return false;
    };
    connection.admit = admit;
    connection.authorizeIndex = index;
    return () => {
      if (connection.authorizeIndex === index) connection.authorizeIndex = originalIndex;
      if (connection.admit === admit) connection.admit = originalAdmit;
    };
  });
}
