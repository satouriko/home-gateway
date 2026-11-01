// Local browser fixture: render the actual npm bundle with React and minimal
// public primitive adapters. No DSH host, network service, credentials, or model.
const { createElement: h } = React;
const Button = React.forwardRef(({ variant, size, children, ...props }, ref) => h('button', { ...props, ref }, children));
const primitives = new Proxy({
  Button,
  Input: React.forwardRef(({ prefix, suffix, ...props }, ref) => h('input', { ...props, ref })),
  Tooltip: ({ children }) => children,
  Modal: ({ open, title, description, footer, children }) => open ? h('div', { role: 'dialog', 'aria-label': title }, description, children, footer) : null,
  SelectMenu: ({ children }) => children,
  Popover: ({ children }) => children,
  useAnchoredPosition: () => ({ left: 20, top: 64 }),
  useDismissOnOutsidePointer: () => {},
}, {
  get(target, key) {
    if (key in target) return target[key];
    if (key.startsWith('Icon')) return ({ size = 16, ...props }) => h('svg', { ...props, width: size, height: size, 'aria-hidden': true });
    return ({ children }) => h('span', null, children);
  },
});
window.__ModuleLoader__ = {
  load({ factory }) {
    window.plugin = factory((name) => ({
      react: React,
      'react-dom': ReactDOM,
      'react/jsx-runtime': { Fragment: React.Fragment, jsx: (type, props, key) => h(type, { ...props, key }), jsxs: (type, props, key) => h(type, { ...props, key }) },
      '@deepseek-ai/dsh-client-ui-primitives': primitives,
    })[name]);
  },
};
window.fixture = {
  requests: [], updates: [], deletes: [], opened: [],
  sessions: { phase: 'ready', ids: ['origin-session', 'run-session'], byId: { 'origin-session': { title: 'Task origin' }, 'run-session': { title: 'Independent run' } } },
  workspaces: { phase: 'ready', state: 'ready', archivedSessionIds: [] },
  task: { id: 'stable-task', sessionId: 'origin-session', title: 'House task', prompt: 'Inspect house', kind: 'every', everySeconds: 3600, createdAt: '2026-11-01T00:00:00Z', scheduledAt: '2026-11-02T00:00:00Z', status: 'active', execution: { kind: 'external', executor: 'home-network' } },
};
const root = ReactDOM.createRoot(document.getElementById('app'));
window.mountHistory = ({ records, nextBefore, nextBeforeDeliveryId, more = [], latest, locale = 'en' }) => {
  fixture.current = { records, nextBefore, nextBeforeDeliveryId, more, latest, locale };
  fixture.loadHistory ??= async (request) => {
    fixture.requests.push(request);
    const state = fixture.current;
    return { ok: true, value: { records: request.beforeDeliveryId || request.before ? state.more : state.records, nextBefore: request.beforeDeliveryId || request.before ? undefined : state.nextBefore, nextBeforeDeliveryId: request.beforeDeliveryId || request.before ? undefined : state.nextBeforeDeliveryId, earlierRecordsPruned: false, retention: { days: 30, records: 200 } } };
  };
  fixture.onOpenSession ??= (id) => fixture.opened.push(id);
  root.render(h(plugin.__fixture.DeliveryHistory, { id: 'stable-task', sessionId: 'origin-session', latestMessageId: latest, latestDeliveryKey: latest, loadHistory: fixture.loadHistory, onOpenSession: fixture.onOpenSession, t: translator(locale) }));
};
const translations = {};
function translator(locale, catalog = false) {
  const key = `${locale}:${catalog}`;
  return translations[key] ??= (name, args = {}) => {
    const dict = catalog ? plugin.__fixture[locale === 'zh' ? 'catalogZh' : 'catalogEn'] : plugin.__fixture[locale];
    return (dict[name] ?? name).replace(/\{([^}]+)\}/g, (_, key) => String(args[key] ?? ''));
  };
}
function detailProps() {
  return {
    task: fixture.task, authoritative: true, id: 'detail', status: 'ready', deleting: [],
    onDelete: async (id) => { fixture.deletes.push(id); return 'deleted'; },
    onRetry: async () => {},
    onUpdateTiming: async (request) => { fixture.updates.push(request); const { id, sessionId, expected, change, ...content } = request; fixture.task = { ...fixture.task, ...content, ...change, ...(change?.every_seconds === undefined ? {} : { everySeconds: change.every_seconds }) }; return { ok: true, value: { record: fixture.task } }; },
    loadHistory: fixture.loadHistory ?? (async () => ({ ok: true, value: { records: [], retention: { days: 30, records: 200 } } })),
    onOpenSession: (id) => fixture.opened.push(id), onEditState: () => {},
    tab: 'rule', onTabChange: () => {}, confirmId: null, onConfirm: () => {}, onDeleted: () => {},
    withinSession: 'origin-session',
    useSessions: (select) => select(fixture.sessions), useWorkspaces: (select) => select(fixture.workspaces), t: translator('en'),
  };
}
window.mountDetail = (overrides = {}) => root.render(h(plugin.__fixture.TaskDetail, { ...detailProps(), ...overrides }));
window.mountCatalog = (locale = 'en') => root.render(h(plugin.__fixture.TaskManagerPage, {
  ...detailProps(),
  useCatalog: (select) => select({ records: [fixture.task, { ...fixture.task, id: 'reminder', title: 'Ordinary reminder', execution: undefined }], status: 'ready', deleting: [], settled: true, readRequest: 0, readSettled: fixture.revision ?? 0 }),
  onNewTask: () => {}, t: translator(locale),
}));
window.mountSessionCatalog = () => root.render(h(plugin.__fixture.ScheduleCatalogAction, {
  useSession: (select) => select({ openState: 'open' }),
  useCatalog: (select) => select({ records: [fixture.task, { ...fixture.task, id: 'reminder', title: 'Ordinary reminder', execution: undefined }], status: 'ready', deleting: [] }),
  onDelete: (id) => fixture.deletes.push(id), onRetry: () => {}, openTaskDetail: () => {}, t: translator('en', true),
}));
