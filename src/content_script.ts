const api = (globalThis as any).chrome ?? (globalThis as any).browser;

window.addEventListener('PG_LOG_EVENT', (event: any) => {
  api.runtime.sendMessage({
    type: 'LOG_PERMISSION_REQUEST',
    payload: event.detail
  });
});