const api = (globalThis as any).chrome ?? (globalThis as any).browser;

export class ExtensionAPI {
  get isAvailable(): boolean {
    return !!api?.runtime?.id;
  }

  async getDashboardData(): Promise<any> {
    return new Promise((resolve) => {
      if (!api?.runtime?.sendMessage) return resolve(null);
      api.runtime.sendMessage({ type: 'GET_DASHBOARD_DATA' }, (response: any) => {
        resolve(response);
      });
    });
  }

  async getStorage(keys: string[]): Promise<any> {
    return new Promise((resolve) => {
      if (!api?.storage?.local?.get) return resolve({});
      api.storage.local.get(keys, (result: any) => resolve(result || {}));
    });
  }

  async setStorage(data: Record<string, any>): Promise<void> {
    return new Promise((resolve) => {
      if (!api?.storage?.local?.set) return resolve();
      api.storage.local.set(data, () => resolve());
    });
  }

  async removeExtension(id: string): Promise<any> {
    return new Promise((resolve) => {
      if (!api?.runtime?.sendMessage) return resolve(null);
      api.runtime.sendMessage({ type: 'REMOVE_EXTENSION', id }, resolve);
    });
  }

  async clearSiteData(origin: string): Promise<any> {
    return new Promise((resolve) => {
      if (!api?.runtime?.sendMessage) return resolve(null);
      api.runtime.sendMessage({ type: 'CLEAR_SITE_DATA', origin }, resolve);
    });
  }
}

export const extensionApi = new ExtensionAPI();