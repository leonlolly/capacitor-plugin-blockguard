import { WebPlugin } from '@capacitor/core';

import type { ConnectionStatus, MtlsFetchOptions, MtlsFetchReturn, NativeAPIPlugin } from './definitions';

export class NativeAPIWeb extends WebPlugin implements NativeAPIPlugin {
  getConnectionStatus(): Promise<ConnectionStatus> {
    throw this.unavailable('getConnectionStatus API not available in browser');
  }

  getVPNClientStatus(): Promise<void> {
    throw this.unavailable('getVPNClientStatus API not available in browser');
  }

  disconnectVPN(): Promise<void> {
    throw this.unavailable('disconnectVPN API not available in browser');
  }

  mtlsFetch(options: MtlsFetchOptions): Promise<MtlsFetchReturn> {
    if (options === undefined) {
      throw Error("mtlsFetch API not available in browser");
    }
    throw this.unavailable('mtlsFetch API not available in browser');
  }

  connectVPN(): Promise<void> {
    throw this.unavailable('connectVPN API not available in browser');
  }

}

