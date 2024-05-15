import { WebPlugin } from '@capacitor/core';

import type { MtlsFetchOptions, MtlsFetchReturn, NativeAPIPlugin } from './definitions';

export class NativeAPIWeb extends WebPlugin implements NativeAPIPlugin {
  mtlsFetch(options: MtlsFetchOptions): Promise<MtlsFetchReturn> {
    if(options === undefined){
      throw Error("options undefined")
    }
      throw this.unavailable('mtlsFetch API not available in browser');
  }
  connectVPN(): Promise<void> {
    throw this.unavailable('mtlsFetch API not available in browser');
  }

}

