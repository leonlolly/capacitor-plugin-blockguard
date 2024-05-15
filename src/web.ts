import { WebPlugin } from '@capacitor/core';

import type { NativeAPIPlugin } from './definitions';

export class NativeAPIWeb extends WebPlugin implements NativeAPIPlugin {
  async echo(options: { value: string }): Promise<{ value: string }> {
    console.log('ECHO', options);
    return options;
  }
}
