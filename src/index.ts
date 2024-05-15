import { registerPlugin } from '@capacitor/core';

import type { NativeAPIPlugin } from './definitions';

const NativeAPI = registerPlugin<NativeAPIPlugin>('NativeAPI', {
  web: () => import('./web').then(m => new m.NativeAPIWeb()),
});

export * from './definitions';
export { NativeAPI };
