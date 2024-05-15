export interface NativeAPIPlugin {
  echo(options: { value: string }): Promise<{ value: string }>;
}
