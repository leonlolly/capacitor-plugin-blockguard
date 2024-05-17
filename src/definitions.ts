export interface NativeAPIPlugin {

  getVPNClientStatus(): Promise<void>

  connectVPN(options:ConnectVPNOptions): Promise<void>

  disconnectVPN(): Promise<void>

  getConnectionStatus(): Promise<ConnectionStatus>

  mtlsFetch(options: MtlsFetchOptions): Promise<MtlsFetchReturn>;


}


export interface ConnectVPNOptions {
  method: string, url: string, body: string, clientCertificate: string, privateKey: string
}

export interface ConnectionStatus {
  status: string,
  incomingBytes: number,
  outgoingBytes: number
}
export interface MtlsFetchOptions {
  method: string, url: string, body: string, clientCertificate: string, privateKey: string
}

export interface MtlsFetchReturn { success: boolean, statusCode: number, body: string }

