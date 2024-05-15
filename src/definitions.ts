export interface NativeAPIPlugin {
  mtlsFetch(options: MtlsFetchOptions): Promise<MtlsFetchReturn>;

  connectVPN():Promise<void>

}

export interface MtlsFetchOptions
  {
     method: string,url:string,body: string,clientCertificate:string,privateKey:string 
    }

    export interface MtlsFetchReturn
    { success: boolean,statusCode:number,body:string }

