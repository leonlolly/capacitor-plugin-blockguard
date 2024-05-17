# capacitor-plugin-blockguard

/

## Install

```bash
npm install capacitor-plugin-blockguard
npx cap sync
```

## API

<docgen-index>

* [`getVPNClientStatus()`](#getvpnclientstatus)
* [`connectVPN(...)`](#connectvpn)
* [`disconnectVPN()`](#disconnectvpn)
* [`getConnectionStatus()`](#getconnectionstatus)
* [`mtlsFetch(...)`](#mtlsfetch)
* [Interfaces](#interfaces)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### getVPNClientStatus()

```typescript
getVPNClientStatus() => Promise<void>
```

--------------------


### connectVPN(...)

```typescript
connectVPN(options: ConnectVPNOptions) => Promise<void>
```

| Param         | Type                                                            |
| ------------- | --------------------------------------------------------------- |
| **`options`** | <code><a href="#connectvpnoptions">ConnectVPNOptions</a></code> |

--------------------


### disconnectVPN()

```typescript
disconnectVPN() => Promise<void>
```

--------------------


### getConnectionStatus()

```typescript
getConnectionStatus() => Promise<ConnectionStatus>
```

**Returns:** <code>Promise&lt;<a href="#connectionstatus">ConnectionStatus</a>&gt;</code>

--------------------


### mtlsFetch(...)

```typescript
mtlsFetch(options: MtlsFetchOptions) => Promise<MtlsFetchReturn>
```

| Param         | Type                                                          |
| ------------- | ------------------------------------------------------------- |
| **`options`** | <code><a href="#mtlsfetchoptions">MtlsFetchOptions</a></code> |

**Returns:** <code>Promise&lt;<a href="#mtlsfetchreturn">MtlsFetchReturn</a>&gt;</code>

--------------------


### Interfaces


#### ConnectVPNOptions

| Prop                    | Type                |
| ----------------------- | ------------------- |
| **`method`**            | <code>string</code> |
| **`url`**               | <code>string</code> |
| **`body`**              | <code>string</code> |
| **`clientCertificate`** | <code>string</code> |
| **`privateKey`**        | <code>string</code> |


#### ConnectionStatus

| Prop                | Type                |
| ------------------- | ------------------- |
| **`status`**        | <code>string</code> |
| **`incomingBytes`** | <code>number</code> |
| **`outgoingBytes`** | <code>number</code> |


#### MtlsFetchReturn

| Prop             | Type                 |
| ---------------- | -------------------- |
| **`success`**    | <code>boolean</code> |
| **`statusCode`** | <code>number</code>  |
| **`body`**       | <code>string</code>  |


#### MtlsFetchOptions

| Prop                    | Type                |
| ----------------------- | ------------------- |
| **`method`**            | <code>string</code> |
| **`url`**               | <code>string</code> |
| **`body`**              | <code>string</code> |
| **`clientCertificate`** | <code>string</code> |
| **`privateKey`**        | <code>string</code> |

</docgen-api>
