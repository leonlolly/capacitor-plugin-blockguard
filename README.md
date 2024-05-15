# capacitor-plugin-blockguard

/

## Install

```bash
npm install capacitor-plugin-blockguard
npx cap sync
```

## API

<docgen-index>

* [`mtlsFetch(...)`](#mtlsfetch)
* [`connectVPN()`](#connectvpn)
* [Interfaces](#interfaces)

</docgen-index>

<docgen-api>
<!--Update the source file JSDoc comments and rerun docgen to update the docs below-->

### mtlsFetch(...)

```typescript
mtlsFetch(options: MtlsFetchOptions) => Promise<MtlsFetchReturn>
```

| Param         | Type                                                          |
| ------------- | ------------------------------------------------------------- |
| **`options`** | <code><a href="#mtlsfetchoptions">MtlsFetchOptions</a></code> |

**Returns:** <code>Promise&lt;<a href="#mtlsfetchreturn">MtlsFetchReturn</a>&gt;</code>

--------------------


### connectVPN()

```typescript
connectVPN() => Promise<void>
```

--------------------


### Interfaces


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
