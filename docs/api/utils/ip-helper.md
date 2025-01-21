# IP Helper

A utility function for extracting client IP addresses from HTTP request headers.

## getClientIP()

Extracts the client IP address from HTTP headers, with fallback options.

```ts
function getClientIP(headers: Headers, defaultIP: string = '0.0.0.0'): string
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `headers` | `Headers` | Required | HTTP headers object |
| `defaultIP` | `string` | `'0.0.0.0'` | Fallback IP address |

### Returns

Returns a string containing the client's IP address, or the default IP if none is found.

### Header Priority

1. `X-Real-IP`: Primary source
2. `X-Forwarded-For`: Secondary source (first IP in chain)
3. Default IP: Used when no valid IP is found

### Examples

```ts
import { getClientIP } from 'tokenly'

// Using X-Real-IP
const headers = {
  'x-real-ip': '192.168.1.1'
}
getClientIP(headers) // Returns: '192.168.1.1'

// Using X-Forwarded-For
const proxyHeaders = {
  'x-forwarded-for': '192.168.1.1, 10.0.0.1'
}
getClientIP(proxyHeaders) // Returns: '192.168.1.1'

// No valid headers
getClientIP({}) // Returns: '0.0.0.0'

// Custom default IP
getClientIP({}, '127.0.0.1') // Returns: '127.0.0.1'
```

### Type Definition

```ts
interface Headers {
  'x-real-ip'?: string
  'x-forwarded-for'?: string
  [key: string]: string | string[] | undefined
}
```

::: tip
The function automatically handles header validation and string trimming.
:::