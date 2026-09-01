import { CookieJar } from 'tough-cookie'

/**
 * This script sets up a global fetch and dispatcher for use by mcp-remote to allow for
 * mutual TLS authentication using a client certificate (PFX) and passphrase, managing
 * resulting cookies. It also allows for generation and management of portal tokens if an
 * API key is not explicitly provided.
 */

type FetchConfiguration = {
  useCustomFetch: boolean
  generatePortalToken: boolean
  portalUrl?: string
}

// Used to generate a portal token if an API key is not provided. This is the URL of the portal that will be used to generate the token.
let portal: string = process.env.PORTAL_URL || ''
let shouldGeneratePortalToken = !!portal

// Cookie jar to store cookies across requests
const jar = new CookieJar()

// Domains that have completed cert-based authentication
const primed = new Set()

// Effective debouncers for concurrent requests when re-priming cookies or refreshing token.
let tokenInflight: Promise<any> | null = null
let primeInflight = new Map<string, Promise<void>>()

// Portal token and expiration time for the current session
let token: string | null = null,
  tokenExp = 0

const rawFetch = globalThis.fetch.bind(globalThis)
let fetchConfigured = false

export function configureFetch({ useCustomFetch, generatePortalToken, portalUrl }: FetchConfiguration): void {
  portal = portalUrl || ''
  shouldGeneratePortalToken = generatePortalToken && portal.length > 0

  if (fetchConfigured) {
    return
  }

  fetchConfigured = true

  if (!useCustomFetch) {
    return
  }

  // Setup global fetch to handle mutual TLS, cookies, and token management
  globalThis.fetch = async (input, init = {}) => {
    const req = new Request(input, init)
    const url = req.url

    const headers = new Headers(init.headers)

    // Extract host and check if cookies have been obtained for this host; if not, prime the connection
    const host = new URL(url).host
    if (!primed.has(host)) {
      await prime(new URL(url).origin)
    }

    let res
    const providedToken = headers.get('Authorization')

    // If the request already has an Authorization header, send it as-is
    // This is useful for requests that already include a token or API key
    if (providedToken || !shouldGeneratePortalToken) {
      res = await send(url, init)
    } else {
      const auth = `Bearer ${await getToken()}`
      headers.set('Authorization', auth)
      res = await send(url, { ...init, headers })
    }

    // 404's just return
    if (res.status === 404) {
      return res
    }

    // If token was generated using the portal and the response is 401, refresh the token and retry
    if (res.status === 401 && !providedToken && shouldGeneratePortalToken) {
      await res.body?.cancel()
      await refreshToken()
      const auth = `Bearer ${await getToken()}`
      headers.set('Authorization', auth)
      res = await send(url, {
        ...init,
        headers,
      })
    }

    // NOT else-if, so that if refreshToken above returns stale cookies, we can re-prime and retry the request
    if (stale(res)) {
      await res.body?.cancel()
      await reprime(url)

      if (!providedToken && shouldGeneratePortalToken) {
        const auth = `Bearer ${await getToken()}`
        headers.set('Authorization', auth)
        res = await send(url, {
          ...init,
          headers,
        })
      } else {
        res = await send(url, init)
      }
    }

    // 401's with a provided token
    return res
  }
}

async function send(url: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers)
  const cookie = await jar.getCookieString(url)
  if (cookie) {
    headers.set('cookie', cookie)
  }
  const res = await rawFetch(url, {
    ...init,
    redirect: 'manual',
    headers,
  })
  for (const c of res.headers.getSetCookie?.() ?? []) {
    await jar.setCookie(c, res.url || url).catch(() => {})
  }
  return res
}

async function prime(url: string) {
  const host = new URL(url).host
  let next = url
  for (let i = 0; i < 12; i++) {
    const res = await send(next, { redirect: 'manual' })
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location') || ''
      next = new URL(location, next).toString()
      continue
    }
    await res.body?.cancel()
    primed.add(host)
    return
  }
  throw new Error(`prime: redirect loop on ${host}`)
}

async function getToken() {
  if (token && Date.now() < tokenExp) return token
  if (!primed.has(new URL(portal).host)) {
    await prime(portal)
  }

  const res = await send(`${portal}/sharing/rest/generateToken`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      f: 'json',
      client: 'referer',
      referer: portal,
      expiration: '60',
    }),
  })
  const text = await res.text()

  const data = JSON.parse(text) as { token?: string; expires?: number }
  if (!data.token) throw new Error(`generateToken: ${JSON.stringify(data)}`)
  token = data.token

  // Refresh a min early
  if (data.expires === undefined || isNaN(data.expires)) {
    const requestedMs = 60 * 60_000
    tokenExp = (data.expires ?? Date.now() + requestedMs) - 60_000
  } else {
    tokenExp = data.expires - 60_000
  }
  return token
}

// Two conditions for a response to be considered stale seen so far.
// 1. Hosting server returns a redirect to a different domain that actually performs the TLS handshake, and/or
// 2. It doesn't redirect but returns an HTML page (e.g., a login page) instead of the expected JSON response.
function stale(res: Response) {
  const ct = res.headers.get('content-type') || ''
  return (res.status >= 300 && res.status < 400) || ct.includes('text/html')
}

async function refreshToken() {
  if (tokenInflight) return tokenInflight
  tokenInflight = doRefresh()
  try {
    return await tokenInflight
  } finally {
    tokenInflight = null
  }
}

async function doRefresh() {
  token = null
  return getToken()
}

async function reprime(url: string) {
  const host = new URL(url).host
  if (!primeInflight.has(host)) {
    const p = (async () => {
      primed.delete(host)
      token = null // token came from a dead session
      await prime(new URL(url).origin)
    })().finally(() => primeInflight.delete(host))
    primeInflight.set(host, p)
  }
  return primeInflight.get(host)
}
