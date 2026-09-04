import { CookieJar } from 'tough-cookie'

/**
 * This script sets up a global fetch and dispatcher for use by mcp-remote to allow for
 * mutual TLS authentication using a client certificate (PFX) and passphrase, managing
 * resulting cookies. It also allows for generation and management of portal tokens if an
 * API key is not explicitly provided.
 */

type FetchConfiguration = {
  allowedDomains?: string[]
  enableCookies?: boolean
  portalUrl?: string
}

// Used to generate a portal token if an API key is not provided. This is the URL of the portal that will be used to generate the token.
let portal: string = process.env.PORTAL_URL || ''
let shouldGeneratePortalToken = !!portal

let allowAll = false
let allowedDomainsSet: Set<string> = new Set()

// Cookie jar to store cookies across requests
const jar = new CookieJar()
let cookiesEnabled = false

// Effective debouncers for concurrent requests when re-priming cookies or refreshing token.
let tokenInflight: Promise<any> | null = null
let primeInflight = new Map<string, Promise<void>>()

// Portal token and expiration time for the current session
let token: string | null = null,
  tokenExp = 0

const rawFetch = globalThis.fetch.bind(globalThis)
let fetchConfigured = false

export function configureFetch({ allowedDomains, portalUrl, enableCookies }: FetchConfiguration): void {
  portal = portalUrl || ''
  shouldGeneratePortalToken = portal.length > 0
  allowAll = !Array.isArray(allowedDomains) || allowedDomains.length === 0 || allowedDomains.includes('*')
  allowedDomainsSet = new Set(allowedDomains || [])
  cookiesEnabled = !!enableCookies

  if (fetchConfigured) {
    return
  }

  fetchConfigured = true

  // No reason to customize fetch
  if (allowAll && !cookiesEnabled) {
    return
  }

  globalThis.fetch = async (input, init = {}) => {
    const req = new Request(input, init)
    const url = req.url

    const headers = new Headers(init.headers)

    let res
    const providedToken = headers.get('Authorization')

    // If the request already has an Authorization header, send it as-is
    // This is useful for requests that already include a token or API key
    if (providedToken || !shouldGeneratePortalToken) {
      res = await request(url, init)
    } else {
      const auth = `Bearer ${await getToken()}`
      headers.set('Authorization', auth)
      res = await request(url, { ...init, headers })
    }

    // 404's just return
    if (res.status === 404) {
      return res
    }

    // If token was generated using the portal and the response is 401, try refresh the token and retry
    if (res.status === 401 && !providedToken && shouldGeneratePortalToken) {
      await res.body?.cancel()
      await refreshToken()
      const auth = `Bearer ${await getToken()}`
      headers.set('Authorization', auth)
      res = await request(url, {
        ...init,
        headers,
      })
    }

    // NOT else-if, so that if refreshToken still returns evidence of stale cookies, we can re-prime and retry the request
    if (stale(res)) {
      await res.body?.cancel()
      await reprime(url)

      if (!providedToken && shouldGeneratePortalToken) {
        const auth = `Bearer ${await getToken()}`
        headers.set('Authorization', auth)
        res = await request(url, {
          ...init,
          headers,
        })
      } else {
        res = await request(url, init)
      }
    }

    // 401's with a provided token
    return res
  }
}

async function request(url: string, init: RequestInit = {}) {
  const host = new URL(url).host
  let next = url
  for (let i = 0; i < 12; i++) {
    const res = await send(next, { ...init, redirect: 'manual' })
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location')
      if (!location) return res
      next = new URL(location, next).toString()
      continue
    }
    return res
  }
  throw new Error(`redirect loop on ${host}`)
}

async function send(url: string, init: RequestInit = {}) {
  if (!allowAll && !isDomainAllowed(new URL(url).host)) {
    throw new Error(`send to disallowed host: ${new URL(url).host}`)
  }

  const headers = new Headers(init.headers)

  if (cookiesEnabled) {
    const cookie = await jar.getCookieString(url)
    if (cookie) {
      headers.set('cookie', cookie)
    }
  }

  const res = await rawFetch(url, {
    ...init,
    redirect: 'manual',
    headers,
  })

  if (cookiesEnabled) {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      await jar.setCookie(c, res.url || url).catch(() => {})
    }
  }

  return res
}

async function getToken() {
  if (token && Date.now() < tokenExp) {
    return token
  }

  const res = await request(`${portal}/sharing/rest/generateToken`, {
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

// Responses that indicate the current authenticated session may no longer be valid.
function stale(res: Response) {
  const ct = res.headers.get('content-type') || ''
  return (
    res.status === 401 || res.status === 419 || res.status === 440 || (res.status >= 300 && res.status < 400) || ct.includes('text/html')
  )
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
      token = null // token came from a dead session
      await request(new URL(url).origin)
    })().finally(() => primeInflight.delete(host))
    primeInflight.set(host, p)
  }
  return primeInflight.get(host)
}

function isDomainAllowed(domain: string) {
  if (allowAll) {
    return true
  }

  for (const allowedDomain of allowedDomainsSet) {
    let cpy = allowedDomain
    if (allowedDomain.startsWith('*.')) {
      cpy = cpy.slice(2)
      if (cpy.includes('*')) {
        return false
      }
      const allowedDomainParts = cpy.split('.')
      const domainParts = domain.split('.')

      if (domainParts.length != allowedDomainParts.length + 1) {
        continue
      }

      if (domainParts.slice(-allowedDomainParts.length).join('.') === cpy) {
        return true
      }
    } else if (domain === cpy) {
      console.error(`Domain ${domain} matches allowed domain exactly: ${cpy}`)
      return true
    }
  }
  return false
}
