import { next } from '@vercel/functions';

// Password gate for the whole site (Vercel Edge Middleware, runs before any
// static file is served). The password is NOT stored in this (public) repo —
// it lives in the Vercel project env var SITE_PASSWORD, so it can be rotated
// or removed from the Vercel dashboard without a code change.
//
// Mechanism: HTTP Basic Auth. Any username is accepted; only the password is
// checked. If SITE_PASSWORD is unset the gate fails closed (denies everyone),
// which is the safe default.

export const config = {
  // Run on every route except Vercel's internal endpoints.
  matcher: '/((?!_vercel).*)',
};

const REALM = 'Roman Leinwather — private';

function unauthorized() {
  return new Response('Authentication required.', {
    status: 401,
    headers: {
      'WWW-Authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

export default function middleware(request) {
  const expected = process.env.SITE_PASSWORD;
  const auth = request.headers.get('authorization') || '';

  if (expected && auth.startsWith('Basic ')) {
    try {
      const decoded = atob(auth.slice(6));
      const sep = decoded.indexOf(':');
      const pwd = sep === -1 ? decoded : decoded.slice(sep + 1);
      if (pwd === expected) {
        return next();
      }
    } catch {
      // malformed header -> fall through to 401
    }
  }

  return unauthorized();
}
