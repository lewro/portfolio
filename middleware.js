import { next } from '@vercel/functions';

// Password gate for the whole site (Vercel Edge Middleware, runs before any
// static file is served).
//
// Why a cookie + login page instead of HTTP Basic Auth: Vercel strips the
// `WWW-Authenticate` response header from Middleware responses, so a browser
// never shows the native Basic-Auth dialog. Instead we serve a small login
// page; a correct password sets an HttpOnly cookie that unlocks the site.
//
// The password itself is NOT stored in this (public) repo — it lives in the
// Vercel project env var SITE_PASSWORD and can be rotated/removed from the
// Vercel dashboard without a code change. The cookie stores only a SHA-256
// token derived from the password, so it reveals nothing and cannot be forged
// without knowing the password. Fails closed if SITE_PASSWORD is unset.

export const config = {
  // Run on every route except Vercel's internal endpoints.
  matcher: '/((?!_vercel).*)',
};

const COOKIE = 'rl_gate';
const SALT = 'rl-portfolio-gate-v1';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days

async function tokenFor(password) {
  const data = new TextEncoder().encode(`${SALT}:${password}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function loginPage(showError) {
  const err = showError
    ? '<p class="err">Wrong password. Try again.</p>'
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Private</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%23111111'/%3E%3Ctext x='32' y='42' font-family='Helvetica,Arial,sans-serif' font-size='26' font-weight='600' fill='%23f9f9f9' text-anchor='middle'%3ERL%3C/text%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  :root{--bg:#f9f9f9;--card:#ffffff;--text:#111111;--muted:#666;--line:#dcdcdc;--accent:#111}
  @media (prefers-color-scheme:dark){
    :root{--bg:#0d0d0d;--card:#161616;--text:#f2f2f2;--muted:#9a9a9a;--line:#2c2c2c;--accent:#f2f2f2}
  }
  html,body{height:100%}
  body{font-family:'Instrument Sans',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;padding:24px}
  .card{width:100%;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:32px 28px;text-align:center}
  .mark{width:44px;height:44px;border-radius:11px;background:var(--accent);color:var(--card);display:flex;align-items:center;justify-content:center;font-weight:600;font-size:18px;margin:0 auto 18px}
  h1{font-size:19px;font-weight:500;margin-bottom:6px}
  p.sub{color:var(--muted);font-size:14px;margin-bottom:22px}
  form{display:flex;flex-direction:column;gap:12px}
  input{width:100%;padding:12px 14px;font:inherit;font-size:15px;color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:10px;outline:none}
  input:focus{border-color:var(--accent)}
  button{width:100%;padding:12px 14px;font:inherit;font-size:15px;font-weight:500;color:var(--card);background:var(--accent);border:none;border-radius:10px;cursor:pointer}
  button:hover{opacity:.9}
  .err{color:#d33;font-size:13px;margin-top:-4px}
  @media (prefers-color-scheme:dark){.err{color:#ff6b6b}}
</style>
</head>
<body>
  <div class="card">
    <div class="mark">RL</div>
    <h1>This site is private</h1>
    <p class="sub">Enter the password to continue.</p>
    <form method="POST" action="/__auth">
      <input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password" required>
      ${err}
      <button type="submit">Enter</button>
    </form>
  </div>
</body>
</html>`;
}

function gateResponse(showError) {
  return new Response(loginPage(showError), {
    status: showError ? 401 : 401,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

export default async function middleware(request) {
  const password = process.env.SITE_PASSWORD;
  if (!password) {
    return new Response('Site locked: SITE_PASSWORD is not configured.', {
      status: 503,
      headers: { 'cache-control': 'no-store' },
    });
  }

  const expected = await tokenFor(password);
  const url = new URL(request.url);

  // Already unlocked?
  const cookies = request.headers.get('cookie') || '';
  const unlocked = cookies
    .split(';')
    .some((c) => c.trim() === `${COOKIE}=${expected}`);
  if (unlocked) return next();

  // Login submission.
  if (request.method === 'POST' && url.pathname === '/__auth') {
    let supplied = '';
    try {
      const form = await request.formData();
      supplied = (form.get('password') || '').toString();
    } catch {
      // ignore parse errors -> treated as wrong password
    }
    if (supplied === password) {
      return new Response(null, {
        status: 303,
        headers: {
          Location: '/',
          'Set-Cookie': `${COOKIE}=${expected}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`,
          'cache-control': 'no-store',
        },
      });
    }
    return gateResponse(true);
  }

  // Not unlocked -> show the gate.
  return gateResponse(false);
}
