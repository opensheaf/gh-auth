// opensheaf/gh-auth: GitHub sign-in for browser pages.
//
// A page cannot finish GitHub's sign-in by itself: turning the code into a
// token needs the application's client secret, and GitHub's token endpoint
// does not answer cross-origin requests. This Worker does that one step and
// nothing else. It keeps no state beyond a short-lived cookie during the
// sign-in, and it stores and logs no tokens.
//
//   GET  /login?origin=<page origin>   start the sign-in (opened in a popup)
//   GET  /callback                     GitHub returns here; the token is
//                                      posted to the page that opened the popup
//   POST /refresh                      renew an expiring token (GitHub Apps)
//
// Settings (see wrangler.toml and README.md):
//   GITHUB_CLIENT_ID      variable
//   GITHUB_CLIENT_SECRET  secret
//   ALLOWED_ORIGINS       variable: origins allowed to receive tokens,
//                         separated by commas or spaces
//   SCOPE                 variable, optional: OAuth App scopes; leave unset
//                         for a GitHub App, whose permissions are its own

const GITHUB = "https://github.com";
const COOKIE = "__Host-gh-auth";
const FLOW_SECONDS = 600;
const MESSAGE_TYPE = "opensheaf-gh-auth";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/login" && request.method === "GET")
        return login(url, env);
      if (url.pathname === "/callback" && request.method === "GET")
        return await callback(request, url, env);
      if (url.pathname === "/refresh")
        return await refresh(request, env);
      if (url.pathname === "/" && request.method === "GET")
        return text("opensheaf/gh-auth: GitHub sign-in for OpenSheaf pages.\n" +
                    "See https://github.com/opensheaf/gh-auth\n");
      return text("Not found\n", 404);
    } catch (e) {
      return text("Internal error\n", 500);
    }
  },
};

// --- settings --------------------------------------------------------------

function allowedOrigins(env) {
  return new Set((env.ALLOWED_ORIGINS || "").split(/[\s,]+/).filter(Boolean));
}

function isAllowed(origin, env) {
  return typeof origin === "string" && allowedOrigins(env).has(origin);
}

function configured(env) {
  return Boolean(env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);
}

// --- /login ----------------------------------------------------------------

async function login(url, env) {
  if (!configured(env)) return text("Service not configured\n", 500);
  const origin = url.searchParams.get("origin");
  if (!isAllowed(origin, env))
    return text("This page is not allowed to sign in here: " +
                String(origin) + "\n", 403);

  const state = randomString(32);
  const verifier = randomString(48);
  const challenge = base64url(await sha256(verifier));

  const authorize = new URL(GITHUB + "/login/oauth/authorize");
  authorize.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", url.origin + "/callback");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("allow_signup", "true");
  if (env.SCOPE) authorize.searchParams.set("scope", env.SCOPE);

  const flow = base64url(new TextEncoder().encode(
    JSON.stringify({ state, verifier, origin })));
  return new Response(null, {
    status: 302,
    headers: {
      Location: authorize.toString(),
      "Set-Cookie": `${COOKIE}=${flow}; Path=/; Max-Age=${FLOW_SECONDS}; ` +
                    "HttpOnly; Secure; SameSite=Lax",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
    },
  });
}

// --- /callback -------------------------------------------------------------

async function callback(request, url, env) {
  if (!configured(env)) return text("Service not configured\n", 500);
  const flow = readFlow(request);
  // GitHub comes here after an installation of the app when the app asks
  // for authorisation during installation, or has this address as its
  // setup URL; no sign-in was started, so there is nothing to finish.
  if (!flow && url.searchParams.has("installation_id"))
    return text("The app is installed. Close this window and sign in " +
                "from the page you were using.\n");
  if (!flow || !isAllowed(flow.origin, env))
    return text("The sign-in expired or was started elsewhere. " +
                "Close this window and try again.\n", 400);

  // From here on the result goes back to the page, which may show it.
  const reply = (message) => resultPage(flow.origin, message);

  const state = url.searchParams.get("state");
  if (!state || !timingSafeEqual(state, flow.state))
    return reply({ error: "state_mismatch",
                   error_description: "The sign-in could not be verified." });

  const error = url.searchParams.get("error");
  if (error)
    return reply({ error,
                   error_description: url.searchParams.get("error_description") || "" });

  const code = url.searchParams.get("code");
  if (!code)
    return reply({ error: "no_code", error_description: "GitHub returned no code." });

  const result = await tokenRequest(env, {
    code,
    redirect_uri: url.origin + "/callback",
    code_verifier: flow.verifier,
  });
  return reply(result);
}

function readFlow(request) {
  const header = request.headers.get("Cookie") || "";
  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name !== COOKIE) continue;
    try {
      const flow = JSON.parse(new TextDecoder().decode(fromBase64url(rest.join("="))));
      if (typeof flow.state === "string" && typeof flow.verifier === "string" &&
          typeof flow.origin === "string")
        return flow;
    } catch (e) { /* ignore a malformed cookie */ }
  }
  return null;
}

// The page posts the result to the window that opened it, but only if that
// window is at the origin named when the sign-in started: postMessage with a
// target origin drops the message otherwise.
function resultPage(origin, message) {
  const nonce = randomString(16);
  const data = JSON.stringify({ type: MESSAGE_TYPE, ...message })
    .replace(/</g, "\\u003c");
  const target = JSON.stringify(origin).replace(/</g, "\\u003c");
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GitHub sign-in</title></head>
<body><p id="m">Finishing the sign-in...</p>
<script nonce="${nonce}">
(function () {
  var data = ${data}, target = ${target};
  var m = document.getElementById("m");
  if (window.opener) {
    window.opener.postMessage(data, target);
    m.textContent = data.error ? "Sign-in failed: " + (data.error_description || data.error)
                               : "Signed in. You can close this window.";
    if (!data.error) window.close();
  } else {
    m.textContent = "The page that started the sign-in is no longer open. Close this window and try again.";
  }
})();
</script></body></html>
`;
  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        `default-src 'none'; script-src 'nonce-${nonce}'; base-uri 'none'; ` +
        "form-action 'none'; frame-ancestors 'none'",
      "Set-Cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

// --- /refresh --------------------------------------------------------------

async function refresh(request, env) {
  const origin = request.headers.get("Origin");
  if (!isAllowed(origin, env)) return text("Origin not allowed\n", 403);
  const cors = {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
  };
  if (request.method === "OPTIONS")
    return new Response(null, {
      status: 204,
      headers: { ...cors,
                 "Access-Control-Allow-Methods": "POST",
                 "Access-Control-Allow-Headers": "Content-Type",
                 "Access-Control-Max-Age": "86400" },
    });
  if (request.method !== "POST") return text("Method not allowed\n", 405, cors);
  if (!configured(env)) return json({ error: "not_configured" }, 500, cors);

  let body;
  try { body = await request.json(); } catch (e) { body = null; }
  const token = body && body.refresh_token;
  if (typeof token !== "string" || !token)
    return json({ error: "invalid_request",
                  error_description: "refresh_token is missing." }, 400, cors);

  const result = await tokenRequest(env, {
    grant_type: "refresh_token",
    refresh_token: token,
  });
  return json(result, result.error ? 400 : 200, cors);
}

// --- GitHub's token endpoint -----------------------------------------------

// Returns the fields a page needs, or { error, error_description }.
async function tokenRequest(env, params) {
  const body = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    ...params,
  });
  let response;
  try {
    response = await fetch(GITHUB + "/login/oauth/access_token", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "opensheaf-gh-auth",
      },
      body,
    });
  } catch (e) {
    return { error: "github_unreachable", error_description: "GitHub could not be reached." };
  }
  let data;
  try { data = await response.json(); } catch (e) { data = null; }
  if (!response.ok || !data)
    return { error: "github_error",
             error_description: `GitHub answered with status ${response.status}.` };
  if (data.error || !data.access_token)
    return { error: String(data.error || "no_token"),
             error_description: String(data.error_description || "") };

  const out = { access_token: data.access_token,
                token_type: data.token_type || "bearer" };
  for (const k of ["scope", "expires_in", "refresh_token",
                   "refresh_token_expires_in"])
    if (data[k] !== undefined && data[k] !== "") out[k] = data[k];
  for (const k of ["expires_in", "refresh_token_expires_in"])
    if (out[k] !== undefined) out[k] = Number(out[k]);
  return out;
}

// --- helpers ---------------------------------------------------------------

function text(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8",
               "Cache-Control": "no-store", ...headers },
  });
}

function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json",
               "Cache-Control": "no-store", ...headers },
  });
}

function randomString(bytes) {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function sha256(s) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256",
                                                   new TextEncoder().encode(s)));
}

function base64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64url(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
