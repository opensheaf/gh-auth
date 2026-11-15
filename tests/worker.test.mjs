// Tests of the Worker, run by Node's own test runner: node --test tests/*.test.mjs
// GitHub is replaced by a stub of fetch.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import worker from "../src/worker.js";

const SERVICE = "https://gh-auth.example.workers.dev";
const PAGE = "https://opensheaf.org";
const env = {
  GITHUB_CLIENT_ID: "Iv1.client",
  GITHUB_CLIENT_SECRET: "secret",
  ALLOWED_ORIGINS: "https://opensheaf.org, http://localhost:8000",
};

let calls;
let githubAnswer;
beforeEach(() => {
  calls = [];
  githubAnswer = () => Response.json({
    access_token: "ghu_token", token_type: "bearer", scope: "",
    expires_in: 28800, refresh_token: "ghr_refresh",
    refresh_token_expires_in: 15897600,
  });
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init,
                 body: Object.fromEntries(new URLSearchParams(String(init.body))) });
    return githubAnswer();
  };
});

const get = (path, headers = {}) =>
  worker.fetch(new Request(SERVICE + path, { headers }), env);

async function startLogin(origin = PAGE) {
  const r = await get("/login?origin=" + encodeURIComponent(origin));
  assert.equal(r.status, 302);
  const location = new URL(r.headers.get("Location"));
  const cookie = r.headers.get("Set-Cookie").split(";")[0];
  return { location, cookie, setCookie: r.headers.get("Set-Cookie") };
}

function postedMessage(html) {
  const m = html.match(/var data = (.*), target = (.*);\n/);
  return { data: JSON.parse(m[1]), target: JSON.parse(m[2]) };
}

test("login redirects to GitHub with state and PKCE", async () => {
  const { location, setCookie } = await startLogin();
  assert.equal(location.origin + location.pathname,
               "https://github.com/login/oauth/authorize");
  const p = location.searchParams;
  assert.equal(p.get("client_id"), "Iv1.client");
  assert.equal(p.get("redirect_uri"), SERVICE + "/callback");
  assert.equal(p.get("code_challenge_method"), "S256");
  assert.ok(p.get("state").length >= 40);
  assert.equal(p.get("scope"), null);
  assert.match(setCookie, /^__Host-gh-auth=/);
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /Secure/);
  assert.match(setCookie, /SameSite=Lax/);
});

test("login passes SCOPE for an OAuth App", async () => {
  const r = await worker.fetch(
    new Request(SERVICE + "/login?origin=" + encodeURIComponent(PAGE)),
    { ...env, SCOPE: "public_repo" });
  assert.equal(new URL(r.headers.get("Location")).searchParams.get("scope"),
               "public_repo");
});

test("login refuses origins not in the list", async () => {
  for (const o of ["https://evil.example", "https://opensheaf.org.evil.example",
                   "https://opensheaf.org/", ""]) {
    const r = await get("/login?origin=" + encodeURIComponent(o));
    assert.equal(r.status, 403, o);
  }
  assert.equal((await get("/login")).status, 403);
});

test("callback exchanges the code and posts the token to the page", async () => {
  const { location, cookie } = await startLogin();
  const state = location.searchParams.get("state");
  const r = await get(`/callback?code=abc&state=${state}`, { Cookie: cookie });
  assert.equal(r.status, 200);
  assert.match(r.headers.get("Set-Cookie"), /Max-Age=0/);
  assert.match(r.headers.get("Content-Security-Policy"), /default-src 'none'/);
  assert.equal(r.headers.get("Cache-Control"), "no-store");

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://github.com/login/oauth/access_token");
  const b = calls[0].body;
  assert.equal(b.code, "abc");
  assert.equal(b.client_secret, "secret");
  assert.equal(b.redirect_uri, SERVICE + "/callback");
  const challenge = createHash("sha256").update(b.code_verifier).digest("base64url");
  assert.equal(challenge, location.searchParams.get("code_challenge"));

  const { data, target } = postedMessage(await r.text());
  assert.equal(target, PAGE);
  assert.equal(data.type, "opensheaf-gh-auth");
  assert.equal(data.access_token, "ghu_token");
  assert.equal(data.refresh_token, "ghr_refresh");
  assert.equal(data.expires_in, 28800);
  assert.equal(data.scope, undefined);
});

test("callback without the cookie does not call GitHub", async () => {
  const { location } = await startLogin();
  const state = location.searchParams.get("state");
  const r = await get(`/callback?code=abc&state=${state}`);
  assert.equal(r.status, 400);
  assert.equal(calls.length, 0);
});

test("callback after an installation says so and does not call GitHub", async () => {
  const r = await get("/callback?code=abc&installation_id=42&setup_action=install");
  assert.equal(r.status, 200);
  assert.match(await r.text(), /The app is installed/);
  assert.equal(calls.length, 0);
});

test("callback with a wrong state does not call GitHub", async () => {
  const { cookie } = await startLogin();
  const r = await get(`/callback?code=abc&state=wrong`, { Cookie: cookie });
  assert.equal(postedMessage(await r.text()).data.error, "state_mismatch");
  assert.equal(calls.length, 0);
});

test("callback reports a refusal by the user", async () => {
  const { location, cookie } = await startLogin();
  const state = location.searchParams.get("state");
  const r = await get(`/callback?error=access_denied&state=${state}`,
                      { Cookie: cookie });
  assert.equal(postedMessage(await r.text()).data.error, "access_denied");
  assert.equal(calls.length, 0);
});

test("callback reports GitHub's errors without a token", async () => {
  githubAnswer = () => Response.json({ error: "bad_verification_code",
                                       error_description: "The code is wrong." });
  const { location, cookie } = await startLogin();
  const state = location.searchParams.get("state");
  const { data } = postedMessage(await (await get(
    `/callback?code=abc&state=${state}`, { Cookie: cookie })).text());
  assert.equal(data.error, "bad_verification_code");
  assert.equal(data.access_token, undefined);
});

test("the result page cannot be broken out of by GitHub's text", async () => {
  githubAnswer = () => Response.json({ error: "x",
                                       error_description: "</script><script>alert(1)" });
  const { location, cookie } = await startLogin();
  const state = location.searchParams.get("state");
  const html = await (await get(`/callback?code=abc&state=${state}`,
                                { Cookie: cookie })).text();
  assert.equal(html.match(/<\/script>/g).length, 1);
});

const post = (body, origin = PAGE, method = "POST") =>
  worker.fetch(new Request(SERVICE + "/refresh", {
    method, headers: { Origin: origin, "Content-Type": "application/json" },
    body: method === "POST" ? JSON.stringify(body) : undefined,
  }), env);

test("refresh renews a token for an allowed origin", async () => {
  const r = await post({ refresh_token: "ghr_old" });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("Access-Control-Allow-Origin"), PAGE);
  const data = await r.json();
  assert.equal(data.access_token, "ghu_token");
  assert.equal(calls[0].body.grant_type, "refresh_token");
  assert.equal(calls[0].body.refresh_token, "ghr_old");
  assert.equal(calls[0].body.client_secret, "secret");
});

test("refresh answers the preflight", async () => {
  const r = await post(null, PAGE, "OPTIONS");
  assert.equal(r.status, 204);
  assert.equal(r.headers.get("Access-Control-Allow-Origin"), PAGE);
  assert.equal(r.headers.get("Access-Control-Allow-Methods"), "POST");
});

test("refresh refuses other origins and bad requests", async () => {
  assert.equal((await post({ refresh_token: "x" }, "https://evil.example")).status, 403);
  assert.equal((await post({})).status, 400);
  assert.equal(calls.length, 0);
  githubAnswer = () => Response.json({ error: "bad_refresh_token" });
  const r = await post({ refresh_token: "x" });
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "bad_refresh_token");
});

test("unconfigured service refuses to start", async () => {
  const r = await worker.fetch(
    new Request(SERVICE + "/login?origin=" + encodeURIComponent(PAGE)),
    { ALLOWED_ORIGINS: PAGE });
  assert.equal(r.status, 500);
});
