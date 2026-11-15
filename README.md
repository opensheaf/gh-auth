# gh-auth: GitHub sign-in for OpenSheaf pages

A small [Cloudflare Worker](https://developers.cloudflare.com/workers/) that
lets a page in the browser, such as a deposit tool beside the
[Explorer](https://opensheaf.org/explorer/), sign its user in with GitHub and
write to their archive repository.

A page cannot do this alone. GitHub's sign-in ends with a request that turns
a one-time code into a token; that request needs the application's client
secret, which cannot be put in a public page, and GitHub's token endpoint
does not answer cross-origin requests from browsers (PKCE, which GitHub
supports since July 2025, does not change either). This service makes that
request and nothing else. It has no database: during a sign-in it keeps a
cookie for ten minutes, and it stores and logs no tokens.

The alternative, which needs no service, is a fine-grained personal access
token limited to the archive's repository, pasted by the author. Pages
should keep offering it.

## How it works

1. The page opens a popup at `/login?origin=<page origin>`. The service
   checks the origin against its list, keeps a random `state` and a PKCE
   verifier in a cookie on its own domain, and sends the popup to GitHub.
2. The author signs in on github.com and authorises the application.
3. GitHub sends the popup to `/callback` with a code. The service checks
   `state`, exchanges the code (with the secret and the PKCE verifier) for a
   token, and answers with a page that posts the token to the window that
   opened the popup, with `postMessage` restricted to the origin named in
   step 1, then closes.
4. Tokens of GitHub Apps expire after eight hours; the page renews them with
   `POST /refresh` (a cross-origin request, allowed for the same origins),
   which again needs the secret.

The token then goes from the page straight to GitHub's API; it never passes
through the service again.

Security properties:

- Only pages at an origin in `ALLOWED_ORIGINS` receive tokens. Origins are
  matched exactly; there are no wildcards, since any page at an allowed
  origin can ask for a token.
- A page elsewhere can open the popup naming an allowed origin, but the
  browser delivers the message only to a window at that origin.
- `state` (checked against a `__Host-` cookie, `HttpOnly`, `Secure`,
  `SameSite=Lax`) ties the callback to a sign-in started in the same
  browser; PKCE ties the code to it as well.
- Answers are `no-store`; the result page has a strict content security
  policy.

## The GitHub App

Use a GitHub App, not an OAuth App. A token of an OAuth App carries broad
scopes (`public_repo` reaches every public repository of the user); a token
of a GitHub App reaches only the repositories where the user installed the
app, with only the app's permissions, and expires.

Register it under the organisation (Settings -> Developer settings -> GitHub
Apps -> New GitHub App):

- **Homepage URL**: `https://opensheaf.org/`.
- **Callback URL**: `https://<service>/callback` (and, for local work,
  `http://localhost:8787/callback`; several are allowed).
- **Expire user authorization tokens**: on.
- **Request user authorization (OAuth) during installation**: on, so that
  installing the app also signs the author in.
- **Webhook**: off (untick *Active*).
- **Repository permissions**: *Contents*: read and write. (*Metadata*: read
  is added by GitHub.) Add others only when a page needs them, for instance
  *Workflows* to write under `.github/workflows/`, or *Pages* to set up
  GitHub Pages.
- **Where can this GitHub App be installed**: any account.

Then generate a client secret. The client ID (it starts with `Iv`) is
public; the secret is not.

The author installs the app on their archive repository only
(`https://github.com/apps/<app name>/installations/new`, *Only select
repositories*). A page can list the installations a token reaches with
`GET https://api.github.com/user/installations`, and send the author to the
installation page when there is none. Commits made with the token are the
author's, marked as made through the app.

An OAuth App also works: set `SCOPE` (for instance `public_repo`); its
tokens do not expire, and `/refresh` is not used.

## Deploying

With a Cloudflare account (the free plan is enough) and Node:

```sh
# set GITHUB_CLIENT_ID and ALLOWED_ORIGINS in wrangler.toml, then
npx wrangler@4 login
npx wrangler@4 secret put GITHUB_CLIENT_SECRET
npx wrangler@4 deploy
```

The service answers at `https://opensheaf-gh-auth.<account>.workers.dev`,
or at a custom domain (`routes` in `wrangler.toml`; the domain must be on
Cloudflare). Put its `/callback` among the GitHub App's callback URLs.

To allow another page, add its origin to `ALLOWED_ORIGINS` and deploy
again. Anyone can run their own copy, with their own GitHub App, for their
own pages.

## Using it from a page

`client/gh-auth.js` is a small module with the browser side:

```js
import { signIn, refresh } from "./gh-auth.js";

const service = "https://opensheaf-gh-auth.example.workers.dev";
button.onclick = async () => {               // a click, or the popup is blocked
  const auth = await signIn(service);        // { access_token, expires_at,
                                             //   refresh_token, ... }
  // ... call https://api.github.com with
  //     Authorization: Bearer <auth.access_token>
  // before auth.expires_at:
  //     auth = await refresh(service, auth.refresh_token)
};
```

Keep tokens in memory, or in `sessionStorage` at most; not in
`localStorage`.

## Working on it

- `src/worker.js`: the service. `client/gh-auth.js`: the browser side.
- Tests: `node --test tests/` (Node 20 or later; GitHub is replaced by a
  stub).
- Local run: put the settings in `.dev.vars` (not committed):

  ```
  GITHUB_CLIENT_ID=Iv...
  GITHUB_CLIENT_SECRET=...
  ALLOWED_ORIGINS=http://localhost:8000
  ```

  then `npx wrangler@4 dev` (port 8787) and, at the root of the repository,
  `python3 -m http.server 8000`; open
  `http://localhost:8000/examples/demo.html`. The demo signs in, shows who
  you are and what the token reaches, and renews the token. (The `__Host-`
  cookie needs a browser that treats `http://localhost` as secure, as
  Chrome and Firefox do.)

## Licence

GPL-3.0-or-later, as the other OpenSheaf tools. See `LICENSE`.
