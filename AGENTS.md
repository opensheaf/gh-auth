# Working on gh-auth

A Cloudflare Worker that completes GitHub's sign-in for OpenSheaf pages;
see `README.md` for what it does and why. Plain JavaScript, no build step
and no dependencies.

- `src/worker.js` is the service; `client/gh-auth.js` the browser side;
  `examples/demo.html` a page to try a deployment by hand.
- Run `node --test tests/` after every change; add a test for every new
  path, in particular every check that keeps a token from the wrong page.
- The service must stay stateless and must not store or log tokens or
  codes. Do not add wildcard origins.
- Never commit the client secret or `.dev.vars`.
- Plain, precise British English in the documentation, as in the
  specification's repository.
