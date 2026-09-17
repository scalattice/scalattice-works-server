# works-server

Company (or personal) desk server for Works. The hosted UI at `https://works.scalattice.com` is static; this binary is the data, accounts, sandboxes, and shells.

A public tab at `works.scalattice.com` **cannot** call `localhost` (browsers block it). Open this server in the browser instead — it proxies that UI onto the same origin as the API.

## Run

```bash
# Personal desk on this machine — open http://127.0.0.1:8787
works-server --personal --bind 127.0.0.1:8787

# Company install — bind on the LAN / public interface, data on disk you control
works-server --bind 0.0.0.0:8787 --data /var/lib/works --name "Acme"
```

First visit: `GET /.well-known/works.json` returns `setup_required: true`. The Connect screen creates the first **admin**. That admin’s dashboard can:

- Create users (`admin` or `member`)
- Attach **sandboxes** to real directories on this machine
- Grant per-user `read` / `write` / `shell` on each sandbox

A terminal in the desk is a PTY on **this** server, jailed to that sandbox path (`bwrap` on Linux when available).

`--api-only` disables the UI proxy. `WORKS_UI_ORIGIN` defaults to `https://works.scalattice.com`. Put extra SPA origins in `WORKS_CORS` if you host the UI yourself.

## API

| | |
| --- | --- |
| `GET /.well-known/works.json` | Discovery |
| `POST /v1/setup` | First admin |
| `POST /v1/login` | Bearer token |
| `GET /v1/me` | User + sandboxes you can see |
| `GET/POST /v1/users` | Admin |
| `GET/POST /v1/sandboxes` | Admin; `path` is an absolute directory |
| `PUT /v1/grants` | Admin ACL |
| `GET/PUT /v1/sandboxes/:id/file` | Desk files |
| `GET /v1/term/:id?token=` | WebSocket PTY |

Clients send `Authorization: Bearer <token>` except the WebSocket, which also accepts `?token=`.

## Reverse proxy

TLS terminates at nginx/caddy. Forward `/` (API + UI) and `/v1/term` (WebSocket) to this process. Employees can use this host directly, or keep the SPA on `works.scalattice.com` and type this host into Connect.

License: MIT. See [LICENSE](LICENSE).
