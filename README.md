# works-server

Company (or personal) desk server for Works. The hosted UI at `https://works.scalattice.com` is static; this binary is the data, accounts, sandboxes, and shells.

## Run

```bash
# Company install — bind on the LAN / public interface, data on disk you control
works-server --bind 0.0.0.0:8787 --data /var/lib/works --name "Acme"

# Personal — what the desktop app starts for you
works-server --personal --bind 127.0.0.1:8787
```

First visit: `GET /.well-known/works.json` returns `setup_required: true`. The UI’s Connect screen creates the first **admin**. That admin’s dashboard can:

- Create users (`admin` or `member`)
- Attach **sandboxes** to real directories on this machine
- Grant per-user `read` / `write` / `shell` on each sandbox

A terminal in the desk is a PTY on **this** server, jailed to that sandbox path (`bwrap` on Linux when available).

Put `https://works.scalattice.com` (and your own UI origin, if you host the SPA) in `WORKS_CORS`.

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

TLS terminates at nginx/caddy. Forward `/` (API) and `/v1/term` (WebSocket) to this process. The SPA stays on `works.scalattice.com`; employees type `works.acme.com` (this host) into Connect.

License: MIT. See [LICENSE](LICENSE).
