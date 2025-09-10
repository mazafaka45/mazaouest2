# noest-proxy (Go/Gin) — Render-ready API

A tiny reverse-proxy API for `https://app.noest-dz.com` with an **inspect mode** for `/login` that returns the status code and cookies as JSON.

## Endpoints

- `POST /login`
  - Proxies to upstream `/login`.
  - **Inspect mode**: add `?inspect=1` (or send `Accept: application/json`) and you'll get:
    ```json
    {
      "status": 302,
      "location": "https://app.noest-dz.com/home",
      "cookies": {
        "XSRF-TOKEN": "...",
        "noest_express_session": "..."
      },
      "raw_set_cookie": [
        "XSRF-TOKEN=...; path=/; ...",
        "noest_express_session=...; path=/; httponly; ..."
      ]
    }
    ```

- `GET /shippingAPI/scoring?phone=+213...`
  - Proxies to upstream scoring endpoint (path configurable via `SCORE_PATH`).

- `GET /healthz`
  - Liveness probe.

## Local Run

```bash
go mod tidy
go run .
