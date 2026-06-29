# Deploying Kyora IQ for a classroom

Host one server; students connect their assistants to it.

## 1. Pick a token

```bash
python -c "import secrets; print(secrets.token_urlsafe(24))"
```

## 2. Deploy to Render (free, automatic HTTPS)

1. Push this repo to GitHub.
2. In Render: **New → Blueprint**, select the repo. It reads `render.yaml`.
3. In the service's **Environment**, set `KYORA_TOKEN` to your token.
4. Deploy. Your server is at `https://<service>.onrender.com/mcp`,
   health at `/health`.

Other hosts (Railway, Fly.io) work the same way: set `KYORA_HOST=0.0.0.0`,
`KYORA_TOKEN`, honor the platform's `PORT`, start with `python server/gateway.py`.

## 3. Test it

```bash
curl https://<service>.onrender.com/health
# {"status":"ok","service":"kyora-iq-mcp"}
```

## 4. Hand out the details

Give students `docs/STUDENT-GUIDE.md` with the URL and token filled in.

## Run locally first (recommended)

```bash
cp .env.example .env        # then set KYORA_TOKEN in .env
pip install -r requirements.txt
python ingestion/ingest_all.py
python server/gateway.py     # http://127.0.0.1:8000  (set KYORA_HOST=0.0.0.0 to expose)
```

## Security notes

- Auth is a single shared token — fine for a classroom over HTTPS. For anything
  beyond that, issue per-user tokens and add audit logging (the next gateway step).
- Data is read-only and public-reference; there are no secrets in the server.
- Never commit `.env`. Set the token in the host's dashboard, not in the repo.
