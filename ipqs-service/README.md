# IPQualityScore helper backend (Render)
Dedicated Node.js microservice. Does not affect the domain Worker or production site.

Deploy on Render **New > Web Service**, source `jmarf37/monkeytoolV2`, branch `main`.
- Root directory: `ipqs-service`
- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Health check: `/health`
- Plan: Free (development/testing; cold starts and outbound IP restrictions apply).

Configure environment variables on Render:
- `IPQ_API`: fresh IPQualityScore key
- `IPQS_PROXY_TOKEN`: randomly generated long shared bearer secret (minimum 32 unpredictable bytes)
- Do not store keys or tokens in GitHub.

Then configure **only** Cloudflare Worker `monkeytoolv2` (IP), Settings > Variables and Secrets:
- `IPQS_PROXY_URL` : `https://YOUR-RENDER-SERVICE.onrender.com` (variable, NOT key)
- `IPQS_PROXY_TOKEN`: exactly the same token used at Render (Secret).

The Worker continues using its original sources and routes IPQS queries to Render when both variables are present.
Do not configure these variables on the domain Worker. The separate public Render service exposes only POST /lookup with bearer authentication. No CORS.

Test Render /health first. Then analyze `1.1.1.1` from GitHub Pages. If IPQS responds with 61771 from Render too, its outgoing IP is blocked; use an IPQS-authorized hosting provider / static egress IP or consult their support. Do not attempt to bypass platform controls.

Note: Render Free services can sleep and initial cold-start requests may time out. For more reliable testing a paid plan may be needed.
