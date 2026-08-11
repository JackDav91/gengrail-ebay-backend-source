# Gengrail eBay Backend Source

Source repository for the existing Cloudflare Worker `gengrail-ebay-backend`.

## Important
This repository contains source code only. Do **not** commit eBay credentials, refresh tokens, client secrets, verification tokens, or other secrets.

Runtime secrets remain configured in Cloudflare under the Worker's **Settings → Variables & Secrets**.

## Cloudflare build settings
- Production branch: `main`
- Build command: leave blank
- Deploy command: `npx wrangler deploy`
- Root directory: leave blank

`wrangler.jsonc` deliberately uses `keep_vars: true` so dashboard-managed runtime variables are retained on deploy.

Version: Gengrail v19.3.3 Listing Resolver

GitHub → Cloudflare automatic deployment enabled.
