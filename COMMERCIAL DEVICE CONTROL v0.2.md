# ShanX13 AiGG Direct Commander — Commercial Device Control v0.2 (Pilot)

Owner: X, ShanX Services LLC.
Service model: one customer account / one tenant / own approved agents / own request ledger. **Owner X is the first enrolled trial customer; the server is not hardcoded to MONSTER or to his customer identity.**

## Source
`worker.mjs` retains the existing independent Access-authenticated account portal. `customer-device-routes.mjs` implements separately authenticated, tenant-isolated, server-side device enrollment, device-control modes, signed-in customer job submission, token-authenticated device polling, receipts, and STOP. `customer-device-schema.sql` adds two tables without altering the canonical HemiSync/WQE/Infinity Sync ledger.

`agent/` contains the generic Node.js device agent with genuine local OS file handlers, an approved workspace root, independent local authorization, signed request checking, expiry and replay prevention, and an fsynced no-credentials receipt journal. No globally accessible shell, deletions, system-drive traversal, or unattended automatic device authorization.

## Tests already performed on MONSTER
- Original authentication, subscription isolation, JWT cryptography and usage tests: 10 PASS.
- Real SQLite customer/agent job lifecycle and physical file write verification: 12 PASS.
- Real loopback HTTP command submit -> cloud-style route -> bearer-authenticated agent poll -> file write on MONSTER M -> receipt -> STOP: PASS.
- Cloudflare Wrangler dry run: PASS (35.29 KiB worker).
- Dedicated live D1 backup was exported to M:\Downloads and SHA-256 verified on B:, then only two additive tables were applied. Existing Customer #1 row readback unchanged.

The HTTP loopback integration is NOT proof that the public Cloudflare route reached a device. Live Cloudflare-to-agent acceptance is a separate release gate.

## Security boundaries
- Login: real Cloudflare Access-signed JWT, verified issuer/AUD; customer tenant derived from D1 account row, not client-supplied email.
- Customer #1 is a normal trial row in `accounts`. The separate owner administrative role does not automatically grant access to other customer devices in customer routes.
- Device tokens: one-time 48 random bytes, only SHA-256 hashes in D1. Device actions still require local owner approval; remote GO never supplies that approval.
- Customer STOP latches and cancels queued/delivered jobs. Executing jobs may be marked UNKNOWN until reconciled; never equate sent/delivered/executed/verified.
- Workspace read/write denies absolute paths, traversal and symlinks, and write uses exclusive new-file creation (no overwrites).
- All personal content, tokens, receipts, host process data and customer files require tenant protections. No payment is processed by this prototype.

## Important remaining gates
1. Deploy and verify this new Worker using the correct dedicated Cloudflare account, preserving existing OWNER_EMAILS secret.
2. Connect one physically installed commercial customer device agent using an authorized one-time token, verify actual HTTPS-based command and readback, and test STOP from the customer portal.
3. Production hardening: durable Worker's retry/reconciliation, journal recovery, per-customer usage limits, schema migration versioning, rate control, customer approval UI, security review, full installer and signed update channel.
4. Real merchant-approved payment/checkout, plans and entitlements, cancellation/refunds, support and policy review.
5. Standard OAuth MCP client connectivity, third-party real customer sign-in, OpenAI public Directory submission/approval and listing.
6. Upstream MIT attribution when any third-party open-source DesktopCommanderMCP code is incorporated. This custom prototype currently uses its own code and does not purport to clone a third-party hosted commercial backend.

## Rollback
Current remote dedicated D1 original exported pre-migration to B:\X13 ROLLBACK\ShanX13 AiGG Direct Commander\Cloudflare D1 Before Device Jobs 2026-11-22. Original account Worker and Wrangler source were copied to B: before staging changes. Git original HEAD: bec99828582a27efdcbfa7602653584fdf438548. No old Commander relay or company website changed.
