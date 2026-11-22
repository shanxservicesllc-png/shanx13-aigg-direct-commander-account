# ShanX13 AiGG Direct Commander Cloudflare Worker

Owner: X / ShanX Services LLC.

This repository is the dedicated **Cloudflare deployment mirror** for ShanX13 AiGG Direct Commander account services. It is separate from both the old `shanx-commander-cloud-relay` Worker and the existing ShanXServices.com website. The original code and old deployments must not be overwritten.

Source: `worker.mjs` at repository root, with `wrangler.jsonc` pointing to it.
Dedicated new D1 database binding: `DB` to `shanx13-aigg-direct-commander-usage`.

Cloudflare's initial import build showed `entry-point worker.mjs not found` before the source import appeared in the repository. A fresh commit on the main branch is intended to trigger a new build against the **real** source tree, not repeat the failed empty bootstrap snapshot.

**This is not a commercial release.** Required production acceptance: Cloudflare Access on all traffic, cryptographic JWT + owner claims, database-backed tenant isolation and genuine usage statistics, customer billing/subscription controls, safe remotely enrolled customer agents, MCP OAuth, and public ChatGPT directory approval.

No runtime secret, authentication token, payment identifier, customer data, or machine command belongs in this repository.
