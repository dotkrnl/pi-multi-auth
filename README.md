# pi-multi-auth

> **This is the [dotkrnl fork](https://github.com/dotkrnl/pi-multi-auth), ported to Pi 0.84.x.**
> Upstream (MasuRii/pi-multi-auth 0.10.0) targets Pi 0.74–0.78 and does not run on Pi ≥ 0.80,
> which removed the global OAuth provider registry this extension relied on.
>
> - Requires **Pi ≥ 0.84** (`@earendil-works/pi-ai` / `pi-coding-agent` / `pi-tui` `^0.84.0`).
> - Install: `pi install github:dotkrnl/pi-multi-auth`
> - Upstream project: https://github.com/MasuRii/pi-multi-auth

[![npm version](https://img.shields.io/npm/v/pi-multi-auth?style=flat-square)](https://www.npmjs.com/package/pi-multi-auth) [![License](https://img.shields.io/github/license/MasuRii/pi-multi-auth?style=flat-square)](LICENSE)

<img width="1024" height="506" alt="image" src="https://github.com/user-attachments/assets/1aff63b4-0e1e-4eaa-93b4-5f4f9188224b" />

`pi-multi-auth` is a Pi extension for multi-provider credential management, OAuth login, and quota-aware account rotation.

- **npm**: https://www.npmjs.com/package/pi-multi-auth
- **GitHub**: https://github.com/MasuRii/pi-multi-auth

## Capabilities

- Wraps discovered Pi providers with multi-account rotation, quota-aware cooldowns, failover, health scoring, and optional pool selection.
- Supports OAuth credential management for providers exposed by Pi and registers first-class Cline, Kilo, Kimi For Coding, and Qwen OAuth login and refresh handling.
- Applies per-credential request overrides for provider base URLs and headers, with Cloudflare Workers AI credentials using account-scoped OpenAI-compatible base URLs and token/account discovery during credential setup.
- Enriches status-only provider failures with bounded diagnostic probes so authentication, permission, billing, and rate-limit errors include actionable provider response details when available.
- Provides lightweight rotation for API-key providers that do not expose external usage state, including delegated parent-session lease reuse.
- Filters removed legacy Google Gemini CLI and Google Antigravity providers so stale provider definitions are not offered for credential setup or usage refreshes.
- Persists extension state and usage snapshots under Pi's runtime directory while keeping local `config.json` and debug output outside the published package.
- Coordinates fresh usage refreshes across selection, startup, modal, and manual refresh flows with bounded concurrency, candidate windows, cooldowns, and circuit breaking.

## Provider capability matrix

The following table shows credential and usage support for each recognized provider. Providers marked **API Key** appear in the credential setup dialog; providers marked **OAuth** support browser-based or device-code login flows.

| Provider | API Key | OAuth | Usage / Quota | Notes |
|---|---|---|---|---|
| Anthropic | ✅ | — | ✅ | Usage via dedicated Anthropic endpoint |
| Amazon Bedrock | ✅ | — | — | |
| Azure OpenAI Responses | ✅ | — | — | |
| BlazeAPI | ✅ | — | ✅ | Usage via `/api/usage` (daily requests + premium credits); rotation defaults to `usage-based` and routes credentials by plan tier (Premium → Pro → Free) with automatic fallback when the active tier's daily-request or premium-credit budget is exhausted |
| Cerebras | ✅ | — | — | |
| Cline | — | ✅ | — | OAuth only; browser callback |
| Cloudflare Workers AI | ✅ | — | — | Requires account-scoped base URL |
| Cloudflare AI Gateway | ✅ | — | — | |
| DeepSeek | ✅ | — | — | |
| Fireworks | ✅ | — | — | |
| GitHub Copilot | ✅ | — | ✅ | Legacy discovery; usage via Copilot API |
| Google Gemini | ✅ | — | — | |
| Google Vertex AI | ✅ | — | — | |
| Groq | ✅ | — | — | |
| Hugging Face | ✅ | — | — | |
| Kimi For Coding | ✅ | ✅ | ✅ | Device-code OAuth; usage via `/usages` endpoint |
| Kilo | — | ✅ | — | OAuth only; device authorization |
| MiniMax | ✅ | — | — | |
| MiniMax (China) | ✅ | — | — | |
| Mistral | ✅ | — | — | |
| OpenAI | ✅ | — | ✅ | Usage via Codex entitlement |
| OpenAI Codex | ✅ | — | ✅ | Legacy discovery; Codex usage + entitlement |
| OpenCode Go | ✅ | — | — | |
| OpenCode Zen | ✅ | — | — | |
| OpenRouter | ✅ | — | — | |
| Qwen | — | ✅ | — | OAuth only; device code with PKCE |
| Vercel AI Gateway | ✅ | — | — | |
| xAI | ✅ | — | — | |
| Xiaomi MiMo | ✅ | — | — | |
| ZAI | ✅ | — | — | |
| Z.AI Coding CN | ✅ | — | ✅ | GLM China coding plan; usage via `bigmodel.cn` `/api/monitor/usage/quota/limit` (5-hour request window + weekly token budget) |

> **Legacy providers** `openai-codex` and `github-copilot` are retained for discovery and migration seed paths.
> **Removed providers** Google Gemini CLI and Google Antigravity are filtered from credential setup and usage refreshes.

## Repository structure

This package follows a conventional `src/` layout. The published entrypoint stays at the repository root as `index.ts`, runtime implementation lives under `src/`, and package exports map stable balancer subpaths to `src/balancer/*`.

```text
pi-multi-auth/
├── index.ts
├── src/
│   ├── index.ts
│   ├── balancer/
│   ├── formatters/
│   ├── usage/
│   └── *.ts
├── tests/
├── .env.example
├── package.json
├── package-lock.json
├── tsconfig.json
├── tsconfig.test.json
├── README.md
├── CHANGELOG.md
└── LICENSE
```

## Installation

### This fork (Pi 0.84+)

```bash
pi install github:dotkrnl/pi-multi-auth
```

### npm package (upstream, Pi 0.74–0.78)

```bash
pi install npm:pi-multi-auth
```

### Local extension folder

Place this folder in one of Pi's extension discovery paths:

| Scope | Path |
|-------|------|
| Global default | `~/.pi/agent/extensions/pi-multi-auth` (respects `PI_CODING_AGENT_DIR`) |
| Project | `.pi/extensions/pi-multi-auth` |

Pi discovers the extension through the root `index.ts` entry listed in `package.json`, which forwards to `src/index.ts`.

The global path above is the default when `PI_CODING_AGENT_DIR` is unset; otherwise Pi resolves the global extension path under `$PI_CODING_AGENT_DIR/extensions/pi-multi-auth`.

## Configuration

Runtime configuration lives in `config.json` at the extension root. The extension creates the file automatically with defaults on first load if it does not already exist.

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `debug` | `boolean` | `false` | Enables JSONL debug logging under `debug/pi-multi-auth-debug.jsonl` |
| `hiddenProviders` | `string[]` | `[]` | Hides selected providers from the multi-auth UI and runtime work |
| `rotationModes` | `Record<string, "round-robin" \| "usage-based" \| "balancer">` | `{}` | Overrides provider rotation modes outside `multi-auth.json` |

The published package intentionally excludes `config.json` and `debug/`; both are created locally as needed by the running extension. Usage snapshots are cached in Pi's runtime directory as `multi-auth-usage-cache.json` so operational and display-only usage state can survive extension restarts without publishing local state.

### Credential request overrides

Credentials may include a `request` object with provider-specific request settings:

| Key | Type | Purpose |
|-----|------|---------|
| `request.baseUrl` | `string` | Overrides the model base URL for that credential after URL validation |
| `request.headers` | `Record<string, string>` | Adds credential-scoped headers to the provider request |

Cloudflare Workers AI credentials must use `https://api.cloudflare.com/client/v4/accounts/<account_id>/ai/v1` as the OpenAI-compatible base URL. When adding a Cloudflare API-key credential, the extension can extract `cfat_` tokens, account IDs, dashboard token URLs, or full Workers AI base URLs from pasted input. It discovers the base URL automatically when the token can list exactly one account; otherwise add `request.baseUrl` manually for the intended account.

## Environment variables

The extension reads optional environment variables to override OAuth client settings, runtime paths, and display behavior. See [`.env.example`](.env.example) for a copy-ready template.

### OAuth client overrides

| Variable | Provider | Default | Purpose |
|---|---|---|---|
| `KIMI_CODING_OAUTH_CLIENT_ID` | Kimi For Coding | Built-in app ID | Override the OAuth application client ID |
| `QWEN_OAUTH_CLIENT_ID` | Qwen | Built-in app ID | Override the OAuth application client ID |

### Runtime path overrides

| Variable | Default | Purpose |
|---|---|---|
| `PI_DELEGATED_AUTH_RUNTIME_DIR` | Pi agent runtime directory | Override the directory for usage cache and `multi-auth.json` |
| `PI_MULTI_AUTH_RUNTIME_DIR` | Pi agent runtime directory | Legacy alias for `PI_DELEGATED_AUTH_RUNTIME_DIR`; used only when the delegated variable is unset |
| `PI_CODING_AGENT_DIR` | `~/.pi/agent` | Override the Pi agent directory (affects `models.json` and runtime path resolution) |

### Display overrides

| Variable | Default | Purpose |
|---|---|---|
| `PI_MULTI_AUTH_ASCII_BORDERS` | Auto-detected | Force ASCII border rendering in the extension TUI (`1`, `true`, `yes`, `on`) |

## Validation

```bash
npm run build
npm run lint
npm run test
npm run check
```

## Related Pi Extensions

- [pi-permission-system](https://github.com/MasuRii/pi-permission-system) — Permission enforcement for tool and command access
- [pi-tool-display](https://github.com/MasuRii/pi-tool-display) — Compact tool rendering and diff visualization
- [pi-MUST-have-extension](https://github.com/MasuRii/pi-MUST-have-extension) — RFC 2119 keyword normalization for prompts
- [pi-rtk-optimizer](https://github.com/MasuRii/pi-rtk-optimizer) — RTK command rewriting and output compaction

## License

MIT