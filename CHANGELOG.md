# Changelog

All notable changes to this project will be documented in this file.

## 0.12.0 - 2026-08-11

### Added
- Footer quota indicator: active-account usage percentages (e.g. `kimi-coding×2:35%/27%w  openai-codex:7%`) are shown in the Pi footer via `ctx.ui.setStatus()`, refreshed every 30s and after credential-set changes, and cleared on session shutdown.
- `/multi-auth status` subcommand prints an inline per-provider/per-account report (rotation mode, usage windows, plan, active/expired/quota-exhausted markers).
- Live credential discovery: the runtime directory is watched for `auth.json` credential-set changes (atomic-rename safe, debounced, keyed on the credential-id set so token refreshes don't trigger churn) and provider wrappers re-register without a Pi restart.
- Regression tests for same-millisecond usage-cache dedup and the status summary formatters.

### Changed
- `anthropic`, `github-copilot`, and `kimi-coding` now default to `usage-based` rotation (previously round-robin), matching their working quota endpoints.

### Fixed
- Usage cache dedup (`pruneEntries`/`pruneDisplayEntries`) now lets the later write win an exact `fetchedAt` tie. Previously two fetches within the same millisecond kept the stale entry, which made `usage-persistent-cache` ambiguity tests flaky (~17% failure rate) and could show a stale display snapshot after a rapid refetch.

## 0.11.0 - 2026-08-11

### Changed
- Ported to Pi 0.84.x: pi-ai 0.80+ removed the global OAuth provider registry, so `oauth-compat` now keeps a local registry for extension-registered providers and adapts built-in provider factories (`provider.auth.oauth`, AuthInteraction login API) to the extension's legacy OAuth surface on demand.
- Switched `getModels`/`getProviders`/`getApiProvider`/`registerApiProvider` imports to the `@earendil-works/pi-ai/compat` entry point.
- Handle nullable `ProviderHeaders` values (header deletion semantics) when stripping credential-managed auth headers.
- Peer dependencies now require Pi 0.84.x (`@earendil-works/pi-ai`, `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`).

## 0.10.0 - 2026-06-01

### Added
- Added delegated auth broker support with `PI_DELEGATED_AUTH_*` runtime environment variables and legacy fallback handling.
- Added retry-budget and half-open probe controls for credential balancing, token-weighted usage accounting, and background exclusion handling for credentials missing refresh tokens.
- Added backup recovery, atomic writes, and Windows ACL hardening for credential and state file persistence.
- Added persistent usage cache and usage coordinator robustness improvements, import handling updates, and longer Codex usage request timeouts.

### Changed
- Improved provider retry behavior with jittered exponential backoff, abortable sleeps, retry-budget integration, and token-estimate-aware success recording.
- Updated OAuth command flows for missing refresh token messaging and OmniOnboard naming.
- Widened Pi peer dependency compatibility to include Pi 0.77.x and 0.78.x and updated development tooling.

### Fixed
- Decayed stale quota errors over time with success-streak recovery so recovered credentials can return to rotation.
- Improved auth writer and storage recovery from partial or corrupted snapshots.

### Removed
- Removed unused carousel and quota bar formatter code.

## 0.9.0 - 2026-05-26

### Added
- Added process-scoped credential leases that track which credentials are held by each running process, preventing concurrent credential reuse across parallel Pi sessions while allowing shared-lease fallback when no unleased alternatives exist.
- Added `ProviderCredentialLeaseState` type and `credentialLeases` field on `ProviderRotationState` in `multi-auth.json` for persistent lease tracking.
- Added automatic migration of legacy per-provider rotation modes from `multi-auth.json` to `config.json` `rotationModes` on first initialization, preserving user overrides.
- Added exhausted-quota credential detection in the multi-auth modal that marks credentials with five or more consecutive quota errors and a lingering `lastQuotaError` as "Exhaust" instead of "Ready".
- Added `enqueueAllCredentialUsageRefresh` for bulk usage refresh scheduling across all provider credentials.

### Changed
- Simplified `config.json` to expose only `debug`, `hiddenProviders`, and `rotationModes` configuration keys; removed `excludeProviders`, `cascade`, `health`, `historyPersistence`, `modelEntitlements`, `oauthRefresh`, and `usageCoordination` keys from the user-facing configuration surface.
- Moved hidden-provider state from `multi-auth.json` `ui.hiddenProviders` to `config.json` `hiddenProviders` so provider visibility survives `multi-auth.json` resets.
- Moved cascade, health, OAuth-refresh, and usage-coordination configuration to internal defaults so the extension no longer depends on user-facing configuration for subsystem tuning.
- Updated Codex OAuth refresh lead time to five minutes to reduce last-second token refresh failures.
- Widened Pi peer dependency ranges to `^0.74.0 || ^0.75.0` and bumped dev dependencies to `^0.75.5`.

### Removed
- Removed `src/history-storage.ts` module and `MultiAuthHistoryStore`; health and cascade history persistence is no longer user-configurable.
- Removed `MultiAuthUiState` interface and `ui` top-level key from `MultiAuthState` in `multi-auth.json`.

## 0.8.0 - 2026-05-22

### Added
- Added first-class Kimi For Coding OAuth login using device code flow with token refresh support.
- Added first-class Qwen OAuth login using device code flow with PKCE, resource-URL base-URL discovery, and token refresh.
- Added Kimi For Coding usage/quota provider that fetches rate-limit windows from the `/usages` endpoint with timed and untimed window classification.
- Added BlazeAPI usage/quota provider (`src/usage/blazeapi.ts`) that fetches plan limits (`daily_requests`, `premium_daily_credits`, `rate_limit_rpm`, `expires_at`), daily request counters, and premium credit consumption from `GET /api/usage` using `Authorization: Bearer blz_*`. Translates the counters into the shared `RateLimitWindow` primary (daily requests) and secondary (premium credits) windows with a UTC-midnight reset estimate, surfaces the remaining premium credit balance via `UsageCredits`, and routes through the existing `quotaClassifier` and `usageCoordinator` pathways. Verified live against `https://blazeai.boxu.dev/api/usage`.
- Added a backward-compatible parser fallback for the legacy `/api/account` flat usage shape (numeric `usage.today` with a sibling `usage.premium_used`) so the provider keeps working if BlazeAPI rolls back to that response format.
- Added `blazeapi: "BlazeAPI"` to `API_KEY_LOGIN_PROVIDER_DISPLAY_NAMES` so BlazeAPI appears in the API-key credential setup dialog with a friendly display name, and registered `blazeapiUsageProvider` in `src/usage/providers.ts`, which auto-enables `hasExternalAccountState: true` and the standard rotation profile via `provider-rotation-profile.ts`.
- Added `tests/blazeapi-usage.test.ts` covering provider registration, Pro plan parsing against the live `/api/usage` payload shape, Free plan parsing with zero premium credits, credential-scoped `baseUrl` normalization (stripping `/v1/chat/completions` suffixes), legacy `/api/account` shape fallback, 401 token-expiration handling, and missing-plan-limit rejection.
- Added BlazeAPI model-plan eligibility routing in `src/model-entitlements.ts`: `BlazeApiPlanType`, `normalizeBlazeApiPlanType`, `isBlazeApiPlanEligibleForPremiumModel`, and a curated set + regex patterns for premium-credit-charging models (`claude-opus-*`, `claude-sonnet-*`, `moonshotai/kimi-k2.6`, `qwen/qwen3.5-397b`, `z-ai/glm-5.1`). `modelRequiresEntitlement` now routes through BlazeAPI logic for the `blazeapi` provider so premium-charging models auto-route to `Pro`/`Premium` credentials (where `premium_daily_credits > 0`).
- Added BlazeAPI plan-tier routing via `rankBlazeApiCredentialsByPlanTier`, `providerUsesPlanTierRanking`, and a new `preferredCredentialTiers` field on `CredentialModelEligibility`. BlazeAPI credentials are ranked Premium → Pro → Free for every model call: higher tiers receive faster server-side pool priority and are tried first; when an active tier exhausts its `daily_requests` (primary) or `premium_daily_credits` (secondary) budget, rotation automatically falls back to the next tier and finally to the catch-all eligible set. This reverses the prior conservation-oriented preference (which routed free-tier models to Free credentials) in favor of "benefit from the highest plan first, fall back as quotas exhaust."
- Added BlazeAPI-aware `normalizeBlazeApiModelId` that preserves vendor namespaces (`moonshotai/`, `z-ai/`, `qwen/`) and only strips the leading `blazeapi/` provider prefix, so namespaced model IDs configured in `settings.json` (e.g. `blazeapi/moonshotai/kimi-k2.6`) match the entitlement catalog correctly. Fixed a latent bug where `resolveCredentialModelEligibility` was passing the codex-normalized (namespace-stripped) model id to entitlement helpers, which prevented BlazeAPI namespaced premium models from triggering entitlement filtering at runtime.
- Added a BlazeAPI-specific failure message in `resolveCredentialModelEligibility` when no `Pro`/`Premium` credential is available: *“No BlazeAPI credentials with premium daily credits available for … Upgrade to BlazeAPI Pro or Premium, or add a Pro/Premium credential to call premium-charging models.”*
- Added a generalized multi-pass selection loop in `AccountManager.acquireCredential` that consumes `preferredCredentialTiers` when present: each non-empty tier is tried as its own selection pass (with the configured rotation mode applied within the tier) before falling back to the next tier, ending in the catch-all `available` pass. Existing single-tier `preferredCredentialIds` consumers (codex) keep working unchanged.
- Added `tests/blazeapi-entitlement.test.ts` cases covering: `providerUsesPlanTierRanking`, `rankBlazeApiCredentialsByPlanTier` ordering with trailing unknown-plan bucket, premium-charging model selects Premium first, free-tier model selects Premium first (server-side priority benefit), Premium-exhausted free-tier model falls back to Pro, Premium+Pro-exhausted free-tier model falls back to Free, premium-credit-exhausted Premium credential falls back to Pro for premium-charging models, BlazeAPI-specific failure message when no premium tier is reachable, and the asserted-removal of the old `modelPrefersFreePlan` BlazeAPI preference.
- Added provider capability matrix to README documenting API key, OAuth, and usage/quota support for all recognized providers.
- Added environment variable documentation and `.env.example` template for OAuth client overrides, runtime path overrides, and display overrides.

### Changed
- Updated README OAuth provider coverage to list supported first-class OAuth providers: Cline, Kilo, Kimi For Coding, and Qwen.
- Added BlazeAPI to the README provider capability matrix as an API-key provider with usage/quota support.
- Changed the BlazeAPI default rotation mode to `usage-based` in `resolveDefaultRotationMode`, matching the `openai-codex` default, so newly-added BlazeAPI provider state starts in usage-based rotation. Existing persisted `rotationMode` in `multi-auth.json` is preserved; the live workspace state file was migrated separately from `round-robin` to `usage-based` so the rotation now respects per-credential premium-credit consumption.
- Updated package metadata, published file list, and lockfile version to `0.8.0`, including `.env.example` so the README-linked environment template is included in the package.

## 0.7.0 - 2026-05-04

### Added
- Added first-class Kilo OAuth device authorization, refresh handling, and Kilo editor request headers for model calls.
- Added Cloudflare Workers AI credential parsing for pasted `cfat_` tokens, account IDs, dashboard token URLs, and full account-scoped base URLs.

### Changed
- Updated Cloudflare Workers AI setup to discover account-scoped OpenAI-compatible base URLs when a token can list exactly one account, with actionable fallback guidance when manual selection is required.
- Removed legacy Google Gemini CLI and Google Antigravity provider handling from usage refresh and credential setup paths.
- Updated package metadata and lockfile version to `0.7.0` for release preparation.

### Fixed
- Improved Cloudflare credential identity resolution so existing credentials can derive account context from request overrides or token discovery instead of relying on stale provider metadata.

## 0.6.0 - 2026-04-30

### Added
- Added a guided provider configuration dialog for API-key and OAuth setup that separates configured and available providers, supports search, and preserves credential-count context.
- Added API-key provider discovery from Pi built-ins, `models.json`, and known `auth.json` credentials so supported providers can be selected before credentials exist.
- Added delegated credential pinning for parent-session credential reuse with explicit unavailable and model-entitlement diagnostics.

### Changed
- Refined the account manager modal to show visible account counts, alias/account columns, and color-highlighted plan details.
- Updated Cloudflare Workers AI daily allocation classification to infer UTC reset windows and reconcile persisted cooldown state from saved quota errors.
- Updated Pi development dependencies and lockfile entries to `0.70.6` for release preparation.

## 0.5.0 - 2026-04-28

### Changed
- Updated OpenAI Codex account selection to prefer fresh or durable cached usage evidence before scheduling bounded background refreshes, reducing selection latency while preserving quota-aware routing.
- Refined usage coordination with rotating candidate windows, preferred credential cache keys, and cache disambiguation for reused Codex credential ids.
- Updated Codex paid-entitlement checks to use durable negative usage evidence without forcing a fresh bootstrap when cached plan data is authoritative.
- Added explicit Codex usage request timeouts, including IPv4 fallback timeout handling, so stalled usage probes fail with clear diagnostic errors.
- Updated package metadata and lockfile version to `0.5.0` for release preparation.

## 0.4.0 - 2026-04-27

### Added
- Added per-credential request overrides for provider base URLs and headers, including Cloudflare Workers AI account-scoped base URL validation and account discovery for Cloudflare API-key credentials.
- Added provider response diagnostics for status-only OpenAI-compatible failures so authentication, permission, billing, and rate-limit errors can surface provider status codes, codes, messages, and operator actions.
- Added persistent usage snapshot caching under Pi's runtime directory with display-only last-known entries for warm starts and degraded usage visibility.
- Added coordinated usage refresh admission control with global and per-provider concurrency limits, operation-specific candidate windows, account/provider cooldowns, and circuit breakers.

### Changed
- Updated usage selection, blocked-account reconciliation, startup refinement, modal refresh, and manual refresh flows to share the persistent cache and usage coordinator instead of issuing unbounded fresh usage requests.
- Centralized local development runners so lint emits a stable empty JSON result on success and compiled tests are discovered from `.test-dist/tests` automatically.
- Updated package metadata and lockfile version to `0.4.0` for release preparation.

## 0.3.0 - 2026-04-25

### Added
- Added first-class Cline OAuth registration, browser callback handling, token exchange, token refresh, WorkOS request secret formatting, and Cline client request headers.
- Added Cline credential identity deduplication and Cline-specific token expiration handling for proactive refresh scheduling.
- Added delegated runtime credential override handling and explicit lightweight parent-session lease release support.

### Changed
- Updated package compatibility metadata to Pi 0.70.x packages.
- Preserved still-active Cline OAuth tokens when refresh failures are permanent but the current access token remains usable.
- Hardened startup, shutdown, abort, and credential lookup paths with shared structured error helpers.

### Fixed
- Skipped expired JWT-backed API key credentials during Cline selection and surfaced clear re-authentication errors for expired manual selections.
- Ensured Cline OAuth request secrets are formatted consistently without requiring runtime OAuth registry state.
- Prevented stale lightweight leases from surviving cooldown and parent-session release flows.

## 0.2.0 - 2026-04-22

### Added
- Added lightweight rotation support for non-OAuth providers, including provider-agnostic rotation classification, staged state flushing, and parent-session lease reuse in the key distributor.
- Added configurable Codex entitlement handling for usage lookup failures together with extracted health and cascade history persistence for provider state.

### Changed
- Updated startup and session lifecycle handling so warmup begins on `session_start`, reloads refresh extension config, and delegated runtimes resolve state paths through Pi's agent runtime directory.
- Updated package compatibility metadata to Pi 0.68.1 and documented the `PI_CODING_AGENT_DIR`-aware global install path.

### Fixed
- Preserved caller-initiated abort semantics during rotated requests while keeping retries limited to extension-owned timeout cases.
- Improved OAuth refresh failure summaries and quota cooldown persistence, including rate-limit-derived exhaustion windows and provider metadata refresh after `models.json` changes.

## 0.1.2 - 2026-04-01

### Changed
- Enhanced package discoverability with aligned npm keywords for better searchability.
- Added npm and GitHub repository links in `package.json` and `README.md` for package discoverability.
- Added Related Pi Extensions cross-linking section in README for ecosystem navigation.

## 0.1.1 - 2026-04-01

### Fixed
- Preserve `StreamAttemptTimeoutError` identity when abort signals propagate through generic `AbortError` surfaces. Timeout-triggered aborts now correctly surface the original timeout error context instead of wrapping it in generic abort messages.
- Properly distinguish caller-initiated aborts from timeout-triggered aborts to ensure caller aborts remain terminal without retry looping.

## 0.1.0 - 2026-03-31

### Changed
- Added public-repository packaging metadata and published file selection for the extension package.
- Added repository artifacts for open-source distribution: `README.md`, `CHANGELOG.md`, `LICENSE`, `.npmignore`, and TypeScript project configs.
- Kept the runtime entrypoint and existing source import layout unchanged to preserve extension behavior.
