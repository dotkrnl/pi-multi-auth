import type { Api, Model } from "@earendil-works/pi-ai";
import type { OAuthCredentials } from "./oauth-compat.js";
import type { ProviderCascadeState } from "./types-cascade.js";
import type { FailoverChain, FailoverChainState } from "./types-failover.js";
import type { ProviderHealthState } from "./types-health.js";
import type { CredentialPool, ProviderPoolConfig, ProviderPoolState } from "./types-pool.js";
import type { QuotaStateForCredential } from "./types-quota.js";
import type { UsageSnapshot } from "./usage/types.js";

/**
 * Legacy providers retained as seed/fallback values for migration and discovery.
 */
export const LEGACY_SUPPORTED_PROVIDERS = [
	"openai-codex",
	"github-copilot",
	"anthropic",
] as const;

/** Provider IDs handled by pi-multi-auth. */
export type SupportedProviderId = string;

/** Rotation strategies for selecting credentials. */
export type RotationMode = "round-robin" | "usage-based" | "balancer";

export interface CredentialRequestOverrides {
	/** Credential-scoped endpoint override used when the endpoint is account-specific. */
	baseUrl?: string;
	/** Credential-scoped request headers merged after provider headers. */
	headers?: Record<string, string>;
}

/**
 * Per-credential cookie-based OpenCode Go (opencode.ai) quota lookup config.
 *
 * OpenCode Go has no public quota API keyed on the model access key, so quota
 * is read from the authenticated workspace dashboard HTML using the browser
 * `auth` session cookie. Each OpenCode Go credential carries the workspace id
 * and cookie for its own workspace.
 */
export interface OpenCodeGoQuotaConfig {
	/** Workspace id, e.g. `wrk_01EXAMPLE0EXAMPLE0EXAMPLE0EXAMPL`. */
	workspaceId: string;
	/** Browser `auth` session cookie value from opencode.ai. */
	cookie: string;
}

export interface StoredCredentialRequestConfig {
	/** Optional request overrides that travel with a single credential. */
	request?: CredentialRequestOverrides;
	/** Cookie-based OpenCode Go quota lookup (opencode-go credentials only). */
	opencodeGo?: OpenCodeGoQuotaConfig;
}

/** OAuth credential payload stored in auth.json entries. */
export type StoredOAuthCredential = {
	type: "oauth";
} & OAuthCredentials & StoredCredentialRequestConfig;

/** API key payload stored in auth.json entries. */
export interface StoredApiKeyCredential extends StoredCredentialRequestConfig {
	type: "api_key";
	key: string;
}

/** Any credential payload stored in auth.json. */
export type StoredAuthCredential = StoredOAuthCredential | StoredApiKeyCredential;

/** Full auth.json structure. */
export type AuthFileData = Record<string, StoredAuthCredential>;

export interface ModelCredentialIncompatibilityState {
	modelId: string;
	blockedUntil: number;
	blockedAt: number;
	error: string;
}

export interface QuotaDrainStateForCredential {
	draining: boolean;
	enteredAt?: number;
	lastUsedPercent?: number;
	updatedAt: number;
}

export type CredentialBackgroundExclusionReason = "missing_refresh_token_on_import";

export interface CredentialBackgroundExclusionState {
	reason: CredentialBackgroundExclusionReason;
	excludedAt: number;
}

/** Soft process/session lease for a credential persisted in multi-auth.json. */
export interface ProviderCredentialLeaseState {
	ownerId: string;
	credentialId: string;
	acquiredAt: number;
	lastSeenAt: number;
	expiresAt: number;
}

/** Per-provider rotation state persisted in multi-auth.json. */
export interface ProviderRotationState {
	credentialIds: string[];
	activeIndex: number;
	rotationMode: RotationMode;
	manualActiveCredentialId?: string;
	lastUsedAt: Record<string, number>;
	/** Local usage units: one per routed request plus token-weighted increments when response usage is available. */
	usageCount: Record<string, number>;
	/** Recent quota-error count; selection uses time/success decay instead of lifetime penalty. */
	quotaErrorCount: Record<string, number>;
	/** Last quota-error timestamp per credential, used to decay stale error penalties. */
	quotaErrorLastSeenAt?: Record<string, number>;
	/** Consecutive successful probes after a quota error, used to restore credential trust. */
	quotaRecoverySuccessCount?: Record<string, number>;
	quotaExhaustedUntil: Record<string, number>;
	/** Last error message per credential, used to show users why a credential is exhausted. */
	lastQuotaError: Record<string, string>;
	/** Last transient provider/transport error per credential, used to explain cooldowns. */
	lastTransientError: Record<string, string>;
	/** Consecutive transient provider failures per credential, used for exponential backoff. */
	transientErrorCount: Record<string, number>;
	/** Consecutive weekly quota failures per credential, used for exponential backoff. */
	weeklyQuotaAttempts: Record<string, number>;
	friendlyNames: Record<string, string>;
	/** Permanently disabled credentials that require manual re-enablement.
	 * Key is credentialId, value contains the error message and timestamp when disabled.
	 * Used for balance exhaustion and other unrecoverable errors.
	 */
	disabledCredentials: Record<string, { error: string; disabledAt: number; planType?: string }>;
	/** Persisted cascade retry state keyed by provider ID. */
	cascadeState?: Record<string, ProviderCascadeState>;
	/** Persisted credential health scores and request history. */
	healthState?: ProviderHealthState;
	/** Scheduled OAuth refresh timestamps keyed by credential ID. */
	oauthRefreshScheduled?: Record<string, number>;
	/** @experimental Optional pool definitions for this provider. */
	pools?: CredentialPool[];
	/** @experimental Provider-level pool selection settings. */
	poolConfig?: ProviderPoolConfig;
	/** @experimental Pool rotation state when pools are configured. */
	poolState?: ProviderPoolState;
	/** @experimental Cross-provider failover chains that include this provider. */
	chains?: FailoverChain[];
	/** @experimental Active failover state shared across linked providers. */
	activeChain?: FailoverChainState;
	/** Richer quota classifications keyed by credential ID. */
	quotaStates?: Record<string, QuotaStateForCredential>;
	/** Persisted balancer quota-draining hysteresis state keyed by credential ID. */
	quotaDrainStates?: Record<string, QuotaDrainStateForCredential>;
	/** Temporary per-model credential incompatibilities keyed by credential ID then normalized model ID. */
	modelIncompatibilities?: Record<string, Record<string, ModelCredentialIncompatibilityState>>;
	/** Soft process/session leases used to avoid concurrent credential reuse when alternatives exist. */
	credentialLeases?: Record<string, ProviderCredentialLeaseState>;
	/** Credentials excluded from automatic background refresh and usage probes. */
	backgroundCredentialExclusions?: Record<string, CredentialBackgroundExclusionState>;
}

/** Top-level multi-auth.json shape. */
export interface MultiAuthState {
	version: 1;
	providers: Record<string, ProviderRotationState>;
}

/** Credential kind shown in status output. */
export type CredentialType = StoredAuthCredential["type"];

/** Selected credential used to execute a provider request. */
export interface SelectedCredential {
	provider: SupportedProviderId;
	credentialId: string;
	credential: StoredAuthCredential;
	secret: string;
	index: number;
}

/** Readable credential status for command output. */
export interface CredentialStatus {
	credentialId: string;
	credentialType: CredentialType;
	redactedSecret: string;
	friendlyName?: string;
	/** Stable identity email extracted from OAuth claims/user profile when available. */
	identityEmail?: string;
	/** Stable plan label extracted from OAuth claims when usage data is unavailable. */
	identityPlanType?: string;
	index: number;
	isActive: boolean;
	isManualActive?: boolean;
	expiresAt: number | null;
	isExpired: boolean;
	quotaExhaustedUntil?: number;
	/** Local usage units: one per routed request plus token-weighted increments when response usage is available. */
	usageCount: number;
	/** Count of recent generic quota errors (hourly/daily resets). */
	quotaErrorCount: number;
	/** Count of consecutive transient provider failures (used for exponential backoff). */
	transientErrorCount?: number;
	/** Count of consecutive weekly quota errors (used for exponential backoff). */
	weeklyQuotaAttempts?: number;
	/** Last quota error message for this credential. */
	lastQuotaError?: string;
	/** Last transient provider error for this credential. */
	lastTransientError?: string;
	lastUsedAt?: number;
	usageSnapshot?: UsageSnapshot | null;
	usageSnapshotDisplayOnly?: boolean;
	usageFetchError?: string;
	disabledError?: string;
	/** OpenCode Go workspace id when cookie-based quota lookup is configured. */
	opencodeGoWorkspaceId?: string;
}

/** Readable provider status for command output. */
export interface ProviderStatus {
	provider: SupportedProviderId;
	rotationMode: RotationMode;
	activeIndex: number;
	manualActiveCredentialId?: string;
	credentials: CredentialStatus[];
}

/** Normalized model definition used for provider registration. */
export interface ProviderModelDefinition {
	id: string;
	name: string;
	api?: Api;
	baseUrl?: string;
	reasoning: boolean;
	thinkingLevelMap?: Model<Api>["thinkingLevelMap"];
	input: ("text" | "image")[];
	cost: {
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
	};
	contextWindow: number;
	maxTokens: number;
	headers?: Record<string, string>;
	compat?: Record<string, unknown>;
}

/** Provider metadata required for wrapper registration. */
export interface ProviderRegistrationMetadata {
	provider: SupportedProviderId;
	/** Primary API type for this provider. */
	api: Api;
	/** All unique API types used by models in this provider. */
	apis: Api[];
	baseUrl: string;
	models: ProviderModelDefinition[];
}

/** Auth writer result for backup credential creation flows. */
export interface BackupAndStoreResult {
	credentialId: string;
	isBackupCredential: boolean;
	credentialIds: string[];
	didAddCredential?: boolean;
	duplicateOfCredentialId?: string;
	deduplicatedCount?: number;
	renumberedCredentialIds?: boolean;
}


