import type { Api } from "@earendil-works/pi-ai";
import {
	formatOAuthProviderLabel,
	formatOAuthRefreshFailureSummary,
	getErrorMessage,
	inferOAuthRefreshFailureMetadata,
	isRecord,
	normalizeStructuredAuthField,
	raceWithSignal,
	throwIfAborted,
} from "./auth-error-utils.js";
import type { OAuthCredentials, OAuthLoginCallbacks } from "./oauth-compat.js";
import { getOAuthProvider, refreshOAuthCredential } from "./oauth-compat.js";
import { CascadeStateManager } from "./cascade-state.js";
import { DEFAULT_CASCADE_CONFIG } from "./types-cascade.js";
import { discoverCloudflareWorkersAiBaseUrl } from "./cloudflare-account-discovery.js";
import {
	extractCloudflareCredentialAccountId,
	fetchCloudflareCredentialIdentity,
	type CloudflareCredentialIdentity,
} from "./cloudflare-credential-identity.js";
import { isCloudflareWorkersAiProvider } from "./cloudflare-provider.js";
import { CLINE_REFRESH_LEAD_TIME_MS } from "./cline-compat.js";
import { isValidCloudflareOpenAIBaseUrl } from "./credential-request-overrides.js";
import { isRemovedLegacyGoogleProvider } from "./removed-google-providers.js";
import { FailoverChainManager } from "./failover-chain.js";
import { HealthScorer } from "./health-scorer.js";
import { DEFAULT_HEALTH_CONFIG, DEFAULT_HEALTH_WEIGHTS } from "./types-health.js";
import {
	determineTokenExpiration,
	OAuthRefreshScheduler,
} from "./oauth-refresh-scheduler.js";
import { PoolManager } from "./pool-manager.js";
import { cloneProviderState } from "./provider-state-utils.js";
import { resolveDefaultRotationMode } from "./rotation-modes.js";
import { quotaClassifier } from "./quota-classifier.js";
import {
	getEffectiveQuotaErrorCount,
	getRoundRobinCandidateIndex,
	getUsageBasedCandidateIndex,
	QUOTA_ERROR_DECAY_WINDOW_MS,
	QUOTA_ERROR_PROBE_SUCCESS_STREAK_REQUIRED,
} from "./rotation-selection.js";
import {
	AuthWriter,
	type ApiKeyProviderNormalizationResult,
	type AuthCredentialEntry,
	type CredentialIdentityKeyResolver,
} from "./auth-writer.js";
import {
	getProviderState,
	MultiAuthStorage,
} from "./storage.js";
import {
	type BackupAndStoreResult,
	type CredentialBackgroundExclusionReason,
	type CredentialBackgroundExclusionState,
	type CredentialRequestOverrides,
	type CredentialStatus,
	type MultiAuthState,
	type OpenCodeGoQuotaConfig,
	type ProviderCredentialLeaseState,
	type ProviderRotationState,
	type ProviderStatus,
	type RotationMode,
	type SelectedCredential,
	type StoredAuthCredential,
	type StoredOAuthCredential,
	type SupportedProviderId,
} from "./types.js";
import {
	type BlazeApiPlanType,
	type CodexPlanType,
	type CredentialModelEligibility,
	formatModelReference,
	isBlazeApiPlanEligibleForPremiumModel,
	isKiroPlanEligibleForPaidModel,
	isPlanEligibleForModel,
	type KiroPlanType,
	modelPrefersFreePlan,
	modelRequiresEntitlement,
	normalizeBlazeApiPlanType,
	normalizeCodexPlanType,
	normalizeKiroPlanType,
	normalizeModelId,
	providerUsesPlanTierRanking,
	rankBlazeApiCredentialsByPlanTier,
	rankKiroCredentialsByPlanTier,
} from "./model-entitlements.js";
import { createUsageCredentialCacheKey, UsageService } from "./usage/index.js";
import { DEFAULT_USAGE_COORDINATION_CONFIG } from "./usage/usage-coordinator.js";
import { usageProviders } from "./usage/providers.js";
import type { UsageFetchOptions, UsageFetchResult, UsageSnapshot } from "./usage/types.js";
import {
	formatUsageRequestDeferredNote,
	isUsageRequestDeferredError,
	redactUsageCredentialIdentifier,
	UsageCoordinator,
	type UsageCoordinationOperation,
} from "./usage/usage-coordinator.js";
import {
	formatCredentialRedaction,
	getCredentialExpiration,
	getCredentialRequestSecret,
	getCredentialSecret,
	isExpiredApiKeyCredential,
	validateApiKeyInput,
} from "./credential-display.js";
import {
	ProviderRegistry,
	type AvailableApiKeyProvider,
	type AvailableOAuthProvider,
	type ProviderCapabilities,
} from "./provider-registry.js";
import {
	getGlobalKeyDistributor,
	KeyDistributor,
	registerGlobalKeyDistributor,
	type BalancerUsageSnapshot,
} from "./balancer/index.js";
import { LightweightRotationState } from "./lightweight-rotation-state.js";
import {
	computeExponentialBackoffMs,
	getWeeklyQuotaCooldownMs,
	TRANSIENT_COOLDOWN_BASE_MS,
	TRANSIENT_COOLDOWN_MAX_MS,
} from "./balancer/credential-backoff.js";
import {
	cloneMultiAuthExtensionConfig,
	CONFIG_PATH,
	DEFAULT_MULTI_AUTH_CONFIG,
	type MultiAuthExtensionConfig,
	writeMultiAuthProviderHidden,
	writeMultiAuthProviderRotationMode,
} from "./config.js";
import { describeCredentialErrorAction } from "./credential-error-formatting.js";
import { multiAuthDebugLogger } from "./debug-logger.js";
import {
	classifyCredentialError,
	type CredentialErrorKind,
} from "./error-classifier.js";
import { cloneJson, haveSameJsonValue } from "./json-utils.js";
import {
	formatEnrichedProviderResponseBrief,
	parseEnrichedProviderResponse,
} from "./provider-error-details.js";
import { extractCodexCredentialIdentity } from "./openai-codex-identity.js";
import type { ChainResult, FailoverChain, FailoverChainState } from "./types-failover.js";
import {
	DEFAULT_OAUTH_CONFIG,
	isOAuthRefreshFailureError,
	OAuthRefreshFailureError,
	UNSUPPORTED_OAUTH_REFRESH_PROVIDER_ERROR_CODE,
} from "./types-oauth.js";
import { DEFAULT_PROVIDER_POOL_CONFIG, type CredentialPool, type ProviderPoolConfig, type ProviderPoolState } from "./types-pool.js";
import type { QuotaClassification, QuotaClassificationResult, QuotaStateForCredential } from "./types-quota.js";

const QUOTA_COOLDOWN_MS = 60 * 60 * 1000;
const PRESERVED_OAUTH_REFRESH_MIN_REMAINING_MS = 30_000;
const PRESERVED_OAUTH_REFRESH_ERROR_CODES_BY_PROVIDER = new Map<string, ReadonlySet<string>>([
	["cline", new Set(["failed_to_refresh_token"])],
]);

const MIN_QUOTA_RETRY_WINDOW_MS = 60_000;
const SELECTION_USAGE_MAX_AGE_MS = 15_000;
const CODEX_SELECTION_USAGE_MAX_AGE_MS = 7_000;
const CODEX_STALE_SELECTION_REFRESH_THRESHOLD_PERCENT = 50;
const CODEX_SELECTION_EXHAUSTED_USED_PERCENT = 99;
const TOKEN_USAGE_UNIT_SIZE = 1_000;
const CODEX_USAGE_CACHE_INVALIDATION_TOKEN_THRESHOLD = 16_000;
const BLOCKED_RECONCILE_USAGE_MAX_AGE_MS = 10_000;
const MODEL_INCOMPATIBILITY_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const OPENAI_CODEX_PROVIDER_ID = "openai-codex";
const MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_REASON = "missing_refresh_token_on_import" as const;
const MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_MESSAGE =
	"Credential was imported without a refresh token; skipping automatic OAuth refresh while allowing access-token usage probes.";
const OPERATIONAL_USAGE_WARMUP_WINDOW_MULTIPLIER = 4;
const OPERATIONAL_USAGE_WARMUP_FOLLOW_UP_DELAY_MS = 30_000;
export const CODEX_PROCESS_CREDENTIAL_LEASE_TTL_MS = 30 * 60 * 1000;
const USAGE_PROVIDER_IDS = new Set(usageProviders.map((provider) => provider.id));
const INTERNAL_CASCADE_CONFIG = { ...DEFAULT_CASCADE_CONFIG };
const INTERNAL_HEALTH_CONFIG = {
	...DEFAULT_HEALTH_CONFIG,
	weights: { ...DEFAULT_HEALTH_WEIGHTS },
};
const INTERNAL_OAUTH_REFRESH_CONFIG = {
	...DEFAULT_OAUTH_CONFIG,
	excludedProviders: [...DEFAULT_OAUTH_CONFIG.excludedProviders],
};
const INTERNAL_USAGE_COORDINATION_CONFIG = { ...DEFAULT_USAGE_COORDINATION_CONFIG };

interface AutoActivateOptions {
	avoidUsageApi?: boolean;
}

interface AddApiKeyCredentialOptions {
	request?: CredentialRequestOverrides;
}

interface AddOAuthCredentialOptions {
	backgroundExclusionReason?: CredentialBackgroundExclusionReason;
}

interface AccountManagerRuntimeOptions {
	startOAuthRefreshScheduler?: boolean;
	configPath?: string;
}

function createProcessLeaseOwnerId(): string {
	return `pid:${process.pid}:started:${Date.now().toString(36)}`;
}

export type CredentialRefreshDisposition =
	| "refreshed"
	| "preserved_active_token"
	| "reused_current_token"
	| "skipped_missing_refresh_token";

export interface CredentialRefreshResult {
	credential: StoredOAuthCredential;
	disposition: CredentialRefreshDisposition;
}

export type CloudflareCredentialIdentityRefreshStatus = "updated" | "unchanged" | "unsupported";

export interface CloudflareCredentialIdentityRefreshResult {
	status: CloudflareCredentialIdentityRefreshStatus;
	friendlyName?: string;
	message: string;
}

export interface ProviderRefreshResult {
	provider: SupportedProviderId;
	totalCredentials: number;
	refreshedCredentialIds: string[];
	preservedCredentialIds: string[];
	failedCredentials: Array<{ credentialId: string; error: string }>;
	usageWarnings: Array<{ credentialId: string; warning: string }>;
}

type UsageQuotaState =
	| {
		state: "available";
	}
	| {
		state: "exhausted";
		exhaustedUntil?: number;
	}
	| {
		state: "unknown";
	};

type CredentialSelectionCommitResult =
	| { committed: true; sharedLeaseFallback: boolean }
	| { committed: false; sharedLeaseFallback: false };

export type CredentialUsageSnapshotResult = {
	snapshot: UsageSnapshot | null;
	error: string | null;
	fromCache: boolean;
	displayOnly?: boolean;
};

interface CachedUsageSelectionRead {
	usage: CredentialUsageSnapshotResult | null;
	needsRefresh: boolean;
	hasDurableEvidence: boolean;
}

interface BackgroundUsageRefreshOptions {
	maxAgeMs?: number;
	forceRefresh?: boolean;
}

interface OperationalUsageWarmupCandidate {
	credentialId: string;
	index: number;
	usageCount: number;
	quotaErrorCount: number;
	lastUsedAt: number;
	isActive: boolean;
	hasUsageSnapshot: boolean;
	needsRefresh: boolean;
}

export interface CredentialSelectionCache {
	usageByRequest: Map<string, Promise<CredentialUsageSnapshotResult>>;
}

interface CredentialUsageContext {
	credentialIds: readonly string[];
	credentialsByIdPromise?: Promise<Map<string, StoredAuthCredential>>;
	selectionCache: CredentialSelectionCache;
	signal?: AbortSignal;
}

export function createCredentialSelectionCache(): CredentialSelectionCache {
	return {
		usageByRequest: new Map<string, Promise<CredentialUsageSnapshotResult>>(),
	};
}

function normalizeCredentialIdsForDeletion(credentialIds: readonly string[]): string[] {
	if (credentialIds.length === 0) {
		throw new Error("Select at least one credential to delete.");
	}

	const normalizedCredentialIds: string[] = [];
	const seenCredentialIds = new Set<string>();
	for (const credentialId of credentialIds) {
		if (typeof credentialId !== "string") {
			throw new Error("Credential IDs must be strings.");
		}

		const normalizedCredentialId = credentialId.trim();
		if (!normalizedCredentialId) {
			throw new Error("Credential IDs must be non-empty strings.");
		}
		if (seenCredentialIds.has(normalizedCredentialId)) {
			continue;
		}

		seenCredentialIds.add(normalizedCredentialId);
		normalizedCredentialIds.push(normalizedCredentialId);
	}

	return normalizedCredentialIds;
}

function formatCredentialIdList(credentialIds: readonly string[]): string {
	return credentialIds.map((credentialId) => `'${credentialId}'`).join(", ");
}

function normalizeOptionalCredentialId(credentialId: string | undefined): string | undefined {
	if (typeof credentialId !== "string") {
		return undefined;
	}

	const normalizedCredentialId = credentialId.trim();
	return normalizedCredentialId.length > 0 ? normalizedCredentialId : undefined;
}

type AcquireCredentialOptions = {
	excludedCredentialIds?: Set<string>;
	pinnedCredentialId?: string;
	modelId?: string;
	selectionCache?: CredentialSelectionCache;
	signal?: AbortSignal;
};

export interface ResolvedFailoverTarget extends ChainResult {
	api: Api;
}

function normalizeUsageRequestMaxAgeMs(maxAgeMs: number | undefined): number | undefined {
	return typeof maxAgeMs === "number" && Number.isFinite(maxAgeMs) && maxAgeMs > 0
		? maxAgeMs
		: undefined;
}

function getUsageRequestCacheKey(
	provider: SupportedProviderId,
	credentialId: string,
	options?: UsageFetchOptions,
): string {
	const normalizedMaxAgeMs = normalizeUsageRequestMaxAgeMs(options?.maxAgeMs);
	return [
		provider,
		credentialId,
		options?.forceRefresh === true ? "force" : "cached",
		options?.allowStale === true ? "stale" : "fresh-only",
		normalizedMaxAgeMs === undefined ? "default" : String(normalizedMaxAgeMs),
	].join(":");
}

function getOAuthCredentialAuthMethod(credential: OAuthCredentials): string | undefined {
	const authMethod = (credential as OAuthCredentials & { authMethod?: unknown }).authMethod;
	return normalizeStructuredAuthField(typeof authMethod === "string" ? authMethod : undefined)
		?.toLowerCase();
}

function getOAuthCredentialIdentityEmail(
	provider: SupportedProviderId,
	credential: OAuthCredentials,
): string | undefined {
	if (provider === OPENAI_CODEX_PROVIDER_ID) {
		return extractCodexCredentialIdentity(credential).email ?? undefined;
	}

	const userInfo = isRecord(credential.userInfo) ? credential.userInfo : undefined;
	return (
		normalizeStructuredAuthField(
			typeof userInfo?.email === "string" ? userInfo.email : undefined,
		) ??
		normalizeStructuredAuthField(
			typeof credential.email === "string" ? credential.email : undefined,
		)
	);
}

function getOAuthCredentialIdentityPlanType(
	provider: SupportedProviderId,
	credential: OAuthCredentials,
): string | undefined {
	if (provider !== OPENAI_CODEX_PROVIDER_ID) {
		return undefined;
	}

	return extractCodexCredentialIdentity(credential).planType ?? undefined;
}

function buildGenericOAuthIdentityKey(credential: OAuthCredentials): string | undefined {
	const accountId = normalizeStructuredAuthField(
		typeof credential.accountId === "string" ? credential.accountId : undefined,
	);
	if (accountId) {
		return `account:${accountId}`;
	}

	const userInfo = isRecord(credential.userInfo) ? credential.userInfo : undefined;
	const userInfoId = normalizeStructuredAuthField(
		typeof userInfo?.id === "string" ? userInfo.id : undefined,
	);
	if (userInfoId) {
		return `account:${userInfoId}`;
	}

	const email =
		normalizeStructuredAuthField(
			typeof userInfo?.email === "string" ? userInfo.email : undefined,
		) ??
		normalizeStructuredAuthField(
			typeof credential.email === "string" ? credential.email : undefined,
		);
	return email ? `email:${email.toLowerCase()}` : undefined;
}

function buildOAuthIdentityKey(
	provider: SupportedProviderId,
	credential: OAuthCredentials,
): string | undefined {
	const identityKey = buildGenericOAuthIdentityKey(credential);
	if (!identityKey) {
		return undefined;
	}

	if (provider === "kiro") {
		const authMethod = getOAuthCredentialAuthMethod(credential);
		return authMethod ? `${identityKey}|auth-method:${authMethod}` : identityKey;
	}

	return identityKey;
}

function buildCodexIdentityKey(credential: OAuthCredentials): string | undefined {
	const identity = extractCodexCredentialIdentity(credential);
	if (identity.accountId) {
		return `account:${identity.accountId}`;
	}
	if (identity.accountUserId) {
		return `user:${identity.accountUserId}`;
	}
	return identity.email ? `email:${identity.email.toLowerCase()}` : undefined;
}

function hasOAuthRefreshToken(credential: unknown): boolean {
	return isRecord(credential) && typeof credential.refresh === "string" && credential.refresh.trim().length > 0;
}

function resolveStoredOAuthCredentialForImport(
	existingCredential: StoredOAuthCredential | undefined,
	incomingCredentials: OAuthCredentials,
	options: AddOAuthCredentialOptions,
): OAuthCredentials {
	if (
		options.backgroundExclusionReason === MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_REASON &&
		!hasOAuthRefreshToken(incomingCredentials) &&
		existingCredential &&
		hasOAuthRefreshToken(existingCredential)
	) {
		return {
			...incomingCredentials,
			refresh: existingCredential.refresh,
		};
	}

	return incomingCredentials;
}

function formatCredentialBackgroundExclusionMessage(
	exclusion: CredentialBackgroundExclusionState | undefined,
): string {
	if (exclusion?.reason === MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_REASON) {
		return MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_MESSAGE;
	}
	return "Credential is excluded from automatic background refresh and usage probes.";
}

function getCredentialBackgroundExclusionIds(state: ProviderRotationState): Set<string> {
	return new Set(Object.keys(state.backgroundCredentialExclusions ?? {}));
}

function clearCredentialBackgroundExclusion(
	state: ProviderRotationState,
	credentialId: string,
): void {
	delete state.backgroundCredentialExclusions?.[credentialId];
	if (
		state.backgroundCredentialExclusions &&
		Object.keys(state.backgroundCredentialExclusions).length === 0
	) {
		state.backgroundCredentialExclusions = undefined;
	}
}

function buildCloudflareApiKeyIdentityKey(credential: StoredAuthCredential): string | undefined {
	if (credential.type !== "api_key") {
		return undefined;
	}

	const accountId = extractCloudflareCredentialAccountId(credential);
	return accountId ? `cloudflare-account:${accountId.toLowerCase()}` : undefined;
}

const resolveApiKeyCredentialIdentityKey: CredentialIdentityKeyResolver = (
	provider,
	credential,
): string | undefined => {
	if (isCloudflareWorkersAiProvider(provider)) {
		return buildCloudflareApiKeyIdentityKey(credential);
	}
	return undefined;
};

function isStrongCodexIdentityKey(identityKey: string): boolean {
	return identityKey.startsWith("account:");
}

function normalizeKnownCodexPlanType(planType: string | null | undefined): CodexPlanType | undefined {
	const normalizedPlanType = normalizeCodexPlanType(planType);
	return normalizedPlanType === "unknown" ? undefined : normalizedPlanType;
}

function inferCredentialFriendlyName(
	provider: SupportedProviderId,
	credentialId: string,
	credential: StoredOAuthCredential,
): string | undefined {
	if (provider === "openai-codex") {
		const identity = extractCodexCredentialIdentity(credential);
		const candidate = identity.email ?? identity.accountUserId;
		if (!candidate || candidate === credentialId) {
			return undefined;
		}
		return candidate;
	}

	const userInfo =
		typeof credential.userInfo === "object" && credential.userInfo !== null
			? (credential.userInfo as Record<string, unknown>)
			: undefined;
	const candidate =
		(typeof userInfo?.email === "string" ? userInfo.email.trim() : "") ||
		(typeof userInfo?.displayName === "string" ? userInfo.displayName.trim() : "") ||
		(typeof userInfo?.name === "string" ? userInfo.name.trim() : "") ||
		(typeof userInfo?.username === "string" ? userInfo.username.trim() : "") ||
		(typeof credential.email === "string" ? credential.email.trim() : "") ||
		(typeof credential.name === "string" ? credential.name.trim() : "");
	const kiroAuthMethod = provider === "kiro" ? getOAuthCredentialAuthMethod(credential) : undefined;
	if (!candidate || candidate === credentialId) {
		return kiroAuthMethod;
	}
	return kiroAuthMethod ? `${candidate} (${kiroAuthMethod})` : candidate;
}

function toEpochMs(timestamp: number | null | undefined): number | null {
	if (typeof timestamp !== "number" || !Number.isFinite(timestamp) || timestamp <= 0) {
		return null;
	}

	return timestamp > 1_000_000_000_000 ? timestamp : timestamp * 1000;
}

function inferQuotaStateFromUsageWindows(
	snapshot: UsageSnapshot | null,
	windows: readonly ("primary" | "secondary")[],
): UsageQuotaState {
	if (!snapshot) {
		return { state: "unknown" };
	}

	let hasSignal = false;
	let exhausted = false;
	const exhaustedUntilCandidates: number[] = [];

	const considerWindow = (
		window: { usedPercent: number; resetsAt: number | null } | null,
	): void => {
		if (!window) {
			return;
		}
		hasSignal = true;
		if (window.usedPercent < 100) {
			return;
		}

		exhausted = true;
		const resetAtMs = toEpochMs(window.resetsAt);
		if (resetAtMs !== null) {
			exhaustedUntilCandidates.push(resetAtMs);
		}
	};

	for (const window of windows) {
		considerWindow(window === "primary" ? snapshot.primary : snapshot.secondary);
	}

	if (snapshot.copilotQuota) {
		hasSignal = true;
		const buckets = [snapshot.copilotQuota.chat, snapshot.copilotQuota.completions].filter(
			(bucket): bucket is NonNullable<typeof bucket> => bucket !== null,
		);
		const hasUnlimitedBucket = buckets.some((bucket) => bucket.unlimited);
		if (hasUnlimitedBucket) {
			return { state: "available" };
		}

		const remainingValues = buckets
			.map((bucket) => (typeof bucket.remaining === "number" ? bucket.remaining : null))
			.filter((value): value is number => value !== null);
		if (remainingValues.length > 0 && remainingValues.every((remaining) => remaining <= 0)) {
			exhausted = true;
			const resetAtMs = toEpochMs(snapshot.copilotQuota.resetAt);
			if (resetAtMs !== null) {
				exhaustedUntilCandidates.push(resetAtMs);
			}
		}
	}

	const remainingRequests = snapshot.rateLimitHeaders?.remaining;
	if (typeof remainingRequests === "number") {
		hasSignal = true;
		if (remainingRequests <= 0) {
			exhausted = true;
			const headerResetAt = toEpochMs(
				snapshot.estimatedResetAt ?? snapshot.rateLimitHeaders?.resetAt,
			);
			if (headerResetAt !== null) {
				exhaustedUntilCandidates.push(headerResetAt);
			}
		}
	}

	if (!hasSignal) {
		return { state: "unknown" };
	}
	if (!exhausted) {
		return { state: "available" };
	}

	return {
		state: "exhausted",
		exhaustedUntil:
			exhaustedUntilCandidates.length > 0
				? Math.max(...exhaustedUntilCandidates)
				: undefined,
	};
}

function inferQuotaStateFromUsage(snapshot: UsageSnapshot | null): UsageQuotaState {
	return inferQuotaStateFromUsageWindows(snapshot, ["primary", "secondary"]);
}

function inferOperationalQuotaStateFromUsage(
	provider: SupportedProviderId,
	snapshot: UsageSnapshot | null,
): UsageQuotaState {
	return provider === "blazeapi"
		? inferQuotaStateFromUsageWindows(snapshot, ["primary"])
		: inferQuotaStateFromUsage(snapshot);
}

function inferModelEligibilityQuotaStateFromUsage(
	provider: SupportedProviderId,
	snapshot: UsageSnapshot | null,
	requiresEntitlement: boolean,
): UsageQuotaState {
	if (provider !== "blazeapi") {
		return inferQuotaStateFromUsage(snapshot);
	}
	return inferQuotaStateFromUsageWindows(
		snapshot,
		requiresEntitlement ? ["primary", "secondary"] : ["primary"],
	);
}

function isUsageSnapshotUntouched(snapshot: UsageSnapshot | null): boolean {
	if (!snapshot) {
		return false;
	}

	if (snapshot.copilotQuota) {
		const buckets = [snapshot.copilotQuota.chat, snapshot.copilotQuota.completions].filter(
			(bucket): bucket is NonNullable<typeof bucket> => bucket !== null,
		);
		if (buckets.length === 0) {
			return false;
		}
		if (buckets.some((bucket) => bucket.unlimited)) {
			return true;
		}
		return buckets.every((bucket) => {
			if (typeof bucket.percentUsed === "number") {
				return bucket.percentUsed <= 0;
			}
			if (typeof bucket.used === "number") {
				return bucket.used <= 0;
			}
			return false;
		});
	}

	const primaryUsed = snapshot.primary?.usedPercent;
	const secondaryUsed = snapshot.secondary?.usedPercent;
	if (typeof primaryUsed !== "number" || typeof secondaryUsed !== "number") {
		return false;
	}

	return primaryUsed <= 0 && secondaryUsed <= 0;
}

function getUsageSnapshotResetAt(snapshot: UsageSnapshot | null): number | null {
	if (!snapshot) {
		return null;
	}

	const secondaryResetAt = toEpochMs(snapshot.secondary?.resetsAt);
	if (secondaryResetAt !== null) {
		return secondaryResetAt;
	}

	const primaryResetAt = toEpochMs(snapshot.primary?.resetsAt);
	if (primaryResetAt !== null) {
		return primaryResetAt;
	}

	const rateLimitResetAt = toEpochMs(snapshot.estimatedResetAt ?? snapshot.rateLimitHeaders?.resetAt);
	if (rateLimitResetAt !== null) {
		return rateLimitResetAt;
	}

	return toEpochMs(snapshot.copilotQuota?.resetAt);
}

function getUsageSnapshotUsedPercent(snapshot: UsageSnapshot | null): number | null {
	if (!snapshot) {
		return null;
	}

	const percentages: number[] = [];
	const appendPercentage = (value: number | null | undefined): void => {
		if (typeof value === "number" && Number.isFinite(value)) {
			percentages.push(Math.max(0, value));
		}
	};

	appendPercentage(snapshot.primary?.usedPercent);
	appendPercentage(snapshot.secondary?.usedPercent);

	if (snapshot.copilotQuota) {
		for (const bucket of [snapshot.copilotQuota.chat, snapshot.copilotQuota.completions]) {
			if (!bucket || bucket.unlimited) {
				continue;
			}
			appendPercentage(bucket.percentUsed);
			if (
				typeof bucket.used === "number" &&
				Number.isFinite(bucket.used) &&
				typeof bucket.total === "number" &&
				Number.isFinite(bucket.total) &&
				bucket.total > 0
			) {
				appendPercentage((bucket.used / bucket.total) * 100);
			}
		}
	}

	const rateLimitLimit = snapshot.rateLimitHeaders?.limit;
	const rateLimitRemaining = snapshot.rateLimitHeaders?.remaining;
	if (
		typeof rateLimitLimit === "number" &&
		Number.isFinite(rateLimitLimit) &&
		rateLimitLimit > 0 &&
		typeof rateLimitRemaining === "number" &&
		Number.isFinite(rateLimitRemaining)
	) {
		appendPercentage(((rateLimitLimit - Math.max(0, rateLimitRemaining)) / rateLimitLimit) * 100);
	}

	return percentages.length > 0 ? Math.max(...percentages) : null;
}

function compareNullableNumberAscending(left: number | null, right: number | null): number {
	if (left === right) {
		return 0;
	}
	if (left === null) {
		return 1;
	}
	if (right === null) {
		return -1;
	}
	return left - right;
}

function getSelectionUsageMaxAgeMs(provider: SupportedProviderId): number {
	return provider === OPENAI_CODEX_PROVIDER_ID
		? CODEX_SELECTION_USAGE_MAX_AGE_MS
		: SELECTION_USAGE_MAX_AGE_MS;
}

function getUsageSnapshotWindowUsedPercent(
	snapshot: UsageSnapshot | null,
	window: "primary" | "secondary",
): number | null {
	const usedPercent = snapshot?.[window]?.usedPercent;
	return typeof usedPercent === "number" && Number.isFinite(usedPercent)
		? Math.max(0, usedPercent)
		: null;
}

function normalizeCredentialUsageUnits(tokenEstimate: number | undefined): number {
	if (typeof tokenEstimate !== "number" || !Number.isFinite(tokenEstimate) || tokenEstimate <= 0) {
		return 1;
	}
	return Math.max(1, Math.ceil(tokenEstimate / TOKEN_USAGE_UNIT_SIZE));
}

function shouldInvalidateCodexUsageCacheAfterSuccess(tokenEstimate: number | undefined): boolean {
	return typeof tokenEstimate === "number" &&
		Number.isFinite(tokenEstimate) &&
		tokenEstimate >= CODEX_USAGE_CACHE_INVALIDATION_TOKEN_THRESHOLD;
}

function hasQuotaErrorPenaltyExpired(
	state: ProviderRotationState,
	credentialId: string,
	now: number,
): boolean {
	return getEffectiveQuotaErrorCount(state, credentialId, now) <= 0;
}

function haveEquivalentProviderState(
	left: ProviderRotationState,
	right: ProviderRotationState,
): boolean {
	return JSON.stringify(left) === JSON.stringify(right);
}

function haveSameNumberRecord(
	left: Readonly<Record<string, number>>,
	right: Readonly<Record<string, number>>,
): boolean {
	const leftEntries = Object.entries(left);
	const rightEntries = Object.entries(right);
	if (leftEntries.length !== rightEntries.length) {
		return false;
	}

	for (const [key, value] of leftEntries) {
		if (right[key] !== value) {
			return false;
		}
	}

	return true;
}

function resolveMappedCredentialId(
	credentialId: string | undefined,
	credentialIdMap: Readonly<Record<string, string>>,
	validIds: ReadonlySet<string>,
): string | undefined {
	if (!credentialId) {
		return undefined;
	}

	const remappedCredentialId = credentialIdMap[credentialId] ?? credentialId;
	return validIds.has(remappedCredentialId) ? remappedCredentialId : undefined;
}

function remapNumericRecord(
	record: Record<string, number>,
	credentialIdMap: Readonly<Record<string, string>>,
	validIds: ReadonlySet<string>,
): Record<string, number> {
	const remapped: Record<string, number> = {};
	for (const [credentialId, value] of Object.entries(record)) {
		if (!Number.isFinite(value)) {
			continue;
		}
		const nextCredentialId = resolveMappedCredentialId(credentialId, credentialIdMap, validIds);
		if (!nextCredentialId) {
			continue;
		}
		remapped[nextCredentialId] = value;
	}
	return remapped;
}

function remapStringRecord(
	record: Record<string, string>,
	credentialIdMap: Readonly<Record<string, string>>,
	validIds: ReadonlySet<string>,
): Record<string, string> {
	const remapped: Record<string, string> = {};
	for (const [credentialId, value] of Object.entries(record)) {
		if (typeof value !== "string") {
			continue;
		}
		const nextCredentialId = resolveMappedCredentialId(credentialId, credentialIdMap, validIds);
		if (!nextCredentialId) {
			continue;
		}
		remapped[nextCredentialId] = value;
	}
	return remapped;
}

function remapBackgroundCredentialExclusions(
	exclusions: ProviderRotationState["backgroundCredentialExclusions"],
	credentialIdMap: Readonly<Record<string, string>>,
	validIds: ReadonlySet<string>,
): ProviderRotationState["backgroundCredentialExclusions"] {
	if (!exclusions) {
		return undefined;
	}

	const remapped: NonNullable<ProviderRotationState["backgroundCredentialExclusions"]> = {};
	for (const [credentialId, exclusion] of Object.entries(exclusions)) {
		const nextCredentialId = resolveMappedCredentialId(credentialId, credentialIdMap, validIds);
		if (!nextCredentialId || exclusion.reason !== MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_REASON) {
			continue;
		}
		remapped[nextCredentialId] = {
			reason: MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_REASON,
			excludedAt: typeof exclusion.excludedAt === "number" && Number.isFinite(exclusion.excludedAt)
				? exclusion.excludedAt
				: Date.now(),
		};
	}

	return Object.keys(remapped).length > 0 ? remapped : undefined;
}

function remapQuotaStates(
	quotaStates: ProviderRotationState["quotaStates"],
	credentialIdMap: Readonly<Record<string, string>>,
	validIds: ReadonlySet<string>,
): ProviderRotationState["quotaStates"] {
	if (!quotaStates) {
		return undefined;
	}

	const remapped: NonNullable<ProviderRotationState["quotaStates"]> = {};
	for (const [credentialId, quotaState] of Object.entries(quotaStates)) {
		const nextCredentialId = resolveMappedCredentialId(credentialId, credentialIdMap, validIds);
		if (!nextCredentialId) {
			continue;
		}
		remapped[nextCredentialId] = {
			...quotaState,
			credentialId: nextCredentialId,
		};
	}
	return Object.keys(remapped).length > 0 ? remapped : undefined;
}

function remapPools(
	pools: ProviderRotationState["pools"],
	credentialIdMap: Readonly<Record<string, string>>,
	validIds: ReadonlySet<string>,
): ProviderRotationState["pools"] {
	if (!pools) {
		return undefined;
	}

	const remapped = pools
		.map((pool) => ({
			...pool,
			credentialIds: pool.credentialIds
				.map((credentialId) => resolveMappedCredentialId(credentialId, credentialIdMap, validIds))
				.filter((credentialId): credentialId is string => credentialId !== undefined),
			config: pool.config ? { ...pool.config } : undefined,
		}))
		.filter((pool) => pool.poolId.trim().length > 0 && pool.credentialIds.length > 0);

	return remapped.length > 0 ? remapped : undefined;
}

function resolveProviderPoolConfig(state: ProviderRotationState): ProviderPoolConfig {
	return {
		enablePools: state.poolConfig?.enablePools ?? ((state.pools?.length ?? 0) > 0),
		failoverStrategy:
			state.poolConfig?.failoverStrategy ?? DEFAULT_PROVIDER_POOL_CONFIG.failoverStrategy,
		preferHealthyWithinPool:
			state.poolConfig?.preferHealthyWithinPool ??
			DEFAULT_PROVIDER_POOL_CONFIG.preferHealthyWithinPool,
	};
}

function applyCredentialNormalization(
	provider: SupportedProviderId,
	state: ProviderRotationState,
	result: ApiKeyProviderNormalizationResult,
): void {
	const previousActiveCredentialId = state.credentialIds[state.activeIndex];
	const validIds = new Set(result.credentialIds);

	state.credentialIds = [...result.credentialIds];
	state.lastUsedAt = remapNumericRecord(state.lastUsedAt, result.credentialIdMap, validIds);
	state.usageCount = remapNumericRecord(state.usageCount, result.credentialIdMap, validIds);
	state.quotaErrorCount = remapNumericRecord(
		state.quotaErrorCount,
		result.credentialIdMap,
		validIds,
	);
	state.quotaErrorLastSeenAt = remapNumericRecord(
		state.quotaErrorLastSeenAt ?? {},
		result.credentialIdMap,
		validIds,
	);
	state.quotaRecoverySuccessCount = remapNumericRecord(
		state.quotaRecoverySuccessCount ?? {},
		result.credentialIdMap,
		validIds,
	);
	state.quotaExhaustedUntil = remapNumericRecord(
		state.quotaExhaustedUntil,
		result.credentialIdMap,
		validIds,
	);
	state.lastQuotaError = remapStringRecord(
		state.lastQuotaError,
		result.credentialIdMap,
		validIds,
	);
	state.lastTransientError = remapStringRecord(
		state.lastTransientError,
		result.credentialIdMap,
		validIds,
	);
	state.transientErrorCount = remapNumericRecord(
		state.transientErrorCount,
		result.credentialIdMap,
		validIds,
	);
	state.friendlyNames = remapStringRecord(state.friendlyNames, result.credentialIdMap, validIds);
	state.pools = remapPools(state.pools, result.credentialIdMap, validIds);
	state.quotaStates = remapQuotaStates(state.quotaStates, result.credentialIdMap, validIds);
	state.backgroundCredentialExclusions = remapBackgroundCredentialExclusions(
		state.backgroundCredentialExclusions,
		result.credentialIdMap,
		validIds,
	);
	state.manualActiveCredentialId = resolveMappedCredentialId(
		state.manualActiveCredentialId,
		result.credentialIdMap,
		validIds,
	);

	const nextActiveCredentialId = resolveMappedCredentialId(
		previousActiveCredentialId,
		result.credentialIdMap,
		validIds,
	);
	state.activeIndex = nextActiveCredentialId
		? Math.max(0, state.credentialIds.indexOf(nextActiveCredentialId))
		: 0;
	normalizeProviderState(state, provider);
}

function reconcileActiveQuotaCooldownsFromPersistedErrors(
	state: ProviderRotationState,
	validIds: ReadonlySet<string>,
	now: number = Date.now(),
): void {
	for (const credentialId of validIds) {
		const currentUntil = state.quotaExhaustedUntil[credentialId];
		if (typeof currentUntil !== "number" || currentUntil <= now) {
			continue;
		}

		const errorMessage = state.lastQuotaError[credentialId]?.trim();
		if (!errorMessage) {
			continue;
		}

		const classification = quotaClassifier.classifyFromMessage(errorMessage);
		const windowEndMs = classification.window?.windowEndMs;
		if (typeof windowEndMs !== "number" || windowEndMs <= currentUntil) {
			continue;
		}

		const nextUntil = Math.max(windowEndMs, now + MIN_QUOTA_RETRY_WINDOW_MS);
		state.quotaExhaustedUntil[credentialId] = nextUntil;
		state.quotaStates = state.quotaStates ?? {};
		state.quotaStates[credentialId] = {
			...quotaClassifier.createQuotaState(credentialId, errorMessage, classification, now),
			resetAt: nextUntil,
		};
	}
}

function normalizeProviderState(
	state: ProviderRotationState,
	provider?: SupportedProviderId,
): void {
	const validIds = new Set(state.credentialIds);
	const now = Date.now();

	const keepOnlyValidNumericKeys = (record: Record<string, number>): void => {
		for (const key of Object.keys(record)) {
			if (!validIds.has(key)) {
				delete record[key];
			}
		}
	};

	keepOnlyValidNumericKeys(state.lastUsedAt);
	keepOnlyValidNumericKeys(state.usageCount);
	keepOnlyValidNumericKeys(state.quotaErrorCount);
	state.quotaErrorLastSeenAt = state.quotaErrorLastSeenAt ?? {};
	state.quotaRecoverySuccessCount = state.quotaRecoverySuccessCount ?? {};
	keepOnlyValidNumericKeys(state.quotaErrorLastSeenAt);
	keepOnlyValidNumericKeys(state.quotaRecoverySuccessCount);
	keepOnlyValidNumericKeys(state.quotaExhaustedUntil);
	keepOnlyValidNumericKeys(state.transientErrorCount);

	for (const key of Object.keys(state.lastQuotaError)) {
		if (!validIds.has(key)) {
			delete state.lastQuotaError[key];
		}
	}

	for (const key of Object.keys(state.lastTransientError)) {
		if (!validIds.has(key)) {
			delete state.lastTransientError[key];
		}
	}

	for (const key of Object.keys(state.friendlyNames)) {
		if (!validIds.has(key)) {
			delete state.friendlyNames[key];
			continue;
		}
		const normalized = state.friendlyNames[key]?.trim();
		if (!normalized || normalized === key) {
			delete state.friendlyNames[key];
			continue;
		}
		state.friendlyNames[key] = normalized;
	}

	for (const key of Object.keys(state.disabledCredentials)) {
		if (!validIds.has(key)) {
			delete state.disabledCredentials[key];
			continue;
		}
		const entry = state.disabledCredentials[key];
		const normalizedError = entry?.error?.trim();
		if (!normalizedError) {
			delete state.disabledCredentials[key];
			continue;
		}
		const normalizedPlanType = normalizeKnownCodexPlanType(entry.planType);
		state.disabledCredentials[key] = {
			error: normalizedError,
			disabledAt:
				typeof entry.disabledAt === "number" && Number.isFinite(entry.disabledAt)
					? entry.disabledAt
					: now,
			...(normalizedPlanType ? { planType: normalizedPlanType } : {}),
		};
	}

	if (state.backgroundCredentialExclusions) {
		for (const key of Object.keys(state.backgroundCredentialExclusions)) {
			const entry = state.backgroundCredentialExclusions[key];
			if (!validIds.has(key) || entry?.reason !== MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_REASON) {
				delete state.backgroundCredentialExclusions[key];
				continue;
			}
			state.backgroundCredentialExclusions[key] = {
				reason: MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_REASON,
				excludedAt:
					typeof entry.excludedAt === "number" && Number.isFinite(entry.excludedAt)
						? entry.excludedAt
						: now,
			};
		}
		if (Object.keys(state.backgroundCredentialExclusions).length === 0) {
			state.backgroundCredentialExclusions = undefined;
		}
	}

	keepOnlyValidNumericKeys(state.oauthRefreshScheduled ?? {});
	reconcileActiveQuotaCooldownsFromPersistedErrors(state, validIds, now);

	if (state.cascadeState) {
		for (const providerId of Object.keys(state.cascadeState)) {
			const providerCascadeState = state.cascadeState[providerId];
			if (!providerCascadeState) {
				delete state.cascadeState[providerId];
				continue;
			}
			if (providerCascadeState.active) {
				providerCascadeState.active.cascadePath = providerCascadeState.active.cascadePath.filter(
					(attempt) => validIds.has(attempt.credentialId),
				);
				providerCascadeState.active.attemptCount = providerCascadeState.active.cascadePath.length;
				if (providerCascadeState.active.cascadePath.length === 0) {
					providerCascadeState.active = undefined;
				}
			}
			providerCascadeState.history = providerCascadeState.history
				.map((entry) => ({
					...entry,
					cascadePath: entry.cascadePath.filter((attempt) => validIds.has(attempt.credentialId)),
					attemptCount: entry.cascadePath.filter((attempt) => validIds.has(attempt.credentialId))
						.length,
				}))
				.filter((entry) => entry.cascadePath.length > 0);
			if (!providerCascadeState.active && providerCascadeState.history.length === 0) {
				delete state.cascadeState[providerId];
			}
		}
		if (Object.keys(state.cascadeState).length === 0) {
			state.cascadeState = undefined;
		}
	}

	if (state.healthState) {
		for (const credentialId of Object.keys(state.healthState.scores ?? {})) {
			if (!validIds.has(credentialId)) {
				delete state.healthState.scores[credentialId];
			}
		}
		for (const credentialId of Object.keys(state.healthState.history ?? {})) {
			if (!validIds.has(credentialId)) {
				delete state.healthState.history?.[credentialId];
			}
		}
		if (
			Object.keys(state.healthState.scores ?? {}).length === 0 &&
			Object.keys(state.healthState.history ?? {}).length === 0
		) {
			state.healthState = undefined;
		}
	}

	if (state.pools) {
		state.pools = state.pools
			.map((pool) => ({
				...pool,
				credentialIds: pool.credentialIds.filter((credentialId) => validIds.has(credentialId)),
				config: pool.config ? { ...pool.config } : undefined,
			}))
			.filter((pool) => pool.poolId.trim().length > 0 && pool.credentialIds.length > 0)
			.sort((left, right) => {
				if (left.priority !== right.priority) {
					return left.priority - right.priority;
				}
				return left.poolId.localeCompare(right.poolId);
			});
		if (state.pools.length === 0) {
			state.pools = undefined;
			state.poolState = undefined;
		}
	}

	if (state.poolConfig) {
		state.poolConfig = resolveProviderPoolConfig(state);
		if (
			state.poolConfig.enablePools === DEFAULT_PROVIDER_POOL_CONFIG.enablePools &&
			state.poolConfig.failoverStrategy === DEFAULT_PROVIDER_POOL_CONFIG.failoverStrategy &&
			state.poolConfig.preferHealthyWithinPool ===
				DEFAULT_PROVIDER_POOL_CONFIG.preferHealthyWithinPool
		) {
			state.poolConfig = undefined;
		}
	}

	if (state.poolState) {
		const poolExists = state.pools?.some((pool) => pool.poolId === state.poolState?.activePoolId) ?? false;
		if (!poolExists) {
			state.poolState.activePoolId = undefined;
		}
		if (
			typeof state.poolState.poolIndex === "number" &&
			(!Number.isInteger(state.poolState.poolIndex) || state.poolState.poolIndex < 0)
		) {
			state.poolState.poolIndex = 0;
		}
		if (!state.poolState.activePoolId && state.poolState.poolIndex === undefined) {
			state.poolState = undefined;
		}
	}

	if (state.quotaStates) {
		for (const credentialId of Object.keys(state.quotaStates)) {
			if (!validIds.has(credentialId)) {
				delete state.quotaStates[credentialId];
			}
		}
		if (Object.keys(state.quotaStates).length === 0) {
			state.quotaStates = undefined;
		}
	}

	if (state.modelIncompatibilities) {
		const now = Date.now();
		for (const [credentialId, models] of Object.entries(state.modelIncompatibilities)) {
			if (!validIds.has(credentialId)) {
				delete state.modelIncompatibilities[credentialId];
				continue;
			}
			for (const [modelId, entry] of Object.entries(models)) {
				const normalizedModelId = normalizeModelId(modelId, provider);
				const blockedUntil = entry?.blockedUntil;
				const error = entry?.error?.trim();
				if (!normalizedModelId || typeof blockedUntil !== "number" || blockedUntil <= now || !error) {
					delete models[modelId];
					continue;
				}
				if (normalizedModelId !== modelId) {
					delete models[modelId];
				}
				models[normalizedModelId] = {
					modelId: normalizedModelId,
					blockedUntil,
					blockedAt: typeof entry.blockedAt === "number" && Number.isFinite(entry.blockedAt)
						? entry.blockedAt
						: now,
					error,
				};
			}
			if (Object.keys(models).length === 0) {
				delete state.modelIncompatibilities[credentialId];
			}
		}
		if (Object.keys(state.modelIncompatibilities).length === 0) {
			state.modelIncompatibilities = undefined;
		}
	}

	for (const credentialId of state.credentialIds) {
		if (state.usageCount[credentialId] === undefined) {
			state.usageCount[credentialId] = 0;
		}
		if (state.quotaErrorCount[credentialId] === undefined) {
			state.quotaErrorCount[credentialId] = 0;
		} else if (hasQuotaErrorPenaltyExpired(state, credentialId, now)) {
			delete state.quotaErrorCount[credentialId];
			delete state.quotaErrorLastSeenAt?.[credentialId];
			delete state.quotaRecoverySuccessCount?.[credentialId];
			state.quotaErrorCount[credentialId] = 0;
		}
		if (state.transientErrorCount[credentialId] === undefined) {
			state.transientErrorCount[credentialId] = 0;
		}
		state.oauthRefreshScheduled = state.oauthRefreshScheduled ?? {};
	}

	if (
		typeof state.manualActiveCredentialId === "string" &&
		!validIds.has(state.manualActiveCredentialId)
	) {
		state.manualActiveCredentialId = undefined;
	}

	pruneProviderCredentialLeases(state, Date.now());

	if (state.credentialIds.length === 0) {
		state.activeIndex = 0;
		state.manualActiveCredentialId = undefined;
		state.credentialLeases = undefined;
		return;
	}

	if (state.activeIndex < 0 || state.activeIndex >= state.credentialIds.length) {
		state.activeIndex = 0;
	}

	if (state.manualActiveCredentialId) {
		const manualIndex = state.credentialIds.indexOf(state.manualActiveCredentialId);
		if (manualIndex >= 0) {
			state.activeIndex = manualIndex;
		}
	}
}

function reconcileBackgroundCredentialExclusionsForProvider(
	provider: SupportedProviderId,
	state: ProviderRotationState,
	credentialEntries: readonly AuthCredentialEntry[],
): boolean {
	void provider;
	void credentialEntries;
	if (!state.backgroundCredentialExclusions) {
		return false;
	}

	state.backgroundCredentialExclusions = undefined;
	return true;
}

export function pruneProviderCredentialLeases(
	state: ProviderRotationState,
	now: number,
	ownerIdToRemove?: string,
): boolean {
	const leases = state.credentialLeases;
	if (!leases) {
		return false;
	}

	const validIds = new Set(state.credentialIds);
	const normalizedOwnerIdToRemove = ownerIdToRemove?.trim();
	let didChange = false;
	for (const [ownerId, lease] of Object.entries(leases)) {
		const normalizedOwnerId = lease.ownerId?.trim() || ownerId.trim();
		const credentialId = lease.credentialId?.trim();
		const shouldRemove =
			(normalizedOwnerIdToRemove !== undefined && (ownerId === normalizedOwnerIdToRemove || normalizedOwnerId === normalizedOwnerIdToRemove)) ||
			!normalizedOwnerId ||
			!credentialId ||
			!validIds.has(credentialId) ||
			typeof lease.expiresAt !== "number" ||
			!Number.isFinite(lease.expiresAt) ||
			lease.expiresAt <= now;
		if (shouldRemove) {
			delete leases[ownerId];
			didChange = true;
			continue;
		}
		if (normalizedOwnerId !== lease.ownerId || ownerId !== normalizedOwnerId) {
			delete leases[ownerId];
			leases[normalizedOwnerId] = {
				...lease,
				ownerId: normalizedOwnerId,
				credentialId,
			};
			didChange = true;
			continue;
		}
		if (credentialId !== lease.credentialId) {
			leases[ownerId] = {
				...lease,
				credentialId,
			};
			didChange = true;
		}
	}

	if (Object.keys(leases).length === 0) {
		state.credentialLeases = undefined;
		didChange = true;
	}
	return didChange;
}

export function getOwnedCredentialLease(
	state: ProviderRotationState,
	ownerId: string,
	now: number,
): ProviderCredentialLeaseState | undefined {
	const lease = state.credentialLeases?.[ownerId];
	if (!lease || lease.expiresAt <= now || !state.credentialIds.includes(lease.credentialId)) {
		return undefined;
	}
	return lease;
}

export function getCredentialIdsLeasedByOtherOwners(
	state: ProviderRotationState,
	ownerId: string,
	now: number,
): Set<string> {
	const credentialIds = new Set<string>();
	for (const [leaseOwnerId, lease] of Object.entries(state.credentialLeases ?? {})) {
		if (leaseOwnerId === ownerId || lease.expiresAt <= now) {
			continue;
		}
		if (state.credentialIds.includes(lease.credentialId)) {
			credentialIds.add(lease.credentialId);
		}
	}
	return credentialIds;
}

export function buildCredentialLease(
	ownerId: string,
	credentialId: string,
	now: number,
): ProviderCredentialLeaseState {
	return {
		ownerId,
		credentialId,
		acquiredAt: now,
		lastSeenAt: now,
		expiresAt: now + CODEX_PROCESS_CREDENTIAL_LEASE_TTL_MS,
	};
}

function buildAvailableSet(
	state: ProviderRotationState,
	now: number,
	excludedCredentialIds?: Set<string>,
): Set<string> {
	const available = new Set<string>();

	for (const credentialId of state.credentialIds) {
		// Skip permanently disabled credentials
		if (state.disabledCredentials?.[credentialId]) {
			continue;
		}

		const exhaustedUntil = state.quotaExhaustedUntil[credentialId];
		if (typeof exhaustedUntil === "number" && exhaustedUntil <= now) {
			delete state.quotaExhaustedUntil[credentialId];
		}

		const stillExhausted = state.quotaExhaustedUntil[credentialId];
		if (typeof stillExhausted === "number" && stillExhausted > now) {
			continue;
		}
		if (excludedCredentialIds?.has(credentialId)) {
			continue;
		}
		available.add(credentialId);
	}

	return available;
}

/**
 * Gets the disabled error message for a credential from the provider state.
 */
function getDisabledError(
	state: ProviderRotationState,
	credentialId: string,
): { error: string; disabledAt: number } | null {
	const entry = state.disabledCredentials[credentialId];
	if (!entry || typeof entry.error !== "string" || entry.error.trim().length === 0) {
		return null;
	}
	return {
		error: entry.error.trim(),
		disabledAt: typeof entry.disabledAt === "number" ? entry.disabledAt : Date.now(),
	};
}

function getModelIncompatibility(
	state: ProviderRotationState,
	provider: SupportedProviderId,
	credentialId: string,
	modelId: string | undefined,
	now: number = Date.now(),
): { error: string; blockedUntil: number } | null {
	const normalizedModelId = normalizeModelId(modelId, provider);
	if (!normalizedModelId) {
		return null;
	}

	const entry = state.modelIncompatibilities?.[credentialId]?.[normalizedModelId];
	if (!entry || entry.blockedUntil <= now || !entry.error.trim()) {
		return null;
	}

	return {
		error: entry.error.trim(),
		blockedUntil: entry.blockedUntil,
	};
}

function formatUnavailableCredentialReason(
	provider: SupportedProviderId,
	state: ProviderRotationState,
	credentialId: string,
	now: number,
	expiredApiKeyCredentialIds: ReadonlySet<string>,
	effectiveExcludedCredentialIds: ReadonlySet<string>,
	requestedModelId: string | undefined,
): { lines: string[]; actionKind?: CredentialErrorKind } {
	const disabledReason = getDisabledError(state, credentialId);
	if (disabledReason) {
		const providerResponse = parseEnrichedProviderResponse(disabledReason.error);
		const classification = classifyCredentialError(
			providerResponse.message ?? disabledReason.error,
			{ providerId: provider },
		);
		const reason = formatEnrichedProviderResponseBrief(providerResponse) ?? disabledReason.error;
		return {
			lines: [`- ${credentialId}: disabled (${reason})`],
			actionKind: classification.kind,
		};
	}

	if (expiredApiKeyCredentialIds.has(credentialId)) {
		return {
			lines: [`- ${credentialId}: expired session token`],
			actionKind: "authentication",
		};
	}

	const exhaustedUntil = state.quotaExhaustedUntil[credentialId];
	if (typeof exhaustedUntil === "number" && exhaustedUntil > now) {
		const lines = [`- ${credentialId}: temporarily exhausted until ${new Date(exhaustedUntil).toISOString()}`];
		const lastQuotaError = state.lastQuotaError[credentialId];
		if (typeof lastQuotaError === "string" && lastQuotaError.trim().length > 0) {
			lines.push(`  - Last quota error: ${lastQuotaError.trim()}`);
		}
		return { lines, actionKind: "quota" };
	}

	const modelIncompatibility = getModelIncompatibility(state, provider, credentialId, requestedModelId, now);
	if (modelIncompatibility) {
		return {
			lines: [
				`- ${credentialId}: incompatible with ${requestedModelId ?? "requested model"} until ${new Date(modelIncompatibility.blockedUntil).toISOString()}`,
				`  - Last model access error: ${modelIncompatibility.error}`,
			],
			actionKind: "invalid_request",
		};
	}

	if (effectiveExcludedCredentialIds.has(credentialId)) {
		return {
			lines: [`- ${credentialId}: already tried or unavailable for this request`],
			actionKind: "unknown",
		};
	}

	return {
		lines: [`- ${credentialId}: unavailable`],
		actionKind: "unknown",
	};
}

function formatDelegatedCredentialUnavailableMessage(
	provider: SupportedProviderId,
	state: ProviderRotationState,
	credentialId: string,
	expiredApiKeyCredentialIds: ReadonlySet<string>,
	effectiveExcludedCredentialIds: ReadonlySet<string>,
	requestedModelId: string | undefined,
): string {
	const now = Date.now();
	const reason = formatUnavailableCredentialReason(
		provider,
		state,
		credentialId,
		now,
		expiredApiKeyCredentialIds,
		effectiveExcludedCredentialIds,
		requestedModelId,
	);
	const action = reason.actionKind
		? describeCredentialErrorAction(reason.actionKind)
		: "Ask the parent router to retry with another delegated credential or resolve the credential state in /multi-auth.";
	const lines = [
		"Delegated credential is unavailable",
		`Provider: ${provider}`,
	];
	if (requestedModelId) {
		lines.push(`Model: ${requestedModelId}`);
	}
	lines.push(
		`Credential: ${credentialId}`,
		"Credential status:",
		...reason.lines,
		`Action: ${action}`,
	);
	return lines.join("\n");
}

function formatAllCredentialsUnavailableMessage(
	provider: SupportedProviderId,
	state: ProviderRotationState,
	expiredApiKeyCredentialIds: ReadonlySet<string>,
	effectiveExcludedCredentialIds: ReadonlySet<string>,
	requestedModelId: string | undefined,
): string {
	const now = Date.now();
	const lines = [
		"All credentials are unavailable",
		`Provider: ${provider}`,
	];
	if (requestedModelId) {
		lines.push(`Model: ${requestedModelId}`);
	}
	lines.push(`Credentials: ${state.credentialIds.length}`);

	let actionKind: CredentialErrorKind | undefined;
	for (const credentialId of state.credentialIds) {
		const reason = formatUnavailableCredentialReason(
			provider,
			state,
			credentialId,
			now,
			expiredApiKeyCredentialIds,
			effectiveExcludedCredentialIds,
			requestedModelId,
		);
		lines.push(...reason.lines);
		actionKind ??= reason.actionKind;
	}

	const action = actionKind
		? describeCredentialErrorAction(actionKind)
		: "Add another account in /multi-auth or re-enable an existing credential after resolving its provider issue.";
	lines.push(`Action: ${action}`);

	return lines.join("\n");
}

function isLegacyCodexOAuthRefreshFailureMessage(message: string | undefined): boolean {
	const normalizedMessage = message?.trim();
	if (!normalizedMessage) {
		return false;
	}

	return (
		/failed to refresh oauth token/i.test(normalizedMessage) &&
		/openai codex refresh rejected permanently/i.test(normalizedMessage)
	);
}

function isCodexUsageAuthenticationFailure(
	provider: SupportedProviderId,
	usage: UsageFetchResult,
): usage is UsageFetchResult & { error: string } {
	if (provider !== OPENAI_CODEX_PROVIDER_ID || usage.fromCache || !usage.error) {
		return false;
	}

	return /openai codex token expired or invalid/i.test(usage.error);
}

function clearRecoveredCodexRefreshFailureState(
	state: ProviderRotationState,
	credentialId: string,
): boolean {
	let changed = false;
	const lastQuotaError = state.lastQuotaError[credentialId];
	if (isLegacyCodexOAuthRefreshFailureMessage(lastQuotaError)) {
		delete state.quotaExhaustedUntil[credentialId];
		delete state.lastQuotaError[credentialId];
		delete state.quotaStates?.[credentialId];
		delete state.weeklyQuotaAttempts?.[credentialId];
		changed = true;
	}

	if (changed && Object.keys(state.disabledCredentials).length === 0) {
		state.disabledCredentials = {};
	}
	if (state.quotaStates && Object.keys(state.quotaStates).length === 0) {
		state.quotaStates = undefined;
	}
	if (state.weeklyQuotaAttempts && Object.keys(state.weeklyQuotaAttempts).length === 0) {
		state.weeklyQuotaAttempts = {};
	}

	return changed;
}

function getEffectiveOAuthCredentialExpiration(
	credential: StoredOAuthCredential,
): number {
	return determineTokenExpiration(credential.access, credential.expires).expiresAt;
}

const CODEX_REFRESH_LEAD_TIME_MS = 5 * 60_000;

function getOAuthRefreshLeadTimeMs(provider: SupportedProviderId, defaultSafetyWindowMs: number): number {
	if (provider === "cline") {
		return Math.max(defaultSafetyWindowMs, CLINE_REFRESH_LEAD_TIME_MS);
	}
	if (provider === "openai-codex") {
		return Math.max(defaultSafetyWindowMs, CODEX_REFRESH_LEAD_TIME_MS);
	}
	return defaultSafetyWindowMs;
}

function getSchedulerExpirationForRefreshLeadTime(
	provider: SupportedProviderId,
	expiresAt: number,
	schedulerSafetyWindowMs: number,
): number {
	const leadTimeMs = getOAuthRefreshLeadTimeMs(provider, schedulerSafetyWindowMs);
	return expiresAt - Math.max(0, leadTimeMs - schedulerSafetyWindowMs);
}

function hasPreservableOAuthTokenLifetime(
	credential: StoredOAuthCredential,
	now: number = Date.now(),
): boolean {
	return getEffectiveOAuthCredentialExpiration(credential) - now > PRESERVED_OAUTH_REFRESH_MIN_REMAINING_MS;
}

function isRecoverableClineOAuthRefreshFailureMessage(message: string | undefined): boolean {
	const normalizedMessage = message?.trim();
	if (!normalizedMessage) {
		return false;
	}

	return (
		/cline refresh rejected permanently/i.test(normalizedMessage) &&
		/code=failed[_\s-]*to[_\s-]*refresh[_\s-]*token/i.test(normalizedMessage)
	);
}

function clearRecoveredClineRefreshFailureState(
	state: ProviderRotationState,
	credentialId: string,
	_credential: StoredOAuthCredential,
	_now: number = Date.now(),
): boolean {
	const disabledEntry = state.disabledCredentials?.[credentialId];
	if (!disabledEntry || !isRecoverableClineOAuthRefreshFailureMessage(disabledEntry.error)) {
		return false;
	}

	delete state.disabledCredentials[credentialId];
	if (Object.keys(state.disabledCredentials).length === 0) {
		state.disabledCredentials = {};
	}
	return true;
}

function shouldPreserveActiveOAuthCredentialAfterRefreshFailure(
	provider: SupportedProviderId,
	credential: StoredOAuthCredential,
	failure: OAuthRefreshFailureError,
	now: number = Date.now(),
): boolean {
	if (!hasPreservableOAuthTokenLifetime(credential, now)) {
		return false;
	}

	if (provider === "cline" && failure.details.permanent) {
		return true;
	}

	const errorCode = normalizeStructuredAuthField(failure.details.errorCode);
	if (!errorCode) {
		return false;
	}

	return PRESERVED_OAUTH_REFRESH_ERROR_CODES_BY_PROVIDER.get(provider)?.has(errorCode) ?? false;
}

function isDisabledByPreservableOAuthRefreshFailure(
	provider: SupportedProviderId,
	errorMessage: string | undefined,
): boolean {
	const normalizedMessage = errorMessage?.trim();
	if (!normalizedMessage) {
		return false;
	}
	if (provider === "cline" && isRecoverableClineOAuthRefreshFailureMessage(normalizedMessage)) {
		return true;
	}

	const inferredFailure = inferOAuthRefreshFailureMetadata(normalizedMessage);
	const errorCode = normalizeStructuredAuthField(inferredFailure.errorCode);
	if (!errorCode) {
		return false;
	}

	return PRESERVED_OAUTH_REFRESH_ERROR_CODES_BY_PROVIDER.get(provider)?.has(errorCode) ?? false;
}

function clearDisabledOAuthRefreshFailureStateForProvider(
	provider: SupportedProviderId,
	state: ProviderRotationState,
): boolean {
	let changed = false;
	for (const [credentialId, entry] of Object.entries(state.disabledCredentials ?? {})) {
		if (!isDisabledByPreservableOAuthRefreshFailure(provider, entry?.error)) {
			continue;
		}
		delete state.disabledCredentials[credentialId];
		changed = true;
	}

	if (changed && Object.keys(state.disabledCredentials).length === 0) {
		state.disabledCredentials = {};
	}

	return changed;
}

function clearRecoveredOAuthRefreshFailureStateForCredential(
	provider: SupportedProviderId,
	state: ProviderRotationState,
	credentialId: string,
	credential: StoredOAuthCredential,
	now: number = Date.now(),
): boolean {
	if (provider === "openai-codex") {
		return clearRecoveredCodexRefreshFailureState(state, credentialId);
	}
	if (provider === "cline") {
		return clearRecoveredClineRefreshFailureState(state, credentialId, credential, now);
	}
	return false;
}

function clearRecoveredOAuthRefreshFailureStateForProvider(
	provider: SupportedProviderId,
	state: ProviderRotationState,
	credentialEntries: readonly AuthCredentialEntry[],
	now: number = Date.now(),
): boolean {
	let changed = false;
	for (const entry of credentialEntries) {
		if (entry.credential.type !== "oauth") {
			continue;
		}
		changed =
			clearRecoveredOAuthRefreshFailureStateForCredential(
				provider,
				state,
				entry.credentialId,
				entry.credential,
				now,
			) || changed;
	}
	return changed;
}

/**
 * Manages multi-account credentials and rotation behavior across providers.
 */
export class AccountManager {
	private readonly keyDistributor: KeyDistributor;
	private extensionConfig: MultiAuthExtensionConfig;
	private readonly cascadeStateManager: CascadeStateManager;
	private readonly healthScorer: HealthScorer;
	private readonly oauthRefreshScheduler: OAuthRefreshScheduler;
	private readonly runtimeOptions: Readonly<Required<AccountManagerRuntimeOptions>>;
	private readonly configPath: string;
	private readonly oauthRefreshInFlight = new Map<string, Promise<StoredOAuthCredential>>();
	private readonly processLeaseOwnerId: string;
	private readonly lightweightRotationState: LightweightRotationState;
	private readonly authWriter: AuthWriter;
	private readonly storage: MultiAuthStorage;
	private readonly usageService: UsageService;
	private readonly usageCoordinator: UsageCoordinator;
	private readonly providerRegistry: ProviderRegistry;
	private readonly cloudflareIdentityLookupByCacheKey = new Map<
		string,
		Promise<CloudflareCredentialIdentity | null>
	>();
	private readonly backgroundUsageRefreshes = new Set<Promise<void>>();
	private readonly operationalUsageWarmupCursors = new Map<SupportedProviderId, number>();
	private readonly operationalUsageWarmupTimers = new Map<SupportedProviderId, ReturnType<typeof setTimeout>>();
	private readonly backgroundCredentialExclusionIdsByProvider = new Map<SupportedProviderId, ReadonlySet<string>>();
	private rotationModeMigrationPromise: Promise<void> | null = null;
	private initializationPromise: Promise<void> | null = null;
	private shutdownPromise: Promise<void> | null = null;
	private isShuttingDown = false;

	constructor(
		authWriter: AuthWriter = new AuthWriter(),
		storage: MultiAuthStorage | undefined = undefined,
		usageService: UsageService = new UsageService(),
		providerRegistry: ProviderRegistry = new ProviderRegistry(authWriter),
		keyDistributor?: KeyDistributor,
		extensionConfig: MultiAuthExtensionConfig = DEFAULT_MULTI_AUTH_CONFIG,
		runtimeOptions: AccountManagerRuntimeOptions = {},
	) {
		this.authWriter = authWriter;
		this.extensionConfig = cloneMultiAuthExtensionConfig(extensionConfig);
		this.processLeaseOwnerId = createProcessLeaseOwnerId();
		this.configPath = runtimeOptions.configPath ?? CONFIG_PATH;
		this.storage = storage ?? new MultiAuthStorage();
		this.usageCoordinator = new UsageCoordinator(INTERNAL_USAGE_COORDINATION_CONFIG);
		this.usageService = usageService;
		this.usageService.setUsageCoordinator(this.usageCoordinator);
		this.providerRegistry = providerRegistry;
		this.lightweightRotationState = new LightweightRotationState(this.storage);
		this.runtimeOptions = {
			startOAuthRefreshScheduler: runtimeOptions.startOAuthRefreshScheduler !== false,
			configPath: this.configPath,
		};
		this.cascadeStateManager = new CascadeStateManager(INTERNAL_CASCADE_CONFIG);
		this.healthScorer = new HealthScorer(INTERNAL_HEALTH_CONFIG);
		const globalKeyDistributor = getGlobalKeyDistributor();
		this.keyDistributor =
			keyDistributor ??
			globalKeyDistributor ??
			new KeyDistributor(this.storage, this.authWriter);
		registerGlobalKeyDistributor(this.keyDistributor);
		this.keyDistributor.setProviderCapabilitiesResolver((providerId) =>
			this.providerRegistry.getProviderCapabilities(providerId),
		);
		this.keyDistributor.setLightweightRotationState(this.lightweightRotationState);
		this.keyDistributor.setModelEligibilityResolver((providerId, credentialIds, modelId, signal) =>
			this.resolveCredentialModelEligibility(providerId, credentialIds, modelId, undefined, signal),
		);
		this.keyDistributor.setCredentialSelectionValidator((providerId, credentialId, _context, signal) =>
			this.validateDelegatedCredentialSelection(providerId, credentialId, signal),
		);
		this.keyDistributor.setUsageSnapshotProvider((providerId, credentialIds, signal) =>
			this.getBalancerUsageSnapshots(providerId, credentialIds, signal),
		);
		this.oauthRefreshScheduler = new OAuthRefreshScheduler(
			async (credentialId, providerId) => this.refreshScheduledOAuthCredential(providerId, credentialId),
			INTERNAL_OAUTH_REFRESH_CONFIG,
		);
		if (this.runtimeOptions.startOAuthRefreshScheduler) {
			this.oauthRefreshScheduler.start();
		}
	}

	/**
	 * Returns the shared key distributor used for credential balancing.
	 */
	public getKeyDistributor(): KeyDistributor {
		return this.keyDistributor;
	}

	/**
	 * Returns the shared provider registry used for discovery and registration.
	 */
	public getProviderRegistry(): ProviderRegistry {
		return this.providerRegistry;
	}

	private isOAuthRefreshManagedForProvider(provider: SupportedProviderId): boolean {
		return (
			INTERNAL_OAUTH_REFRESH_CONFIG.enabled &&
			!INTERNAL_OAUTH_REFRESH_CONFIG.excludedProviders.includes(provider)
		);
	}

	private assertOAuthRefreshManagedForProvider(provider: SupportedProviderId): void {
		if (this.isOAuthRefreshManagedForProvider(provider)) {
			return;
		}
		if (!INTERNAL_OAUTH_REFRESH_CONFIG.enabled) {
			throw new Error("OAuth token refresh is disabled internally.");
		}
		throw new Error(`OAuth token refresh is internally disabled for provider ${provider}.`);
	}

	private updateBackgroundCredentialExclusionCache(
		provider: SupportedProviderId,
		state: ProviderRotationState,
	): void {
		const excludedCredentialIds = getCredentialBackgroundExclusionIds(state);
		if (excludedCredentialIds.size === 0) {
			this.backgroundCredentialExclusionIdsByProvider.delete(provider);
			return;
		}
		this.backgroundCredentialExclusionIdsByProvider.set(provider, excludedCredentialIds);
	}

	private isCredentialCachedBackgroundExcluded(
		provider: SupportedProviderId,
		credentialId: string,
	): boolean {
		return this.backgroundCredentialExclusionIdsByProvider.get(provider)?.has(credentialId) ?? false;
	}

	private async getCredentialBackgroundExclusion(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<CredentialBackgroundExclusionState | undefined> {
		if (!this.isCredentialCachedBackgroundExcluded(provider, credentialId)) {
			return undefined;
		}
		const state = await this.storage.readProviderState(provider);
		this.updateBackgroundCredentialExclusionCache(provider, state);
		return state.backgroundCredentialExclusions?.[credentialId];
	}

	private shouldSkipOAuthRefreshForMissingRefreshToken(
		provider: SupportedProviderId,
		credential: StoredOAuthCredential,
	): boolean {
		return provider === OPENAI_CODEX_PROVIDER_ID && !hasOAuthRefreshToken(credential);
	}

	async shutdown(): Promise<void> {
		if (this.shutdownPromise) {
			return this.shutdownPromise;
		}

		this.isShuttingDown = true;
		this.clearOperationalUsageWarmupTimers();
		this.oauthRefreshScheduler.stop();
		this.lightweightRotationState.shutdown();
		this.shutdownPromise = (async () => {
			await this.releaseProcessCredentialLeases();
			await this.drainBackgroundUsageRefreshes();
		})();
		return this.shutdownPromise;
	}

	private usesProcessCredentialLeases(rotationMode: RotationMode): boolean {
		return rotationMode === "usage-based";
	}

	private async commitProcessCredentialLease(
		provider: SupportedProviderId,
		credentialId: string,
		effectiveExcludedCredentialIds: ReadonlySet<string>,
	): Promise<CredentialSelectionCommitResult> {
		return this.storage.withLock<CredentialSelectionCommitResult>((stored) => {
			const providerState = getProviderState(stored, provider);
			const now = Date.now();
			let sharedLeaseFallback = false;
			pruneProviderCredentialLeases(providerState, now);
			const leasedByOtherOwners = getCredentialIdsLeasedByOtherOwners(
				providerState,
				this.processLeaseOwnerId,
				now,
			);
			const storedAvailable = buildAvailableSet(
				providerState,
				now,
				new Set(effectiveExcludedCredentialIds),
			);
			if (!storedAvailable.has(credentialId)) {
				return { result: { committed: false as const, sharedLeaseFallback: false } };
			}
			const selectedLeasedByOtherOwner = leasedByOtherOwners.has(credentialId);
			if (selectedLeasedByOtherOwner) {
				const hasUnleasedAlternative = [...storedAvailable].some(
					(candidateCredentialId) =>
						candidateCredentialId !== credentialId &&
						!leasedByOtherOwners.has(candidateCredentialId),
				);
				if (hasUnleasedAlternative) {
					return { result: { committed: false as const, sharedLeaseFallback: false } };
				}
				sharedLeaseFallback = true;
			}

			const currentLease = providerState.credentialLeases?.[this.processLeaseOwnerId];
			const nextLease = buildCredentialLease(this.processLeaseOwnerId, credentialId, now);
			providerState.credentialLeases = providerState.credentialLeases ?? {};
			providerState.credentialLeases[this.processLeaseOwnerId] = {
				...nextLease,
				acquiredAt:
					currentLease?.credentialId === credentialId &&
					typeof currentLease.acquiredAt === "number" &&
					Number.isFinite(currentLease.acquiredAt)
						? currentLease.acquiredAt
						: nextLease.acquiredAt,
			};
			return { result: { committed: true as const, sharedLeaseFallback }, next: stored };
		});
	}

	private async releaseProcessCredentialLeases(): Promise<void> {
		await this.storage.withLock((state) => {
			let didChange = false;
			const now = Date.now();
			for (const providerState of Object.values(state.providers)) {
				didChange = pruneProviderCredentialLeases(
					providerState,
					now,
					this.processLeaseOwnerId,
				) || didChange;
			}
			return didChange ? { result: undefined, next: state } : { result: undefined };
		});
	}

	/**
	 * Refreshes extension configuration on reload.
	 * Updates internal config and propagates changes to stateful components.
	 */
	refreshExtensionConfig(config: MultiAuthExtensionConfig): void {
		this.extensionConfig = cloneMultiAuthExtensionConfig(config);
	}

	/**
	 * Returns the dynamically discovered list of provider IDs.
	 */
	async getSupportedProviders(): Promise<readonly SupportedProviderId[]> {
		await this.ensureInitialized();
		return this.providerRegistry.discoverProviderIds();
	}

	/**
	 * Returns the normalized credential IDs currently associated with one provider.
	 */
	async listProviderCredentialIds(provider: SupportedProviderId): Promise<readonly string[]> {
		const state = await this.syncProviderState(provider);
		return [...state.credentialIds];
	}
	/**
	 * Returns whether another credential is actually selectable for the same request.
	 * This mirrors acquisition filters without committing rotation state, so transient
	 * failures do not exclude the only model-eligible credential and hard-stop.
	 */
	async hasUsableAlternateCredential(
		provider: SupportedProviderId,
		options: {
			currentCredentialId: string;
			excludedCredentialIds?: ReadonlySet<string>;
			modelId?: string;
			selectionCache?: CredentialSelectionCache;
			signal?: AbortSignal;
		},
	): Promise<boolean> {
		throwIfAborted(options.signal, `Alternate credential availability check aborted for ${provider}.`);
		const state = await raceWithSignal(
			this.syncProviderState(provider),
			options.signal,
			`Alternate credential availability check aborted for ${provider}.`,
		);
		if (state.credentialIds.length === 0) {
			return false;
		}

		const effectiveExcludedCredentialIds = new Set(options.excludedCredentialIds ?? []);
		effectiveExcludedCredentialIds.add(options.currentCredentialId);
		const disabledCredentialIds = await this.getDisabledCredentialIds(state);
		for (const disabledCredentialId of disabledCredentialIds) {
			effectiveExcludedCredentialIds.add(disabledCredentialId);
		}
		for (const blockedCredentialId of this.cascadeStateManager.getBlockedCredentialIds(provider)) {
			effectiveExcludedCredentialIds.add(blockedCredentialId);
		}

		const requestedModelId = normalizeModelId(options.modelId, provider) ?? undefined;
		if (requestedModelId) {
			const now = Date.now();
			for (const credentialId of state.credentialIds) {
				if (getModelIncompatibility(state, provider, credentialId, requestedModelId, now)) {
					effectiveExcludedCredentialIds.add(credentialId);
				}
			}
		}

		const candidateCredentialIds = state.credentialIds.filter(
			(credentialId) => !effectiveExcludedCredentialIds.has(credentialId),
		);
		if (candidateCredentialIds.length === 0) {
			return false;
		}

		const selectionCache = options.selectionCache ?? createCredentialSelectionCache();
		const usageContext = this.createCredentialUsageContext(
			candidateCredentialIds,
			selectionCache,
			options.signal,
		);
		const modelEligibility = await this.resolveCredentialModelEligibility(
			provider,
			candidateCredentialIds,
			requestedModelId,
			usageContext,
			options.signal,
		);
		for (const ineligibleCredentialId of modelEligibility.ineligibleCredentialIds) {
			effectiveExcludedCredentialIds.add(ineligibleCredentialId);
		}

		return buildAvailableSet(state, Date.now(), effectiveExcludedCredentialIds).size > 0;
	}

	/**
	 * Returns capability flags for one provider.
	 */
	getProviderCapabilities(provider: SupportedProviderId): ProviderCapabilities {
		return this.providerRegistry.getProviderCapabilities(provider);
	}

	/**
	 * Indicates whether a provider has a usage/quota API integration.
	 */
	hasUsageProvider(provider: SupportedProviderId): boolean {
		return this.usageService.hasProvider(provider);
	}

	/**
	 * Drops cached usage snapshots for one credential so the next read refetches
	 * fresh data (used after credential-scoped config changes such as the
	 * cookie-based OpenCode Go quota lookup).
	 */
	clearCredentialUsageCache(provider: SupportedProviderId, credentialId: string): void {
		this.usageService.clearCredential(provider, credentialId);
	}

	/**
	 * Reads the cookie-based OpenCode Go quota config stored on a credential.
	 */
	async getOpenCodeGoQuotaConfig(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<OpenCodeGoQuotaConfig | undefined> {
		const credential = await this.authWriter.getCredential(credentialId);
		return credential?.opencodeGo;
	}

	/**
	 * Persists the cookie-based OpenCode Go quota lookup config on a credential
	 * and clears that credential's usage cache so the next read uses the new
	 * workspace id + cookie. Pass empty values to clear.
	 */
	async setOpenCodeGoQuotaConfig(
		provider: SupportedProviderId,
		credentialId: string,
		workspaceId: string,
		cookie: string,
	): Promise<OpenCodeGoQuotaConfig | null> {
		const trimmedWorkspaceId = workspaceId.trim();
		const trimmedCookie = cookie.trim();
		const config =
			trimmedWorkspaceId && trimmedCookie
				? { workspaceId: trimmedWorkspaceId, cookie: trimmedCookie }
				: null;
		await this.authWriter.setOpenCodeGoQuotaConfig(credentialId, config);
		this.clearCredentialUsageCache(provider, credentialId);
		return config ? { ...config } : null;
	}

	async flushLightweightRotationState(provider?: SupportedProviderId): Promise<void> {
		if (provider) {
			await this.lightweightRotationState.flushProvider(provider);
			return;
		}
		await this.lightweightRotationState.flushAll();
	}

	/**
	 * Returns API-key providers available from pi-mono parity, models.json, and auth.json.
	 */
	async getAvailableApiKeyProviders(): Promise<readonly AvailableApiKeyProvider[]> {
		return this.providerRegistry.listAvailableApiKeyProviders();
	}

	/**
	 * Returns OAuth providers currently available from the runtime registry.
	 */
	getAvailableOAuthProviders(): readonly AvailableOAuthProvider[] {
		return this.providerRegistry.listAvailableOAuthProviders();
	}

	/**
	 * Returns the multi-auth storage path.
	 */
	getStoragePath(): string {
		return this.storage.getPath();
	}

	private isLightweightRotationProvider(provider: SupportedProviderId): boolean {
		return this.getProviderCapabilities(provider).rotationProfile === "lightweight";
	}

	private applyLightweightRotationState(
		provider: SupportedProviderId,
		state: ProviderRotationState,
	): ProviderRotationState {
		if (!this.isLightweightRotationProvider(provider)) {
			return state;
		}
		return this.lightweightRotationState.applyToProviderState(provider, state);
	}

	private async flushLightweightRotationStateIfNeeded(
		provider: SupportedProviderId,
	): Promise<void> {
		if (!this.isLightweightRotationProvider(provider)) {
			return;
		}
		await this.lightweightRotationState.flushProvider(provider);
	}

	private recordLightweightSelection(
		provider: SupportedProviderId,
		state: ProviderRotationState,
		credentialId: string,
		selectedIndex: number,
		nextActiveIndex: number,
		selectedAt: number,
		poolState?: ProviderPoolState,
		incrementUsage: boolean = true,
	): void {
		if (!this.isLightweightRotationProvider(provider)) {
			return;
		}
		this.lightweightRotationState.recordSelection({
			providerId: provider,
			credentialIds: state.credentialIds,
			credentialId,
			selectedIndex,
			nextActiveIndex,
			selectedAt,
			poolState,
			incrementUsage,
		});
	}

	private recordLightweightTelemetry(provider: SupportedProviderId, credentialIds: readonly string[]): void {
		if (!this.isLightweightRotationProvider(provider)) {
			return;
		}
		this.lightweightRotationState.recordTelemetry({
			providerId: provider,
			credentialIds,
			cascadeState: {
				[provider]: this.cascadeStateManager.getProviderState(provider),
			},
			healthState: this.healthScorer.exportState(credentialIds),
		});
	}

	private async migrateLegacyRotationModesToConfig(
		providers: readonly SupportedProviderId[],
	): Promise<void> {
		if (this.rotationModeMigrationPromise) {
			return this.rotationModeMigrationPromise;
		}

		this.rotationModeMigrationPromise = (async () => {
			const state = await this.storage.read();
			for (const provider of providers) {
				if (this.extensionConfig.rotationModes[provider]) {
					continue;
				}
				const legacyRotationMode = state.providers[provider]?.rotationMode;
				if (!legacyRotationMode || legacyRotationMode === resolveDefaultRotationMode(provider)) {
					continue;
				}
				const rotationModes = writeMultiAuthProviderRotationMode(
					provider,
					legacyRotationMode,
					this.configPath,
				);
				this.extensionConfig = {
					...this.extensionConfig,
					rotationModes,
				};
			}
		})();

		return this.rotationModeMigrationPromise;
	}

	private resolveProviderRotationMode(
		provider: SupportedProviderId,
		legacyRotationMode?: RotationMode,
	): RotationMode {
		return (
			this.extensionConfig.rotationModes[provider] ??
			legacyRotationMode ??
			resolveDefaultRotationMode(provider)
		);
	}

	private applyEffectiveProviderRotationMode(
		provider: SupportedProviderId,
		state: ProviderRotationState,
		legacyRotationMode: RotationMode = state.rotationMode,
	): ProviderRotationState {
		state.rotationMode = this.resolveProviderRotationMode(provider, legacyRotationMode);
		return state;
	}

	/**
	 * Returns providers hidden from the /multi-auth modal and runtime work.
	 */
	async getHiddenProviders(): Promise<SupportedProviderId[]> {
		return [...this.extensionConfig.hiddenProviders];
	}

	private async readHiddenProviderSet(): Promise<ReadonlySet<SupportedProviderId>> {
		return new Set(await this.getHiddenProviders());
	}

	private async isProviderHidden(provider: SupportedProviderId): Promise<boolean> {
		return (await this.readHiddenProviderSet()).has(provider);
	}

	private async cancelProviderOperationalWork(
		provider: SupportedProviderId,
		providerState?: ProviderRotationState,
	): Promise<void> {
		this.clearOperationalUsageWarmupTimer(provider);
		this.operationalUsageWarmupCursors.delete(provider);
		this.backgroundCredentialExclusionIdsByProvider.delete(provider);
		const state = providerState ?? await this.storage.readProviderState(provider);
		for (const credentialId of state.credentialIds) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
		}
		for (const credentialId of Object.keys(state.oauthRefreshScheduled ?? {})) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
		}
		this.usageService.clearProvider(provider);
		await this.persistOAuthRefreshSchedule(provider);
	}

	/**
	 * Hides or unhides a provider in the /multi-auth modal.
	 */
	async setProviderHidden(provider: SupportedProviderId, hidden: boolean): Promise<boolean> {
		const hiddenProviders = writeMultiAuthProviderHidden(provider, hidden, this.configPath);
		this.extensionConfig = {
			...this.extensionConfig,
			hiddenProviders,
		};

		const result = await this.storage.withLock((state) => ({
			result: {
				hidden: hiddenProviders.includes(provider),
				providerState: cloneProviderState(getProviderState(state, provider)),
			},
		}));

		if (result.hidden) {
			await this.cancelProviderOperationalWork(provider, result.providerState);
		} else if (this.initializationPromise) {
			await this.syncProviderState(provider);
		}

		return result.hidden;
	}

	/**
	 * Fetches usage/quota snapshot for one credential with provider-specific logic.
	 */
	async getCredentialUsageSnapshot(
		provider: SupportedProviderId,
		credentialId: string,
		options?: UsageFetchOptions,
	): Promise<CredentialUsageSnapshotResult> {
		return this.getCredentialUsageSnapshotWithContext(provider, credentialId, options);
	}

	getCachedCredentialUsageSnapshot(
		provider: SupportedProviderId,
		credentialId: string,
		options?: UsageFetchOptions,
	): CredentialUsageSnapshotResult | null {
		const cachedUsage = this.usageService.readCachedUsage(provider, credentialId, options);
		if (!cachedUsage) {
			return null;
		}
		return {
			snapshot: cachedUsage.snapshot,
			error: cachedUsage.error,
			fromCache: cachedUsage.fromCache,
		};
	}

	getCachedCredentialUsageDisplaySnapshot(
		provider: SupportedProviderId,
		credentialId: string,
	): CredentialUsageSnapshotResult | null {
		const operationalUsage = this.getCachedCredentialUsageSnapshot(provider, credentialId, {
			allowStale: true,
		});
		if (operationalUsage?.snapshot) {
			return operationalUsage;
		}

		const displayUsage = this.usageService.readDisplayUsage(provider, credentialId);
		if (displayUsage?.snapshot) {
			return {
				snapshot: displayUsage.snapshot,
				error: displayUsage.error,
				fromCache: displayUsage.fromCache,
				displayOnly: true,
			};
		}
		return operationalUsage ?? null;
	}

	/**
	 * Harvests rate-limit headers from existing provider response/error hooks.
	 * Normal streaming responses do not currently expose headers to this extension;
	 * this method is intentionally limited to hook points that already provide them.
	 */
	async harvestProviderRateLimitHeaders(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredAuthCredential,
		headers: Record<string, string>,
		status?: number,
	): Promise<void> {
		this.registerCurrentUsageCredentialCacheKey(provider, credentialId, credential);
		const credentialCacheKey = this.computeCurrentUsageCredentialCacheKey(provider, credentialId, credential);
		const harvested = this.usageService.harvestRateLimitHeaders(
			provider,
			credentialId,
			credentialCacheKey,
			headers,
		);
		if (!harvested?.snapshot) {
			return;
		}
		multiAuthDebugLogger.log("provider_rate_limit_headers_harvested", {
			provider,
			credentialRef: redactUsageCredentialIdentifier(credentialId),
			status,
			hasResetAt: harvested.snapshot.rateLimitHeaders?.resetAt !== null,
			hasRemaining: harvested.snapshot.rateLimitHeaders?.remaining !== null,
		});
		if (status === 429) {
			try {
				await this.reconcileQuotaStateFromUsage(provider, credentialId, harvested.snapshot);
			} catch (error: unknown) {
				multiAuthDebugLogger.log("provider_rate_limit_header_reconcile_failed", {
					provider,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
					message: getErrorMessage(error),
				});
			}
		}
	}

	private readCachedOperationalUsageForSelection(
		provider: SupportedProviderId,
		credentialId: string,
	): CachedUsageSelectionRead {
		const freshUsage = this.getCachedCredentialUsageSnapshot(provider, credentialId, {
			maxAgeMs: getSelectionUsageMaxAgeMs(provider),
		});
		if (freshUsage) {
			return {
				usage: freshUsage,
				needsRefresh: false,
				hasDurableEvidence: true,
			};
		}

		const durableUsage = this.getCachedCredentialUsageSnapshot(provider, credentialId, {
			allowStale: true,
		});
		return {
			usage: durableUsage,
			needsRefresh: true,
			hasDurableEvidence: durableUsage !== null,
		};
	}

	private trackBackgroundUsageRefresh(request: Promise<void>): void {
		let trackedRequest!: Promise<void>;
		trackedRequest = request.finally(() => {
			this.backgroundUsageRefreshes.delete(trackedRequest);
		});
		this.backgroundUsageRefreshes.add(trackedRequest);
		void trackedRequest;
	}

	private async drainBackgroundUsageRefreshes(): Promise<void> {
		while (this.backgroundUsageRefreshes.size > 0) {
			await Promise.allSettled([...this.backgroundUsageRefreshes]);
		}
	}

	private clearOperationalUsageWarmupTimer(provider: SupportedProviderId): void {
		const timer = this.operationalUsageWarmupTimers.get(provider);
		if (timer) {
			clearTimeout(timer);
			this.operationalUsageWarmupTimers.delete(provider);
		}
	}

	private clearOperationalUsageWarmupTimers(): void {
		for (const timer of this.operationalUsageWarmupTimers.values()) {
			clearTimeout(timer);
		}
		this.operationalUsageWarmupTimers.clear();
	}

	private enqueueCredentialUsageRefresh(
		provider: SupportedProviderId,
		credentialIds: readonly string[],
		operation: UsageCoordinationOperation,
		options: BackgroundUsageRefreshOptions = {},
	): number {
		if (this.isShuttingDown) {
			return 0;
		}

		const uniqueCredentialIds = [...new Set(credentialIds.map((credentialId) => credentialId.trim()).filter(Boolean))];
		if (uniqueCredentialIds.length === 0) {
			return 0;
		}

		const selectedCredentialIds = this.usageCoordinator.selectCredentialIds(uniqueCredentialIds, operation);
		return this.queueCredentialUsageRefresh(provider, selectedCredentialIds, operation, options);
	}

	private enqueueAllCredentialUsageRefresh(
		provider: SupportedProviderId,
		credentialIds: readonly string[],
		operation: UsageCoordinationOperation,
		options: BackgroundUsageRefreshOptions = {},
	): number {
		if (this.isShuttingDown) {
			return 0;
		}

		const uniqueCredentialIds = [...new Set(credentialIds.map((credentialId) => credentialId.trim()).filter(Boolean))];
		if (uniqueCredentialIds.length === 0) {
			return 0;
		}

		const selectedCredentialIds = this.usageCoordinator
			.selectCredentialIdWindows(uniqueCredentialIds, operation)
			.flat();
		return this.queueCredentialUsageRefresh(provider, selectedCredentialIds, operation, options);
	}

	private queueCredentialUsageRefresh(
		provider: SupportedProviderId,
		credentialIds: readonly string[],
		operation: UsageCoordinationOperation,
		options: BackgroundUsageRefreshOptions,
	): number {
		const eligibleCredentialIds = credentialIds.filter(
			(credentialId) => !this.isCredentialCachedBackgroundExcluded(provider, credentialId),
		);
		if (eligibleCredentialIds.length === 0) {
			return 0;
		}

		const maxAgeMs = options.maxAgeMs ?? getSelectionUsageMaxAgeMs(provider);
		const forceRefresh = options.forceRefresh ?? true;
		for (const credentialId of eligibleCredentialIds) {
			const backgroundRequest = this.getCredentialUsageSnapshotWithContext(
				provider,
				credentialId,
				{
					forceRefresh,
					maxAgeMs,
					coordinationOperation: operation,
				},
			).then((usage) => {
				multiAuthDebugLogger.log("usage_background_refresh_completed", {
					provider,
					operation,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
					hasSnapshot: usage.snapshot !== null,
					hasError: Boolean(usage.error),
					usageError: usage.error ?? undefined,
				});
			}).catch((error: unknown) => {
				multiAuthDebugLogger.log("usage_background_refresh_failed", {
					provider,
					operation,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
					message: getErrorMessage(error),
				});
			});
			this.trackBackgroundUsageRefresh(backgroundRequest);
		}
		return eligibleCredentialIds.length;
	}

	selectUsageRefreshCandidates<TRequest extends { provider: SupportedProviderId; credentialId: string }>(
		requests: readonly TRequest[],
		operation: UsageCoordinationOperation,
	): TRequest[] {
		return this.usageCoordinator.selectCredentialRequests(requests, operation);
	}

	selectUsageRefreshCandidateWindows<TRequest extends { provider: SupportedProviderId; credentialId: string }>(
		requests: readonly TRequest[],
		operation: UsageCoordinationOperation,
	): TRequest[][] {
		return this.usageCoordinator.selectCredentialRequestWindows(requests, operation);
	}

	private computeCurrentUsageCredentialCacheKey(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredAuthCredential,
	): string {
		const accountId =
			credential.type === "oauth" && typeof credential.accountId === "string" && credential.accountId.trim().length > 0
				? credential.accountId
				: undefined;
		return createUsageCredentialCacheKey(provider, credentialId, {
			accessToken: getCredentialRequestSecret(provider, credential).trim(),
			accountId,
			credential: { ...credential },
		});
	}

	private registerCurrentUsageCredentialCacheKey(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredAuthCredential,
	): void {
		this.usageService.setPreferredCredentialCacheKey(
			provider,
			credentialId,
			this.computeCurrentUsageCredentialCacheKey(provider, credentialId, credential),
		);
	}

	private syncCurrentUsageCredentialCacheKeys(
		provider: SupportedProviderId,
		credentialEntries: readonly AuthCredentialEntry[],
		validCredentialIds: ReadonlySet<string>,
	): void {
		for (const entry of credentialEntries) {
			if (!validCredentialIds.has(entry.credentialId)) {
				this.usageService.setPreferredCredentialCacheKey(provider, entry.credentialId, null);
				continue;
			}
			this.registerCurrentUsageCredentialCacheKey(provider, entry.credentialId, entry.credential);
		}
	}

	private createCredentialUsageContext(
		credentialIds: readonly string[],
		selectionCache: CredentialSelectionCache,
		signal?: AbortSignal,
	): CredentialUsageContext {
		return {
			credentialIds,
			selectionCache,
			signal,
		};
	}

	private async getCredentialUsageSnapshotWithContext(
		provider: SupportedProviderId,
		credentialId: string,
		options?: UsageFetchOptions,
		context?: CredentialUsageContext,
	): Promise<CredentialUsageSnapshotResult> {
		const usageRequestCacheKey = getUsageRequestCacheKey(provider, credentialId, options);
		const existingUsageRequest = context?.selectionCache.usageByRequest.get(usageRequestCacheKey);
		if (existingUsageRequest) {
			return existingUsageRequest;
		}

		const usageRequest = this.loadCredentialUsageSnapshot(provider, credentialId, options, context);
		if (!context) {
			return usageRequest;
		}

		context.selectionCache.usageByRequest.set(usageRequestCacheKey, usageRequest);
		return usageRequest;
	}

	private async resolveCredentialForUsage(
		credentialId: string,
		context?: CredentialUsageContext,
	): Promise<StoredAuthCredential | undefined> {
		if (!context) {
			return this.authWriter.getCredential(credentialId);
		}

		context.credentialsByIdPromise ??= this.authWriter.getCredentials(context.credentialIds);
		const credentialsById = await context.credentialsByIdPromise;
		const cachedCredential = credentialsById.get(credentialId);
		if (cachedCredential) {
			return cachedCredential;
		}

		const credential = await this.authWriter.getCredential(credentialId);
		if (credential) {
			credentialsById.set(credentialId, credential);
		}
		return credential;
	}

	private async loadCredentialUsageSnapshot(
		provider: SupportedProviderId,
		credentialId: string,
		options?: UsageFetchOptions,
		context?: CredentialUsageContext,
	): Promise<CredentialUsageSnapshotResult> {
		const cachedUsage = this.usageService.readCachedUsage(provider, credentialId, options);
		if (cachedUsage) {
			return {
				snapshot: cachedUsage.snapshot,
				error: cachedUsage.error,
				fromCache: cachedUsage.fromCache,
			};
		}

		if (await this.isProviderHidden(provider)) {
			const fallbackUsage = this.getCachedCredentialUsageDisplaySnapshot(provider, credentialId);
			return {
				snapshot: fallbackUsage?.snapshot ?? null,
				error: fallbackUsage?.error ?? `Usage lookup skipped because provider ${provider} is hidden.`,
				fromCache: fallbackUsage?.fromCache ?? false,
				displayOnly: fallbackUsage?.displayOnly,
			};
		}

		const backgroundExclusion = await this.getCredentialBackgroundExclusion(provider, credentialId);
		if (backgroundExclusion) {
			return {
				snapshot: null,
				error: formatCredentialBackgroundExclusionMessage(backgroundExclusion),
				fromCache: false,
				displayOnly: true,
			};
		}

		const credential = await raceWithSignal(
			this.resolveCredentialForUsage(credentialId, context),
			context?.signal,
			`Credential usage lookup aborted for ${provider}/${credentialId}.`,
		);
		if (!credential) {
			this.usageService.setPreferredCredentialCacheKey(provider, credentialId, null);
			return {
				snapshot: null,
				error: `Usage unavailable (credential ${credentialId} is missing)`,
				fromCache: false,
			};
		}
		let freshCredential: StoredAuthCredential = credential;
		if (credential.type === "oauth") {
			try {
				freshCredential = await this.refreshIfNeeded(
					provider,
					credentialId,
					credential,
					context?.signal,
				);
			} catch (error: unknown) {
				if (error instanceof Error && error.name === "AbortError") {
					throw error;
				}
				const message = getErrorMessage(error);
				return {
					snapshot: null,
					error: `Usage unavailable (token refresh failed: ${message})`,
					fromCache: false,
				};
			}
		}

		if (context) {
			context.credentialsByIdPromise ??= this.authWriter.getCredentials(context.credentialIds);
			const credentialsById = await context.credentialsByIdPromise;
			credentialsById.set(credentialId, freshCredential);
		}

		const accountId =
			freshCredential.type === "oauth" &&
			typeof freshCredential.accountId === "string" &&
			freshCredential.accountId.trim().length > 0
				? freshCredential.accountId
				: undefined;

		this.registerCurrentUsageCredentialCacheKey(provider, credentialId, freshCredential);
		const hintedCachedUsage = this.usageService.readCachedUsage(provider, credentialId, options);
		if (hintedCachedUsage) {
			return {
				snapshot: hintedCachedUsage.snapshot,
				error: hintedCachedUsage.error,
				fromCache: hintedCachedUsage.fromCache,
			};
		}

		let usage: UsageFetchResult;
		try {
			usage = await raceWithSignal(
				this.usageService.fetchUsage(
					provider,
					credentialId,
					{
						accessToken: getCredentialSecret(freshCredential),
						accountId,
						credential: { ...freshCredential },
					},
					options,
				),
				context?.signal ?? options?.signal,
				`Usage fetch aborted for ${provider}/${credentialId}.`,
			);
		} catch (error: unknown) {
			if (!isUsageRequestDeferredError(error)) {
				throw error;
			}

			const fallbackUsage = this.getCachedCredentialUsageDisplaySnapshot(provider, credentialId);
			const deferredNote = formatUsageRequestDeferredNote(error);
			multiAuthDebugLogger.log("credential_usage_refresh_deferred", {
				provider,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				reason: error.reason,
				retryAt: error.retryAt,
				hasFallbackSnapshot: Boolean(fallbackUsage?.snapshot),
			});
			if (fallbackUsage?.snapshot) {
				return {
					snapshot: fallbackUsage.snapshot,
					error: deferredNote,
					fromCache: true,
					displayOnly: fallbackUsage.displayOnly,
				};
			}
			return {
				snapshot: null,
				error: deferredNote,
				fromCache: false,
			};
		}
		// codex-lb parity: on auth error during usage fetch, force-refresh token and retry once
		if (usage.error && usage.error.length > 0 && freshCredential.type === "oauth") {
			const isAuthLikeUsageError =
				/\b401\b|\b403\b|expired|invalid|denied|missing required usage scope|token|unauthorized/i.test(
					usage.error,
				);
			if (isAuthLikeUsageError && !options?.signal?.aborted) {
				multiAuthDebugLogger.log("usage_fetch_auth_error_force_refresh", {
					provider,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
					message: usage.error,
				});
				try {
					const forceRefreshed = await this.refreshCredentialToken(
						provider,
						credentialId,
						freshCredential,
						context?.signal ?? options?.signal,
					);
					this.registerCurrentUsageCredentialCacheKey(
						provider,
						credentialId,
						forceRefreshed,
					);
					const forcedUsage = await raceWithSignal(
						this.usageService.fetchUsage(
							provider,
							credentialId,
							{
								accessToken: getCredentialSecret(forceRefreshed),
								accountId:
									forceRefreshed.type === "oauth" &&
									typeof forceRefreshed.accountId === "string" &&
									forceRefreshed.accountId.trim().length > 0
										? forceRefreshed.accountId
										: undefined,
								credential: { ...forceRefreshed },
							},
							options,
						),
						context?.signal ?? options?.signal,
						`Usage fetch retry aborted for ${provider}/${credentialId}.`,
					);
					if (context) {
						context.credentialsByIdPromise ??= this.authWriter.getCredentials(
							context.credentialIds,
						);
						const credentialsById = await context.credentialsByIdPromise;
						credentialsById.set(credentialId, forceRefreshed);
					}
					if (!forcedUsage.fromCache) {
						await this.reconcileQuotaStateFromUsage(
							provider,
							credentialId,
							forcedUsage.snapshot,
						);
					}
					return {
						snapshot: forcedUsage.snapshot,
						error: forcedUsage.error,
						fromCache: forcedUsage.fromCache,
					};
				} catch (retryError: unknown) {
					if (retryError instanceof Error && retryError.name === "AbortError") {
						throw retryError;
					}
					multiAuthDebugLogger.log("usage_fetch_auth_retry_failed", {
						provider,
						credentialRef: redactUsageCredentialIdentifier(credentialId),
						message: getErrorMessage(retryError),
					});
					// Fall through to original error handling
				}
			}
		}

		if (isCodexUsageAuthenticationFailure(provider, usage)) {
			const usageError = usage.error;
			try {
				await this.disableCredential(provider, credentialId, usageError, "authentication");
				multiAuthDebugLogger.log("codex_usage_auth_failure_disabled_credential", {
					provider,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
				});
			} catch (error: unknown) {
				multiAuthDebugLogger.log("codex_usage_auth_failure_disable_failed", {
					provider,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
					message: getErrorMessage(error),
				});
			}
		} else if (!usage.fromCache) {
			await this.reconcileQuotaStateFromUsage(provider, credentialId, usage.snapshot);
		}
		return {
			snapshot: usage.snapshot,
			error: usage.error,
			fromCache: usage.fromCache,
		};
	}

	private async addCredentialUsageUnits(
		provider: SupportedProviderId,
		credentialId: string,
		usageUnits: number,
	): Promise<void> {
		if (!Number.isFinite(usageUnits) || usageUnits <= 0) {
			return;
		}
		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: undefined };
			}
			providerState.usageCount[credentialId] =
				(providerState.usageCount[credentialId] ?? 0) + usageUnits;
			return { result: undefined, next: state };
		});
	}

	async recordCredentialSuccess(
		provider: SupportedProviderId,
		credentialId: string,
		latencyMs: number,
		modelId?: string,
		tokenEstimate?: number,
	): Promise<void> {
		await this.ensureInitialized();
		const usageUnits = normalizeCredentialUsageUnits(tokenEstimate);
		const supplementalUsageUnits = usageUnits - 1;
		if (supplementalUsageUnits > 0) {
			await this.addCredentialUsageUnits(provider, credentialId, supplementalUsageUnits);
		}
		if (
			provider === OPENAI_CODEX_PROVIDER_ID &&
			shouldInvalidateCodexUsageCacheAfterSuccess(tokenEstimate)
		) {
			this.usageService.clearOperationalCredential(provider, credentialId);
		}
		this.healthScorer.recordSuccess(credentialId, latencyMs);
		this.healthScorer.endCooldown(credentialId);
		this.healthScorer.calculateScore(credentialId);
		this.cascadeStateManager.clearCascade(provider);
		await this.clearTransientProviderError(provider, credentialId);
		await this.clearQuotaExceeded(provider, credentialId);
		if (modelId) {
			await this.clearCredentialModelIncompatibility(provider, credentialId, modelId);
		}
		await this.clearActiveFailoverChains();
		await this.persistProviderTelemetry(provider);
	}

	async recordCredentialFailure(
		provider: SupportedProviderId,
		credentialId: string,
		latencyMs: number,
		errorKind: CredentialErrorKind,
		errorMessage: string,
	): Promise<void> {
		await this.ensureInitialized();
		this.healthScorer.recordFailure(credentialId, latencyMs, errorKind);
		this.healthScorer.recordCooldown(credentialId, errorMessage);
		this.healthScorer.calculateScore(credentialId);
		if (this.cascadeStateManager.hasActiveCascade(provider)) {
			this.cascadeStateManager.recordCascadeAttempt(provider, credentialId, errorKind, errorMessage);
		} else {
			this.cascadeStateManager.createCascade(provider, credentialId, errorKind, errorMessage);
		}
		await this.persistProviderTelemetry(provider);
	}

	/**
	 * Sets or clears a friendly display name for a credential.
	 */
	async setFriendlyName(
		provider: SupportedProviderId,
		credentialId: string,
		friendlyName: string,
	): Promise<string> {
		return this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			normalizeProviderState(providerState, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				throw new Error(`Credential ${credentialId} is not available for provider ${provider}`);
			}

			const normalized = friendlyName.trim();
			if (!normalized || normalized === credentialId) {
				delete providerState.friendlyNames[credentialId];
				return { result: credentialId, next: state };
			}

			providerState.friendlyNames[credentialId] = normalized;
			return { result: normalized, next: state };
		});
	}

	/**
	 * Runs OAuth login for a provider and stores credentials in primary/backup slots.
	 */
	async loginProvider(
		provider: SupportedProviderId,
		callbacks: OAuthLoginCallbacks,
	): Promise<{ credentialId: string; isBackupCredential: boolean; credentialIds: string[] }> {
		if (isRemovedLegacyGoogleProvider(provider)) {
			throw new Error("Legacy Google OAuth providers are no longer supported.");
		}

		const oauthProvider = getOAuthProvider(provider);
		if (!oauthProvider) {
			throw new Error(`OAuth provider is not available: ${provider}`);
		}

		const credentials = await oauthProvider.login(callbacks);
		return this.storeOAuthCredential(provider, credentials);
	}

	/**
	 * Stores an externally imported OAuth credential in primary/backup slot order.
	 */
	async addOAuthCredential(
		provider: SupportedProviderId,
		credentials: OAuthCredentials,
		options: AddOAuthCredentialOptions = {},
	): Promise<BackupAndStoreResult> {
		if (isRemovedLegacyGoogleProvider(provider)) {
			throw new Error("Legacy Google OAuth providers are no longer supported.");
		}

		const oauthProvider = getOAuthProvider(provider);
		if (!oauthProvider) {
			throw new Error(`OAuth provider is not available: ${provider}`);
		}

		return this.storeOAuthCredential(provider, credentials, options);
	}

	private async storeOAuthCredential(
		provider: SupportedProviderId,
		credentials: OAuthCredentials,
		options: AddOAuthCredentialOptions = {},
	): Promise<BackupAndStoreResult> {
		const duplicateCredentialId = await this.findExistingOAuthCredentialIdByIdentity(
			provider,
			credentials,
		);
		if (duplicateCredentialId) {
			const existingCredential = await this.authWriter.getOAuthCredential(duplicateCredentialId);
			const credentialsToStore = resolveStoredOAuthCredentialForImport(
				existingCredential,
				credentials,
				options,
			);
			await this.authWriter.setOAuthCredential(duplicateCredentialId, credentialsToStore);
			const credentialIds = await this.authWriter.listProviderCredentialIds(provider);
			const storedCredential: StoredOAuthCredential = {
				type: "oauth",
				...credentialsToStore,
			};
			await this.persistCredentialList(provider, credentialIds, duplicateCredentialId, storedCredential);
			this.usageService.clearProvider(provider);
			if (provider === OPENAI_CODEX_PROVIDER_ID && hasOAuthRefreshToken(storedCredential)) {
				await this.restoreCodexCredentialAfterOAuthLogin(duplicateCredentialId);
			}
			return {
				credentialId: duplicateCredentialId,
				isBackupCredential: duplicateCredentialId !== provider,
				credentialIds: this.deduplicateCredentialEntries(
					provider,
					await this.authWriter.getProviderCredentialEntries(provider),
				),
				didAddCredential: false,
				duplicateOfCredentialId: duplicateCredentialId,
			};
		}

		const backupResult = await this.authWriter.setOAuthCredentialAsBackup(provider, credentials);
		const storedCredential: StoredOAuthCredential = {
			type: "oauth",
			...credentials,
		};
		await this.persistCredentialList(provider, backupResult.credentialIds, backupResult.credentialId, storedCredential);
		this.usageService.clearProvider(provider);

		return {
			...backupResult,
			didAddCredential: true,
		};
	}

	private async restoreCodexCredentialAfterOAuthLogin(credentialId: string): Promise<void> {
		const restored = await this.storage.withLock((state) => {
			const providerState = getProviderState(state, OPENAI_CODEX_PROVIDER_ID);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: false };
			}

			delete providerState.disabledCredentials[credentialId];
			delete providerState.quotaExhaustedUntil[credentialId];
			delete providerState.lastQuotaError[credentialId];
			delete providerState.quotaErrorCount[credentialId];
			delete providerState.weeklyQuotaAttempts?.[credentialId];
			delete providerState.quotaStates?.[credentialId];
			delete providerState.lastTransientError?.[credentialId];
			delete providerState.transientErrorCount?.[credentialId];
			delete providerState.backgroundCredentialExclusions?.[credentialId];
			delete providerState.modelIncompatibilities?.[credentialId];
			if (providerState.modelIncompatibilities && Object.keys(providerState.modelIncompatibilities).length === 0) {
				providerState.modelIncompatibilities = undefined;
			}
			if (providerState.quotaStates && Object.keys(providerState.quotaStates).length === 0) {
				providerState.quotaStates = undefined;
			}
			if (
				providerState.backgroundCredentialExclusions &&
				Object.keys(providerState.backgroundCredentialExclusions).length === 0
			) {
				providerState.backgroundCredentialExclusions = undefined;
			}
			normalizeProviderState(providerState, OPENAI_CODEX_PROVIDER_ID);
			return { result: true, next: state };
		});

		this.usageService.clearOperationalCredential(OPENAI_CODEX_PROVIDER_ID, credentialId);
		try {
			const usage = await this.getCredentialUsageSnapshot(OPENAI_CODEX_PROVIDER_ID, credentialId, {
				forceRefresh: true,
				coordinationOperation: "manual-account-refresh",
			});
			multiAuthDebugLogger.log("codex_oauth_resurrection_usage_refreshed", {
				provider: OPENAI_CODEX_PROVIDER_ID,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				restored,
				hasSnapshot: usage.snapshot !== null,
				hasError: Boolean(usage.error),
			});
		} catch (error: unknown) {
			multiAuthDebugLogger.log("codex_oauth_resurrection_usage_refresh_failed", {
				provider: OPENAI_CODEX_PROVIDER_ID,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				restored,
				message: getErrorMessage(error),
			});
		}
	}

	private readCachedCodexCredentialPlanType(credentialId: string): CodexPlanType | undefined {
		const cachedUsage =
			this.getCachedCredentialUsageSnapshot(OPENAI_CODEX_PROVIDER_ID, credentialId, {
				allowStale: true,
			}) ?? this.getCachedCredentialUsageDisplaySnapshot(OPENAI_CODEX_PROVIDER_ID, credentialId);
		return normalizeKnownCodexPlanType(cachedUsage?.snapshot?.planType);
	}

	private async resolveCodexLoginPlanType(
		credentialId: string,
		credentials: OAuthCredentials,
	): Promise<CodexPlanType | undefined> {
		const credential: StoredOAuthCredential = {
			type: "oauth",
			...credentials,
		};
		const identity = extractCodexCredentialIdentity(credentials);
		this.registerCurrentUsageCredentialCacheKey(OPENAI_CODEX_PROVIDER_ID, credentialId, credential);
		const usage = await this.usageService.fetchUsage(
			OPENAI_CODEX_PROVIDER_ID,
			credentialId,
			{
				accessToken: credentials.access,
				accountId: identity.accountId ?? undefined,
				credential: { ...credential },
			},
			{
				forceRefresh: true,
				coordinationOperation: "manual-account-refresh",
			},
		);
		if (usage.error) {
			multiAuthDebugLogger.log("codex_oauth_resurrection_plan_lookup_failed", {
				provider: OPENAI_CODEX_PROVIDER_ID,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				message: usage.error,
			});
		}
		return normalizeKnownCodexPlanType(usage.snapshot?.planType);
	}

	private async findCodexOAuthCredentialIdByIdentity(
		credentials: OAuthCredentials,
	): Promise<string | undefined> {
		const identityKey = buildCodexIdentityKey(credentials);
		if (!identityKey) {
			return undefined;
		}

		const providerState = await this.storage.readProviderState(OPENAI_CODEX_PROVIDER_ID);
		const knownCredentialIds = new Set(providerState.credentialIds);
		if (knownCredentialIds.size === 0) {
			return undefined;
		}

		const entries = await this.authWriter.getProviderCredentialEntries(OPENAI_CODEX_PROVIDER_ID);
		const probedCredentialIds = new Set<string>();
		let selectedCredentialId: string | undefined;
		let loginPlanType: CodexPlanType | undefined;

		try {
			for (const entry of entries) {
				if (!knownCredentialIds.has(entry.credentialId) || entry.credential.type !== "oauth") {
					continue;
				}
				if (buildCodexIdentityKey(entry.credential) !== identityKey) {
					continue;
				}

				const disabledEntry = providerState.disabledCredentials[entry.credentialId];
				const credentialStatus = disabledEntry ? "disabled" : "active";
				const existingPlanType =
					normalizeKnownCodexPlanType(disabledEntry?.planType) ??
					this.readCachedCodexCredentialPlanType(entry.credentialId);
				if (existingPlanType) {
					if (!loginPlanType) {
						probedCredentialIds.add(entry.credentialId);
						loginPlanType = await this.resolveCodexLoginPlanType(entry.credentialId, credentials);
					}
					if (loginPlanType === existingPlanType) {
						selectedCredentialId = entry.credentialId;
						break;
					}
					multiAuthDebugLogger.log("codex_oauth_resurrection_plan_mismatch", {
						provider: OPENAI_CODEX_PROVIDER_ID,
						credentialRef: redactUsageCredentialIdentifier(entry.credentialId),
						credentialStatus,
						existingPlanType,
						loginPlanType: loginPlanType ?? "unknown",
					});
					continue;
				}

				if (isStrongCodexIdentityKey(identityKey)) {
					selectedCredentialId = entry.credentialId;
					break;
				}

				multiAuthDebugLogger.log("codex_oauth_resurrection_skipped_missing_plan", {
					provider: OPENAI_CODEX_PROVIDER_ID,
					credentialRef: redactUsageCredentialIdentifier(entry.credentialId),
					credentialStatus,
					identityKind: identityKey.split(":", 1)[0] ?? "unknown",
				});
			}
			return selectedCredentialId;
		} finally {
			for (const credentialId of probedCredentialIds) {
				if (credentialId !== selectedCredentialId) {
					this.usageService.clearOperationalCredential(OPENAI_CODEX_PROVIDER_ID, credentialId);
				}
			}
		}
	}

	private async findExistingOAuthCredentialIdByIdentity(
		provider: SupportedProviderId,
		credentials: OAuthCredentials,
	): Promise<string | undefined> {
		if (provider === OPENAI_CODEX_PROVIDER_ID) {
			return this.findCodexOAuthCredentialIdByIdentity(credentials);
		}

		const identityKey = buildOAuthIdentityKey(provider, credentials);
		if (!identityKey) {
			return undefined;
		}

		const entries = await this.authWriter.getProviderCredentialEntries(provider);
		for (const entry of entries) {
			if (entry.credential.type !== "oauth") {
				continue;
			}
			if (buildOAuthIdentityKey(provider, entry.credential) === identityKey) {
				return entry.credentialId;
			}
		}
		return undefined;
	}

	/**
	 * Adds an API-key credential in primary/backup slot order.
	 */
	async addApiKeyCredential(
		provider: SupportedProviderId,
		apiKeyInput: string,
		options: AddApiKeyCredentialOptions = {},
	): Promise<BackupAndStoreResult> {
		if (isRemovedLegacyGoogleProvider(provider)) {
			throw new Error("Legacy Google API-key providers are no longer supported.");
		}

		const validation = validateApiKeyInput(apiKeyInput);
		if (!validation.ok) {
			throw new Error(validation.message);
		}

		let request = options.request;
		if (isCloudflareWorkersAiProvider(provider)) {
			const configuredBaseUrl = request?.baseUrl;
			if (configuredBaseUrl !== undefined && !isValidCloudflareOpenAIBaseUrl(configuredBaseUrl)) {
				throw new Error(
					`Cloudflare credential for ${provider} must use https://api.cloudflare.com/client/v4/accounts/<account_id>/ai/v1 as request.baseUrl.`,
				);
			}
			request = configuredBaseUrl
				? request
				: {
						...request,
						baseUrl: await discoverCloudflareWorkersAiBaseUrl(validation.value),
					};
		}
		const result = await this.authWriter.setApiKeyCredentialAsBackup(
			provider,
			validation.value,
			request,
			resolveApiKeyCredentialIdentityKey,
		);
		const persistedCredential: StoredAuthCredential = {
			type: "api_key",
			key: validation.value,
			...(request && { request }),
		};
		await this.persistCredentialList(provider, result.credentialIds, result.credentialId, persistedCredential);
		await this.persistCloudflareFriendlyNameForCredential(provider, result.credentialId, persistedCredential);
		this.usageService.clearProvider(provider);
		return result;
	}

	private async persistCredentialList(
		provider: SupportedProviderId,
		credentialIds: string[],
		lastAddedCredentialId: string,
		persistedCredential?: StoredAuthCredential,
	): Promise<void> {
		await this.flushLightweightRotationStateIfNeeded(provider);
		const providerStateAfterPersist = await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			providerState.credentialIds = [...credentialIds];
			normalizeProviderState(providerState, provider);

			const addedIndex = providerState.credentialIds.indexOf(lastAddedCredentialId);
			if (providerState.credentialIds.length === 1) {
				providerState.activeIndex = 0;
			} else if (addedIndex >= 0 && providerState.manualActiveCredentialId === undefined) {
				providerState.activeIndex = Math.max(0, providerState.activeIndex);
			}

			providerState.lastUsedAt[lastAddedCredentialId] = Date.now();
			if (persistedCredential) {
				clearCredentialBackgroundExclusion(providerState, lastAddedCredentialId);
			}
			normalizeProviderState(providerState, provider);
			return { result: cloneProviderState(providerState), next: state };
		});
		this.updateBackgroundCredentialExclusionCache(provider, providerStateAfterPersist);

		const credential = persistedCredential ?? (await this.authWriter.getCredential(lastAddedCredentialId));
		if (credential?.type === "oauth") {
			if (await this.isProviderHidden(provider)) {
				this.oauthRefreshScheduler.cancelRefresh(lastAddedCredentialId);
			} else {
				this.scheduleOAuthRefresh(provider, lastAddedCredentialId, credential);
			}
			await this.persistOAuthRefreshSchedule(provider);
		}
	}

	/**
	 * Sets the active credential index for a provider.
	 */
	async switchActiveCredential(provider: SupportedProviderId, index: number): Promise<void> {
		if (!Number.isInteger(index) || index < 0) {
			throw new Error("Credential index must be a non-negative integer");
		}

		await this.flushLightweightRotationStateIfNeeded(provider);

		const syncedState = await this.syncProviderState(provider);
		if (index >= syncedState.credentialIds.length) {
			throw new Error(
				`Index ${index} is out of range for ${provider} (available: ${syncedState.credentialIds.length})`,
			);
		}

		const credentialId = syncedState.credentialIds[index];
		const disabledReason = getDisabledError(syncedState, credentialId);
		if (disabledReason) {
			throw new Error(
				`Cannot activate disabled credential '${credentialId}' for ${provider}. Re-enable it in /multi-auth first. Reason: ${disabledReason.error}`,
			);
		}

		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			providerState.activeIndex = index;
			providerState.manualActiveCredentialId = providerState.credentialIds[index];
			providerState.lastUsedAt[providerState.credentialIds[index]] = Date.now();
			return { result: undefined, next: state };
		});
	}

	/**
	 * Clears manual active account selection and returns to extension-managed rotation.
	 */
	async clearManualActiveCredential(provider: SupportedProviderId): Promise<void> {
		await this.flushLightweightRotationStateIfNeeded(provider);
		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			providerState.manualActiveCredentialId = undefined;
			return { result: undefined, next: state };
		});
	}

	/**
	 * Deletes one or more credentials from auth.json and syncs provider rotation state.
	 */
	async deleteCredentials(
		provider: SupportedProviderId,
		credentialIds: readonly string[],
	): Promise<void> {
		await this.flushLightweightRotationStateIfNeeded(provider);
		const normalizedCredentialIds = normalizeCredentialIdsForDeletion(credentialIds);
		const state = await this.syncProviderState(provider);
		const availableCredentialIds = new Set(state.credentialIds);
		const missingFromProvider = normalizedCredentialIds.filter(
			(credentialId) => !availableCredentialIds.has(credentialId),
		);
		if (missingFromProvider.length > 0) {
			throw new Error(
				`Credentials ${formatCredentialIdList(missingFromProvider)} are not available for provider ${provider}.`,
			);
		}

		await this.authWriter.withLock((authData) => {
			const missingFromAuth = normalizedCredentialIds.filter(
				(credentialId) => authData[credentialId] === undefined,
			);
			if (missingFromAuth.length > 0) {
				throw new Error(
					`Credentials ${formatCredentialIdList(missingFromAuth)} were not found in auth.json.`,
				);
			}

			const next = { ...authData };
			for (const credentialId of normalizedCredentialIds) {
				delete next[credentialId];
			}
			return { result: undefined, next };
		});

		await this.syncProviderState(provider);
		for (const credentialId of normalizedCredentialIds) {
			this.cascadeStateManager.removeCredential(provider, credentialId);
			this.healthScorer.removeCredential(credentialId);
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			this.usageService.clearCredential(provider, credentialId);
		}
		await this.persistProviderTelemetry(provider);
		await this.persistOAuthRefreshSchedule(provider);
	}

	/**
	 * Deletes a credential from auth.json and syncs provider rotation state.
	 */
	async deleteCredential(provider: SupportedProviderId, credentialId: string): Promise<void> {
		await this.deleteCredentials(provider, [credentialId]);
	}

	private async disableCredential(
		provider: SupportedProviderId,
		credentialId: string,
		rawErrorMessage: string,
		errorKind: CredentialErrorKind,
	): Promise<void> {
		await this.ensureInitialized();

		const errorMessage = rawErrorMessage.trim();
		if (!errorMessage) {
			throw new Error("Cannot disable credential without a non-empty error message.");
		}

		const disabledPlanType = provider === OPENAI_CODEX_PROVIDER_ID
			? this.readCachedCodexCredentialPlanType(credentialId)
			: undefined;
		const didDisable = await this.storage.withLock((stored) => {
			const providerState = getProviderState(stored, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: false };
			}

			if (!providerState.disabledCredentials) {
				providerState.disabledCredentials = {};
			}

			providerState.disabledCredentials[credentialId] = {
				error: errorMessage,
				disabledAt: Date.now(),
				...(disabledPlanType ? { planType: disabledPlanType } : {}),
			};

			if (providerState.manualActiveCredentialId === credentialId) {
				providerState.manualActiveCredentialId = undefined;
			}

			return { result: true, next: stored };
		});
		if (!didDisable) {
			throw new Error(`Credential ${credentialId} is not available for provider ${provider}`);
		}

		await this.recordCredentialFailure(provider, credentialId, 0, errorKind, errorMessage);
		this.cascadeStateManager.removeCredential(provider, credentialId);
		await this.persistProviderTelemetry(provider);
		this.oauthRefreshScheduler.cancelRefresh(credentialId);
		await this.persistOAuthRefreshSchedule(provider);
		this.usageService.clearOperationalCredential(provider, credentialId);
	}

	private createOAuthRefreshFailure(
		provider: SupportedProviderId,
		credentialId: string,
		error: unknown,
	): OAuthRefreshFailureError {
		if (isOAuthRefreshFailureError(error)) {
			const summary = formatOAuthRefreshFailureSummary({
				providerLabel: formatOAuthProviderLabel(error.details.providerId || provider),
				status: error.details.status,
				errorCode: error.details.errorCode,
				reason: error.details.reason,
				permanent: error.details.permanent,
				source: error.details.source,
			});
			return new OAuthRefreshFailureError(
				`Failed to refresh OAuth token for ${credentialId}: ${summary}`,
				{
					...error.details,
					credentialId,
				},
				{ cause: error },
			);
		}

		const inferredMetadata = inferOAuthRefreshFailureMetadata(getErrorMessage(error));
		const summary = formatOAuthRefreshFailureSummary({
			providerLabel: formatOAuthProviderLabel(provider),
			errorCode: inferredMetadata.errorCode,
			reason: inferredMetadata.reason,
			permanent: inferredMetadata.permanent,
			source: "provider",
		});
		return new OAuthRefreshFailureError(
			`Failed to refresh OAuth token for ${credentialId}: ${summary}`,
			{
				providerId: provider,
				credentialId,
				errorCode: inferredMetadata.errorCode,
				reason: inferredMetadata.reason,
				permanent: inferredMetadata.permanent ?? false,
				source: "provider",
			},
			{ cause: error },
		);
	}

	private async clearRecoveredOAuthRefreshFailureState(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredOAuthCredential,
	): Promise<void> {
		if (provider !== "openai-codex" && provider !== "cline") {
			return;
		}

		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: false };
			}

			const changed = clearRecoveredOAuthRefreshFailureStateForCredential(
				provider,
				providerState,
				credentialId,
				credential,
			);
			if (!changed) {
				return { result: false };
			}

			normalizeProviderState(providerState, provider);
			return { result: true, next: state };
		});
	}

	private async tryRecoverConcurrentCodexRefresh(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredOAuthCredential,
		error: unknown,
	): Promise<StoredOAuthCredential | null> {
		if (provider !== "openai-codex" || !isOAuthRefreshFailureError(error)) {
			return null;
		}

		const isRefreshTokenReuseFailure =
			error.details.errorCode === "refresh_token_reused" ||
			/already been used to generate a new access token/i.test(error.message);
		if (!isRefreshTokenReuseFailure) {
			return null;
		}

		const currentCredential = await this.authWriter.getCredential(credentialId);
		if (!currentCredential || currentCredential.type !== "oauth") {
			return null;
		}

		const hasRotatedRefreshToken = currentCredential.refresh !== credential.refresh;
		const hasRotatedAccessToken = currentCredential.access !== credential.access;
		const hasNewerExpiry = currentCredential.expires > credential.expires;
		if (!hasRotatedRefreshToken && !hasRotatedAccessToken && !hasNewerExpiry) {
			return null;
		}

		await this.clearRecoveredOAuthRefreshFailureState(provider, credentialId, currentCredential);
		multiAuthDebugLogger.log("oauth_refresh_reuse_recovered", {
			provider,
			credentialRef: redactUsageCredentialIdentifier(credentialId),
			errorCode: error.details.errorCode,
			hasRotatedRefreshToken,
			hasRotatedAccessToken,
			hasNewerExpiry,
		});
		return currentCredential;
	}

	private async logAndHandleOAuthRefreshFailure(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredOAuthCredential,
		error: unknown,
	): Promise<OAuthRefreshFailureError> {
		const failure = this.createOAuthRefreshFailure(provider, credentialId, error);
		multiAuthDebugLogger.log("oauth_refresh_failed", {
			provider,
			credentialRef: redactUsageCredentialIdentifier(credentialId),
			message: failure.message,
			permanent: failure.details.permanent,
			source: failure.details.source,
			status: failure.details.status,
			errorCode: failure.details.errorCode,
			reason: failure.details.reason,
		});

		if (failure.details.errorCode === UNSUPPORTED_OAUTH_REFRESH_PROVIDER_ERROR_CODE) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			await this.persistOAuthRefreshSchedule(provider);
			multiAuthDebugLogger.log("oauth_refresh_provider_unavailable", {
				provider,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				message: failure.message,
				errorCode: failure.details.errorCode,
				source: failure.details.source,
			});
			return failure;
		}

		if (failure.details.permanent) {
			const now = Date.now();
			if (
				shouldPreserveActiveOAuthCredentialAfterRefreshFailure(
					provider,
					credential,
					failure,
					now,
				)
			) {
				await this.clearRecoveredOAuthRefreshFailureState(provider, credentialId, credential);
				this.oauthRefreshScheduler.cancelRefresh(credentialId);
				await this.persistOAuthRefreshSchedule(provider);
				multiAuthDebugLogger.log("oauth_refresh_active_token_preserved", {
					provider,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
					message: failure.message,
					status: failure.details.status,
					errorCode: failure.details.errorCode,
					reason: failure.details.reason,
					expiresAt: credential.expires,
					remainingMs: Math.max(0, credential.expires - now),
				});
				return failure;
			}

			if (provider === "openai-codex") {
				await this.disableCredential(provider, credentialId, failure.message, "authentication");
				multiAuthDebugLogger.log("oauth_refresh_codex_disabled", {
					provider,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
					message: failure.message,
					status: failure.details.status,
					errorCode: failure.details.errorCode,
					reason: failure.details.reason,
				});
			} else {
				await this.disableCredential(provider, credentialId, failure.message, "authentication");
				multiAuthDebugLogger.log("oauth_refresh_permanently_disabled", {
					provider,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
					message: failure.message,
					status: failure.details.status,
					errorCode: failure.details.errorCode,
				});
			}
		}

		return failure;
	}

	/**
	 * Marks a credential as disabled in multi-auth.json (not auth.json).
	 * Disabled credentials are excluded from rotation until manually re-enabled.
	 */
	async disableApiKeyCredential(
		provider: SupportedProviderId,
		credentialId: string,
		rawErrorMessage: string,
		errorKind: CredentialErrorKind = "balance_exhausted",
	): Promise<void> {
		await this.disableCredential(provider, credentialId, rawErrorMessage, errorKind);
	}

	private async clearDisabledCredentialForReenable(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<ProviderRotationState | null> {
		return this.storage.withLock((stored) => {
			const providerState = getProviderState(stored, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: null };
			}
			if (!providerState.disabledCredentials?.[credentialId]) {
				return { result: null };
			}

			delete providerState.disabledCredentials[credentialId];
			if (Object.keys(providerState.disabledCredentials).length === 0) {
				providerState.disabledCredentials = {};
			}

			clearCredentialBackgroundExclusion(providerState, credentialId);

			normalizeProviderState(providerState, provider);
			return { result: cloneProviderState(providerState), next: stored };
		});
	}

	/**
	 * Re-enables a previously disabled credential, allowing it to participate in rotation again.
	 * Clears the disabled state from multi-auth.json and reschedules OAuth refresh if applicable.
	 */
	async reenableCredential(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<void> {
		await this.ensureInitialized();
		const state = await this.syncProviderState(provider);
		if (!state.credentialIds.includes(credentialId) || !state.disabledCredentials?.[credentialId]) {
			throw new Error(
				`Credential ${credentialId} is not available or not disabled for provider ${provider}`,
			);
		}

		const credential = await this.authWriter.getCredential(credentialId);
		if (!credential) {
			throw new Error(`Credential ${credentialId} was not found in auth.json`);
		}

		if (credential.type === "oauth" && this.shouldSkipOAuthRefreshForMissingRefreshToken(provider, credential)) {
			const providerState = await this.clearDisabledCredentialForReenable(
				provider,
				credentialId,
			);
			if (!providerState) {
				throw new Error(
					`Credential ${credentialId} is not available or not disabled for provider ${provider}`,
				);
			}
			this.updateBackgroundCredentialExclusionCache(provider, providerState);
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			await this.persistOAuthRefreshSchedule(provider);
			this.usageService.clearOperationalCredential(provider, credentialId);
			multiAuthDebugLogger.log("credential_reenabled_without_refresh_token", {
				provider,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				reason: MISSING_REFRESH_TOKEN_BACKGROUND_EXCLUSION_REASON,
			});
			return;
		}

		if (credential.type === "oauth") {
			const refreshResult = await this.refreshCredential(provider, credentialId);
			if (refreshResult.disposition === "refreshed") {
				this.scheduleOAuthRefresh(provider, credentialId, refreshResult.credential);
				await this.persistOAuthRefreshSchedule(provider);
			}
		}

		const providerState = await this.clearDisabledCredentialForReenable(
			provider,
			credentialId,
		);
		if (!providerState) {
			throw new Error(
				`Credential ${credentialId} is not available or not disabled for provider ${provider}`,
			);
		}
		this.updateBackgroundCredentialExclusionCache(provider, providerState);
		this.usageService.clearOperationalCredential(provider, credentialId);
	}

	/**
	 * Refreshes a specific OAuth credential after a runtime request rejected the selected token.
	 * If another concurrent refresh already rotated the credential, reuses that persisted token
	 * instead of spending the newly rotated refresh token again.
	 */
	async refreshCredentialForAuthFailure(
		provider: SupportedProviderId,
		credentialId: string,
		failedCredential: StoredOAuthCredential,
	): Promise<CredentialRefreshResult> {
		if (await this.isProviderHidden(provider)) {
			throw new Error(`OAuth refresh skipped because provider ${provider} is hidden.`);
		}
		const state = await this.syncProviderState(provider);
		if (!state.credentialIds.includes(credentialId)) {
			throw new Error(`Credential ${credentialId} is not available for provider ${provider}`);
		}
		this.assertOAuthRefreshManagedForProvider(provider);

		const currentCredential = await this.authWriter.getCredential(credentialId);
		if (!currentCredential) {
			throw new Error(`Credential ${credentialId} was not found in auth.json`);
		}
		if (currentCredential.type !== "oauth") {
			throw new Error(
				`Credential ${credentialId} is an API key and does not support OAuth token refresh.`,
			);
		}

		const hasConcurrentRotation =
			currentCredential.access !== failedCredential.access ||
			currentCredential.refresh !== failedCredential.refresh ||
			currentCredential.expires > failedCredential.expires;
		if (hasConcurrentRotation) {
			this.scheduleOAuthRefresh(provider, credentialId, currentCredential);
			await this.persistOAuthRefreshSchedule(provider);
			this.usageService.clearOperationalCredential(provider, credentialId);
			return {
				credential: currentCredential,
				disposition: "reused_current_token",
			};
		}
		if (this.shouldSkipOAuthRefreshForMissingRefreshToken(provider, currentCredential)) {
			throw new Error(
				`OAuth refresh skipped for ${credentialId} because it was imported without a refresh token.`,
			);
		}

		return this.refreshCredential(provider, credentialId);
	}

	/**
	 * Refreshes a specific OAuth credential token and persists it back to auth.json.
	 */
	async refreshCredential(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<CredentialRefreshResult> {
		if (await this.isProviderHidden(provider)) {
			throw new Error(`OAuth refresh skipped because provider ${provider} is hidden.`);
		}
		const state = await this.syncProviderState(provider);
		if (!state.credentialIds.includes(credentialId)) {
			throw new Error(`Credential ${credentialId} is not available for provider ${provider}`);
		}

		const credential = await this.authWriter.getCredential(credentialId);
		if (!credential) {
			throw new Error(`Credential ${credentialId} was not found in auth.json`);
		}
		if (credential.type !== "oauth") {
			throw new Error(
				`Credential ${credentialId} is an API key and does not support OAuth token refresh.`,
			);
		}
		this.assertOAuthRefreshManagedForProvider(provider);
		if (this.shouldSkipOAuthRefreshForMissingRefreshToken(provider, credential)) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			await this.persistOAuthRefreshSchedule(provider);
			this.registerCurrentUsageCredentialCacheKey(provider, credentialId, credential);
			return {
				credential,
				disposition: "skipped_missing_refresh_token",
			};
		}

		let effectiveCredential: StoredOAuthCredential;
		let disposition: CredentialRefreshDisposition = "refreshed";
		let shouldPersistRefreshSchedule = true;
		try {
			effectiveCredential = await this.refreshCredentialToken(provider, credentialId, credential);
			this.scheduleOAuthRefresh(provider, credentialId, effectiveCredential);
		} catch (error) {
			if (
				isOAuthRefreshFailureError(error) &&
				shouldPreserveActiveOAuthCredentialAfterRefreshFailure(provider, credential, error)
			) {
				effectiveCredential = credential;
				disposition = "preserved_active_token";
				shouldPersistRefreshSchedule = false;
			} else {
				throw error;
			}
		}
		await this.storage.withLock((stored) => {
			const providerState = getProviderState(stored, provider);
			providerState.lastUsedAt[credentialId] = Date.now();
			return { result: undefined, next: stored };
		});
		if (shouldPersistRefreshSchedule) {
			await this.persistOAuthRefreshSchedule(provider);
		}
		this.registerCurrentUsageCredentialCacheKey(provider, credentialId, effectiveCredential);

		return {
			credential: effectiveCredential,
			disposition,
		};
	}

	/**
	 * Refreshes and persists the friendly-name identity for a Cloudflare API-key credential.
	 */
	async refreshCloudflareCredentialIdentity(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<CloudflareCredentialIdentityRefreshResult> {
		if (!isCloudflareWorkersAiProvider(provider)) {
			return {
				status: "unsupported",
				message: `Provider ${provider} does not support Cloudflare identity lookup.`,
			};
		}

		const state = await this.syncProviderState(provider);
		if (!state.credentialIds.includes(credentialId)) {
			throw new Error(`Credential ${credentialId} is not available for provider ${provider}`);
		}

		const credential = await this.authWriter.getCredential(credentialId);
		if (!credential) {
			throw new Error(`Credential ${credentialId} was not found in auth.json`);
		}
		if (credential.type !== "api_key") {
			return {
				status: "unsupported",
				message: `Credential ${credentialId} is not a Cloudflare API key.`,
			};
		}

		const identity = await this.getCloudflareIdentityLookup(provider, credentialId, credential, {
			forceRefresh: true,
		});
		const friendlyName = identity?.displayName?.trim();
		if (!friendlyName) {
			return {
				status: "unsupported",
				message: `Cloudflare did not return an email identity for credential ${credentialId}.`,
			};
		}

		const previousFriendlyName = state.friendlyNames[credentialId]?.trim();
		await this.setFriendlyName(provider, credentialId, friendlyName);

		if (previousFriendlyName === friendlyName) {
			return {
				status: "unchanged",
				friendlyName,
				message: `Cloudflare identity ${friendlyName} is already saved.`,
			};
		}

		return {
			status: "updated",
			friendlyName,
			message: `Saved Cloudflare identity ${friendlyName}.`,
		};
	}

	/**
	 * Refreshes all credentials for a provider and reconciles persisted quota state from fresh usage data.
	 */
	async refreshProviderCredentials(
		provider: SupportedProviderId,
	): Promise<ProviderRefreshResult> {
		const state = await this.syncProviderState(provider);
		const totalCredentials = state.credentialIds.length;
		const refreshedCredentialIds: string[] = [];
		const preservedCredentialIds: string[] = [];
		const failedCredentials: Array<{ credentialId: string; error: string }> = [];
		const usageWarnings: Array<{ credentialId: string; warning: string }> = [];
		const usageReconciliationCredentialIds = this.usageService.hasProvider(provider)
			? new Set(
				this.usageCoordinator.selectCredentialIds(
					state.credentialIds,
					"manual-provider-refresh",
				),
			)
			: new Set<string>();
		const credentialsById = await this.authWriter.getCredentials(state.credentialIds);

		for (const credentialId of state.credentialIds) {
			const credential = credentialsById.get(credentialId);
			if (!credential) {
				failedCredentials.push({
					credentialId,
					error: `Credential ${credentialId} is missing from auth.json`,
				});
				continue;
			}

			if (credential.type === "oauth") {
				try {
					const refreshResult = await this.refreshCredential(provider, credentialId);
					if (
						refreshResult.disposition === "preserved_active_token" ||
						refreshResult.disposition === "skipped_missing_refresh_token"
					) {
						preservedCredentialIds.push(credentialId);
					} else {
						refreshedCredentialIds.push(credentialId);
					}
				} catch (error: unknown) {
					const message = getErrorMessage(error);
					failedCredentials.push({ credentialId, error: message });
					continue;
				}
			} else {
				refreshedCredentialIds.push(credentialId);
			}

			if (!usageReconciliationCredentialIds.has(credentialId)) {
				continue;
			}

			try {
				const usage = await this.getCredentialUsageSnapshot(provider, credentialId, {
					forceRefresh: true,
					coordinationOperation: "manual-provider-refresh",
				});
				if (usage.error) {
					usageWarnings.push({ credentialId, warning: usage.error });
				}
			} catch (error: unknown) {
				const message = getErrorMessage(error);
				usageWarnings.push({
					credentialId,
					warning: `Usage reconciliation failed (${message})`,
				});
			}
		}

		if (this.usageService.hasProvider(provider)) {
			this.enqueueAllCredentialUsageRefresh(
				provider,
				state.credentialIds.filter((credentialId) => !usageReconciliationCredentialIds.has(credentialId)),
				"manual-provider-refresh",
			);
		}

		return {
			provider,
			totalCredentials,
			refreshedCredentialIds,
			preservedCredentialIds,
			failedCredentials,
			usageWarnings,
		};
	}

	async resolveFailoverTarget(
		provider: SupportedProviderId,
		errorKind: CredentialErrorKind,
		modelId: string,
	): Promise<ResolvedFailoverTarget | null> {
		return this.storage.withLock(async (state) => {
			const chainDefinitions = this.collectFailoverChains(state, provider);
			if (chainDefinitions.length === 0) {
				return { result: null };
			}

			const manager = new FailoverChainManager(chainDefinitions);
			const activeState = this.getActiveFailoverState(state, chainDefinitions);
			manager.loadState(activeState);
			if (!manager.shouldFailover(errorKind)) {
				return { result: null };
			}

			const next = manager.getNextInChain(provider, errorKind, modelId);
			if (!next) {
				this.clearFailoverStateFromState(state, chainDefinitions);
				return { result: null, next: state };
			}

			const metadata = await this.providerRegistry.resolveProviderRegistrationMetadata(next.providerId);
			if (!metadata) {
				return {
					result: null,
					next: state,
				};
			}

			const resolvedModel = metadata.models.find((candidate) => candidate.id === next.modelId);
			if (!resolvedModel) {
				return {
					result: null,
					next: state,
				};
			}

			const exportedState = manager.exportState();
			this.persistFailoverStateToProviders(state, chainDefinitions, exportedState);
			return {
				result: {
					...next,
					api: resolvedModel.api ?? metadata.api,
				},
				next: state,
			};
		});
	}

	private collectFailoverChains(
		state: MultiAuthState,
		provider: SupportedProviderId,
	): FailoverChain[] {
		const deduped = new Map<string, FailoverChain>();
		for (const providerState of Object.values(state.providers)) {
			for (const chain of providerState.chains ?? []) {
				if (!chain.providers.some((entry) => entry.providerId === provider)) {
					continue;
				}
				if (!deduped.has(chain.chainId)) {
					deduped.set(chain.chainId, cloneJson(chain));
				}
			}
		}
		return [...deduped.values()];
	}

	private getActiveFailoverState(
		state: MultiAuthState,
		chains: readonly FailoverChain[],
	): FailoverChainState | undefined {
		const chainIds = new Set(chains.map((chain) => chain.chainId));
		for (const providerState of Object.values(state.providers)) {
			if (providerState.activeChain && chainIds.has(providerState.activeChain.chainId)) {
				return cloneJson(providerState.activeChain);
			}
		}
		return undefined;
	}

	private persistFailoverStateToProviders(
		state: MultiAuthState,
		chains: readonly FailoverChain[],
		activeState: FailoverChainState | undefined,
	): void {
		const providerIds = new Set<string>();
		for (const chain of chains) {
			for (const provider of chain.providers) {
				providerIds.add(provider.providerId);
			}
		}
		for (const providerId of providerIds) {
			const providerState = getProviderState(state, providerId);
			providerState.activeChain = activeState ? cloneJson(activeState) : undefined;
		}
	}

	private clearFailoverStateFromState(
		state: MultiAuthState,
		chains?: readonly FailoverChain[],
	): void {
		if (chains && chains.length > 0) {
			this.persistFailoverStateToProviders(state, chains, undefined);
			return;
		}

		for (const providerState of Object.values(state.providers)) {
			providerState.activeChain = undefined;
		}
	}

	private async clearActiveFailoverChains(): Promise<void> {
		await this.storage.withLock((state) => {
			const hadActiveChain = Object.values(state.providers).some(
				(providerState) => providerState.activeChain !== undefined,
			);
			if (!hadActiveChain) {
				return { result: undefined };
			}
			this.clearFailoverStateFromState(state);
			return { result: undefined, next: state };
		});
	}

	private async selectPooledCredential(
		provider: SupportedProviderId,
		state: ProviderRotationState,
		available: Set<string>,
		healthScores: ProviderRotationState["healthState"],
		usageContext?: CredentialUsageContext,
		signal?: AbortSignal,
	): Promise<{ selectedIndex: number; poolMode: RotationMode; poolState: ProviderPoolState } | null> {
		throwIfAborted(signal, `Pooled credential selection aborted for ${provider}.`);
		if (!state.pools || state.pools.length === 0) {
			return null;
		}

		const poolConfig = resolveProviderPoolConfig(state);
		const poolManager = new PoolManager({
			enablePools: poolConfig.enablePools,
			pools: state.pools,
			failoverStrategy: poolConfig.failoverStrategy,
			preferHealthyWithinPool: poolConfig.preferHealthyWithinPool,
		});
		const selection = poolManager.selectPool([...available], {
			scores: healthScores?.scores,
			state: state.poolState,
		});
		if (!selection) {
			return null;
		}

		const poolAvailable = new Set(selection.availableCredentialIds);
		let selectedIndex: number | undefined;
		switch (selection.pool.poolMode) {
			case "usage-based":
				selectedIndex = await this.getUsageBasedCandidateIndex(
					provider,
					state,
					poolAvailable,
					usageContext,
				);
				break;
			case "balancer": {
				const selectedCredentialId = await this.keyDistributor.acquireKey(
					{
						providerId: provider,
						excludedIds: state.credentialIds.filter(
							(credentialId) => !poolAvailable.has(credentialId),
						),
						requestingSessionId: `orchestrator:${provider}:pool:${selection.pool.poolId}`,
						rotationMode: selection.pool.poolMode,
					},
					{ signal },
				);
				selectedIndex = state.credentialIds.indexOf(selectedCredentialId);
				break;
			}
			case "round-robin":
			default:
				selectedIndex = getRoundRobinCandidateIndex(state, poolAvailable);
				break;
		}
		if (selectedIndex === undefined || selectedIndex < 0) {
			return null;
		}

		return {
			selectedIndex,
			poolMode: selection.pool.poolMode,
			poolState: selection.poolState,
		};
	}

	private buildQuotaState(
		credentialId: string,
		errorMessage: string,
		classification: QuotaClassificationResult,
	): QuotaStateForCredential {
		return quotaClassifier.createQuotaState(credentialId, errorMessage, classification);
	}

	private async ensureCredentialRequestConfiguration(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredAuthCredential,
		signal?: AbortSignal,
	): Promise<StoredAuthCredential> {
		if (!isCloudflareWorkersAiProvider(provider)) {
			return credential;
		}

		const configuredBaseUrl = credential.request?.baseUrl;
		if (
			typeof configuredBaseUrl === "string" &&
			isValidCloudflareOpenAIBaseUrl(configuredBaseUrl)
		) {
			return credential;
		}

		const apiToken = getCredentialRequestSecret(provider, credential).trim();
		if (!apiToken) {
			throw new Error(
				`Cloudflare credential '${credentialId}' cannot discover an account ID because its request secret is empty.`,
			);
		}

		const baseUrl = await discoverCloudflareWorkersAiBaseUrl(apiToken, { signal });
		const updatedCredential = await this.authWriter.setCredentialRequestOverrides(
			credentialId,
			{ baseUrl },
		);
		multiAuthDebugLogger.log("cloudflare_account_base_url_discovered", {
			provider,
			credentialRef: redactUsageCredentialIdentifier(credentialId),
		});
		return updatedCredential;
	}

	/**
	 * Selects a credential for request execution and refreshes token if needed.
	 */
	async acquireCredential(
		provider: SupportedProviderId,
		options?: AcquireCredentialOptions,
	): Promise<SelectedCredential> {
		const acquisitionStartedAt = Date.now();
		throwIfAborted(options?.signal, `Credential acquisition aborted for ${provider}.`);
		if (await this.isProviderHidden(provider)) {
			throw new Error(`Provider ${provider} is hidden. Unhide it in /multi-auth before using it.`);
		}
		let state = await raceWithSignal(
			this.syncProviderState(provider),
			options?.signal,
			`Credential acquisition aborted for ${provider}.`,
		);
		if (state.credentialIds.length === 0) {
			throw new Error(`No credentials available for ${provider}. Open /multi-auth and add an account.`);
		}

		let disabledCredentialIds = await this.getDisabledCredentialIds(state);
		if (
			state.manualActiveCredentialId &&
			disabledCredentialIds.has(state.manualActiveCredentialId)
		) {
			await this.clearManualActiveCredential(provider);
			state = await raceWithSignal(
				this.syncProviderState(provider),
				options?.signal,
				`Credential acquisition aborted for ${provider}.`,
			);
			disabledCredentialIds = await this.getDisabledCredentialIds(state);
		}

		const expiredApiKeyCredentialIds = new Set<string>();
		if (provider === "cline") {
			const credentialSnapshot = await raceWithSignal(
				this.authWriter.getCredentials(state.credentialIds),
				options?.signal,
				`Credential acquisition aborted for ${provider}.`,
			);
			const expirationCheckTimestamp = Date.now();
			for (const credentialId of state.credentialIds) {
				const credential = credentialSnapshot.get(credentialId);
				if (credential && isExpiredApiKeyCredential(provider, credential, expirationCheckTimestamp)) {
					expiredApiKeyCredentialIds.add(credentialId);
				}
			}
		}

		const pinnedCredentialId = normalizeOptionalCredentialId(options?.pinnedCredentialId);
		if (pinnedCredentialId && !state.credentialIds.includes(pinnedCredentialId)) {
			throw new Error(
				`Delegated credential '${pinnedCredentialId}' is not available for ${provider}.`,
			);
		}

		const requestedModelId = normalizeModelId(options?.modelId, provider) ?? undefined;
		const effectiveExcludedCredentialIds = new Set(options?.excludedCredentialIds ?? []);
		for (const disabledCredentialId of disabledCredentialIds) {
			effectiveExcludedCredentialIds.add(disabledCredentialId);
		}
		for (const expiredCredentialId of expiredApiKeyCredentialIds) {
			effectiveExcludedCredentialIds.add(expiredCredentialId);
		}
		if (requestedModelId) {
			const now = Date.now();
			for (const credentialId of state.credentialIds) {
				if (getModelIncompatibility(state, provider, credentialId, requestedModelId, now)) {
					effectiveExcludedCredentialIds.add(credentialId);
				}
			}
		}
		const recoveryExcludedCredentialIds = new Set(effectiveExcludedCredentialIds);
		for (const blockedCredentialId of this.cascadeStateManager.getBlockedCredentialIds(provider)) {
			effectiveExcludedCredentialIds.add(blockedCredentialId);
		}

		const selectionCache = options?.selectionCache ?? createCredentialSelectionCache();
		const modelEligibilityCredentialIds = state.credentialIds.filter(
			(credentialId) => !effectiveExcludedCredentialIds.has(credentialId),
		);
		const usageContext = this.createCredentialUsageContext(
			modelEligibilityCredentialIds,
			selectionCache,
			options?.signal,
		);
		const modelEligibility = modelEligibilityCredentialIds.length > 0
			? await this.resolveCredentialModelEligibility(
				provider,
				modelEligibilityCredentialIds,
				requestedModelId,
				usageContext,
			)
			: {
				appliesConstraint: false,
				eligibleCredentialIds: [],
				ineligibleCredentialIds: [],
			} satisfies CredentialModelEligibility;

		for (const ineligibleCredentialId of modelEligibility.ineligibleCredentialIds) {
			effectiveExcludedCredentialIds.add(ineligibleCredentialId);
			recoveryExcludedCredentialIds.add(ineligibleCredentialId);
		}

		if (
			modelEligibility.appliesConstraint &&
			modelEligibility.eligibleCredentialIds.length === 0 &&
			modelEligibility.failureMessage
		) {
			throw new Error(modelEligibility.failureMessage);
		}

		let selectedIndex: number | undefined;
		let selectedRotationMode: RotationMode | undefined;
		let selectedPoolState: ProviderPoolState | undefined;
		if (pinnedCredentialId) {
			selectedIndex = state.credentialIds.indexOf(pinnedCredentialId);
			if (
				modelEligibility.appliesConstraint &&
				modelEligibility.ineligibleCredentialIds.includes(pinnedCredentialId) &&
				requestedModelId !== undefined
			) {
				throw new Error(
					`Delegated credential '${pinnedCredentialId}' for ${provider} is not eligible for ${formatModelReference(provider, requestedModelId)}. Ask the parent router to retry with another delegated credential or choose an entitled account in /multi-auth.`,
				);
			}

			const exhaustedUntil = state.quotaExhaustedUntil[pinnedCredentialId];
			if (
				effectiveExcludedCredentialIds.has(pinnedCredentialId) ||
				(typeof exhaustedUntil === "number" && exhaustedUntil > Date.now())
			) {
				throw new Error(
					formatDelegatedCredentialUnavailableMessage(
						provider,
						state,
						pinnedCredentialId,
						expiredApiKeyCredentialIds,
						effectiveExcludedCredentialIds,
						requestedModelId,
					),
				);
			}
		} else if (expiredApiKeyCredentialIds.size === state.credentialIds.length) {
			throw new Error(
				`All credentials for ${provider} are expired WorkOS session tokens. Re-authenticate the account in /multi-auth.`,
			);
		}

		const manualCredentialId = pinnedCredentialId ? undefined : state.manualActiveCredentialId;
		if (manualCredentialId) {
			if (
				modelEligibility.appliesConstraint &&
				modelEligibility.ineligibleCredentialIds.includes(manualCredentialId) &&
				requestedModelId !== undefined
			) {
				throw new Error(
					`Manual active account '${manualCredentialId}' for ${provider} is not eligible for ${formatModelReference(provider, requestedModelId)}. Clear manual active selection in /multi-auth to let automatic rotation use an entitled account.`,
				);
			}
			if (effectiveExcludedCredentialIds.has(manualCredentialId)) {
				if (expiredApiKeyCredentialIds.has(manualCredentialId)) {
					throw new Error(
						`Manual active account '${manualCredentialId}' for ${provider} uses an expired WorkOS token. Re-authenticate the account or clear manual active selection in /multi-auth to let automatic rotation recover.`,
					);
				}
				const disabledReason = getDisabledError(state, manualCredentialId);
				if (disabledReason) {
					throw new Error(
						`Manual active account '${manualCredentialId}' for ${provider} is disabled due to a previous provider error. Clear manual active selection in /multi-auth to let automatic rotation recover.`,
					);
				}
				const modelIncompatibility = getModelIncompatibility(state, provider, manualCredentialId, requestedModelId);
				if (modelIncompatibility) {
					throw new Error(
						`Manual active account '${manualCredentialId}' for ${provider} is incompatible with ${formatModelReference(provider, requestedModelId ?? "requested model")} until ${new Date(modelIncompatibility.blockedUntil).toISOString()}. Clear manual active selection in /multi-auth to let automatic rotation recover.`,
					);
				}
				throw new Error(
					`Manual active account '${manualCredentialId}' for ${provider} is quota-limited for this request. Disable manual active selection in /multi-auth to let automatic rotation recover.`,
				);
			}

			selectedIndex = state.credentialIds.indexOf(manualCredentialId);
			if (selectedIndex < 0) {
				await this.clearManualActiveCredential(provider);
				state = await raceWithSignal(
					this.syncProviderState(provider),
					options?.signal,
					`Credential acquisition aborted for ${provider}.`,
				);
				selectedIndex = undefined;
			} else {
				const exhaustedUntil = state.quotaExhaustedUntil[manualCredentialId];
				if (typeof exhaustedUntil === "number" && exhaustedUntil > Date.now()) {
					throw new Error(
						`Manual active account '${manualCredentialId}' for ${provider} is marked exhausted until ${new Date(exhaustedUntil).toISOString()}. Clear manual active selection in /multi-auth to let automatic rotation use other accounts.`,
					);
				}
			}
		}

		if (selectedIndex === undefined) {
			let now = Date.now();
			let available = buildAvailableSet(state, now, effectiveExcludedCredentialIds);
			if (available.size === 0) {
				await this.reconcileBlockedCredentialsFromUsage(
					provider,
					state,
					recoveryExcludedCredentialIds,
					usageContext,
				);
				state = await raceWithSignal(
					this.syncProviderState(provider),
					options?.signal,
					`Credential acquisition aborted for ${provider}.`,
				);
				now = Date.now();
				available = buildAvailableSet(state, now, effectiveExcludedCredentialIds);
			}

			if (available.size === 0) {
				const recoveredState = await this.releaseOneRecoverableCooldownLock(
					provider,
					state,
					recoveryExcludedCredentialIds,
				);
				if (recoveredState) {
					state = recoveredState;
					now = Date.now();
					available = buildAvailableSet(state, now, effectiveExcludedCredentialIds);
				}
			}

			if (available.size === 0) {
				throw new Error(
					formatAllCredentialsUnavailableMessage(
						provider,
						state,
						expiredApiKeyCredentialIds,
						effectiveExcludedCredentialIds,
						requestedModelId,
					),
				);
			}

			let selectableAvailable = available;
			if (this.usesProcessCredentialLeases(state.rotationMode)) {
				const ownLease = getOwnedCredentialLease(state, this.processLeaseOwnerId, now);
				const leasedByOtherOwners = getCredentialIdsLeasedByOtherOwners(
					state,
					this.processLeaseOwnerId,
					now,
				);
				const unleasedAvailable = new Set(
					[...available].filter((credentialId) => !leasedByOtherOwners.has(credentialId)),
				);
				if (
					ownLease &&
					available.has(ownLease.credentialId) &&
					!leasedByOtherOwners.has(ownLease.credentialId)
				) {
					// Process already holds a lease on this credential. Don't short-circuit
					// rotation — let the normal selection logic run so the usage-based
					// ranking can still rotate fairly within the same process. The lease
					// will be transferred to the selected credential in the commit step.
					selectableAvailable = unleasedAvailable;
				} else if (unleasedAvailable.size > 0) {
					selectableAvailable = unleasedAvailable;
				} else {
					if (ownLease && available.has(ownLease.credentialId)) {
						selectedIndex = state.credentialIds.indexOf(ownLease.credentialId);
					}
					if (leasedByOtherOwners.size > 0) {
						multiAuthDebugLogger.log("credential_lease_shared_fallback", {
							provider,
							availableCount: available.size,
							leasedCredentialCount: leasedByOtherOwners.size,
						});
					}
				}
			}

			// Build the ordered list of selection passes. When the eligibility result
			// includes plan-tier ranking (BlazeAPI: Premium → Pro → Free), each non-empty
			// tier becomes its own pass so a higher tier is fully tried (and exhausted)
			// before falling back to the next. The catch-all `available` pass is always
			// appended last so any eligible credential not covered by a preference tier
			// (e.g. unknown plan type) still gets a chance.
			const selectionPasses: Set<string>[] = [];
			const preferredTiers = modelEligibility.preferredCredentialTiers;
			if (selectedIndex !== undefined) {
				selectionPasses.push(new Set([state.credentialIds[selectedIndex]]));
			} else if (preferredTiers && preferredTiers.length > 0) {
				for (const tier of preferredTiers) {
					const tierAvailable = new Set(
						[...selectableAvailable].filter((credentialId) => tier.includes(credentialId)),
					);
					if (tierAvailable.size > 0) {
						selectionPasses.push(tierAvailable);
					}
				}
			} else {
				const preferredAvailable = new Set(
					[...selectableAvailable].filter((credentialId) =>
						modelEligibility.preferredCredentialIds?.includes(credentialId),
					),
				);
				if (preferredAvailable.size > 0) {
					selectionPasses.push(preferredAvailable);
				}
			}
			selectionPasses.push(selectableAvailable);
			for (const selectionAvailable of selectionPasses) {
				const pooledSelection = await this.selectPooledCredential(
					provider,
					state,
					selectionAvailable,
					state.healthState,
					usageContext,
					options?.signal,
				);
				if (pooledSelection) {
					selectedIndex = pooledSelection.selectedIndex;
					selectedRotationMode = pooledSelection.poolMode;
					selectedPoolState = pooledSelection.poolState;
					break;
				}
				if (state.rotationMode === "balancer") {
					const selectionExcludedCredentialIds = new Set(effectiveExcludedCredentialIds);
					for (const credentialId of state.credentialIds) {
						if (!selectionAvailable.has(credentialId)) {
							selectionExcludedCredentialIds.add(credentialId);
						}
					}
					const selectedCredentialId = await this.keyDistributor.acquireKey(
						{
							providerId: provider,
							excludedIds: [...selectionExcludedCredentialIds],
							requestingSessionId: `orchestrator:${provider}`,
							rotationMode: state.rotationMode,
						},
						{ signal: options?.signal },
					);
					selectedIndex = state.credentialIds.indexOf(selectedCredentialId);
					if (selectedIndex < 0) {
						state = await raceWithSignal(
							this.syncProviderState(provider),
							options?.signal,
							`Credential acquisition aborted for ${provider}.`,
						);
						selectedIndex = state.credentialIds.indexOf(selectedCredentialId);
					}
					break;
				}

				selectedIndex =
					state.rotationMode === "usage-based"
						? await this.getUsageBasedCandidateIndex(provider, state, selectionAvailable, usageContext)
						: getRoundRobinCandidateIndex(state, selectionAvailable);
				if (selectedIndex !== undefined) {
					break;
				}
			}
		}

		if (selectedIndex === undefined) {
			throw new Error(`Could not find an available credential for ${provider}`);
		}

		const credentialId = state.credentialIds[selectedIndex];
		const credential = await raceWithSignal(
			this.authWriter.getCredential(credentialId),
			options?.signal,
			`Credential acquisition aborted for ${provider}.`,
		);
		if (!credential) {
			await raceWithSignal(
				this.syncProviderState(provider),
				options?.signal,
				`Credential acquisition aborted for ${provider}.`,
			);
			throw new Error(
				`Credential ${credentialId} is missing from auth.json. Open /multi-auth and add the account again if needed.`,
			);
		}

		const disabledReason = getDisabledError(state, credentialId);
		if (disabledReason) {
			const nextExcludedCredentialIds = new Set(effectiveExcludedCredentialIds);
			nextExcludedCredentialIds.add(credentialId);
			return this.acquireCredential(provider, {
				excludedCredentialIds: nextExcludedCredentialIds,
				modelId: options?.modelId,
				selectionCache,
				signal: options?.signal,
			});
		}

		const freshCredential =
			credential.type === "oauth"
				? await this.refreshIfNeeded(provider, credentialId, credential, options?.signal)
				: credential;
		const requestReadyCredential = await this.ensureCredentialRequestConfiguration(
			provider,
			credentialId,
			freshCredential,
			options?.signal,
		);
		const effectiveRotationMode = selectedRotationMode ?? state.rotationMode;
		const shouldUseProcessCredentialLease =
			this.usesProcessCredentialLeases(effectiveRotationMode) &&
			pinnedCredentialId === undefined &&
			state.manualActiveCredentialId === undefined;
		throwIfAborted(options?.signal, `Credential acquisition aborted for ${provider}.`);

		if (shouldUseProcessCredentialLease) {
			const leaseCommit = await this.commitProcessCredentialLease(
				provider,
				credentialId,
				effectiveExcludedCredentialIds,
			);
			if (!leaseCommit.committed) {
				const nextExcludedCredentialIds = new Set(effectiveExcludedCredentialIds);
				nextExcludedCredentialIds.add(credentialId);
				return this.acquireCredential(provider, {
					excludedCredentialIds: nextExcludedCredentialIds,
					modelId: options?.modelId,
					selectionCache,
					signal: options?.signal,
				});
			}
			if (leaseCommit.sharedLeaseFallback) {
				multiAuthDebugLogger.log("credential_lease_shared_committed", {
					provider,
					credentialRef: redactUsageCredentialIdentifier(credentialId),
				});
			}
		}

		const selectedAt = Date.now();
		const hasSelectionExclusions = effectiveExcludedCredentialIds.size > 0 || pinnedCredentialId !== undefined;
		const nextRoundRobinIndex =
			state.credentialIds.length > 0 ? (selectedIndex + 1) % state.credentialIds.length : selectedIndex;
		const nextActiveIndex = state.manualActiveCredentialId
			? selectedIndex
			: effectiveRotationMode === "round-robin" || effectiveRotationMode === "usage-based"
				? hasSelectionExclusions
					? selectedIndex
					: nextRoundRobinIndex
				: selectedIndex;
		if (this.isLightweightRotationProvider(provider)) {
			this.recordLightweightSelection(
				provider,
				state,
				credentialId,
				selectedIndex,
				nextActiveIndex,
				selectedAt,
				selectedPoolState,
			);
			if (selectedPoolState) {
				await this.flushLightweightRotationStateIfNeeded(provider);
			}
		} else {
			await this.storage.withLock((stored) => {
				const providerState = getProviderState(stored, provider);
				providerState.activeIndex = nextActiveIndex;
				providerState.usageCount[credentialId] = (providerState.usageCount[credentialId] ?? 0) + 1;
				providerState.lastUsedAt[credentialId] = selectedAt;
				if (selectedPoolState) {
					providerState.poolState = { ...selectedPoolState };
				}
				return { result: undefined, next: stored };
			});
		}

		multiAuthDebugLogger.log("credential_acquisition_timing", {
			provider,
			modelId: requestedModelId ?? "default",
			credentialRef: redactUsageCredentialIdentifier(credentialId),
			rotationMode: effectiveRotationMode,
			credentialCount: state.credentialIds.length,
			selectedIndex,
			totalMs: Date.now() - acquisitionStartedAt,
			selectionCommitMs: Date.now() - selectedAt,
		});

		return {
			provider,
			credentialId,
			credential: requestReadyCredential,
			secret: getCredentialRequestSecret(provider, requestReadyCredential),
			index: selectedIndex,
		};
	}

	/**
	 * Marks a credential as quota exhausted so it is skipped by the selector for a cooldown period.
	 * Rich quota classification is persisted additively for UI and recovery decisions.
	 */
	async markQuotaExceeded(
		provider: SupportedProviderId,
		credentialId: string,
		options?: {
			errorMessage?: string;
			isWeekly?: boolean;
			quotaClassification?: QuotaClassification;
			recommendedCooldownMs?: number;
			errorKind?: CredentialErrorKind;
		},
	): Promise<void> {
		const { errorMessage, isWeekly, quotaClassification, recommendedCooldownMs, errorKind } = options ?? {};
		const normalizedMessage =
			errorMessage?.trim() || (isWeekly ? "Weekly quota exhausted" : "Quota exhausted");
		const classifiedQuota = quotaClassification
			? {
				classification: quotaClassification,
				cooldownMs:
					typeof recommendedCooldownMs === "number" && Number.isFinite(recommendedCooldownMs)
						? recommendedCooldownMs
						: quotaClassifier.classifyFromMessage(normalizedMessage).cooldownMs,
				recoveryAction: quotaClassifier.getRecoveryAction(quotaClassification),
				confidence: "high" as const,
				source: "message" as const,
			} satisfies QuotaClassificationResult
			: quotaClassifier.classifyFromMessage(normalizedMessage);
		const weeklyQuota = isWeekly || classifiedQuota.classification === "weekly";
		const failureKind = errorKind ?? (weeklyQuota ? "quota_weekly" : "quota");
		await this.recordCredentialFailure(
			provider,
			credentialId,
			0,
			failureKind,
			normalizedMessage,
		);

		let cooldownMs =
			typeof classifiedQuota.cooldownMs === "number" && Number.isFinite(classifiedQuota.cooldownMs)
				? classifiedQuota.cooldownMs
				: QUOTA_COOLDOWN_MS;
		const quotaState = this.buildQuotaState(credentialId, normalizedMessage, classifiedQuota);

		const shouldApplyBalancerCooldown = await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: false };
			}

			const now = Date.now();
			providerState.lastQuotaError = providerState.lastQuotaError ?? {};
			providerState.lastQuotaError[credentialId] = normalizedMessage.slice(0, 500);
			providerState.quotaStates = providerState.quotaStates ?? {};
			providerState.quotaStates[credentialId] = quotaState;

			if (weeklyQuota) {
				providerState.weeklyQuotaAttempts = providerState.weeklyQuotaAttempts ?? {};
				const attempts = (providerState.weeklyQuotaAttempts[credentialId] ?? 0) + 1;
				providerState.weeklyQuotaAttempts[credentialId] = attempts;
				cooldownMs = Math.max(cooldownMs, getWeeklyQuotaCooldownMs(attempts));
			} else if (providerState.weeklyQuotaAttempts?.[credentialId] !== undefined) {
				delete providerState.weeklyQuotaAttempts[credentialId];
			}

			const currentUntil = providerState.quotaExhaustedUntil[credentialId] ?? 0;
			const nextUntil = Math.max(currentUntil, now + cooldownMs);
			providerState.quotaExhaustedUntil[credentialId] = nextUntil;
			providerState.quotaStates[credentialId] = {
				...providerState.quotaStates[credentialId],
				resetAt: nextUntil,
			};
			providerState.quotaErrorCount[credentialId] =
				(providerState.quotaErrorCount[credentialId] ?? 0) + 1;
			providerState.quotaErrorLastSeenAt = providerState.quotaErrorLastSeenAt ?? {};
			providerState.quotaErrorLastSeenAt[credentialId] = now;
			providerState.quotaRecoverySuccessCount = providerState.quotaRecoverySuccessCount ?? {};
			delete providerState.quotaRecoverySuccessCount[credentialId];

			return {
				result: providerState.rotationMode === "balancer",
				next: state,
			};
		});

		if (shouldApplyBalancerCooldown) {
			await this.keyDistributor.applyCooldown(
				credentialId,
				cooldownMs,
				weeklyQuota
					? "weekly-quota-exhausted"
					: failureKind === "rate_limit"
						? `rate-limit-${classifiedQuota.classification}`
						: `quota-${classifiedQuota.classification}`,
				provider,
				weeklyQuota,
				normalizedMessage,
			);
		}

		this.usageService.clearOperationalCredential(provider, credentialId);
	}

	/**
	 * Marks a credential as transiently unhealthy so repeated provider/transport failures
	 * back off exponentially instead of hammering the same key immediately.
	 */
	async markTransientProviderError(
		provider: SupportedProviderId,
		credentialId: string,
		errorMessage: string,
	): Promise<number> {
		const message = errorMessage.trim().slice(0, 500) || "Transient provider error";
		await this.recordCredentialFailure(provider, credentialId, 0, "provider_transient", message);
		let cooldownMs = TRANSIENT_COOLDOWN_BASE_MS;

		const shouldApplyBalancerCooldown = await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: false };
			}

			const now = Date.now();
			const attempts = (providerState.transientErrorCount[credentialId] ?? 0) + 1;
			providerState.transientErrorCount[credentialId] = attempts;
			providerState.lastTransientError = providerState.lastTransientError ?? {};
			providerState.lastTransientError[credentialId] = message;
			cooldownMs = computeExponentialBackoffMs(
				TRANSIENT_COOLDOWN_BASE_MS,
				attempts,
				TRANSIENT_COOLDOWN_MAX_MS,
			);

			const currentUntil = providerState.quotaExhaustedUntil[credentialId] ?? 0;
			providerState.quotaExhaustedUntil[credentialId] = Math.max(
				currentUntil,
				now + cooldownMs,
			);

			return {
				result: providerState.rotationMode === "balancer",
				next: state,
			};
		});

		if (shouldApplyBalancerCooldown) {
			await this.keyDistributor.applyCooldown(
				credentialId,
				cooldownMs,
				"transient-provider-error",
				provider,
				false,
				message,
			);
		}

		this.usageService.clearOperationalCredential(provider, credentialId);
		return cooldownMs;
	}

	/**
	 * Releases transient retry blocks for the selected credential when rotation has
	 * no alternate credential to try. This preserves transient failure counters for
	 * diagnostics/backoff while preventing the retry loop from immediately turning
	 * a provider-side transient error into "all credentials unavailable".
	 */
	async releaseTransientProviderRetryBlock(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<void> {
		await this.ensureInitialized();
		this.cascadeStateManager.removeCredential(provider, credentialId);

		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: undefined };
			}

			const hasTransientErrorState =
				typeof providerState.lastTransientError?.[credentialId] === "string" ||
				typeof providerState.transientErrorCount[credentialId] === "number";
			const hasQuotaState = providerState.quotaStates?.[credentialId] !== undefined;
			if (
				hasTransientErrorState &&
				!hasQuotaState &&
				providerState.quotaExhaustedUntil[credentialId] !== undefined
			) {
				delete providerState.quotaExhaustedUntil[credentialId];
				return { result: undefined, next: state };
			}

			return { result: undefined };
		});

		await this.persistProviderTelemetry(provider);
		this.usageService.clearOperationalCredential(provider, credentialId);
	}

	async markCredentialModelIncompatible(
		provider: SupportedProviderId,
		credentialId: string,
		modelId: string,
		errorMessage: string,
		cooldownMs: number = MODEL_INCOMPATIBILITY_COOLDOWN_MS,
	): Promise<number> {
		const normalizedModelId = normalizeModelId(modelId, provider);
		if (!normalizedModelId) {
			throw new Error(`Cannot mark model incompatibility for ${provider}: model ID is empty.`);
		}

		await this.ensureInitialized();
		const message = errorMessage.trim().slice(0, 500) ||
			`Credential is not compatible with ${formatModelReference(provider, normalizedModelId)}.`;
		const safeCooldownMs = typeof cooldownMs === "number" && Number.isFinite(cooldownMs) && cooldownMs > 0
			? cooldownMs
			: MODEL_INCOMPATIBILITY_COOLDOWN_MS;
		const blockedUntil = await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: 0 };
			}

			const now = Date.now();
			const nextBlockedUntil = now + safeCooldownMs;
			providerState.modelIncompatibilities = providerState.modelIncompatibilities ?? {};
			providerState.modelIncompatibilities[credentialId] =
				providerState.modelIncompatibilities[credentialId] ?? {};
			providerState.modelIncompatibilities[credentialId][normalizedModelId] = {
				modelId: normalizedModelId,
				blockedAt: now,
				blockedUntil: nextBlockedUntil,
				error: message,
			};

			return { result: nextBlockedUntil, next: state };
		});

		this.usageService.clearOperationalCredential(provider, credentialId);
		return blockedUntil;
	}

	async clearCredentialModelIncompatibility(
		provider: SupportedProviderId,
		credentialId: string,
		modelId: string,
	): Promise<void> {
		const normalizedModelId = normalizeModelId(modelId, provider);
		if (!normalizedModelId) {
			return;
		}

		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			const modelEntries = providerState.modelIncompatibilities?.[credentialId];
			if (!modelEntries?.[normalizedModelId]) {
				return { result: undefined };
			}

			delete modelEntries[normalizedModelId];
			if (Object.keys(modelEntries).length === 0) {
				delete providerState.modelIncompatibilities?.[credentialId];
			}
			if (
				providerState.modelIncompatibilities &&
				Object.keys(providerState.modelIncompatibilities).length === 0
			) {
				providerState.modelIncompatibilities = undefined;
			}

			return { result: undefined, next: state };
		});
	}

	/**
	 * Clears transient provider-error backoff after a successful request.
	 */
	async clearTransientProviderError(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<void> {
		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: undefined };
			}

			let didChange = false;
			if (providerState.transientErrorCount[credentialId] !== undefined) {
				delete providerState.transientErrorCount[credentialId];
				didChange = true;
			}
			if (providerState.lastTransientError?.[credentialId] !== undefined) {
				delete providerState.lastTransientError[credentialId];
				didChange = true;
			}
			if (
				typeof providerState.quotaExhaustedUntil[credentialId] === "number" &&
				providerState.quotaExhaustedUntil[credentialId] <= Date.now()
			) {
				delete providerState.quotaExhaustedUntil[credentialId];
				didChange = true;
			}

			return didChange ? { result: undefined, next: state } : { result: undefined };
		});
	}

	/**
	 * Clears the quota exhausted state for a credential (called on successful request).
	 * Resets weekly quota attempt counter.
	 */
	async clearQuotaExceeded(provider: SupportedProviderId, credentialId: string): Promise<void> {
		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: undefined };
			}

			const now = Date.now();
			let didChange = false;
			if (providerState.quotaExhaustedUntil[credentialId] !== undefined) {
				delete providerState.quotaExhaustedUntil[credentialId];
				didChange = true;
			}
			if (providerState.lastQuotaError?.[credentialId] !== undefined) {
				delete providerState.lastQuotaError[credentialId];
				didChange = true;
			}
			if (providerState.weeklyQuotaAttempts?.[credentialId] !== undefined) {
				delete providerState.weeklyQuotaAttempts[credentialId];
				didChange = true;
			}
			if (providerState.quotaStates?.[credentialId] !== undefined) {
				delete providerState.quotaStates[credentialId];
				didChange = true;
			}
			const quotaErrorCount = providerState.quotaErrorCount[credentialId] ?? 0;
			if (quotaErrorCount > 0) {
				providerState.quotaRecoverySuccessCount = providerState.quotaRecoverySuccessCount ?? {};
				const successCount = (providerState.quotaRecoverySuccessCount[credentialId] ?? 0) + 1;
				if (
					successCount >= QUOTA_ERROR_PROBE_SUCCESS_STREAK_REQUIRED ||
					now - (providerState.quotaErrorLastSeenAt?.[credentialId] ?? 0) >= QUOTA_ERROR_DECAY_WINDOW_MS
				) {
					delete providerState.quotaErrorCount[credentialId];
					delete providerState.quotaErrorLastSeenAt?.[credentialId];
					delete providerState.quotaRecoverySuccessCount[credentialId];
					providerState.quotaErrorCount[credentialId] = 0;
				} else {
					providerState.quotaRecoverySuccessCount[credentialId] = successCount;
				}
				didChange = true;
			}

			return didChange ? { result: undefined, next: state } : { result: undefined };
		});
	}

	/**
	 * Updates rotation mode for a provider.
	 */
	async setRotationMode(provider: SupportedProviderId, rotationMode: RotationMode): Promise<void> {
		await this.flushLightweightRotationStateIfNeeded(provider);
		const rotationModes = writeMultiAuthProviderRotationMode(provider, rotationMode, this.configPath);
		this.extensionConfig = {
			...this.extensionConfig,
			rotationModes,
		};
		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			providerState.rotationMode = resolveDefaultRotationMode(provider);
			return { result: undefined, next: state };
		});
	}

	/**
	 * Returns true when balancer mode should be preferred for a provider.
	 */
	async shouldUseBalancerMode(provider: SupportedProviderId): Promise<boolean> {
		if (!USAGE_PROVIDER_IDS.has(provider)) {
			return true;
		}

		const state = await this.syncProviderState(provider);
		if (state.credentialIds.length === 0) {
			return false;
		}

		const credentialsById = await this.authWriter.getCredentials(state.credentialIds);
		for (const credentialId of state.credentialIds) {
			const credential = credentialsById.get(credentialId);
			if (!credential || credential.type !== "api_key") {
				return false;
			}
		}

		return true;
	}

	/**
	 * Auto-selects the best currently available credential for each provider.
	 */
	async autoActivatePreferredCredentials(options: AutoActivateOptions = {}): Promise<void> {
		await this.ensureInitialized();
		const providers = await this.providerRegistry.discoverProviderIds();
		const hiddenProviders = await this.readHiddenProviderSet();
		for (const provider of providers) {
			if (hiddenProviders.has(provider)) {
				await this.cancelProviderOperationalWork(provider);
				continue;
			}
			let state = await this.syncProviderState(provider);
			if (state.credentialIds.length === 0) {
				continue;
			}

			if (state.manualActiveCredentialId) {
				const manualCredentialId = state.manualActiveCredentialId;
				const manualIndex = state.credentialIds.indexOf(manualCredentialId);
				if (manualIndex >= 0) {
					if (state.activeIndex !== manualIndex) {
						await this.storage.withLock((stored) => {
							const providerState = getProviderState(stored, provider);
							const nextManualIndex = providerState.credentialIds.indexOf(manualCredentialId);
							if (nextManualIndex >= 0) {
								providerState.activeIndex = nextManualIndex;
							}
							return { result: undefined, next: stored };
						});
					}
					continue;
				}

				await this.clearManualActiveCredential(provider);
				state = await this.syncProviderState(provider);
				if (state.credentialIds.length === 0) {
					continue;
				}
			}

			const disabledCredentialIds = await this.getDisabledCredentialIds(state);
			let now = Date.now();
			let available = buildAvailableSet(state, now, disabledCredentialIds);
			if (available.size === 0 && !options.avoidUsageApi) {
				await this.reconcileBlockedCredentialsFromUsage(provider, state, disabledCredentialIds);
				state = await this.syncProviderState(provider);
				now = Date.now();
				available = buildAvailableSet(state, now, disabledCredentialIds);
			}

			if (available.size === 0) {
				continue;
			}

			const usagePreferredIndex = options.avoidUsageApi
				? getUsageBasedCandidateIndex(state, available)
				: await this.getUsageBasedCandidateIndex(
						provider,
						state,
						available,
						undefined,
						"startup-refinement",
					);
			const roundRobinIndex = getRoundRobinCandidateIndex(state, available);
			const selectedIndex = usagePreferredIndex ?? roundRobinIndex;
			if (selectedIndex === undefined) {
				continue;
			}

			await this.storage.withLock((stored) => {
				const providerState = getProviderState(stored, provider);
				if (selectedIndex < 0 || selectedIndex >= providerState.credentialIds.length) {
					return { result: undefined, next: stored };
				}

				providerState.activeIndex = selectedIndex;
				return { result: undefined, next: stored };
			});
		}
	}

	/**
	 * Warms operational usage caches from the session lifecycle. The refresh is
	 * cache-aware and bounded so large credential pools improve progressively
	 * without making provider registration or startup perform a bulk usage crawl.
	 */
	async warmupOperationalUsageCaches(providers?: readonly SupportedProviderId[]): Promise<void> {
		await this.ensureInitialized();
		const providerIds = providers ?? await this.providerRegistry.discoverProviderIds();
		const uniqueProviderIds = [...new Set(providerIds.map((provider) => provider.trim()).filter(Boolean))];
		for (const provider of uniqueProviderIds) {
			if (this.isShuttingDown) {
				return;
			}
			await this.warmupOperationalUsageCache(provider);
		}
	}

	private compareOperationalUsageWarmupCandidates(
		left: OperationalUsageWarmupCandidate,
		right: OperationalUsageWarmupCandidate,
	): number {
		const getPriority = (candidate: OperationalUsageWarmupCandidate): number => {
			if (candidate.isActive) {
				return 0;
			}
			if (!candidate.hasUsageSnapshot) {
				return 1;
			}
			return candidate.needsRefresh ? 2 : 3;
		};
		const priorityComparison = getPriority(left) - getPriority(right);
		if (priorityComparison !== 0) {
			return priorityComparison;
		}
		if (left.quotaErrorCount !== right.quotaErrorCount) {
			return left.quotaErrorCount - right.quotaErrorCount;
		}
		if (left.usageCount !== right.usageCount) {
			return left.usageCount - right.usageCount;
		}
		if (left.lastUsedAt !== right.lastUsedAt) {
			return left.lastUsedAt - right.lastUsedAt;
		}
		return left.index - right.index;
	}

	private selectOperationalUsageWarmupCredentialIds(
		provider: SupportedProviderId,
		state: ProviderRotationState,
	): { credentialIds: string[]; shouldScheduleFollowUp: boolean } {
		const activeCredentialId = state.credentialIds[state.activeIndex];
		const now = Date.now();
		const excludedCredentialIds = getCredentialBackgroundExclusionIds(state);
		const candidates = state.credentialIds
			.map((credentialId, index): OperationalUsageWarmupCandidate | null => {
				if (excludedCredentialIds.has(credentialId)) {
					return null;
				}
				const cachedUsage = this.readCachedOperationalUsageForSelection(provider, credentialId);
				const snapshot = cachedUsage.usage?.snapshot ?? null;
				return {
					credentialId,
					index,
					usageCount: state.usageCount[credentialId] ?? 0,
					quotaErrorCount: getEffectiveQuotaErrorCount(state, credentialId, now),
					lastUsedAt: state.lastUsedAt[credentialId] ?? 0,
					isActive: credentialId === activeCredentialId,
					hasUsageSnapshot: snapshot !== null,
					needsRefresh: cachedUsage.needsRefresh,
				};
			})
			.filter((candidate): candidate is OperationalUsageWarmupCandidate => candidate !== null)
			.filter((candidate) => candidate.needsRefresh || !candidate.hasUsageSnapshot)
			.sort((left, right) => this.compareOperationalUsageWarmupCandidates(left, right));

		if (candidates.length === 0) {
			this.operationalUsageWarmupCursors.delete(provider);
			return { credentialIds: [], shouldScheduleFollowUp: false };
		}

		const shouldScheduleFollowUp = candidates.some((candidate) => !candidate.hasUsageSnapshot);
		const windowSize = this.usageCoordinator.getOperationWindowSize("startup-refinement");
		const batchSize = Math.min(
			candidates.length,
			Math.max(windowSize, windowSize * OPERATIONAL_USAGE_WARMUP_WINDOW_MULTIPLIER),
		);
		const pinnedCandidates = candidates.filter((candidate) => candidate.isActive);
		const rotatingCandidates = candidates.filter((candidate) => !candidate.isActive);
		const cursor = rotatingCandidates.length > 0
			? (this.operationalUsageWarmupCursors.get(provider) ?? 0) % rotatingCandidates.length
			: 0;
		const rotatedCandidates = rotatingCandidates.length > 0
			? [...rotatingCandidates.slice(cursor), ...rotatingCandidates.slice(0, cursor)]
			: [];
		const selectedCandidates = [...pinnedCandidates, ...rotatedCandidates].slice(0, batchSize);
		if (rotatingCandidates.length > 0 && selectedCandidates.length < candidates.length) {
			const consumedRotatingCount = selectedCandidates.filter((candidate) => !candidate.isActive).length;
			this.operationalUsageWarmupCursors.set(
				provider,
				(cursor + consumedRotatingCount) % rotatingCandidates.length,
			);
		} else {
			this.operationalUsageWarmupCursors.delete(provider);
		}
		return {
			credentialIds: selectedCandidates.map((candidate) => candidate.credentialId),
			shouldScheduleFollowUp,
		};
	}

	private scheduleOperationalUsageWarmupFollowUp(provider: SupportedProviderId): void {
		if (this.isShuttingDown || this.operationalUsageWarmupTimers.has(provider)) {
			return;
		}
		const timer = setTimeout(() => {
			this.operationalUsageWarmupTimers.delete(provider);
			if (this.isShuttingDown) {
				return;
			}
			void this.warmupOperationalUsageCache(provider).catch((error: unknown) => {
				multiAuthDebugLogger.log("provider_operational_usage_warmup_follow_up_failed", {
					provider,
					message: getErrorMessage(error),
				});
			});
		}, OPERATIONAL_USAGE_WARMUP_FOLLOW_UP_DELAY_MS);
		this.operationalUsageWarmupTimers.set(provider, timer);
	}

	async warmupOperationalUsageCache(provider: SupportedProviderId): Promise<number> {
		await this.ensureInitialized();
		if (this.isShuttingDown || await this.isProviderHidden(provider)) {
			this.clearOperationalUsageWarmupTimer(provider);
			return 0;
		}
		if (!this.usageService.hasProvider(provider)) {
			this.clearOperationalUsageWarmupTimer(provider);
			return 0;
		}
		const state = await this.syncProviderState(provider);
		if (state.credentialIds.length === 0) {
			this.clearOperationalUsageWarmupTimer(provider);
			this.operationalUsageWarmupCursors.delete(provider);
			return 0;
		}
		const selection = this.selectOperationalUsageWarmupCredentialIds(provider, state);
		if (selection.credentialIds.length === 0) {
			return 0;
		}
		const count = this.enqueueAllCredentialUsageRefresh(
			provider,
			selection.credentialIds,
			"startup-refinement",
			{ maxAgeMs: getSelectionUsageMaxAgeMs(provider), forceRefresh: false },
		);
		if (selection.shouldScheduleFollowUp) {
			this.scheduleOperationalUsageWarmupFollowUp(provider);
		}
		multiAuthDebugLogger.log("provider_operational_usage_warmup_dispatched", {
			provider,
			credentialCount: state.credentialIds.length,
			candidateCount: selection.credentialIds.length,
			refreshQueuedCount: count,
			cacheAware: true,
			followUpScheduled: selection.shouldScheduleFollowUp,
		});
		return count;
	}

	/**
	 * Returns provider IDs that currently have credentials in auth.json.
	 */
	async getProvidersWithCredentials(): Promise<SupportedProviderId[]> {
		await this.ensureInitialized();
		const providers = await this.providerRegistry.discoverProviderIds();
		const providersWithCredentials = new Set(await this.authWriter.listProviderIds(providers));
		return providers.filter((provider) => providersWithCredentials.has(provider));
	}

	/**
	 * Returns status information for providers that currently have credentials.
	 */
	async getStatus(): Promise<ProviderStatus[]> {
		const providers = await this.getProvidersWithCredentials();
		const statuses = await Promise.all(providers.map((provider) => this.getProviderStatus(provider)));
		return statuses.filter((status) => status.credentials.length > 0);
	}

	private getCloudflareIdentityLookup(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredAuthCredential,
		options: { forceRefresh?: boolean } = {},
	): Promise<CloudflareCredentialIdentity | null> {
		const cacheKey = createUsageCredentialCacheKey(provider, credentialId, {
			accessToken: getCredentialRequestSecret(provider, credential),
			credential: credential as unknown as Record<string, unknown>,
		});
		const existing = this.cloudflareIdentityLookupByCacheKey.get(cacheKey);
		if (existing && !options.forceRefresh) {
			return existing;
		}

		const lookup = fetchCloudflareCredentialIdentity(
			getCredentialRequestSecret(provider, credential),
			{ baseUrl: credential.request?.baseUrl },
		).catch((error: unknown) => {
			multiAuthDebugLogger.log("cloudflare_identity_lookup_failed", {
				provider,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				errorMessage: getErrorMessage(error).slice(0, 200),
			});
			return null;
		});
		this.cloudflareIdentityLookupByCacheKey.set(cacheKey, lookup);
		return lookup;
	}

	private async persistCloudflareFriendlyNameForCredential(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredAuthCredential,
	): Promise<void> {
		if (!isCloudflareWorkersAiProvider(provider) || credential.type !== "api_key") {
			return;
		}

		const identity = await this.getCloudflareIdentityLookup(provider, credentialId, credential);
		if (!identity?.displayName) {
			return;
		}

		await this.persistInferredFriendlyNames(
			provider,
			new Map([[credentialId, identity.displayName]]),
		);
	}

	private async persistInferredFriendlyNames(
		provider: SupportedProviderId,
		friendlyNames: ReadonlyMap<string, string>,
	): Promise<void> {
		if (friendlyNames.size === 0) {
			return;
		}

		await this.storage.withLock((stored) => {
			const providerState = getProviderState(stored, provider);
			let didChange = false;
			for (const [credentialId, friendlyName] of friendlyNames.entries()) {
				const normalized = friendlyName.trim();
				if (
					!normalized ||
					normalized === credentialId ||
					!providerState.credentialIds.includes(credentialId) ||
					providerState.friendlyNames[credentialId]
				) {
					continue;
				}
				providerState.friendlyNames[credentialId] = normalized;
				didChange = true;
			}

			if (!didChange) {
				return { result: undefined };
			}
			normalizeProviderState(providerState, provider);
			return { result: undefined, next: stored };
		});
	}

	private async resolveCloudflareInferredFriendlyNames(
		provider: SupportedProviderId,
		state: ProviderRotationState,
		credentialsById: ReadonlyMap<string, StoredAuthCredential>,
	): Promise<Map<string, string>> {
		const friendlyNames = new Map<string, string>();
		if (!isCloudflareWorkersAiProvider(provider)) {
			return friendlyNames;
		}

		const pending = state.credentialIds
			.map((credentialId) => ({
				credentialId,
				credential: credentialsById.get(credentialId),
			}))
			.filter(
				(entry): entry is { credentialId: string; credential: StoredAuthCredential } =>
					entry.credential?.type === "api_key" && !state.friendlyNames[entry.credentialId],
			);
		if (pending.length === 0) {
			return friendlyNames;
		}

		const maxConcurrentLookups = 8;
		let cursor = 0;
		const workers = Array.from(
			{ length: Math.min(maxConcurrentLookups, pending.length) },
			async () => {
				while (cursor < pending.length) {
					const entry = pending[cursor];
					cursor += 1;
					if (!entry) {
						continue;
					}
					const identity = await this.getCloudflareIdentityLookup(
						provider,
						entry.credentialId,
						entry.credential,
					);
					if (identity?.displayName) {
						friendlyNames.set(entry.credentialId, identity.displayName);
						multiAuthDebugLogger.log("cloudflare_identity_lookup_succeeded", {
							provider,
							credentialRef: redactUsageCredentialIdentifier(entry.credentialId),
							hasEmail: Boolean(identity.email),
							hasAccountName: Boolean(identity.accountName),
							tokenStatus: identity.tokenStatus,
						});
					}
				}
			},
		);
		await Promise.all(workers);
		await this.persistInferredFriendlyNames(provider, friendlyNames);
		return friendlyNames;
	}

	/**
	 * Returns status information for a single provider.
	 */
	async getProviderStatus(
		provider: SupportedProviderId,
		options: { allowExternalIdentityLookups?: boolean } = {},
	): Promise<ProviderStatus> {
		const state = await this.syncProviderState(provider);
		const isHiddenProvider = await this.isProviderHidden(provider);
		const now = Date.now();
		const credentials: CredentialStatus[] = [];
		const credentialsById = await this.authWriter.getCredentials(state.credentialIds);
		const cloudflareInferredFriendlyNames = isHiddenProvider || options.allowExternalIdentityLookups === false
			? new Map<string, string>()
			: await this.resolveCloudflareInferredFriendlyNames(
				provider,
				state,
				credentialsById,
			);

		for (let index = 0; index < state.credentialIds.length; index += 1) {
			const credentialId = state.credentialIds[index];
			const credential = credentialsById.get(credentialId);
			if (!credential) {
				continue;
			}

			const persistedFriendlyName = state.friendlyNames[credentialId];
			const inferredFriendlyName =
				credential.type === "oauth"
					? inferCredentialFriendlyName(provider, credentialId, credential)
					: undefined;
			const identityEmail = credential.type === "oauth"
				? getOAuthCredentialIdentityEmail(provider, credential)
				: undefined;
			const identityPlanType = credential.type === "oauth"
				? getOAuthCredentialIdentityPlanType(provider, credential)
				: undefined;
			const expiresAt = getCredentialExpiration(provider, credential);
			const isExpired = typeof expiresAt === "number" ? expiresAt <= now : false;
			const usage = this.hasUsageProvider(provider)
				? this.getCachedCredentialUsageDisplaySnapshot(provider, credentialId)
				: null;
			const disabledError = state.disabledCredentials?.[credentialId]?.error;
			const lastQuotaError = state.lastQuotaError?.[credentialId];

			credentials.push({
				credentialId,
				credentialType: credential.type,
				redactedSecret: formatCredentialRedaction(credential),
				friendlyName:
					persistedFriendlyName ??
					inferredFriendlyName ??
					cloudflareInferredFriendlyNames.get(credentialId),
				identityEmail,
				identityPlanType,
				index,
				isActive: index === state.activeIndex,
				isManualActive: state.manualActiveCredentialId === credentialId,
				expiresAt,
				isExpired,
				quotaExhaustedUntil: state.quotaExhaustedUntil[credentialId],
				usageCount: state.usageCount[credentialId] ?? 0,
				quotaErrorCount: state.quotaErrorCount[credentialId] ?? 0,
				transientErrorCount: state.transientErrorCount?.[credentialId],
				weeklyQuotaAttempts: state.weeklyQuotaAttempts?.[credentialId],
				lastQuotaError,
				lastTransientError: state.lastTransientError?.[credentialId],
				lastUsedAt: state.lastUsedAt[credentialId],
				usageSnapshot: usage?.snapshot,
				usageSnapshotDisplayOnly: usage?.displayOnly,
				usageFetchError: usage?.error ?? undefined,
				disabledError,
				opencodeGoWorkspaceId: credential.opencodeGo?.workspaceId,
			});
		}

		return {
			provider,
			rotationMode: state.rotationMode,
			activeIndex: state.activeIndex,
			manualActiveCredentialId: state.manualActiveCredentialId,
			credentials,
		};
	}

	private async getDisabledCredentialIds(state: ProviderRotationState): Promise<Set<string>> {
		const disabledCredentialIds = new Set<string>();
		for (const credentialId of Object.keys(state.disabledCredentials)) {
			if (state.credentialIds.includes(credentialId)) {
				disabledCredentialIds.add(credentialId);
			}
		}
		return disabledCredentialIds;
	}

	private async releaseOneRecoverableCooldownLock(
		provider: SupportedProviderId,
		state: ProviderRotationState,
		excludedCredentialIds?: Set<string>,
	): Promise<ProviderRotationState | null> {
		const now = Date.now();
		let candidateCredentialId: string | null = null;
		let candidateExhaustedUntil = Number.POSITIVE_INFINITY;

		for (const credentialId of state.credentialIds) {
			if (excludedCredentialIds?.has(credentialId) || state.disabledCredentials?.[credentialId]) {
				continue;
			}
			if (state.quotaStates?.[credentialId]?.recoveryAction.requiresManual) {
				continue;
			}

			const exhaustedUntil = state.quotaExhaustedUntil[credentialId];
			if (typeof exhaustedUntil !== "number" || exhaustedUntil <= now) {
				continue;
			}

			if (exhaustedUntil < candidateExhaustedUntil) {
				candidateCredentialId = credentialId;
				candidateExhaustedUntil = exhaustedUntil;
			}
		}

		if (!candidateCredentialId) {
			return null;
		}

		const releasedCredentialId = candidateCredentialId;
		const didUpdate = await this.storage.withLock((stored) => {
			const providerState = getProviderState(stored, provider);
			const currentExhaustedUntil = providerState.quotaExhaustedUntil[releasedCredentialId];
			if (typeof currentExhaustedUntil !== "number" || currentExhaustedUntil <= Date.now()) {
				return { result: false };
			}
			if (providerState.disabledCredentials?.[releasedCredentialId]) {
				return { result: false };
			}
			if (providerState.quotaStates?.[releasedCredentialId]?.recoveryAction.requiresManual) {
				return { result: false };
			}

			delete providerState.quotaExhaustedUntil[releasedCredentialId];
			delete providerState.quotaStates?.[releasedCredentialId];
			if (providerState.quotaStates && Object.keys(providerState.quotaStates).length === 0) {
				providerState.quotaStates = undefined;
			}
			return { result: true, next: stored };
		});

		if (!didUpdate) {
			return null;
		}

		multiAuthDebugLogger.log("credential_cooldown_released_for_rotation", {
			provider,
			credentialRef: redactUsageCredentialIdentifier(releasedCredentialId),
			hasUsageProvider: this.usageService.hasProvider(provider),
			exhaustedUntil: candidateExhaustedUntil,
		});
		this.usageService.clearOperationalCredential(provider, releasedCredentialId);
		return this.syncProviderState(provider);
	}

	private async getUsageBasedCandidateIndex(
		provider: SupportedProviderId,
		state: ProviderRotationState,
		available: Set<string>,
		usageContext?: CredentialUsageContext,
		operation: UsageCoordinationOperation = "selection",
	): Promise<number | undefined> {
		const selectionStartedAt = Date.now();
		throwIfAborted(
			usageContext?.signal,
			`Usage-based credential selection aborted for ${provider}.`,
		);
		const fallbackIndex = getUsageBasedCandidateIndex(state, available);
		const backgroundExcludedCredentialIds = getCredentialBackgroundExclusionIds(state);
		const candidates = state.credentialIds
			.map((credentialId, index) => ({
				credentialId,
				index,
				usageCount: state.usageCount[credentialId] ?? 0,
				quotaErrorCount: getEffectiveQuotaErrorCount(state, credentialId, selectionStartedAt),
				lastUsedAt: state.lastUsedAt[credentialId] ?? 0,
			}))
			.filter((candidate) => available.has(candidate.credentialId));

		if (candidates.length === 0) {
			return undefined;
		}

		if (provider === OPENAI_CODEX_PROVIDER_ID && operation === "selection") {
			return this.getCacheFirstUsageBasedCandidateIndex(
				provider,
				state,
				candidates,
				fallbackIndex,
				selectionStartedAt,
				usageContext,
			);
		}

		const candidateWindows = this.usageCoordinator.selectCredentialRequestWindows(
			candidates.map((candidate) => ({ ...candidate, provider })),
			operation,
		);
		let fallbackWindowIndex: number | undefined;

		for (const candidateWindow of candidateWindows) {
			const usageResults = await Promise.allSettled(
				candidateWindow.map((candidate) =>
					backgroundExcludedCredentialIds.has(candidate.credentialId)
						? Promise.resolve({
								snapshot: null,
								error: null,
								fromCache: false,
								displayOnly: true,
							} satisfies CredentialUsageSnapshotResult)
						: this.getCredentialUsageSnapshotWithContext(
							provider,
							candidate.credentialId,
							{
								maxAgeMs: getSelectionUsageMaxAgeMs(provider),
								coordinationOperation: operation,
							},
							usageContext,
						),
				),
			);

			throwIfAborted(
				usageContext?.signal,
				`Usage-based credential selection aborted for ${provider}.`,
			);

			const ranked = candidateWindow
				.map((candidate, index) => {
					const usageResult = usageResults[index];
					if (usageResult?.status !== "fulfilled") {
						return {
							...candidate,
							hasUsageSnapshot: false,
							isUntouched: false,
							usedPercent: null,
							primaryUsedPercent: null,
							secondaryUsedPercent: null,
							resetAt: null,
							quotaState: { state: "unknown" } as UsageQuotaState,
						};
					}

					const snapshot = usageResult.value.snapshot;
					return {
						...candidate,
						hasUsageSnapshot: snapshot !== null,
						isUntouched: isUsageSnapshotUntouched(snapshot),
						usedPercent: getUsageSnapshotUsedPercent(snapshot),
						primaryUsedPercent: getUsageSnapshotWindowUsedPercent(snapshot, "primary"),
						secondaryUsedPercent: getUsageSnapshotWindowUsedPercent(snapshot, "secondary"),
						resetAt: getUsageSnapshotResetAt(snapshot),
						quotaState: inferOperationalQuotaStateFromUsage(provider, snapshot),
					};
				})
				.filter((candidate) => candidate.quotaState.state !== "exhausted");

			if (ranked.length === 0) {
				continue;
			}

			const hasUsageSignals = ranked.some((candidate) => candidate.hasUsageSnapshot);
			if (!hasUsageSignals) {
				fallbackWindowIndex ??= ranked[0]?.index;
				continue;
			}

			ranked.sort((left, right) => {
				if (left.hasUsageSnapshot !== right.hasUsageSnapshot) {
					return left.hasUsageSnapshot ? -1 : 1;
				}
				if (left.isUntouched !== right.isUntouched) {
					return left.isUntouched ? -1 : 1;
				}
				const secondaryUsageComparison = compareNullableNumberAscending(
					left.secondaryUsedPercent,
					right.secondaryUsedPercent,
				);
				if (secondaryUsageComparison !== 0) {
					return secondaryUsageComparison;
				}
				const primaryUsageComparison = compareNullableNumberAscending(
					left.primaryUsedPercent,
					right.primaryUsedPercent,
				);
				if (primaryUsageComparison !== 0) {
					return primaryUsageComparison;
				}
				const usageComparison = compareNullableNumberAscending(
					left.usedPercent,
					right.usedPercent,
				);
				if (usageComparison !== 0) {
					return usageComparison;
				}
				const resetComparison = compareNullableNumberAscending(left.resetAt, right.resetAt);
				if (resetComparison !== 0) {
					return resetComparison;
				}
				if (left.quotaErrorCount !== right.quotaErrorCount) {
					return left.quotaErrorCount - right.quotaErrorCount;
				}
				if (left.usageCount !== right.usageCount) {
					return left.usageCount - right.usageCount;
				}
				if (left.lastUsedAt !== right.lastUsedAt) {
					return right.lastUsedAt - left.lastUsedAt;
				}
				return left.index - right.index;
			});

			return ranked[0]?.index ?? fallbackIndex ?? fallbackWindowIndex;
		}

		return fallbackIndex ?? fallbackWindowIndex;
	}

	private isCodexSelectionUsageExhausted(usage: CredentialUsageSnapshotResult): boolean {
		if (usage.fromCache || usage.displayOnly || !usage.snapshot) {
			return false;
		}
		const quotaState = inferOperationalQuotaStateFromUsage(OPENAI_CODEX_PROVIDER_ID, usage.snapshot);
		const usedPercent = getUsageSnapshotUsedPercent(usage.snapshot);
		return quotaState.state === "exhausted" ||
			(usedPercent !== null && usedPercent >= CODEX_SELECTION_EXHAUSTED_USED_PERCENT);
	}

	private async validateDelegatedCredentialSelection(
		provider: SupportedProviderId,
		credentialId: string,
		signal?: AbortSignal,
	): Promise<{ available: boolean; reason?: string }> {
		if (provider !== OPENAI_CODEX_PROVIDER_ID) {
			return { available: true };
		}

		throwIfAborted(signal, `Delegated credential usage validation aborted for ${provider}/${credentialId}.`);
		if (this.isCredentialCachedBackgroundExcluded(provider, credentialId)) {
			return { available: true };
		}
		const cachedUsage = this.readCachedOperationalUsageForSelection(provider, credentialId);
		const snapshot = cachedUsage.usage?.snapshot ?? null;
		const cachedUsedPercent = getUsageSnapshotUsedPercent(snapshot);
		if (snapshot) {
			const cachedQuotaState = inferOperationalQuotaStateFromUsage(provider, snapshot);
			if (cachedQuotaState.state === "exhausted" ||
				(cachedUsedPercent !== null && cachedUsedPercent >= CODEX_SELECTION_EXHAUSTED_USED_PERCENT)) {
				return { available: false, reason: "cached-usage-exhausted" };
			}
		}

		const shouldRefreshBeforeDelegation = snapshot === null ||
			cachedUsage.needsRefresh ||
			(cachedUsedPercent !== null && cachedUsedPercent >= CODEX_STALE_SELECTION_REFRESH_THRESHOLD_PERCENT);
		if (!shouldRefreshBeforeDelegation) {
			return { available: true };
		}

		if (snapshot !== null) {
			this.enqueueCredentialUsageRefresh(provider, [credentialId], "selection");
			multiAuthDebugLogger.log("delegated_credential_usage_stale_served", {
				provider,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				needsRefresh: cachedUsage.needsRefresh,
				usedPercent: cachedUsedPercent,
			});
			return { available: true };
		}

		try {
			const liveUsage = await this.getCredentialUsageSnapshotWithContext(
				provider,
				credentialId,
				{
					forceRefresh: true,
					maxAgeMs: getSelectionUsageMaxAgeMs(provider),
					coordinationOperation: "selection",
					signal,
				},
			);
			return this.isCodexSelectionUsageExhausted(liveUsage)
				? { available: false, reason: "live-usage-exhausted" }
				: { available: true };
		} catch (error: unknown) {
			if (error instanceof Error && error.name === "AbortError") {
				throw error;
			}
			multiAuthDebugLogger.log("delegated_credential_usage_validation_failed", {
				provider,
				credentialRef: redactUsageCredentialIdentifier(credentialId),
				message: getErrorMessage(error),
			});
			return { available: true };
		}
	}

	private getBalancerUsageSnapshots(
		provider: SupportedProviderId,
		credentialIds: readonly string[],
		signal?: AbortSignal,
	): Record<string, BalancerUsageSnapshot | undefined> {
		if (provider !== OPENAI_CODEX_PROVIDER_ID || credentialIds.length === 0) {
			return {};
		}
		throwIfAborted(signal, `Balancer usage snapshot lookup aborted for ${provider}.`);
		const snapshots: Record<string, BalancerUsageSnapshot | undefined> = {};
		const refreshCredentialIds: string[] = [];
		for (const credentialId of credentialIds) {
			if (this.isCredentialCachedBackgroundExcluded(provider, credentialId)) {
				continue;
			}
			const cachedUsage = this.readCachedOperationalUsageForSelection(provider, credentialId);
			const usage = cachedUsage.usage;
			const snapshot = usage?.snapshot ?? null;
			if (cachedUsage.needsRefresh || snapshot === null) {
				refreshCredentialIds.push(credentialId);
			}
			if (!usage || snapshot === null || usage.displayOnly) {
				continue;
			}
			const usedPercent = getUsageSnapshotUsedPercent(snapshot);
			snapshots[credentialId] = {
				snapshot,
				usedPercent,
				quotaState: inferOperationalQuotaStateFromUsage(provider, snapshot),
				fromCache: usage.fromCache,
				needsRefresh: cachedUsage.needsRefresh,
			};
		}
		this.enqueueCredentialUsageRefresh(provider, refreshCredentialIds, "selection");
		return snapshots;
	}

	private async getCacheFirstUsageBasedCandidateIndex(
		provider: SupportedProviderId,
		state: ProviderRotationState,
		candidates: ReadonlyArray<{
			credentialId: string;
			index: number;
			usageCount: number;
			quotaErrorCount: number;
			lastUsedAt: number;
		}>,
		fallbackIndex: number | undefined,
		selectionStartedAt: number,
		usageContext?: CredentialUsageContext,
	): Promise<number | undefined> {
		type RankedCandidate = (typeof candidates)[number] & {
			hasUsageSnapshot: boolean;
			isStaleUsage: boolean;
			isCachedExhausted: boolean;
			isUntouched: boolean;
			usedPercent: number | null;
			primaryUsedPercent: number | null;
			secondaryUsedPercent: number | null;
			resetAt: number | null;
		};

		let staleCredentialCount = 0;
		let syncValidationCount = 0;
		let staleExhaustedSkipCount = 0;
		const backgroundExcludedCredentialIds = getCredentialBackgroundExclusionIds(state);
		const hydrateCandidateUsage = (
			candidate: (typeof candidates)[number],
			usage: CredentialUsageSnapshotResult | null,
			isStaleUsage: boolean,
		): RankedCandidate => {
			const snapshot = usage?.snapshot ?? null;
			const usedPercent = getUsageSnapshotUsedPercent(snapshot);
			const quotaState = inferOperationalQuotaStateFromUsage(provider, snapshot);
			const isCachedExhausted = snapshot !== null && (quotaState.state === "exhausted" ||
				(usedPercent !== null && usedPercent >= CODEX_SELECTION_EXHAUSTED_USED_PERCENT));
			return {
				...candidate,
				hasUsageSnapshot: snapshot !== null,
				isStaleUsage,
				isCachedExhausted,
				isUntouched: isUsageSnapshotUntouched(snapshot),
				usedPercent,
				primaryUsedPercent: getUsageSnapshotWindowUsedPercent(snapshot, "primary"),
				secondaryUsedPercent: getUsageSnapshotWindowUsedPercent(snapshot, "secondary"),
				resetAt: getUsageSnapshotResetAt(snapshot),
			};
		};

		const ranked = candidates.map((candidate) => {
			if (backgroundExcludedCredentialIds.has(candidate.credentialId)) {
				return hydrateCandidateUsage(candidate, null, false);
			}
			const cachedUsage = this.readCachedOperationalUsageForSelection(
				provider,
				candidate.credentialId,
			);
			if (cachedUsage.needsRefresh) {
				staleCredentialCount += 1;
			}
			return hydrateCandidateUsage(candidate, cachedUsage.usage, cachedUsage.needsRefresh);
		});

		const backgroundRefreshCredentialIds = new Set(
			ranked
				.filter(
					(candidate) =>
						!backgroundExcludedCredentialIds.has(candidate.credentialId) &&
						(candidate.isStaleUsage || !candidate.hasUsageSnapshot),
				)
				.map((candidate) => candidate.credentialId),
		);
		let selectableRanked = ranked.filter((candidate) => {
			if (!candidate.isCachedExhausted) {
				return true;
			}
			staleExhaustedSkipCount += 1;
			return false;
		});
		let hasUsageSignals = selectableRanked.some((candidate) => candidate.hasUsageSnapshot);

		if (selectableRanked.length > 1 && !hasUsageSignals) {
			const syncCandidates = this.usageCoordinator.selectCredentialRequests(
				selectableRanked
					.filter((candidate) => !backgroundExcludedCredentialIds.has(candidate.credentialId))
					.map((candidate) => ({ ...candidate, provider })),
				"selection",
			);
			syncValidationCount = syncCandidates.length;
			const usageResults = await Promise.allSettled(
				syncCandidates.map((candidate) =>
					this.getCredentialUsageSnapshotWithContext(
						provider,
						candidate.credentialId,
						{
							forceRefresh: true,
							maxAgeMs: getSelectionUsageMaxAgeMs(provider),
							coordinationOperation: "selection",
						},
						usageContext,
					),
				),
			);
			throwIfAborted(
				usageContext?.signal,
				`Usage-based credential selection aborted for ${provider}.`,
			);

			const refreshedByCredentialId = new Map<string, RankedCandidate>();
			for (let index = 0; index < syncCandidates.length; index += 1) {
				const candidate = syncCandidates[index];
				const usageResult = usageResults[index];
				if (!candidate || usageResult?.status !== "fulfilled") {
					continue;
				}
				backgroundRefreshCredentialIds.delete(candidate.credentialId);
				refreshedByCredentialId.set(
					candidate.credentialId,
					hydrateCandidateUsage(candidate, usageResult.value, false),
				);
			}

			selectableRanked = selectableRanked
				.map((candidate) => refreshedByCredentialId.get(candidate.credentialId) ?? candidate)
				.filter((candidate) => {
					if (!candidate.isCachedExhausted) {
						return true;
					}
					staleExhaustedSkipCount += 1;
					return false;
				});
			hasUsageSignals = selectableRanked.some((candidate) => candidate.hasUsageSnapshot);
		}

		let selectedIndex: number | undefined;
		if (selectableRanked.length === 0) {
			selectedIndex = undefined;
		} else if (!hasUsageSignals) {
			selectedIndex = fallbackIndex ?? selectableRanked[0]?.index;
		} else {
			const compareUsageSignals = (left: RankedCandidate, right: RankedCandidate): number => {
				if (left.isUntouched !== right.isUntouched) {
					return left.isUntouched ? -1 : 1;
				}
				const secondaryUsageComparison = compareNullableNumberAscending(
					left.secondaryUsedPercent,
					right.secondaryUsedPercent,
				);
				if (secondaryUsageComparison !== 0) {
					return secondaryUsageComparison;
				}
				const primaryUsageComparison = compareNullableNumberAscending(
					left.primaryUsedPercent,
					right.primaryUsedPercent,
				);
				if (primaryUsageComparison !== 0) {
					return primaryUsageComparison;
				}
				const usageComparison = compareNullableNumberAscending(
					left.usedPercent,
					right.usedPercent,
				);
				if (usageComparison !== 0) {
					return usageComparison;
				}
				return compareNullableNumberAscending(left.resetAt, right.resetAt);
			};

			selectableRanked.sort((left, right) => {
				if (left.hasUsageSnapshot !== right.hasUsageSnapshot) {
					return left.hasUsageSnapshot ? -1 : 1;
				}

				// Actual API usage signals are the primary sort key regardless
				// of cache freshness — they reflect real provider quota state.
				const usageSignalComparison = compareUsageSignals(left, right);
				if (usageSignalComparison !== 0) {
					return usageSignalComparison;
				}

				// Prefer credentials with fewer recent quota errors. The value is
				// already time-decayed and reduced by successful recovery probes.
				if (left.quotaErrorCount !== right.quotaErrorCount) {
					return left.quotaErrorCount - right.quotaErrorCount;
				}

				// STICKY: when actual usage is identical, keep using the same
				// credential instead of rotating based on the local request counter.
				if (left.lastUsedAt !== right.lastUsedAt) {
					return right.lastUsedAt - left.lastUsedAt;
				}

				// Local request counter is token-aware and only a final tiebreaker.
				if (left.usageCount !== right.usageCount) {
					return left.usageCount - right.usageCount;
				}

				return left.index - right.index;
			});

			selectedIndex = selectableRanked[0]?.index;
		}

		const refreshQueuedCount = this.enqueueCredentialUsageRefresh(
			provider,
			[...backgroundRefreshCredentialIds],
			"selection",
		);
		multiAuthDebugLogger.log("credential_usage_selection_timing", {
			provider,
			operation: "selection",
			cacheFirst: true,
			candidateCount: candidates.length,
			refreshQueuedCount,
			staleCredentialCount,
			syncValidationCount,
			staleExhaustedSkipCount,
			hasUsageSignals,
			durationMs: Date.now() - selectionStartedAt,
		});
		return selectedIndex;
	}

	private async reconcileBlockedCredentialsFromUsage(
		provider: SupportedProviderId,
		state: ProviderRotationState,
		excludedCredentialIds?: Set<string>,
		usageContext?: CredentialUsageContext,
	): Promise<void> {
		throwIfAborted(
			usageContext?.signal,
			`Blocked credential reconciliation aborted for ${provider}.`,
		);
		const now = Date.now();
		const cascadeBlockedCredentialIds = this.cascadeStateManager.getBlockedCredentialIds(provider, now);
		const backgroundExcludedCredentialIds = getCredentialBackgroundExclusionIds(state);
		const blockedCredentialIds = state.credentialIds.filter((credentialId) => {
			if (excludedCredentialIds?.has(credentialId) || backgroundExcludedCredentialIds.has(credentialId)) {
				return false;
			}
			const exhaustedUntil = state.quotaExhaustedUntil[credentialId];
			return (
				(typeof exhaustedUntil === "number" && exhaustedUntil > now) ||
				cascadeBlockedCredentialIds.has(credentialId)
			);
		});
		if (blockedCredentialIds.length === 0) {
			return;
		}

		const boundedBlockedCredentialIds = this.usageCoordinator.selectCredentialIds(
			blockedCredentialIds,
			"blocked-reconciliation",
		);

		await Promise.allSettled(
			boundedBlockedCredentialIds.map(async (credentialId) => {
				await this.getCredentialUsageSnapshotWithContext(
					provider,
					credentialId,
					{
						forceRefresh: true,
						maxAgeMs: BLOCKED_RECONCILE_USAGE_MAX_AGE_MS,
						coordinationOperation: "blocked-reconciliation",
					},
					usageContext,
				);
			}),
		);
		throwIfAborted(
			usageContext?.signal,
			`Blocked credential reconciliation aborted for ${provider}.`,
		);
	}

	private async reconcileQuotaStateFromUsage(
		provider: SupportedProviderId,
		credentialId: string,
		snapshot: UsageSnapshot | null,
	): Promise<void> {
		const quotaState = inferOperationalQuotaStateFromUsage(provider, snapshot);
		if (quotaState.state === "unknown") {
			return;
		}

		const classificationResult = quotaClassifier.classifyFromUsage(
			snapshot?.primary ?? null,
			snapshot?.secondary ?? null,
			snapshot?.rateLimitHeaders,
		);
		const didUpdateState = await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			if (!providerState.credentialIds.includes(credentialId)) {
				return { result: false };
			}

			if (quotaState.state === "available") {
				const hadPersistedState =
					providerState.quotaExhaustedUntil[credentialId] !== undefined ||
					providerState.lastQuotaError?.[credentialId] !== undefined ||
					providerState.quotaStates?.[credentialId] !== undefined;
				delete providerState.quotaExhaustedUntil[credentialId];
				delete providerState.lastQuotaError?.[credentialId];
				if (providerState.quotaStates?.[credentialId] !== undefined) {
					delete providerState.quotaStates[credentialId];
				}
				return hadPersistedState ? { result: true, next: state } : { result: false };
			}

			const now = Date.now();
			const fallbackUntil = now + QUOTA_COOLDOWN_MS;
			const nextUntil = Math.max(
				now + MIN_QUOTA_RETRY_WINDOW_MS,
				quotaState.exhaustedUntil ?? classificationResult.window?.windowEndMs ?? fallbackUntil,
			);
			const currentUntil = providerState.quotaExhaustedUntil[credentialId] ?? 0;
			providerState.quotaExhaustedUntil[credentialId] = Math.max(currentUntil, nextUntil);
			providerState.quotaStates = providerState.quotaStates ?? {};
			providerState.quotaStates[credentialId] = {
				...this.buildQuotaState(credentialId, "Quota inferred from usage snapshot", classificationResult),
				resetAt: nextUntil,
			};
			return { result: true, next: state };
		});

		if (quotaState.state === "available") {
			this.cascadeStateManager.removeCredential(provider, credentialId);
			await this.persistProviderTelemetry(provider);
		}

		if (didUpdateState) {
			this.usageService.clearOperationalCredential(provider, credentialId);
		}
	}

	private async refreshIfNeeded(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredOAuthCredential,
		signal?: AbortSignal,
	): Promise<StoredOAuthCredential> {
		if (!this.isOAuthRefreshManagedForProvider(provider) || await this.isProviderHidden(provider)) {
			return credential;
		}
		if (this.shouldSkipOAuthRefreshForMissingRefreshToken(provider, credential)) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			await this.persistOAuthRefreshSchedule(provider);
			return credential;
		}

		const safetyWindowMs = getOAuthRefreshLeadTimeMs(
			provider,
			INTERNAL_OAUTH_REFRESH_CONFIG.safetyWindowMs,
		);
		if (Date.now() < credential.expires - safetyWindowMs) {
			return credential;
		}

		try {
			const refreshedCredential = await this.refreshCredentialToken(
				provider,
				credentialId,
				credential,
				signal,
			);
			this.scheduleOAuthRefresh(provider, credentialId, refreshedCredential);
			await this.persistOAuthRefreshSchedule(provider);
			return refreshedCredential;
		} catch (error) {
			if (
				isOAuthRefreshFailureError(error) &&
				shouldPreserveActiveOAuthCredentialAfterRefreshFailure(provider, credential, error)
			) {
				return credential;
			}
			throw error;
		}
	}

	private async refreshCredentialToken(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredOAuthCredential,
		signal?: AbortSignal,
	): Promise<StoredOAuthCredential> {
		if (await this.isProviderHidden(provider)) {
			throw new Error(`OAuth refresh skipped because provider ${provider} is hidden.`);
		}
		this.assertOAuthRefreshManagedForProvider(provider);
		if (this.shouldSkipOAuthRefreshForMissingRefreshToken(provider, credential)) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			await this.persistOAuthRefreshSchedule(provider);
			return credential;
		}
		const refreshKey = `${provider}:${credentialId}`;
		const inFlightRefresh = this.oauthRefreshInFlight.get(refreshKey);
		if (inFlightRefresh) {
			return raceWithSignal(
				inFlightRefresh,
				signal,
				`OAuth refresh aborted for ${provider}/${credentialId}.`,
			);
		}

		const refreshPromise = (async (): Promise<StoredOAuthCredential> => {
			let refreshed: OAuthCredentials;
			try {
				refreshed = await refreshOAuthCredential(provider, credential, {
					requestTimeoutMs: INTERNAL_OAUTH_REFRESH_CONFIG.requestTimeoutMs,
				});
			} catch (error) {
				const recoveredCredential = await this.tryRecoverConcurrentCodexRefresh(
					provider,
					credentialId,
					credential,
					error,
				);
				if (recoveredCredential) {
					return recoveredCredential;
				}

				const failure = await this.logAndHandleOAuthRefreshFailure(
					provider,
					credentialId,
					credential,
					error,
				);
				throw failure;
			}

			await this.authWriter.setOAuthCredential(credentialId, refreshed);
			await this.clearRecoveredOAuthRefreshFailureState(provider, credentialId, {
				type: "oauth",
				...refreshed,
			});
			return {
				type: "oauth",
				...refreshed,
			};
		})().finally(() => {
			this.oauthRefreshInFlight.delete(refreshKey);
		});

		this.oauthRefreshInFlight.set(refreshKey, refreshPromise);
		return raceWithSignal(
			refreshPromise,
			signal,
			`OAuth refresh aborted for ${provider}/${credentialId}.`,
		);
	}

	private deduplicateCredentialEntries(
		provider: SupportedProviderId,
		credentialEntries: readonly AuthCredentialEntry[],
	): string[] {
		const credentialIds = credentialEntries.map((entry) => entry.credentialId);
		if (provider !== "cline" || credentialIds.length <= 1) {
			return credentialIds;
		}

		const selectedByIdentity = new Map<
			string,
			{ credentialId: string; expiresAt: number; index: number }
		>();

		for (const [index, entry] of credentialEntries.entries()) {
			if (entry.credential.type !== "oauth") {
				continue;
			}

			const identityKey = buildGenericOAuthIdentityKey(entry.credential);
			if (!identityKey) {
				continue;
			}

			const existing = selectedByIdentity.get(identityKey);
			if (!existing) {
				selectedByIdentity.set(identityKey, {
					credentialId: entry.credentialId,
					expiresAt: entry.credential.expires,
					index,
				});
				continue;
			}

			const shouldReplace =
				entry.credential.expires > existing.expiresAt ||
				(entry.credential.expires === existing.expiresAt && index < existing.index);
			if (shouldReplace) {
				selectedByIdentity.set(identityKey, {
					credentialId: entry.credentialId,
					expiresAt: entry.credential.expires,
					index,
				});
			}
		}

		if (selectedByIdentity.size === 0) {
			return credentialIds;
		}

		const retainedCredentialIds = new Set(
			[...selectedByIdentity.values()].map((entry) => entry.credentialId),
		);
		return credentialIds.filter((credentialId) => retainedCredentialIds.has(credentialId));
	}

	private async syncProviderState(provider: SupportedProviderId): Promise<ProviderRotationState> {
		await this.ensureInitialized();
		const isHiddenProvider = await this.isProviderHidden(provider);
		const isLightweightProvider = this.isLightweightRotationProvider(provider);
		const credentialEntries = await this.authWriter.getProviderCredentialEntries(provider);
		const credentialIds = credentialEntries.map((entry) => entry.credentialId);
		const normalizedCredentialIds = this.deduplicateCredentialEntries(provider, credentialEntries);
		const normalizedCredentialIdSet = new Set(normalizedCredentialIds);
		for (const credentialId of credentialIds) {
			if (!normalizedCredentialIdSet.has(credentialId)) {
				this.usageService.clearCredential(provider, credentialId);
			}
		}
		this.syncCurrentUsageCredentialCacheKeys(provider, credentialEntries, normalizedCredentialIdSet);

		const currentProviderState = cloneProviderState(
			await this.storage.readProviderState(provider),
		);
		const legacyRotationMode = currentProviderState.rotationMode;
		const normalizedProviderState = cloneProviderState(currentProviderState);
		normalizedProviderState.credentialIds = [...normalizedCredentialIds];
		normalizedProviderState.rotationMode = resolveDefaultRotationMode(provider);
		normalizeProviderState(normalizedProviderState, provider);
		reconcileBackgroundCredentialExclusionsForProvider(
			provider,
			normalizedProviderState,
			credentialEntries,
		);
		clearRecoveredOAuthRefreshFailureStateForProvider(
			provider,
			normalizedProviderState,
			credentialEntries,
		);
		if (provider === "cline" || !this.isOAuthRefreshManagedForProvider(provider)) {
			clearDisabledOAuthRefreshFailureStateForProvider(provider, normalizedProviderState);
		}

		if (haveEquivalentProviderState(currentProviderState, normalizedProviderState)) {
			const effectiveProviderState = this.applyEffectiveProviderRotationMode(
				provider,
				isLightweightProvider
					? this.applyLightweightRotationState(provider, cloneProviderState(currentProviderState))
					: currentProviderState,
				legacyRotationMode,
			);
			this.updateBackgroundCredentialExclusionCache(provider, effectiveProviderState);
			if (isHiddenProvider) {
				await this.cancelProviderOperationalWork(provider, effectiveProviderState);
				return effectiveProviderState;
			}
			this.loadProviderTelemetry(provider, effectiveProviderState);
			await this.syncProviderOAuthSchedules(provider, effectiveProviderState, credentialEntries);
			return effectiveProviderState;
		}

		const providerState = await this.storage.withLock((state) => {
			const storedProviderState = getProviderState(state, provider);
			storedProviderState.credentialIds = [...normalizedCredentialIds];
			storedProviderState.rotationMode = resolveDefaultRotationMode(provider);
			normalizeProviderState(storedProviderState, provider);
			reconcileBackgroundCredentialExclusionsForProvider(
				provider,
				storedProviderState,
				credentialEntries,
			);
			clearRecoveredOAuthRefreshFailureStateForProvider(
				provider,
				storedProviderState,
				credentialEntries,
			);
			if (provider === "cline" || !this.isOAuthRefreshManagedForProvider(provider)) {
				clearDisabledOAuthRefreshFailureStateForProvider(provider, storedProviderState);
			}
			return {
				result: cloneProviderState(storedProviderState),
				next: state,
			};
		});
		const effectiveProviderState = this.applyEffectiveProviderRotationMode(
			provider,
			isLightweightProvider
				? this.applyLightweightRotationState(provider, cloneProviderState(providerState))
				: providerState,
			legacyRotationMode,
		);
		this.updateBackgroundCredentialExclusionCache(provider, effectiveProviderState);
		if (isHiddenProvider) {
			await this.cancelProviderOperationalWork(provider, effectiveProviderState);
			return effectiveProviderState;
		}
		this.loadProviderTelemetry(provider, effectiveProviderState);
		await this.syncProviderOAuthSchedules(provider, effectiveProviderState, credentialEntries);
		return effectiveProviderState;
	}

	/**
	 * Ensures the multi-auth.json file exists and contains provider slots.
	 */
	async ensureInitialized(): Promise<void> {
		if (this.initializationPromise) {
			return this.initializationPromise;
		}

		const initializationPromise = (async () => {
			const providers = await this.providerRegistry.discoverProviderIds();
			await this.migrateLegacyRotationModesToConfig(providers);
			const hiddenProviders = await this.readHiddenProviderSet();
			const operationalProviders = providers.filter((provider) => !hiddenProviders.has(provider));
			const normalizedProviders = await this.authWriter.normalizeProviderCredentials(operationalProviders, {
				identityKeyResolver: resolveApiKeyCredentialIdentityKey,
			});
			for (const provider of providers) {
				if (hiddenProviders.has(provider)) {
					this.usageService.clearProvider(provider);
				}
			}
			for (const result of normalizedProviders) {
				this.usageService.clearProvider(result.provider);
			}
			const credentialIdsByProvider = new Map<SupportedProviderId, string[]>();
			const credentialEntriesByProvider = new Map<SupportedProviderId, readonly AuthCredentialEntry[]>();
			for (const provider of operationalProviders) {
				const credentialEntries = await this.authWriter.getProviderCredentialEntries(provider);
				credentialEntriesByProvider.set(provider, credentialEntries);
				const credentialIds = credentialEntries.map((entry) => entry.credentialId);
				const normalizedCredentialIds = this.deduplicateCredentialEntries(provider, credentialEntries);
				credentialIdsByProvider.set(provider, normalizedCredentialIds);
				const normalizedCredentialIdSet = new Set(normalizedCredentialIds);
				for (const credentialId of credentialIds) {
					if (!normalizedCredentialIdSet.has(credentialId)) {
						this.usageService.clearCredential(provider, credentialId);
					}
				}
				this.syncCurrentUsageCredentialCacheKeys(provider, credentialEntries, normalizedCredentialIdSet);
			}

			const validUsageCredentialCacheKeys = new Map<string, ReadonlySet<string>>();
			for (const [provider, credentialEntries] of credentialEntriesByProvider.entries()) {
				const validCredentialIds = new Set(credentialIdsByProvider.get(provider) ?? []);
				for (const entry of credentialEntries) {
					if (!validCredentialIds.has(entry.credentialId)) {
						continue;
					}
					const indexKey = `${provider}:${entry.credentialId}`;
					const cacheKeys = new Set(validUsageCredentialCacheKeys.get(indexKey) ?? []);
					cacheKeys.add(createUsageCredentialCacheKey(provider, entry.credentialId, {
						accessToken: getCredentialSecret(entry.credential),
						accountId: entry.credential.type === "oauth" && typeof entry.credential.accountId === "string"
							? entry.credential.accountId
							: undefined,
						credential: { ...entry.credential },
					}));
					validUsageCredentialCacheKeys.set(indexKey, cacheKeys);
				}
			}
			const resolveCurrentUsageCredentialCacheKey = (providerId: string, credentialId: string): string | null => {
				const cacheKeys = validUsageCredentialCacheKeys.get(`${providerId}:${credentialId}`);
				if (!cacheKeys || cacheKeys.size !== 1) {
					return null;
				}
				return [...cacheKeys][0] ?? null;
			};
			const validUsageCredentialIdsByProvider = new Map(
				[...credentialIdsByProvider.entries()].map(([providerId, credentialIds]) => [
					providerId,
					new Set(credentialIds),
				]),
			);
			await this.usageService.hydratePersistedCache({
				isCredentialValid: (providerId, credentialId, credentialCacheKey) =>
					validUsageCredentialCacheKeys.get(`${providerId}:${credentialId}`)?.has(credentialCacheKey) ?? false,
				isDisplayCredentialValid: (providerId, credentialId) =>
					validUsageCredentialIdsByProvider.get(providerId)?.has(credentialId) ?? false,
				resolveLegacyCredentialCacheKey: resolveCurrentUsageCredentialCacheKey,
				pruneInvalidEntries: true,
			});

			const persistedProviders = await this.storage.withLock((state) => {
				for (const provider of providers) {
					const providerState = getProviderState(state, provider);
					if (hiddenProviders.has(provider)) {
						providerState.oauthRefreshScheduled = {};
						continue;
					}
					providerState.credentialIds = [...(credentialIdsByProvider.get(provider) ?? [])];
					providerState.rotationMode = resolveDefaultRotationMode(provider);
					normalizeProviderState(providerState, provider);
					reconcileBackgroundCredentialExclusionsForProvider(
						provider,
						providerState,
						credentialEntriesByProvider.get(provider) ?? [],
					);
					if (provider === "cline" || !this.isOAuthRefreshManagedForProvider(provider)) {
						clearDisabledOAuthRefreshFailureStateForProvider(provider, providerState);
					}
				}
				for (const result of normalizedProviders) {
					const providerState = getProviderState(state, result.provider);
					applyCredentialNormalization(result.provider, providerState, result);
				}

				return {
					result: Object.fromEntries(
						operationalProviders.map((provider) => [provider, cloneProviderState(getProviderState(state, provider))]),
					),
					next: state as MultiAuthState,
				};
			});
			for (const provider of providers) {
				if (hiddenProviders.has(provider)) {
					await this.cancelProviderOperationalWork(provider);
				}
			}
			for (const [provider, providerState] of Object.entries(persistedProviders)) {
				const effectiveProviderState = this.applyEffectiveProviderRotationMode(provider, providerState);
				this.updateBackgroundCredentialExclusionCache(provider, effectiveProviderState);
				this.loadProviderTelemetry(provider, effectiveProviderState);
				await this.syncProviderOAuthSchedules(
					provider,
					effectiveProviderState,
					credentialEntriesByProvider.get(provider),
				);
			}
		})();

		this.initializationPromise = initializationPromise;

		try {
			await initializationPromise;
		} catch (error) {
			if (this.initializationPromise === initializationPromise) {
				this.initializationPromise = null;
			}
			throw error;
		}
	}

	private loadProviderTelemetry(
		_provider: SupportedProviderId,
		providerState: ProviderRotationState,
	): void {
		this.cascadeStateManager.loadFromState(providerState.cascadeState);
		this.healthScorer.loadState(providerState.healthState);
	}

	private async persistProviderTelemetry(provider: SupportedProviderId): Promise<void> {
		if (this.isLightweightRotationProvider(provider)) {
			const providerState = this.applyLightweightRotationState(
				provider,
				await this.storage.readProviderState(provider),
			);
			this.recordLightweightTelemetry(provider, providerState.credentialIds);
			await this.lightweightRotationState.flushProvider(provider);
			return;
		}
		await this.storage.withLock((state) => {
			const storedProviderState = getProviderState(state, provider);
			const nextCascadeState = {
				[provider]: this.cascadeStateManager.getProviderState(provider),
			};
			const nextHealthState = this.healthScorer.exportState(storedProviderState.credentialIds);
			const didChange =
				!haveSameJsonValue(storedProviderState.cascadeState, nextCascadeState) ||
				!haveSameJsonValue(storedProviderState.healthState, nextHealthState);
			if (!didChange) {
				return { result: undefined };
			}
			storedProviderState.cascadeState = nextCascadeState;
			storedProviderState.healthState = nextHealthState;
			normalizeProviderState(storedProviderState, provider);
			return { result: undefined, next: state };
		});
	}

	private scheduleOAuthRefresh(
		provider: SupportedProviderId,
		credentialId: string,
		credential: StoredOAuthCredential,
	): void {
		if (
			!this.isOAuthRefreshManagedForProvider(provider) ||
			this.shouldSkipOAuthRefreshForMissingRefreshToken(provider, credential)
		) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			return;
		}

		const expiration = determineTokenExpiration(credential.access, credential.expires);
		const scheduledExpiration = getSchedulerExpirationForRefreshLeadTime(
			provider,
			expiration.expiresAt,
			INTERNAL_OAUTH_REFRESH_CONFIG.safetyWindowMs,
		);
		this.oauthRefreshScheduler.scheduleRefresh(credentialId, provider, scheduledExpiration);
	}

	private async syncProviderOAuthSchedules(
		provider: SupportedProviderId,
		providerState: ProviderRotationState,
		credentialEntries?: readonly AuthCredentialEntry[],
	): Promise<void> {
		if (!this.isOAuthRefreshManagedForProvider(provider) || await this.isProviderHidden(provider)) {
			for (const credentialId of providerState.credentialIds) {
				this.oauthRefreshScheduler.cancelRefresh(credentialId);
			}
			for (const credentialId of Object.keys(providerState.oauthRefreshScheduled ?? {})) {
				this.oauthRefreshScheduler.cancelRefresh(credentialId);
			}
			await this.persistOAuthRefreshSchedule(provider);
			return;
		}

		const validCredentialIds = new Set(providerState.credentialIds);
		const availableCredentialIds = buildAvailableSet(providerState, Date.now());
		const credentialsById = credentialEntries
			? new Map(credentialEntries.map((entry) => [entry.credentialId, entry.credential]))
			: await this.authWriter.getCredentials(providerState.credentialIds);
		for (const credentialId of providerState.credentialIds) {
			const credential = credentialsById.get(credentialId);
			if (credential?.type === "oauth" && availableCredentialIds.has(credentialId)) {
				this.scheduleOAuthRefresh(provider, credentialId, credential);
			} else {
				this.oauthRefreshScheduler.cancelRefresh(credentialId);
			}
		}
		for (const credentialId of Object.keys(providerState.oauthRefreshScheduled ?? {})) {
			if (!validCredentialIds.has(credentialId)) {
				this.oauthRefreshScheduler.cancelRefresh(credentialId);
			}
		}
		await this.persistOAuthRefreshSchedule(provider);
	}

	private async persistOAuthRefreshSchedule(provider: SupportedProviderId): Promise<void> {
		const scheduled = this.oauthRefreshScheduler.getPendingRefreshes();
		await this.storage.withLock((state) => {
			const providerState = getProviderState(state, provider);
			const nextScheduled: Record<string, number> = {};
			for (const credentialId of providerState.credentialIds) {
				const scheduledEntry = scheduled.get(credentialId);
				if (scheduledEntry?.providerId === provider) {
					nextScheduled[credentialId] = scheduledEntry.scheduledAt;
				}
			}
			const currentScheduled = providerState.oauthRefreshScheduled ?? {};
			if (haveSameNumberRecord(currentScheduled, nextScheduled)) {
				return { result: undefined };
			}
			providerState.oauthRefreshScheduled = nextScheduled;
			return { result: undefined, next: state };
		});
	}

	private async refreshScheduledOAuthCredential(
		provider: SupportedProviderId,
		credentialId: string,
	): Promise<number | undefined> {
		if (!this.isOAuthRefreshManagedForProvider(provider) || await this.isProviderHidden(provider)) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			await this.persistOAuthRefreshSchedule(provider);
			return undefined;
		}

		const credential = await this.authWriter.getCredential(credentialId);
		if (!credential || credential.type !== "oauth") {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			await this.persistOAuthRefreshSchedule(provider);
			return undefined;
		}
		if (this.shouldSkipOAuthRefreshForMissingRefreshToken(provider, credential)) {
			this.oauthRefreshScheduler.cancelRefresh(credentialId);
			await this.persistOAuthRefreshSchedule(provider);
			return undefined;
		}

		try {
			const refreshed = await this.refreshCredentialToken(provider, credentialId, credential);
			this.scheduleOAuthRefresh(provider, credentialId, refreshed);
			await this.persistOAuthRefreshSchedule(provider);
			this.enqueueCredentialUsageRefresh(provider, [credentialId], "manual-account-refresh");
			return determineTokenExpiration(refreshed.access, refreshed.expires).expiresAt;
		} catch (error) {
			if (isOAuthRefreshFailureError(error) && error.details.permanent) {
				throw error;
			}
			return undefined;
		}
	}

	private async resolveCodexCredentialModelEligibilityCacheFirst(
		provider: SupportedProviderId,
		credentialIds: readonly string[],
		normalizedModelId: string | undefined,
		requiresEntitlement: boolean,
		prefersFreePlan: boolean,
		usageContext: CredentialUsageContext | undefined,
		signal: AbortSignal | undefined,
	): Promise<CredentialModelEligibility> {
		const resolutionStartedAt = Date.now();
		const verifiedEligibleCredentialIds: string[] = [];
		const preferredCredentialIds: string[] = [];
		const knownFreePlanCredentialIds: string[] = [];
		const unknownFreePlanCredentialIds: string[] = [];
		const usageFailureCredentialIds: string[] = [];
		const unknownPlanCredentialIds: string[] = [];
		const ineligibleCredentialIds: string[] = [];
		const bootstrapCandidateCredentialIds: string[] = [];
		let staleCredentialCount = 0;
		let hasUnknownPlanType = false;
		let hasUsageFailure = false;
		let hasQuotaExhausted = false;

		const pushUnique = (target: string[], credentialId: string): void => {
			if (!target.includes(credentialId)) {
				target.push(credentialId);
			}
		};
		const removeFromList = (target: string[], credentialId: string): void => {
			const index = target.indexOf(credentialId);
			if (index >= 0) {
				target.splice(index, 1);
			}
		};
		const removeFromEligibilityLists = (credentialId: string): void => {
			removeFromList(verifiedEligibleCredentialIds, credentialId);
			removeFromList(preferredCredentialIds, credentialId);
			removeFromList(knownFreePlanCredentialIds, credentialId);
			removeFromList(unknownFreePlanCredentialIds, credentialId);
			removeFromList(usageFailureCredentialIds, credentialId);
			removeFromList(unknownPlanCredentialIds, credentialId);
			removeFromList(ineligibleCredentialIds, credentialId);
		};
		const processUsage = (
			credentialId: string,
			usage: CredentialUsageSnapshotResult | null,
			options: { planOnly?: boolean } = {},
		): void => {
			if (!usage) {
				if (requiresEntitlement) {
					pushUnique(unknownPlanCredentialIds, credentialId);
					hasUnknownPlanType = true;
				} else {
					pushUnique(verifiedEligibleCredentialIds, credentialId);
					if (prefersFreePlan) {
						pushUnique(preferredCredentialIds, credentialId);
						pushUnique(unknownFreePlanCredentialIds, credentialId);
					}
				}
				return;
			}

			const snapshot = usage.snapshot;
			if (!snapshot) {
				if (requiresEntitlement) {
					if (usage.error) {
						pushUnique(usageFailureCredentialIds, credentialId);
						hasUsageFailure = true;
					} else {
						pushUnique(unknownPlanCredentialIds, credentialId);
						hasUnknownPlanType = true;
					}
				} else {
					pushUnique(verifiedEligibleCredentialIds, credentialId);
					if (prefersFreePlan) {
						pushUnique(preferredCredentialIds, credentialId);
						pushUnique(unknownFreePlanCredentialIds, credentialId);
					}
				}
				return;
			}

			const planType = normalizeCodexPlanType(snapshot.planType);
			const quotaState = usage.displayOnly || options.planOnly
				? ({ state: "unknown" } satisfies UsageQuotaState)
				: inferQuotaStateFromUsage(snapshot);
			if (requiresEntitlement) {
				if (isPlanEligibleForModel(planType)) {
					if (quotaState.state === "exhausted") {
						pushUnique(ineligibleCredentialIds, credentialId);
						hasQuotaExhausted = true;
						return;
					}
					pushUnique(verifiedEligibleCredentialIds, credentialId);
					return;
				}

				if (planType === "unknown") {
					pushUnique(unknownPlanCredentialIds, credentialId);
					hasUnknownPlanType = true;
					return;
				}

				pushUnique(ineligibleCredentialIds, credentialId);
				return;
			}

			if (quotaState.state === "exhausted") {
				pushUnique(ineligibleCredentialIds, credentialId);
				return;
			}

			pushUnique(verifiedEligibleCredentialIds, credentialId);
			if (prefersFreePlan && planType === "free") {
				pushUnique(preferredCredentialIds, credentialId);
				pushUnique(knownFreePlanCredentialIds, credentialId);
			}
			if (prefersFreePlan && planType === "unknown") {
				pushUnique(preferredCredentialIds, credentialId);
				pushUnique(unknownFreePlanCredentialIds, credentialId);
			}
		};

		// Quota recovery bypass: check which credentials have stale quota cooldown
		const providerState = await this.storage.readProviderState(provider);
		const now = Date.now();
		const backgroundExcludedCredentialIds = getCredentialBackgroundExclusionIds(providerState);
		const quotaRecoveryCandidates = new Set<string>();
		for (const id of credentialIds) {
			const exhaustedUntil = providerState.quotaExhaustedUntil?.[id] ?? 0;
			const quotaState = providerState.quotaStates?.[id];
			if (exhaustedUntil > 0 && exhaustedUntil <= now) {
				quotaRecoveryCandidates.add(id);
			}
			if (quotaState?.resetAt && typeof quotaState.resetAt === "number" && quotaState.resetAt <= now) {
				quotaRecoveryCandidates.add(id);
			}
		}

		for (const credentialId of credentialIds) {
			if (backgroundExcludedCredentialIds.has(credentialId)) {
				processUsage(credentialId, null);
				continue;
			}
			const cachedUsage = this.readCachedOperationalUsageForSelection(provider, credentialId);
			let usage = cachedUsage.usage;
			let hasPlanEvidence = cachedUsage.hasDurableEvidence;
			if (cachedUsage.needsRefresh) {
				staleCredentialCount += 1;
			}

			if (!usage?.snapshot) {
				const displayUsage = this.getCachedCredentialUsageDisplaySnapshot(provider, credentialId);
				if (displayUsage?.snapshot) {
					usage = displayUsage;
					hasPlanEvidence = true;
				}
			}

			const planType = usage?.snapshot
				? normalizeCodexPlanType(usage.snapshot.planType)
				: "unknown";
			if (
				requiresEntitlement &&
				!usage?.error &&
				(!hasPlanEvidence || planType === "unknown")
			) {
				pushUnique(bootstrapCandidateCredentialIds, credentialId);
			}
			// Force re-verification for credentials whose quota cooldown has expired
			if (quotaRecoveryCandidates.has(credentialId)) {
				if (usage?.snapshot) {
					// Mark as stale so processUsage uses planOnly mode, which triggers bootstrap
					processUsage(credentialId, usage, { planOnly: true });
					pushUnique(bootstrapCandidateCredentialIds, credentialId);
				} else {
					processUsage(credentialId, usage);
				}
			} else {
				processUsage(credentialId, usage, { planOnly: cachedUsage.needsRefresh });
			}
		}

		let bootstrapPerformed = false;
		let synchronousFetchCount = 0;
		const bootstrapCredentialIds =
			requiresEntitlement && verifiedEligibleCredentialIds.length === 0
				? bootstrapCandidateCredentialIds.filter(
					(credentialId) => !backgroundExcludedCredentialIds.has(credentialId),
				)
				: [];

		if (bootstrapCredentialIds.length > 0) {
			bootstrapPerformed = true;
			hasUnknownPlanType = false;
			hasUsageFailure = false;
			const bootstrapCredentialIdWindows = this.usageCoordinator.selectCredentialIdWindows(
				bootstrapCredentialIds,
				"entitlement",
			);
			for (const bootstrapWindowCredentialIds of bootstrapCredentialIdWindows) {
				const usageResults = await Promise.allSettled(
					bootstrapWindowCredentialIds.map((credentialId) =>
						this.getCredentialUsageSnapshotWithContext(
							provider,
							credentialId,
							{
								forceRefresh: true,
								maxAgeMs: SELECTION_USAGE_MAX_AGE_MS,
								coordinationOperation: "entitlement",
							},
							usageContext,
						),
					),
				);
				throwIfAborted(
					signal,
					`Model eligibility resolution aborted for ${provider}/${normalizedModelId ?? "unknown"}.`,
				);
				for (let index = 0; index < bootstrapWindowCredentialIds.length; index += 1) {
					const credentialId = bootstrapWindowCredentialIds[index];
					synchronousFetchCount += 1;
					removeFromEligibilityLists(credentialId);
					const usageResult = usageResults[index];
					if (usageResult?.status === "fulfilled") {
						processUsage(credentialId, usageResult.value);
					} else {
						pushUnique(usageFailureCredentialIds, credentialId);
						hasUsageFailure = true;
					}
				}
				if (verifiedEligibleCredentialIds.length >= 1) {
					break;
				}
			}
		}

		const backgroundRefreshCandidateCredentialIds = bootstrapPerformed
			? []
			: credentialIds.filter((credentialId) =>
				!backgroundExcludedCredentialIds.has(credentialId) &&
				(bootstrapCandidateCredentialIds.includes(credentialId) ||
					unknownPlanCredentialIds.includes(credentialId) ||
					usageFailureCredentialIds.includes(credentialId)),
			);
		const backgroundRefreshQueuedCount = this.enqueueCredentialUsageRefresh(
			provider,
			backgroundRefreshCandidateCredentialIds,
			"entitlement",
		);

		let eligibleCredentialIds = [...verifiedEligibleCredentialIds];
		const allowUnverifiedOnUsageFailure = false;
		if (requiresEntitlement) {
			const unverifiedCredentialIds = [...usageFailureCredentialIds];
			for (const credentialId of unknownPlanCredentialIds) {
				pushUnique(unverifiedCredentialIds, credentialId);
			}
			if (eligibleCredentialIds.length === 0 && allowUnverifiedOnUsageFailure && unverifiedCredentialIds.length > 0) {
				eligibleCredentialIds = unverifiedCredentialIds;
				multiAuthDebugLogger.log("codex_entitlement_usage_uncertain_bypass", {
					provider,
					modelId: normalizedModelId ?? "unknown",
					credentialRefs: unverifiedCredentialIds.map(redactUsageCredentialIdentifier),
					hadUsageFailure: usageFailureCredentialIds.length > 0,
					hadUnknownPlan: unknownPlanCredentialIds.length > 0,
				});
			} else {
				for (const credentialId of usageFailureCredentialIds) {
					pushUnique(ineligibleCredentialIds, credentialId);
				}
				for (const credentialId of unknownPlanCredentialIds) {
					pushUnique(ineligibleCredentialIds, credentialId);
				}
			}
		}

		let failureMessage: string | undefined;
		if (requiresEntitlement && eligibleCredentialIds.length === 0) {
			if (hasUsageFailure) {
				failureMessage = `Unable to verify plan eligibility for ${formatModelReference(provider, normalizedModelId ?? "unknown")}. All credentials failed usage lookup.`;
			} else if (hasUnknownPlanType) {
				failureMessage = `Unable to determine plan type for any credential. Cannot verify eligibility for ${formatModelReference(provider, normalizedModelId ?? "unknown")}.`;
			} else if (hasQuotaExhausted) {
				failureMessage = `All paid-plan credentials for ${formatModelReference(provider, normalizedModelId ?? "unknown")} are quota-exhausted.`;
			} else {
				failureMessage = `No credentials available with a paid plan for ${formatModelReference(provider, normalizedModelId ?? "unknown")}. Upgrade to ChatGPT Plus, Pro, Team, Business, or Enterprise to use this model.`;
			}
		}

		const preferredCredentialTiers = prefersFreePlan
			? [knownFreePlanCredentialIds, unknownFreePlanCredentialIds].filter((tier) => tier.length > 0)
			: undefined;

		multiAuthDebugLogger.log("codex_entitlement_selection_timing", {
			provider,
			modelId: normalizedModelId ?? "unknown",
			credentialCount: credentialIds.length,
			eligibleCount: eligibleCredentialIds.length,
			ineligibleCount: ineligibleCredentialIds.length,
			cacheFirst: true,
			bootstrapPerformed,
			backgroundRefreshQueuedCount,
			bootstrapCandidateCount: bootstrapCredentialIds.length,
			synchronousFetchCount,
			staleCredentialCount,
			durationMs: Date.now() - resolutionStartedAt,
		});

		return {
			appliesConstraint: true,
			eligibleCredentialIds,
			ineligibleCredentialIds,
			preferredCredentialIds,
			preferredCredentialTiers: preferredCredentialTiers && preferredCredentialTiers.length > 0
				? preferredCredentialTiers
				: undefined,
			failureMessage,
		};
	}

	private async resolveCredentialModelEligibility(
		provider: SupportedProviderId,
		credentialIds: readonly string[],
		modelId: string | undefined,
		usageContext?: CredentialUsageContext,
		signal?: AbortSignal,
	): Promise<CredentialModelEligibility> {
		const effectiveSignal = signal ?? usageContext?.signal;
		throwIfAborted(
			effectiveSignal,
			`Model eligibility resolution aborted for ${provider}/${modelId ?? "unknown"}.`,
		);
		const normalizedModelId = normalizeModelId(modelId, provider) ?? undefined;
		const requiresEntitlement = modelRequiresEntitlement(provider, modelId);
		const prefersFreePlan = modelPrefersFreePlan(provider, modelId);
		const usesPlanTierRanking = providerUsesPlanTierRanking(provider);
		if (!requiresEntitlement && !prefersFreePlan && !usesPlanTierRanking) {
			return {
				appliesConstraint: false,
				eligibleCredentialIds: [...credentialIds],
				ineligibleCredentialIds: [],
			};
		}

		if (provider === OPENAI_CODEX_PROVIDER_ID) {
			return this.resolveCodexCredentialModelEligibilityCacheFirst(
				provider,
				credentialIds,
				normalizedModelId,
				requiresEntitlement,
				prefersFreePlan,
				usageContext,
				effectiveSignal,
			);
		}

		const credentialIdWindows = this.usageCoordinator.selectCredentialIdWindows(
			credentialIds,
			"entitlement",
		);
		const targetEligibleCredentialCount = this.usageCoordinator.getOperationWindowSize("entitlement");
		const queriedCredentialIds = new Set<string>();
		const verifiedEligibleCredentialIds: string[] = [];
		const preferredCredentialIds: string[] = [];
		const usageFailureCredentialIds: string[] = [];
		const ineligibleCredentialIds: string[] = [];
		let hasUnknownPlanType = false;
		let hasUsageFailure = false;
		let hasQuotaExhausted = false;
		const allowUnverifiedOnUsageFailure = false;

		// Provider-aware plan classification: codex paths use `normalizeCodexPlanType` +
		// `isPlanEligibleForModel`; BlazeAPI and Kiro paths route through their own
		// enums so user-facing labels like "Premium", "Pro+", or "KIRO FREE" are
		// evaluated against provider-specific model access rules.
		const isBlazeApiProvider = provider === "blazeapi";
		const isKiroProvider = provider === "kiro";
		const classifyPlan = (rawPlanType: string | null | undefined): {
			eligibleForEntitlement: boolean;
			isFreeTier: boolean;
			isUnknown: boolean;
		} => {
			if (isBlazeApiProvider) {
				const planType = normalizeBlazeApiPlanType(rawPlanType);
				return {
					eligibleForEntitlement: isBlazeApiPlanEligibleForPremiumModel(planType),
					isFreeTier: planType === "free",
					isUnknown: planType === "unknown",
				};
			}
			if (isKiroProvider) {
				const planType = normalizeKiroPlanType(rawPlanType);
				return {
					eligibleForEntitlement: isKiroPlanEligibleForPaidModel(planType),
					isFreeTier: planType === "free",
					isUnknown: planType === "unknown",
				};
			}
			const planType = normalizeCodexPlanType(rawPlanType);
			return {
				eligibleForEntitlement: isPlanEligibleForModel(planType),
				isFreeTier: planType === "free",
				isUnknown: planType === "unknown",
			};
		};

		// Captures verified plan tiers so providers with plan-aware routing can
		// return ordered preference lists for the rotation selector.
		const blazeApiPlanTypeByCredentialId = new Map<string, BlazeApiPlanType>();
		const kiroPlanTypeByCredentialId = new Map<string, KiroPlanType>();

		for (const credentialIdWindow of credentialIdWindows) {
			const usageResults = await Promise.allSettled(
				credentialIdWindow.map((credentialId) => {
					if (isBlazeApiProvider || isKiroProvider) {
						const cachedPlanEvidence = this.getCachedCredentialUsageDisplaySnapshot(provider, credentialId);
						if (cachedPlanEvidence?.snapshot) {
							return Promise.resolve(cachedPlanEvidence);
						}
					}
					return this.getCredentialUsageSnapshotWithContext(
						provider,
						credentialId,
						{
							maxAgeMs: SELECTION_USAGE_MAX_AGE_MS,
							coordinationOperation: "entitlement",
						},
						usageContext,
					);
				}),
			);

			throwIfAborted(
				effectiveSignal,
				`Model eligibility resolution aborted for ${provider}/${normalizedModelId ?? "unknown"}.`,
			);

			for (let index = 0; index < credentialIdWindow.length; index += 1) {
				const credentialId = credentialIdWindow[index];
				queriedCredentialIds.add(credentialId);
				const usageResult = usageResults[index];
				let usage: CredentialUsageSnapshotResult | null = null;
				let usePlanEvidenceOnly = false;

				if (usageResult?.status === "fulfilled") {
					usage = usageResult.value;
				}

				if (!usage?.snapshot && (isBlazeApiProvider || isKiroProvider)) {
					const displayUsage = this.getCachedCredentialUsageDisplaySnapshot(provider, credentialId);
					if (displayUsage?.snapshot) {
						usage = displayUsage;
						usePlanEvidenceOnly = true;
					}
				}

				if (!usage) {
					if (requiresEntitlement) {
						usageFailureCredentialIds.push(credentialId);
						hasUsageFailure = true;
					} else {
						verifiedEligibleCredentialIds.push(credentialId);
					}
					continue;
				}

				const snapshot = usage.snapshot;
				if (!snapshot) {
					if (requiresEntitlement) {
						if (usage.error) {
							usageFailureCredentialIds.push(credentialId);
							hasUsageFailure = true;
						} else {
							ineligibleCredentialIds.push(credentialId);
							hasUnknownPlanType = true;
						}
					} else {
						verifiedEligibleCredentialIds.push(credentialId);
					}
					continue;
				}

				const planClassification = classifyPlan(snapshot.planType);
				const quotaState = usePlanEvidenceOnly || usage.displayOnly
					? ({ state: "unknown" } satisfies UsageQuotaState)
					: inferModelEligibilityQuotaStateFromUsage(provider, snapshot, requiresEntitlement);
				if (isBlazeApiProvider) {
					blazeApiPlanTypeByCredentialId.set(
						credentialId,
						normalizeBlazeApiPlanType(snapshot.planType),
					);
				}
				if (isKiroProvider) {
					kiroPlanTypeByCredentialId.set(
						credentialId,
						normalizeKiroPlanType(snapshot.planType),
					);
				}
				if (requiresEntitlement) {
					if (planClassification.eligibleForEntitlement) {
						if (quotaState.state === "exhausted") {
							ineligibleCredentialIds.push(credentialId);
							hasQuotaExhausted = true;
							continue;
						}
						verifiedEligibleCredentialIds.push(credentialId);
						continue;
					}

					ineligibleCredentialIds.push(credentialId);
					if (planClassification.isUnknown) {
						hasUnknownPlanType = true;
					}
					continue;
				}

				if (quotaState.state === "exhausted") {
					ineligibleCredentialIds.push(credentialId);
					continue;
				}

				verifiedEligibleCredentialIds.push(credentialId);
				if (prefersFreePlan && planClassification.isFreeTier) {
					preferredCredentialIds.push(credentialId);
				}
			}

			if (verifiedEligibleCredentialIds.length >= targetEligibleCredentialCount) {
				break;
			}
		}

		const unqueriedCredentialIds = credentialIds.filter(
			(credentialId) => !queriedCredentialIds.has(credentialId),
		);
		if (requiresEntitlement) {
			if (verifiedEligibleCredentialIds.length === 0) {
				usageFailureCredentialIds.push(...unqueriedCredentialIds);
				if (unqueriedCredentialIds.length > 0) {
					hasUsageFailure = true;
				}
			}
		} else {
			verifiedEligibleCredentialIds.push(...unqueriedCredentialIds);
		}

		let eligibleCredentialIds = [...verifiedEligibleCredentialIds];
		if (requiresEntitlement) {
			if (eligibleCredentialIds.length === 0 && allowUnverifiedOnUsageFailure && usageFailureCredentialIds.length > 0) {
				eligibleCredentialIds = [...usageFailureCredentialIds];
				multiAuthDebugLogger.log("codex_entitlement_usage_failure_bypass", {
					provider,
					modelId: normalizedModelId ?? "unknown",
					credentialRefs: usageFailureCredentialIds.map(redactUsageCredentialIdentifier),
				});
			} else {
				for (const credentialId of usageFailureCredentialIds) {
					ineligibleCredentialIds.push(credentialId);
				}
			}
		}

		let failureMessage: string | undefined;
		if (requiresEntitlement && eligibleCredentialIds.length === 0) {
			const modelRef = formatModelReference(provider, normalizedModelId ?? "unknown");
			if (hasUsageFailure) {
				failureMessage = `Unable to verify plan eligibility for ${modelRef}. All credentials failed usage lookup.`;
			} else if (hasUnknownPlanType) {
				failureMessage = `Unable to determine plan type for any credential. Cannot verify eligibility for ${modelRef}.`;
			} else if (hasQuotaExhausted) {
				if (isKiroProvider) {
					failureMessage = `All Kiro Pro, Pro+, or Power credentials for ${modelRef} are quota-exhausted.`;
				} else {
					failureMessage = `All paid-plan credentials for ${modelRef} are quota-exhausted.`;
				}
			} else if (isBlazeApiProvider) {
				failureMessage = `No BlazeAPI credentials with premium daily credits available for ${modelRef}. Upgrade to BlazeAPI Pro or Premium, or add a Pro/Premium credential to call premium-charging models.`;
			} else if (isKiroProvider) {
				failureMessage = `No Kiro Pro, Pro+, or Power credentials available for ${modelRef}. Add or switch to a paid Kiro credential to call this model.`;
			} else {
				failureMessage = `No credentials available with a paid plan for ${modelRef}. Upgrade to ChatGPT Plus, Pro, Team, Business, or Enterprise to use this model.`;
			}
		}

		let preferredCredentialTiers: readonly (readonly string[])[] | undefined;
		if (usesPlanTierRanking) {
			const eligibleSet = new Set(eligibleCredentialIds);
			let tiers: readonly (readonly string[])[] = [];
			if (isBlazeApiProvider) {
				const rankingInput = new Map<string, BlazeApiPlanType>();
				for (const [credentialId, planType] of blazeApiPlanTypeByCredentialId) {
					if (eligibleSet.has(credentialId)) {
						rankingInput.set(credentialId, planType);
					}
				}
				tiers = rankBlazeApiCredentialsByPlanTier(rankingInput);
			} else if (isKiroProvider) {
				const rankingInput = new Map<string, KiroPlanType>();
				for (const [credentialId, planType] of kiroPlanTypeByCredentialId) {
					if (eligibleSet.has(credentialId)) {
						rankingInput.set(credentialId, planType);
					}
				}
				tiers = rankKiroCredentialsByPlanTier(rankingInput, {
					preferFreeTier: !requiresEntitlement,
				});
			}
			if (tiers.length > 0) {
				preferredCredentialTiers = tiers;
				// Mirror the topmost non-empty tier into the legacy flat field so callers
				// that only consume `preferredCredentialIds` still see the highest-tier
				// preference (or Kiro's Free-preserving preference for Free-accessible models).
				if (preferredCredentialIds.length === 0) {
					preferredCredentialIds.push(...tiers[0]);
				}
			}
		}

		return {
			appliesConstraint: true,
			eligibleCredentialIds,
			ineligibleCredentialIds,
			preferredCredentialIds,
			preferredCredentialTiers,
			failureMessage,
		};
	}
}
