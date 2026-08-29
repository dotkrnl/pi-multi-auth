import { createHash } from "node:crypto";
import { getErrorMessage } from "../auth-error-utils.js";
import { multiAuthDebugLogger } from "../debug-logger.js";
import { quotaClassifier } from "../quota-classifier.js";
import { rateLimitHeaderParser } from "../rate-limit-headers.js";
import { usageProviders } from "./providers.js";
import {
	UsageRefreshLockTimeoutError,
	UsageSnapshotCacheStore,
	type UsageCacheHydrationOptions,
	type UsageCacheHydrationSnapshot,
	type UsageCachePersistenceOptions,
	type UsageCacheRecord,
	type UsageDisplayCacheRecord,
} from "./persistent-cache.js";
import { UsageCoordinator, type UsageCoordinationOperation } from "./usage-coordinator.js";
import type {
	UsageAuth,
	UsageFetchOptions,
	UsageFetchResult,
	UsageProvider,
	UsageSnapshot,
} from "./types.js";

const DEFAULT_USAGE_FRESH_TTL_MS = 30_000;
const DEFAULT_USAGE_STALE_TTL_MS = 5 * 60_000;
const DEFAULT_USAGE_ERROR_TTL_MS = 10_000;
const DEFAULT_USAGE_AUTH_ERROR_TTL_MS = 3_000;
const MIN_SUCCESS_FRESH_TTL_MS = 5_000;

interface UsageCacheEntry {
	result: Omit<UsageFetchResult, "fromCache">;
	freshUntil: number;
	staleUntil: number;
	revision?: number;
}

interface UsageDisplayCacheEntry {
	result: Omit<UsageFetchResult, "fromCache">;
	displayUntil: number;
	revision?: number;
}

interface ResolvedUsageCacheRead {
	result: UsageFetchResult;
	isStale: boolean;
}

interface FreshUsageExecution {
	result: Omit<UsageFetchResult, "fromCache">;
	fromSharedCache: boolean;
}

interface UsageCacheEntryVersion {
	revision: number;
	fetchedAt: number;
	freshUntil: number;
	staleUntil: number;
}

export interface UsageServiceOptions {
	persistentCache?: UsageSnapshotCacheStore | UsageCachePersistenceOptions | false;
}

class UsageFetchCompletedWithError extends Error {
	constructor(readonly execution: FreshUsageExecution) {
		super(execution.result.error ?? "Usage unavailable");
		this.name = "UsageFetchCompletedWithError";
	}
}

function normalizeCredentialCacheComponent(value: unknown): string | null {
	if (typeof value !== "string") {
		return null;
	}
	const normalized = value.trim();
	return normalized.length > 0 ? normalized : null;
}

function getCredentialRecordString(
	credential: Record<string, unknown> | undefined,
	key: string,
): string | null {
	return normalizeCredentialCacheComponent(credential?.[key]);
}

function digestUsageCacheComponent(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

export function createUsageCredentialCacheKey(
	providerId: string,
	credentialId: string,
	auth?: UsageAuth,
): string {
	const accountId =
		normalizeCredentialCacheComponent(auth?.accountId) ??
		getCredentialRecordString(auth?.credential, "accountId");
	const credentialProvider = getCredentialRecordString(auth?.credential, "provider");
	const secretDigest = auth?.accessToken
		? digestUsageCacheComponent(auth.accessToken).slice(0, 32)
		: null;
	return `v1:${digestUsageCacheComponent(JSON.stringify({
		providerId,
		credentialId,
		accountId,
		credentialProvider,
		secretDigest,
	}))}`;
}

function providerCredentialIndexKey(providerId: string, credentialId: string): string {
	return `${providerId}\u0000${credentialId}`;
}

function cacheKey(providerId: string, credentialId: string, credentialCacheKey: string): string {
	return `${providerId}\u0000${credentialId}\u0000${credentialCacheKey}`;
}

function isFinitePositiveNumber(value: number | undefined): value is number {
	return typeof value === "number" && Number.isFinite(value) && value > 0;
}

function getSoonestResetAt(snapshot: UsageSnapshot | null): number | null {
	if (!snapshot) {
		return null;
	}

	const candidates = [
		snapshot.primary?.resetsAt,
		snapshot.secondary?.resetsAt,
		snapshot.monthly?.resetsAt,
		snapshot.copilotQuota?.resetAt,
		snapshot.estimatedResetAt,
		snapshot.rateLimitHeaders?.resetAt,
	].filter((value): value is number => typeof value === "number" && Number.isFinite(value));

	if (candidates.length === 0) {
		return null;
	}

	return Math.min(...candidates);
}

function isAuthLikeUsageError(message: string): boolean {
	return /\b401\b|\b403\b|expired|invalid|denied|missing required usage scope|token/i.test(
		message,
	);
}

function hasUsableRateLimitHeaders(headers: UsageSnapshot["rateLimitHeaders"]): boolean {
	return Boolean(
		headers &&
		(
			headers.limit !== null ||
			headers.remaining !== null ||
			headers.resetAt !== null ||
			headers.retryAfterSeconds !== null
		),
	);
}

function createPersistentCacheStore(
	options: UsageServiceOptions,
): UsageSnapshotCacheStore | undefined {
	if (options.persistentCache === false) {
		return undefined;
	}
	if (options.persistentCache instanceof UsageSnapshotCacheStore) {
		return options.persistentCache;
	}
	return new UsageSnapshotCacheStore(options.persistentCache);
}

/**
 * Orchestrates provider-specific usage fetching with single-flight in-memory cache.
 */
export class UsageService {
	private readonly providers = new Map<string, UsageProvider<UsageAuth>>();
	private readonly cache = new Map<string, UsageCacheEntry>();
	private readonly cacheKeysByCredential = new Map<string, Set<string>>();
	private readonly displayCache = new Map<string, UsageDisplayCacheEntry>();
	private readonly displayCacheKeysByCredential = new Map<string, Set<string>>();
	private readonly preferredCredentialCacheKeys = new Map<string, string>();
	private readonly inFlight = new Map<string, Promise<FreshUsageExecution>>();
	private readonly persistentCacheStore?: UsageSnapshotCacheStore;
	private persistentCacheFingerprint: string | null | undefined;
	private persistentHydrationOptions: UsageCacheHydrationOptions = {};
	private persistentRefreshInFlight: Promise<void> | null = null;

	constructor(
		private readonly freshTtlMs: number = DEFAULT_USAGE_FRESH_TTL_MS,
		private readonly staleTtlMs: number = DEFAULT_USAGE_STALE_TTL_MS,
		private readonly errorTtlMs: number = DEFAULT_USAGE_ERROR_TTL_MS,
		private usageCoordinator?: UsageCoordinator,
		options: UsageServiceOptions = {},
	) {
		this.persistentCacheStore = createPersistentCacheStore(options);
		for (const provider of usageProviders) {
			this.register(provider);
		}
	}

	/**
	 * Registers a usage provider implementation.
	 */
	register(provider: UsageProvider<UsageAuth>): void {
		this.providers.set(provider.id, provider);
	}

	/**
	 * Attaches the shared coordinator that admits only bounded fresh usage requests.
	 */
	setUsageCoordinator(usageCoordinator: UsageCoordinator): void {
		this.usageCoordinator = usageCoordinator;
	}

	/**
	 * Indicates whether a provider has a dedicated usage implementation.
	 */
	hasProvider(providerId: string): boolean {
		return this.providers.has(providerId);
	}

	/**
	 * Returns the persistent warm-start cache path, when persistence is enabled.
	 */
	getPersistentCachePath(): string | null {
		return this.persistentCacheStore?.getPath() ?? null;
	}

	/**
	 * Hydrates non-expired persisted usage snapshots into the non-authoritative in-memory cache.
	 */
	async hydratePersistedCache(options: UsageCacheHydrationOptions = {}): Promise<void> {
		if (!this.persistentCacheStore) {
			return;
		}
		// Initial hydration may prune records against the credentials known at startup.
		// Subsequent live reads intentionally do not retain those validators: OAuth
		// access-token rotation changes credentialCacheKey, and credentials may be
		// added by another running CLI. Exact preferred-key matching below keeps old
		// credential material from becoming operational while allowing the new key
		// to propagate without a restart.
		this.persistentHydrationOptions = {
			resolveLegacyCredentialCacheKey: options.resolveLegacyCredentialCacheKey,
			pruneInvalidEntries: false,
		};
		const snapshot = await this.persistentCacheStore.readHydrationSnapshot(Date.now(), options);
		this.applyPersistentCacheSnapshot(snapshot);
	}

	/**
	 * Rechecks the shared cache and merges records written by other running CLI processes.
	 */
	async refreshPersistedCache(): Promise<void> {
		if (!this.persistentCacheStore) {
			return;
		}
		if (this.persistentRefreshInFlight) {
			return this.persistentRefreshInFlight;
		}
		const refresh = (async () => {
			const snapshot = await this.persistentCacheStore!.readHydrationSnapshot(
				Date.now(),
				this.persistentHydrationOptions,
			);
			this.applyPersistentCacheSnapshot(snapshot);
		})();
		this.persistentRefreshInFlight = refresh;
		try {
			await refresh;
		} finally {
			if (this.persistentRefreshInFlight === refresh) {
				this.persistentRefreshInFlight = null;
			}
		}
	}

	private async refreshPersistedCacheAfterLock(): Promise<void> {
		if (!this.persistentCacheStore) {
			return;
		}
		// A pre-existing read may have started before the lock winner published.
		// Wait for it, then force a distinct read made after lock acquisition.
		if (this.persistentRefreshInFlight) {
			await this.persistentRefreshInFlight.catch(() => undefined);
		}
		const snapshot = await this.persistentCacheStore.readHydrationSnapshot(
			Date.now(),
			this.persistentHydrationOptions,
		);
		this.applyPersistentCacheSnapshot(snapshot);
	}

	private refreshPersistedCacheIfChangedSync(): void {
		if (!this.persistentCacheStore) {
			return;
		}
		const snapshot = this.persistentCacheStore.readHydrationSnapshotIfChangedSync(
			this.persistentCacheFingerprint,
			Date.now(),
			this.persistentHydrationOptions,
		);
		if (snapshot) {
			this.applyPersistentCacheSnapshot(snapshot);
		}
	}

	private applyPersistentCacheSnapshot(snapshot: UsageCacheHydrationSnapshot): void {
		for (const entry of snapshot.operationalEntries) {
			const key = cacheKey(entry.providerId, entry.credentialId, entry.credentialCacheKey);
			const preferredKey = this.preferredCredentialCacheKeys.get(
				providerCredentialIndexKey(entry.providerId, entry.credentialId),
			);
			if (preferredKey && preferredKey !== key) {
				continue;
			}
			const candidate: UsageCacheEntry = {
				result: entry.result,
				freshUntil: entry.freshUntil,
				staleUntil: entry.staleUntil,
				revision: entry.revision,
			};
			if (this.shouldReplaceCacheEntry(this.cache.get(key), candidate)) {
				this.setCacheEntry(entry.providerId, entry.credentialId, entry.credentialCacheKey, candidate);
			}
		}
		for (const entry of snapshot.displayEntries) {
			this.mergeDisplayCacheEntry(entry);
		}
		this.persistentCacheFingerprint = snapshot.fingerprint;
	}

	/**
	 * Registers the currently active credential material for one provider credential pair.
	 * This lets auth-aware callers prefer the matching cache record when historical entries exist.
	 */
	setPreferredCredentialCacheKey(
		providerId: string,
		credentialId: string,
		credentialCacheKey: string | null,
	): void {
		const indexKey = providerCredentialIndexKey(providerId, credentialId);
		if (!credentialCacheKey) {
			this.preferredCredentialCacheKeys.delete(indexKey);
			return;
		}
		this.preferredCredentialCacheKeys.set(indexKey, cacheKey(providerId, credentialId, credentialCacheKey));
	}

	/**
	 * Clears operational cache for one credential while preserving last-known display data.
	 */
	clearOperationalCredential(providerId: string, credentialId: string): void {
		this.clearIndexedCache(providerId, credentialId, this.cache, this.cacheKeysByCredential, true);
	}

	/**
	 * Clears all cache for one credential.
	 */
	clearCredential(providerId: string, credentialId: string): void {
		this.clearOperationalCredential(providerId, credentialId);
		this.clearIndexedCache(providerId, credentialId, this.displayCache, this.displayCacheKeysByCredential);
		this.preferredCredentialCacheKeys.delete(providerCredentialIndexKey(providerId, credentialId));
	}

	/**
	 * Clears all cached snapshots for a provider.
	 */
	clearProvider(providerId: string): void {
		this.clearIndexedCacheProvider(providerId, this.cache, this.cacheKeysByCredential, true);
		this.clearIndexedCacheProvider(providerId, this.displayCache, this.displayCacheKeysByCredential);
		for (const indexKey of [...this.preferredCredentialCacheKeys.keys()]) {
			if (indexKey.startsWith(`${providerId} `)) {
				this.preferredCredentialCacheKeys.delete(indexKey);
			}
		}
	}


	/**
	 * Reads a cached usage snapshot without triggering a provider fetch.
	 */
	readCachedUsage(
		providerId: string,
		credentialId: string,
		options: UsageFetchOptions = {},
	): UsageFetchResult | null {
		this.refreshPersistedCacheIfChangedSync();
		return this.resolveCachedReadForCredential(providerId, credentialId, options, Date.now())?.result ?? null;
	}

	/**
	 * Reads a display-only last-known usage snapshot without exposing it to operational decisions.
	 */
	readDisplayUsage(providerId: string, credentialId: string): UsageFetchResult | null {
		this.refreshPersistedCacheIfChangedSync();
		return this.resolveDisplayReadForCredential(providerId, credentialId, Date.now());
	}

	/**
	 * Updates operational usage cache from response headers observed by existing provider hooks.
	 */
	async harvestRateLimitHeaders(
		providerId: string,
		credentialId: string,
		credentialCacheKey: string,
		headers: Record<string, string | undefined>,
		observedAt: number = Date.now(),
	): Promise<UsageFetchResult | null> {
		this.refreshPersistedCacheIfChangedSync();
		const parsedHeaders = rateLimitHeaderParser.parseHeaders(headers, providerId);
		if (!hasUsableRateLimitHeaders(parsedHeaders)) {
			return null;
		}

		const key = cacheKey(providerId, credentialId, credentialCacheKey);
		const existingSnapshot = this.resolveCachedRead(key, { allowStale: true }, observedAt)?.result.snapshot ?? null;
		const quotaClassification = quotaClassifier.classifyFromUsage(
			existingSnapshot?.primary ?? null,
			existingSnapshot?.secondary ?? null,
			parsedHeaders,
		).classification;
		const estimatedResetAt = rateLimitHeaderParser.getEstimatedResetAt(parsedHeaders) ?? existingSnapshot?.estimatedResetAt;
		const snapshot: UsageSnapshot = {
			timestamp: existingSnapshot?.timestamp ?? observedAt,
			provider: existingSnapshot?.provider ?? providerId,
			planType: existingSnapshot?.planType ?? null,
			primary: existingSnapshot?.primary ?? null,
			secondary: existingSnapshot?.secondary ?? null,
			credits: existingSnapshot?.credits ?? null,
			copilotQuota: existingSnapshot?.copilotQuota ?? null,
			updatedAt: observedAt,
			rateLimitHeaders: parsedHeaders,
			quotaClassification,
			...(typeof estimatedResetAt === "number" ? { estimatedResetAt } : {}),
		};
		const result: Omit<UsageFetchResult, "fromCache"> = {
			snapshot,
			error: null,
			fetchedAt: observedAt,
		};
		await this.cacheResult(providerId, credentialId, credentialCacheKey, result, false);

		return {
			...result,
			fromCache: true,
		};
	}

	/**
	 * Fetches usage snapshot with cache, request de-duplication, and coordinated fresh calls.
	 */
	async fetchUsage(
		providerId: string,
		credentialId: string,
		auth: UsageAuth,
		options: UsageFetchOptions = {},
	): Promise<UsageFetchResult> {
		this.refreshPersistedCacheIfChangedSync();
		const credentialCacheKey = createUsageCredentialCacheKey(providerId, credentialId, auth);
		const key = cacheKey(providerId, credentialId, credentialCacheKey);
		const resolvedCachedRead = this.resolveCachedRead(key, options, Date.now());
		if (resolvedCachedRead && !resolvedCachedRead.isStale) {
			return resolvedCachedRead.result;
		}

		const staleCandidate = resolvedCachedRead?.isStale ? resolvedCachedRead.result : undefined;
		const baselineVersion = this.captureCacheEntryVersion(this.cache.get(key));
		const existingInFlight = this.inFlight.get(key);
		if (existingInFlight) {
			if (staleCandidate) {
				return staleCandidate;
			}

			const execution = await existingInFlight;
			return {
				...execution.result,
				fromCache: execution.fromSharedCache,
			};
		}

		const fetchPromise = this.fetchFreshUsage(
			providerId,
			credentialId,
			auth,
			key,
			credentialCacheKey,
			options,
			baselineVersion,
			options.coordinationOperation ?? "direct",
		);
		this.inFlight.set(key, fetchPromise);

		const settledFetch = fetchPromise.finally(() => {
			if (this.inFlight.get(key) === fetchPromise) {
				this.inFlight.delete(key);
			}
		});

		if (staleCandidate) {
			void settledFetch.catch(() => undefined);
			return staleCandidate;
		}

		const execution = await settledFetch;
		return {
			...execution.result,
			fromCache: execution.fromSharedCache,
		};
	}


	private setCacheEntry(
		providerId: string,
		credentialId: string,
		credentialCacheKey: string,
		entry: UsageCacheEntry,
	): void {
		const key = cacheKey(providerId, credentialId, credentialCacheKey);
		this.cache.set(key, entry);
		this.setCacheIndex(providerId, credentialId, key, this.cacheKeysByCredential);
	}

	private setDisplayCacheEntry(entry: UsageDisplayCacheRecord): void {
		const key = cacheKey(entry.providerId, entry.credentialId, entry.credentialCacheKey);
		this.displayCache.set(key, {
			result: entry.result,
			displayUntil: entry.displayUntil,
			revision: entry.revision,
		});
		this.setCacheIndex(entry.providerId, entry.credentialId, key, this.displayCacheKeysByCredential);
	}

	private shouldReplaceCacheEntry(
		existing: UsageCacheEntry | undefined,
		candidate: UsageCacheEntry,
	): boolean {
		if (!existing) {
			return true;
		}
		if (candidate.result.fetchedAt !== existing.result.fetchedAt) {
			return candidate.result.fetchedAt > existing.result.fetchedAt;
		}
		const candidateRevision = candidate.revision ?? 0;
		const existingRevision = existing.revision ?? 0;
		if (candidateRevision !== existingRevision) {
			return candidateRevision > existingRevision;
		}
		return candidate.freshUntil >= existing.freshUntil;
	}

	private mergeDisplayCacheEntry(entry: UsageDisplayCacheRecord): void {
		const key = cacheKey(entry.providerId, entry.credentialId, entry.credentialCacheKey);
		const existing = this.displayCache.get(key);
		const incoming: UsageDisplayCacheEntry = {
			result: entry.result,
			displayUntil: entry.displayUntil,
			revision: entry.revision,
		};
		if (existing && !this.isDisplayEntryNewer(incoming, existing)) {
			return;
		}
		this.setDisplayCacheEntry(entry);
	}

	private isDisplayEntryNewer(
		candidate: UsageDisplayCacheEntry,
		existing: UsageDisplayCacheEntry,
	): boolean {
		if (candidate.result.fetchedAt !== existing.result.fetchedAt) {
			return candidate.result.fetchedAt > existing.result.fetchedAt;
		}
		return (candidate.revision ?? 0) >= (existing.revision ?? 0);
	}

	private captureCacheEntryVersion(entry: UsageCacheEntry | undefined): UsageCacheEntryVersion | null {
		return entry
			? {
				revision: entry.revision ?? 0,
				fetchedAt: entry.result.fetchedAt,
				freshUntil: entry.freshUntil,
				staleUntil: entry.staleUntil,
			}
			: null;
	}

	private isCacheEntryNewerThanVersion(
		entry: UsageCacheEntry | undefined,
		baseline: UsageCacheEntryVersion | null,
	): boolean {
		if (!entry) {
			return false;
		}
		if (!baseline) {
			return true;
		}
		const revision = entry.revision ?? 0;
		return revision > baseline.revision ||
			entry.result.fetchedAt > baseline.fetchedAt ||
			entry.freshUntil > baseline.freshUntil ||
			entry.staleUntil > baseline.staleUntil;
	}

	private setCacheIndex(
		providerId: string,
		credentialId: string,
		key: string,
		index: Map<string, Set<string>>,
	): void {
		const indexKey = providerCredentialIndexKey(providerId, credentialId);
		const keys = index.get(indexKey) ?? new Set<string>();
		keys.add(key);
		index.set(indexKey, keys);
	}

	private clearIndexedCache<TEntry>(
		providerId: string,
		credentialId: string,
		cache: Map<string, TEntry>,
		index: Map<string, Set<string>>,
		deleteInFlight: boolean = false,
	): void {
		const indexKey = providerCredentialIndexKey(providerId, credentialId);
		const keys = index.get(indexKey);
		if (!keys) {
			return;
		}
		for (const key of keys) {
			cache.delete(key);
			if (deleteInFlight) {
				this.inFlight.delete(key);
			}
		}
		index.delete(indexKey);
	}

	private clearIndexedCacheProvider<TEntry>(
		providerId: string,
		cache: Map<string, TEntry>,
		index: Map<string, Set<string>>,
		deleteInFlight: boolean = false,
	): void {
		const indexPrefix = `${providerId}\u0000`;
		for (const [indexKey, keys] of index.entries()) {
			if (!indexKey.startsWith(indexPrefix)) {
				continue;
			}
			for (const key of keys) {
				cache.delete(key);
				if (deleteInFlight) {
					this.inFlight.delete(key);
				}
			}
			index.delete(indexKey);
		}
	}

	private resolvePreferredCachedRead(
		providerId: string,
		credentialId: string,
		options: UsageFetchOptions,
		now: number,
	): ResolvedUsageCacheRead | null {
		const preferredKey = this.preferredCredentialCacheKeys.get(
			providerCredentialIndexKey(providerId, credentialId),
		);
		return preferredKey ? this.resolveCachedRead(preferredKey, options, now) : null;
	}

	private resolvePreferredDisplayRead(
		providerId: string,
		credentialId: string,
		now: number,
	): UsageFetchResult | null {
		const preferredKey = this.preferredCredentialCacheKeys.get(
			providerCredentialIndexKey(providerId, credentialId),
		);
		if (!preferredKey) {
			return null;
		}

		const entry = this.displayCache.get(preferredKey);
		if (!entry || !entry.result.snapshot) {
			return null;
		}

		return {
			...entry.result,
			fromCache: true,
		};
	}

	private resolveCachedReadForCredential(
		providerId: string,
		credentialId: string,
		options: UsageFetchOptions,
		now: number,
	): ResolvedUsageCacheRead | null {
		const indexKey = providerCredentialIndexKey(providerId, credentialId);
		if (this.preferredCredentialCacheKeys.has(indexKey)) {
			return this.resolvePreferredCachedRead(providerId, credentialId, options, now);
		}

		const keys = this.cacheKeysByCredential.get(indexKey);
		if (!keys || keys.size === 0) {
			return null;
		}

		let selected: ResolvedUsageCacheRead | null = null;
		let selectedKey: string | null = null;
		for (const key of keys) {
			const read = this.resolveCachedRead(key, options, now);
			if (!read) {
				continue;
			}
			if (selected && selectedKey !== key) {
				return null;
			}
			selected = read;
			selectedKey = key;
		}

		return selected;
	}

	private resolveDisplayReadForCredential(
		providerId: string,
		credentialId: string,
		now: number,
	): UsageFetchResult | null {
		const preferredKey = this.preferredCredentialCacheKeys.get(
			providerCredentialIndexKey(providerId, credentialId),
		);
		const preferredRead = preferredKey ? this.resolvePreferredDisplayRead(providerId, credentialId, now) : null;
		if (preferredRead) {
			return preferredRead;
		}

		const keys = this.displayCacheKeysByCredential.get(providerCredentialIndexKey(providerId, credentialId));
		if (!keys || keys.size === 0) {
			return null;
		}

		let selected: UsageDisplayCacheEntry | null = null;
		let selectedKey: string | null = null;
		for (const key of keys) {
			const entry = this.displayCache.get(key);
			if (!entry || !entry.result.snapshot) {
				continue;
			}
			if (preferredKey) {
				if (!selected || entry.result.fetchedAt > selected.result.fetchedAt) {
					selected = entry;
					selectedKey = key;
				}
				continue;
			}
			if (selected && selectedKey !== key) {
				return null;
			}
			selected = entry;
			selectedKey = key;
		}

		return selected
			? {
				...selected.result,
				fromCache: true,
			}
			: null;
	}

	private resolveCachedRead(
		key: string,
		options: UsageFetchOptions,
		now: number,
	): ResolvedUsageCacheRead | null {
		const cached = this.cache.get(key);
		if (options.forceRefresh) {
			if (cached && this.isFreshNegativeEntry(cached, now)) {
				return {
					result: {
						...cached.result,
						fromCache: true,
					},
					isStale: false,
				};
			}
			return null;
		}
		if (!cached) {
			return null;
		}

		const maxAgeMs = isFinitePositiveNumber(options.maxAgeMs) ? options.maxAgeMs : undefined;
		if (this.isEntryFresh(cached, now, maxAgeMs)) {
			return {
				result: {
					...cached.result,
					fromCache: true,
				},
				isStale: false,
			};
		}

		if (!options.allowStale) {
			return null;
		}

		const staleCandidate = this.getStaleCandidate(cached, now, maxAgeMs);
		if (!staleCandidate) {
			return null;
		}

		return {
			result: {
				...staleCandidate.result,
				fromCache: true,
			},
			isStale: true,
		};
	}

	private isFreshNegativeEntry(entry: UsageCacheEntry, now: number): boolean {
		return entry.result.snapshot === null && entry.result.error !== null && entry.freshUntil > now;
	}

	private isEntryFresh(entry: UsageCacheEntry, now: number, maxAgeMs?: number): boolean {
		if (entry.freshUntil <= now) {
			return false;
		}

		if (maxAgeMs === undefined) {
			return true;
		}

		return now - entry.result.fetchedAt <= maxAgeMs;
	}

	private getStaleCandidate(
		entry: UsageCacheEntry | undefined,
		now: number,
		maxAgeMs?: number,
	): UsageCacheEntry | undefined {
		if (!entry) {
			return undefined;
		}

		if (entry.staleUntil <= now) {
			return undefined;
		}

		if (entry.result.snapshot === null) {
			return undefined;
		}

		if (maxAgeMs !== undefined && now - entry.result.fetchedAt > maxAgeMs) {
			return undefined;
		}

		return entry;
	}

	private fetchFreshUsage(
		providerId: string,
		credentialId: string,
		auth: UsageAuth,
		key: string,
		credentialCacheKey: string,
		options: UsageFetchOptions,
		baselineVersion: UsageCacheEntryVersion | null,
		operation: UsageCoordinationOperation,
	): Promise<FreshUsageExecution> {
		const provider = this.providers.get(providerId);
		const execute = () => this.fetchWithCrossProcessCoordination(
			providerId,
			credentialId,
			auth,
			key,
			credentialCacheKey,
			options,
			baselineVersion,
		);
		if (!this.usageCoordinator || !provider?.fetchUsage) {
			return execute();
		}

		return this.usageCoordinator
			.executeFreshRequest(
				{ provider: providerId, credentialId, operation },
				async () => {
					const execution = await execute();
					if (execution.result.error) {
						throw new UsageFetchCompletedWithError(execution);
					}
					return execution;
				},
			)
			.catch((error: unknown) => {
				if (error instanceof UsageFetchCompletedWithError) {
					return error.execution;
				}
				throw error;
			});
	}

	private async fetchWithCrossProcessCoordination(
		providerId: string,
		credentialId: string,
		auth: UsageAuth,
		key: string,
		credentialCacheKey: string,
		options: UsageFetchOptions,
		baselineVersion: UsageCacheEntryVersion | null,
	): Promise<FreshUsageExecution> {
		if (!this.persistentCacheStore) {
			return this.fetchAndCache(providerId, credentialId, auth, credentialCacheKey);
		}

		try {
			return await this.persistentCacheStore.withCredentialRefreshLock(
				providerId,
				credentialId,
				credentialCacheKey,
				async ({ contended }) => {
					await this.refreshPersistedCacheAfterLock();
					const sharedRead = this.resolveCachedRead(
						key,
						{ ...options, forceRefresh: false, allowStale: false },
						Date.now(),
					);
					const currentEntry = this.cache.get(key);
					const mayConsumeSharedResult = !options.forceRefresh ||
						contended ||
						this.isCacheEntryNewerThanVersion(currentEntry, baselineVersion);
					if (sharedRead && !sharedRead.isStale && mayConsumeSharedResult) {
						return {
							result: {
								snapshot: sharedRead.result.snapshot,
								error: sharedRead.result.error,
								fetchedAt: sharedRead.result.fetchedAt,
							},
							fromSharedCache: true,
						};
					}
					return this.fetchAndCache(providerId, credentialId, auth, credentialCacheKey);
				},
			);
		} catch (error: unknown) {
			// A final cache read covers a winner that published at the wait deadline.
			await this.refreshPersistedCacheAfterLock().catch(() => undefined);
			const sharedRead = this.resolveCachedRead(
				key,
				{ ...options, forceRefresh: false, allowStale: false },
				Date.now(),
			);
			if (sharedRead && !sharedRead.isStale) {
				return {
					result: {
						snapshot: sharedRead.result.snapshot,
						error: sharedRead.result.error,
						fetchedAt: sharedRead.result.fetchedAt,
					},
					fromSharedCache: true,
				};
			}

			const fetchedAt = Date.now();
			const message = error instanceof UsageRefreshLockTimeoutError
				? "timed out waiting for another process to finish the usage refresh"
				: `shared refresh coordination failed: ${getErrorMessage(error)}`;
			const result: Omit<UsageFetchResult, "fromCache"> = {
				snapshot: null,
				error: `Usage unavailable (${message})`,
				fetchedAt,
			};
			// Never publish a coordination failure while another process may still
			// own the refresh lock; that could hide the eventual winner.
			await this.cacheResult(providerId, credentialId, credentialCacheKey, result, true, message, false);
			return { result, fromSharedCache: false };
		}
	}

	private async fetchAndCache(
		providerId: string,
		credentialId: string,
		auth: UsageAuth,
		credentialCacheKey: string,
	): Promise<FreshUsageExecution> {
		const provider = this.providers.get(providerId);
		if (!provider?.fetchUsage) {
			const fetchedAt = Date.now();
			const result: Omit<UsageFetchResult, "fromCache"> = {
				snapshot: null,
				error: "Usage unavailable",
				fetchedAt,
			};
			await this.cacheResult(providerId, credentialId, credentialCacheKey, result, true);
			return { result, fromSharedCache: false };
		}

		try {
			const snapshot = await provider.fetchUsage(auth);
			const fetchedAt = Date.now();
			const result: Omit<UsageFetchResult, "fromCache"> = {
				snapshot,
				error: snapshot ? null : "Usage unavailable",
				fetchedAt,
			};
			await this.cacheResult(providerId, credentialId, credentialCacheKey, result, snapshot === null);
			return { result, fromSharedCache: false };
		} catch (error: unknown) {
			const fetchedAt = Date.now();
			const message = getErrorMessage(error);
			const result: Omit<UsageFetchResult, "fromCache"> = {
				snapshot: null,
				error: `Usage unavailable (${message})`,
				fetchedAt,
			};
			await this.cacheResult(providerId, credentialId, credentialCacheKey, result, true, message);
			return { result, fromSharedCache: false };
		}
	}

	private async cacheResult(
		providerId: string,
		credentialId: string,
		credentialCacheKey: string,
		result: Omit<UsageFetchResult, "fromCache">,
		isError: boolean,
		errorMessage?: string,
		persist: boolean = true,
	): Promise<void> {
		const freshTtlMs = isError
			? this.resolveErrorTtlMs(errorMessage)
			: this.resolveSuccessFreshTtlMs(result.snapshot, result.fetchedAt);
		const staleTtlMs = isError ? freshTtlMs : Math.max(this.staleTtlMs, freshTtlMs);

		const entry: UsageCacheEntry = {
			result,
			freshUntil: result.fetchedAt + freshTtlMs,
			staleUntil: result.fetchedAt + staleTtlMs,
		};
		this.setCacheEntry(providerId, credentialId, credentialCacheKey, entry);

		if (!persist || !this.persistentCacheStore) {
			return;
		}
		const persistentEntry: UsageCacheRecord = {
			providerId,
			credentialId,
			credentialCacheKey,
			result,
			freshUntil: entry.freshUntil,
			staleUntil: entry.staleUntil,
		};
		try {
			const persisted = await this.persistentCacheStore.persistEntry(
				persistentEntry,
				result.fetchedAt,
			);
			if (!persisted) {
				return;
			}
			const persistedEntry: UsageCacheEntry = {
				result: persisted.operationalEntry.result,
				freshUntil: persisted.operationalEntry.freshUntil,
				staleUntil: persisted.operationalEntry.staleUntil,
				revision: persisted.operationalEntry.revision,
			};
			const key = cacheKey(providerId, credentialId, credentialCacheKey);
			if (this.shouldReplaceCacheEntry(this.cache.get(key), persistedEntry)) {
				this.setCacheEntry(providerId, credentialId, credentialCacheKey, persistedEntry);
			}
			if (persisted.displayEntry) {
				this.mergeDisplayCacheEntry(persisted.displayEntry);
			}
		} catch (error: unknown) {
			multiAuthDebugLogger.log("usage_cache_result_persist_failed", {
				provider: providerId,
				credentialRef: digestUsageCacheComponent(credentialId).slice(0, 12),
				error: getErrorMessage(error),
			});
		}
	}

	private resolveErrorTtlMs(errorMessage?: string): number {
		if (errorMessage && isAuthLikeUsageError(errorMessage)) {
			return DEFAULT_USAGE_AUTH_ERROR_TTL_MS;
		}
		return this.errorTtlMs;
	}

	private resolveSuccessFreshTtlMs(snapshot: UsageSnapshot | null, now: number): number {
		if (!snapshot) {
			return this.errorTtlMs;
		}

		const soonestResetAt = getSoonestResetAt(snapshot);
		if (soonestResetAt === null || soonestResetAt <= now) {
			return this.freshTtlMs;
		}

		const msUntilReset = soonestResetAt - now;
		if (msUntilReset <= MIN_SUCCESS_FRESH_TTL_MS) {
			return MIN_SUCCESS_FRESH_TTL_MS;
		}

		const adaptiveTtl = Math.floor(msUntilReset / 4);
		return Math.max(MIN_SUCCESS_FRESH_TTL_MS, Math.min(this.freshTtlMs, adaptiveTtl));
	}
}
