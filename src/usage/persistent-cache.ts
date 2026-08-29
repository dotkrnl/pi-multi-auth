import { createHash } from "node:crypto";
import { constants as fsConstants, readFileSync, statSync } from "node:fs";
import { access, mkdir, readFile, stat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { getErrorMessage, isRecord } from "../auth-error-utils.js";
import { multiAuthDebugLogger } from "../debug-logger.js";
import {
	isRetryableFileAccessError,
	readTextSnapshotWithRetries,
	writeTextSnapshotWithRetries,
} from "../file-retry.js";
import { acquireFileLock, lockDirPath, writeTextFileAtomically } from "../file-utils.js";
import { resolveAgentRuntimePath } from "../runtime-paths.js";
import type { ParsedRateLimitHeaders, QuotaClassification } from "../types-quota.js";
import type { UsageFetchResult, UsageSnapshot } from "./types.js";

export const USAGE_CACHE_SCHEMA_VERSION = 3;
export const DEFAULT_USAGE_CACHE_MAX_ENTRIES = 5_000;
export const DEFAULT_USAGE_DISPLAY_CACHE_RETENTION_MS = 30 * 24 * 60 * 60_000;

const USAGE_CACHE_V2_SCHEMA_VERSION = 2;
const USAGE_CACHE_LEGACY_SCHEMA_VERSION = 1;

const DEFAULT_USAGE_CACHE_WRITE_LOCK_STALE_MS = 10_000;
const DEFAULT_USAGE_CACHE_WRITE_LOCK_WAIT_MS = 15_000;
const DEFAULT_USAGE_REFRESH_LOCK_STALE_MS = 30_000;
const DEFAULT_USAGE_REFRESH_LOCK_WAIT_MS = 35_000;
const DEFAULT_USAGE_LOCK_POLL_MS = 25;
const DEFAULT_USAGE_REFRESH_LOCK_HEARTBEAT_MS = 5_000;

const QUOTA_CLASSIFICATIONS = new Set<QuotaClassification>([
	"hourly",
	"daily",
	"weekly",
	"monthly",
	"balance",
	"organization",
	"unknown",
]);
const RATE_LIMIT_CONFIDENCE_VALUES = new Set(["high", "medium", "low"]);
const RATE_LIMIT_SOURCE_VALUES = new Set([
	"x-ratelimit-reset",
	"retry-after",
	"estimated",
	"unknown",
]);

export interface UsageCachePersistenceOptions {
	filePath?: string;
	maxEntries?: number;
	displayMaxEntries?: number;
	displayRetentionMs?: number;
	writeLockStaleMs?: number;
	writeLockWaitMs?: number;
	refreshLockStaleMs?: number;
	refreshLockWaitMs?: number;
	lockPollMs?: number;
	refreshLockHeartbeatMs?: number;
}

export interface UsageCacheRecord {
	providerId: string;
	credentialId: string;
	credentialCacheKey: string;
	result: Omit<UsageFetchResult, "fromCache">;
	freshUntil: number;
	staleUntil: number;
	revision?: number;
}

export interface UsageDisplayCacheRecord {
	providerId: string;
	credentialId: string;
	credentialCacheKey: string;
	result: Omit<UsageFetchResult, "fromCache">;
	displayUntil: number;
	revision?: number;
}

export interface UsageCacheHydrationRecords {
	operationalEntries: UsageCacheRecord[];
	displayEntries: UsageDisplayCacheRecord[];
}

export interface UsageCacheHydrationSnapshot extends UsageCacheHydrationRecords {
	fingerprint: string | null;
	revision: number;
}

export interface UsageCachePersistResult {
	operationalEntry: UsageCacheRecord;
	displayEntry: UsageDisplayCacheRecord | null;
}

export interface UsageRefreshLockContext {
	contended: boolean;
}

export class UsageRefreshLockTimeoutError extends Error {
	constructor(readonly lockPath: string, cause?: unknown) {
		super(`Timed out waiting for shared usage refresh lock '${lockPath}'.`, { cause });
		this.name = "UsageRefreshLockTimeoutError";
	}
}

export interface UsageCacheHydrationOptions {
	isCredentialValid?: (providerId: string, credentialId: string, credentialCacheKey: string) => boolean;
	isDisplayCredentialValid?: (providerId: string, credentialId: string, credentialCacheKey: string) => boolean;
	resolveLegacyCredentialCacheKey?: (providerId: string, credentialId: string) => string | null;
	pruneInvalidEntries?: boolean;
}

interface PersistedUsageCacheFile {
	schemaVersion: typeof USAGE_CACHE_SCHEMA_VERSION;
	revision: number;
	generatedAt: number;
	maxEntries: number;
	maxDisplayEntries: number;
	displayRetentionMs: number;
	entries: PersistedUsageCacheEntry[];
	errorEntries: PersistedUsageCacheErrorEntry[];
	displayEntries: SerializedUsageDisplayCacheEntry[];
}

interface ParsedPersistedUsageCacheFile {
	mergeSafe: boolean;
	revision: number;
	entries: PersistedUsageCacheEntry[];
	errorEntries: PersistedUsageCacheErrorEntry[];
	displayEntries: PersistedUsageDisplayCacheEntry[];
	shouldRewrite: boolean;
}

function createEmptyParsedUsageCache(mergeSafe: boolean = true): ParsedPersistedUsageCacheFile {
	return { mergeSafe, revision: 0, entries: [], errorEntries: [], displayEntries: [], shouldRewrite: false };
}

interface CredentialScopedUsageCacheIdentity {
	provider: string;
	credentialId: string;
	credentialCacheKey: string;
	fetchedAt: number;
	revision: number;
}

interface CredentialScopedUsageCacheEntry extends CredentialScopedUsageCacheIdentity {
	snapshot: UsageSnapshot;
}

interface PersistedUsageCacheEntry extends CredentialScopedUsageCacheEntry {
	freshUntil: number;
	staleUntil: number;
}

interface PersistedUsageCacheErrorEntry extends CredentialScopedUsageCacheIdentity {
	error: string;
	freshUntil: number;
	staleUntil: number;
}

interface PersistedUsageDisplayCacheEntry extends CredentialScopedUsageCacheEntry {
	displayUntil: number;
}

interface SerializedUsageDisplayCacheEntry extends Omit<PersistedUsageDisplayCacheEntry, "snapshot"> {
	snapshot?: UsageSnapshot;
}

type PersistedCopilotQuotaBucket = NonNullable<UsageSnapshot["copilotQuota"]>["chat"];

function getDefaultUsageCachePath(): string {
	return resolveAgentRuntimePath("multi-auth-usage-cache.json");
}


function isNonEmptyString(value: unknown): value is string {
	return typeof value === "string" && value.trim().length > 0;
}

function isFiniteTimestamp(value: unknown): value is number {
	return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function parseRevision(value: unknown): number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function createFileFingerprint(fileStats: { mtimeMs: number; ctimeMs: number; size: number; ino: number | bigint }): string {
	return `${fileStats.mtimeMs}:${fileStats.ctimeMs}:${fileStats.size}:${String(fileStats.ino)}`;
}

function isNullableFiniteNumber(value: unknown): value is number | null {
	return value === null || isFiniteTimestamp(value);
}

function createRecordKey(providerId: string, credentialId: string, credentialCacheKey: string): string {
	return JSON.stringify([providerId, credentialId, credentialCacheKey]);
}

async function pathExists(filePath: string): Promise<boolean> {
	try {
		await access(filePath, fsConstants.F_OK);
		return true;
	} catch {
		return false;
	}
}

async function ensureParentDir(filePath: string): Promise<void> {
	const parentDir = dirname(filePath);
	if (!(await pathExists(parentDir))) {
		await mkdir(parentDir, { recursive: true, mode: 0o700 });
	}
}

function parseRateLimitWindow(value: unknown): UsageSnapshot["primary"] | null | undefined {
	if (value === null) {
		return null;
	}
	if (!isRecord(value)) {
		return undefined;
	}
	if (!isFiniteTimestamp(value.usedPercent)) {
		return undefined;
	}
	if (!isNullableFiniteNumber(value.windowMinutes) || !isNullableFiniteNumber(value.resetsAt)) {
		return undefined;
	}
	return {
		usedPercent: value.usedPercent,
		windowMinutes: value.windowMinutes,
		resetsAt: value.resetsAt,
	};
}

function parseCredits(value: unknown): UsageSnapshot["credits"] | null | undefined {
	if (value === null) {
		return null;
	}
	if (!isRecord(value)) {
		return undefined;
	}
	if (typeof value.hasCredits !== "boolean" || typeof value.unlimited !== "boolean") {
		return undefined;
	}
	if (value.balance !== null && typeof value.balance !== "string") {
		return undefined;
	}
	return {
		hasCredits: value.hasCredits,
		unlimited: value.unlimited,
		balance: value.balance,
	};
}

function parseCopilotQuotaBucket(value: unknown): PersistedCopilotQuotaBucket | undefined {
	if (!isRecord(value)) {
		return undefined;
	}
	if (
		!isNullableFiniteNumber(value.used) ||
		!isNullableFiniteNumber(value.total) ||
		!isNullableFiniteNumber(value.remaining) ||
		!isNullableFiniteNumber(value.percentUsed) ||
		typeof value.unlimited !== "boolean"
	) {
		return undefined;
	}
	return {
		used: value.used,
		total: value.total,
		remaining: value.remaining,
		percentUsed: value.percentUsed,
		unlimited: value.unlimited,
	};
}

function parseCopilotQuota(value: unknown): UsageSnapshot["copilotQuota"] | null | undefined {
	if (value === null) {
		return null;
	}
	if (!isRecord(value)) {
		return undefined;
	}
	const chat = parseCopilotQuotaBucket(value.chat);
	if (!chat) {
		return undefined;
	}
	let completions: PersistedCopilotQuotaBucket | null;
	if (value.completions === null) {
		completions = null;
	} else {
		const parsedCompletions = parseCopilotQuotaBucket(value.completions);
		if (!parsedCompletions) {
			return undefined;
		}
		completions = parsedCompletions;
	}
	if (!isNullableFiniteNumber(value.resetAt)) {
		return undefined;
	}
	return {
		chat,
		completions,
		resetAt: value.resetAt,
	};
}

function parseRateLimitHeaders(value: unknown): ParsedRateLimitHeaders | undefined {
	if (value === undefined) {
		return undefined;
	}
	if (!isRecord(value)) {
		return undefined;
	}
	if (
		!isNullableFiniteNumber(value.limit) ||
		!isNullableFiniteNumber(value.remaining) ||
		!isNullableFiniteNumber(value.resetAt) ||
		!isNullableFiniteNumber(value.retryAfterSeconds) ||
		(value.resetAtFormatted !== null && typeof value.resetAtFormatted !== "string") ||
		typeof value.confidence !== "string" ||
		!RATE_LIMIT_CONFIDENCE_VALUES.has(value.confidence) ||
		typeof value.source !== "string" ||
		!RATE_LIMIT_SOURCE_VALUES.has(value.source)
	) {
		return undefined;
	}
	return {
		limit: value.limit,
		remaining: value.remaining,
		resetAt: value.resetAt,
		retryAfterSeconds: value.retryAfterSeconds,
		resetAtFormatted: value.resetAtFormatted,
		confidence: value.confidence as ParsedRateLimitHeaders["confidence"],
		source: value.source as ParsedRateLimitHeaders["source"],
	};
}

function parseQuotaClassification(value: unknown): QuotaClassification | undefined {
	if (value === undefined) {
		return undefined;
	}
	return typeof value === "string" && QUOTA_CLASSIFICATIONS.has(value as QuotaClassification)
		? (value as QuotaClassification)
		: undefined;
}

function parseUsageSnapshot(value: unknown): UsageSnapshot | null {
	if (!isRecord(value)) {
		return null;
	}
	if (
		!isFiniteTimestamp(value.timestamp) ||
		!isNonEmptyString(value.provider) ||
		(value.planType !== null && typeof value.planType !== "string") ||
		!isFiniteTimestamp(value.updatedAt)
	) {
		return null;
	}

	const primary = parseRateLimitWindow(value.primary);
	const secondary = parseRateLimitWindow(value.secondary);
	const monthly = parseRateLimitWindow(value.monthly);
	const credits = parseCredits(value.credits);
	const copilotQuota = parseCopilotQuota(value.copilotQuota);
	if (
		primary === undefined ||
		secondary === undefined ||
		(value.monthly !== undefined && monthly === undefined) ||
		credits === undefined ||
		copilotQuota === undefined
	) {
		return null;
	}

	const rateLimitHeaders = parseRateLimitHeaders(value.rateLimitHeaders);
	if (value.rateLimitHeaders !== undefined && !rateLimitHeaders) {
		return null;
	}
	const quotaClassification = parseQuotaClassification(value.quotaClassification);
	if (value.quotaClassification !== undefined && !quotaClassification) {
		return null;
	}
	if (value.estimatedResetAt !== undefined && !isFiniteTimestamp(value.estimatedResetAt)) {
		return null;
	}

	return {
		timestamp: value.timestamp,
		provider: value.provider,
		planType: value.planType,
		primary,
		secondary,
		...(monthly !== undefined ? { monthly } : {}),
		credits,
		copilotQuota,
		updatedAt: value.updatedAt,
		...(rateLimitHeaders ? { rateLimitHeaders } : {}),
		...(quotaClassification ? { quotaClassification } : {}),
		...(typeof value.estimatedResetAt === "number" ? { estimatedResetAt: value.estimatedResetAt } : {}),
	};
}

function parsePersistedEntry(value: unknown): PersistedUsageCacheEntry | null {
	if (!isRecord(value)) {
		return null;
	}
	if (!isNonEmptyString(value.credentialCacheKey)) {
		return null;
	}
	return parseCredentialScopedEntry(value, value.credentialCacheKey);
}

function parsePersistedErrorEntry(value: unknown): PersistedUsageCacheErrorEntry | null {
	if (
		!isRecord(value) ||
		!isNonEmptyString(value.provider) ||
		!isNonEmptyString(value.credentialId) ||
		!isNonEmptyString(value.credentialCacheKey) ||
		!isNonEmptyString(value.error) ||
		!isFiniteTimestamp(value.fetchedAt) ||
		!isFiniteTimestamp(value.freshUntil) ||
		!isFiniteTimestamp(value.staleUntil) ||
		value.freshUntil > value.staleUntil
	) {
		return null;
	}
	return {
		provider: value.provider,
		credentialId: value.credentialId,
		credentialCacheKey: value.credentialCacheKey,
		fetchedAt: value.fetchedAt,
		revision: parseRevision(value.revision),
		error: value.error,
		freshUntil: value.freshUntil,
		staleUntil: value.staleUntil,
	};
}

function parsePersistedDisplayEntry(
	value: unknown,
	resolveSnapshot?: (provider: string, credentialId: string, credentialCacheKey: string) => UsageSnapshot | null,
): PersistedUsageDisplayCacheEntry | null {
	if (!isRecord(value) || !isNonEmptyString(value.credentialCacheKey)) {
		return null;
	}
	if (
		!isNonEmptyString(value.provider) ||
		!isNonEmptyString(value.credentialId) ||
		!isFiniteTimestamp(value.fetchedAt) ||
		!isFiniteTimestamp(value.displayUntil)
	) {
		return null;
	}
	const snapshot = parseUsageSnapshot(value.snapshot) ??
		(value.snapshot === undefined
			? resolveSnapshot?.(value.provider, value.credentialId, value.credentialCacheKey) ?? null
			: null);
	if (!snapshot || snapshot.provider !== value.provider) {
		return null;
	}
	return {
		provider: value.provider,
		credentialId: value.credentialId,
		credentialCacheKey: value.credentialCacheKey,
		fetchedAt: value.fetchedAt,
		revision: parseRevision(value.revision),
		displayUntil: value.displayUntil,
		snapshot,
	};
}

function parseLegacyPersistedEntry(
	value: unknown,
	options: UsageCacheHydrationOptions,
): PersistedUsageCacheEntry | null {
	if (!isRecord(value)) {
		return null;
	}
	if (!isNonEmptyString(value.provider) || !isNonEmptyString(value.credentialId)) {
		return null;
	}
	const credentialCacheKey = resolveLegacyCredentialCacheKey(value.provider, value.credentialId, options);
	if (!credentialCacheKey) {
		return null;
	}
	return parseCredentialScopedEntry(value, credentialCacheKey);
}

function parseCredentialScopedEntry(
	value: Record<string, unknown>,
	credentialCacheKey: string,
): PersistedUsageCacheEntry | null {
	if (
		!isNonEmptyString(value.provider) ||
		!isNonEmptyString(value.credentialId) ||
		!isFiniteTimestamp(value.fetchedAt) ||
		!isFiniteTimestamp(value.freshUntil) ||
		!isFiniteTimestamp(value.staleUntil) ||
		value.freshUntil > value.staleUntil
	) {
		return null;
	}
	const snapshot = parseUsageSnapshot(value.snapshot);
	if (!snapshot || snapshot.provider !== value.provider) {
		return null;
	}
	return {
		provider: value.provider,
		credentialId: value.credentialId,
		credentialCacheKey,
		fetchedAt: value.fetchedAt,
		revision: parseRevision(value.revision),
		freshUntil: value.freshUntil,
		staleUntil: value.staleUntil,
		snapshot,
	};
}

function resolveLegacyCredentialCacheKey(
	providerId: string,
	credentialId: string,
	options: UsageCacheHydrationOptions,
): string | null {
	if (!options.resolveLegacyCredentialCacheKey) {
		return null;
	}
	try {
		const credentialCacheKey = options.resolveLegacyCredentialCacheKey(providerId, credentialId);
		if (typeof credentialCacheKey !== "string") {
			return null;
		}
		const normalized = credentialCacheKey.trim();
		return normalized.length > 0 ? normalized : null;
	} catch (error: unknown) {
		multiAuthDebugLogger.log("usage_cache_legacy_key_resolution_error", {
			provider: providerId,
			credentialId,
			error: getErrorMessage(error),
		});
		return null;
	}
}

function compareEntriesForRetention(
	left: CredentialScopedUsageCacheIdentity,
	right: CredentialScopedUsageCacheIdentity,
): number {
	const fetchedDelta = right.fetchedAt - left.fetchedAt;
	if (fetchedDelta !== 0) {
		return fetchedDelta;
	}
	const revisionDelta = right.revision - left.revision;
	if (revisionDelta !== 0) {
		return revisionDelta;
	}
	const providerDelta = left.provider.localeCompare(right.provider);
	if (providerDelta !== 0) {
		return providerDelta;
	}
	return left.credentialId.localeCompare(right.credentialId);
}

function shouldReplaceSameIdentity(
	candidate: CredentialScopedUsageCacheIdentity,
	existing: CredentialScopedUsageCacheIdentity,
): boolean {
	if (candidate.revision > 0 && existing.revision > 0 && candidate.revision !== existing.revision) {
		return candidate.revision > existing.revision;
	}
	return compareEntriesForRetention(candidate, existing) <= 0;
}

function isEntryAllowed(
	entry: CredentialScopedUsageCacheIdentity,
	options: UsageCacheHydrationOptions,
): boolean {
	if (!options.isCredentialValid) {
		return true;
	}
	try {
		return options.isCredentialValid(entry.provider, entry.credentialId, entry.credentialCacheKey);
	} catch (error: unknown) {
		multiAuthDebugLogger.log("usage_cache_credential_validation_error", {
			provider: entry.provider,
			credentialId: entry.credentialId,
			error: getErrorMessage(error),
		});
		return false;
	}
}

function isDisplayEntryAllowed(
	entry: CredentialScopedUsageCacheIdentity,
	options: UsageCacheHydrationOptions,
): boolean {
	const validator = options.isDisplayCredentialValid ?? options.isCredentialValid;
	if (!validator) {
		return true;
	}
	try {
		return validator(entry.provider, entry.credentialId, entry.credentialCacheKey);
	} catch (error: unknown) {
		multiAuthDebugLogger.log("usage_cache_display_credential_validation_error", {
			provider: entry.provider,
			credentialId: entry.credentialId,
			error: getErrorMessage(error),
		});
		return false;
	}
}

export class UsageSnapshotCacheStore {
	private readonly filePath: string;
	private readonly maxEntries: number;
	private readonly displayMaxEntries: number;
	private readonly displayRetentionMs: number;
	private readonly writeLockStaleMs: number;
	private readonly writeLockWaitMs: number;
	private readonly refreshLockStaleMs: number;
	private readonly refreshLockWaitMs: number;
	private readonly lockPollMs: number;
	private readonly refreshLockHeartbeatMs: number;

	constructor(options: UsageCachePersistenceOptions = {}) {
		this.filePath = options.filePath ?? getDefaultUsageCachePath();
		this.maxEntries = Math.max(1, Math.floor(options.maxEntries ?? DEFAULT_USAGE_CACHE_MAX_ENTRIES));
		this.displayMaxEntries = Math.max(1, Math.floor(options.displayMaxEntries ?? this.maxEntries));
		this.displayRetentionMs = Math.max(1, Math.floor(options.displayRetentionMs ?? DEFAULT_USAGE_DISPLAY_CACHE_RETENTION_MS));
		this.writeLockStaleMs = Math.max(1, Math.floor(options.writeLockStaleMs ?? DEFAULT_USAGE_CACHE_WRITE_LOCK_STALE_MS));
		this.writeLockWaitMs = Math.max(1, Math.floor(options.writeLockWaitMs ?? DEFAULT_USAGE_CACHE_WRITE_LOCK_WAIT_MS));
		this.refreshLockStaleMs = Math.max(1, Math.floor(options.refreshLockStaleMs ?? DEFAULT_USAGE_REFRESH_LOCK_STALE_MS));
		this.refreshLockWaitMs = Math.max(1, Math.floor(options.refreshLockWaitMs ?? DEFAULT_USAGE_REFRESH_LOCK_WAIT_MS));
		this.lockPollMs = Math.max(1, Math.floor(options.lockPollMs ?? DEFAULT_USAGE_LOCK_POLL_MS));
		this.refreshLockHeartbeatMs = Math.max(
			1,
			Math.min(
				Math.floor(options.refreshLockHeartbeatMs ?? DEFAULT_USAGE_REFRESH_LOCK_HEARTBEAT_MS),
				Math.max(1, Math.floor(this.refreshLockStaleMs / 3)),
			),
		);
	}

	getPath(): string {
		return this.filePath;
	}

	getCredentialRefreshLockPath(
		providerId: string,
		credentialId: string,
		credentialCacheKey: string,
	): string {
		void credentialCacheKey;
		const digest = createHash("sha256")
			// Coordinate the provider/credential slot even while OAuth material rotates.
			// Cache-key matching still isolates results, so a waiter with different
			// credential material will fetch sequentially rather than reuse them.
			.update(JSON.stringify([providerId, credentialId]))
			.digest("hex");
		return lockDirPath(join(`${this.filePath}.refresh-locks`, digest));
	}

	async withCredentialRefreshLock<T>(
		providerId: string,
		credentialId: string,
		credentialCacheKey: string,
		run: (context: UsageRefreshLockContext) => Promise<T>,
	): Promise<T> {
		const lockPath = this.getCredentialRefreshLockPath(providerId, credentialId, credentialCacheKey);
		const lockTargetPath = lockPath.slice(0, -".lock".length);
		await ensureParentDir(lockTargetPath);
		let contended = false;
		let timedOut = false;
		let release: (() => Promise<void>) | undefined;
		try {
			release = await acquireFileLock(
				lockTargetPath,
				{
					realpath: false,
					retries: this.createLockRetryOptions(this.refreshLockWaitMs),
					stale: this.refreshLockStaleMs,
					timeoutMs: this.refreshLockWaitMs,
					update: this.refreshLockHeartbeatMs,
					onCompromised: () => {
						contended = true;
					},
				},
				{
					onRetry: () => {
						contended = true;
					},
					onStaleLockRemoved: ({ ageMs }) => {
						contended = true;
						multiAuthDebugLogger.log("usage_refresh_stale_lock_removed", {
							cachePath: this.filePath,
							lockPath,
							ageMs,
						});
					},
					onTimeout: () => {
						timedOut = true;
					},
				},
			);
		} catch (error: unknown) {
			if (timedOut) {
				throw new UsageRefreshLockTimeoutError(lockPath, error);
			}
			throw error;
		}

		try {
			return await run({ contended });
		} finally {
			if (release) {
				await release().catch(() => undefined);
			}
		}
	}

	async readEntries(
		now: number = Date.now(),
		options: UsageCacheHydrationOptions = {},
	): Promise<UsageCacheRecord[]> {
		return (await this.readHydrationEntries(now, options)).operationalEntries;
	}

	async readDisplayEntries(
		now: number = Date.now(),
		options: UsageCacheHydrationOptions = {},
	): Promise<UsageDisplayCacheRecord[]> {
		return (await this.readHydrationEntries(now, options)).displayEntries;
	}

	async readHydrationEntries(
		now: number = Date.now(),
		options: UsageCacheHydrationOptions = {},
	): Promise<UsageCacheHydrationRecords> {
		const snapshot = await this.readHydrationSnapshot(now, options);
		return {
			operationalEntries: snapshot.operationalEntries,
			displayEntries: snapshot.displayEntries,
		};
	}

	async readHydrationSnapshot(
		now: number = Date.now(),
		options: UsageCacheHydrationOptions = {},
	): Promise<UsageCacheHydrationSnapshot> {
		// Capture before reading. If an atomic replacement races the read, retaining
		// the older fingerprint guarantees the next cheap check rereads the file.
		let fingerprint = await this.readFingerprint();
		let persisted = await this.readPersistedEntries(options);
		let records = this.createHydrationRecords(persisted, now, options);
		if (options.pruneInvalidEntries && this.shouldRewritePersistedEntries(persisted, now, options)) {
			await this.rewritePrunedEntries(now, options);
			fingerprint = await this.readFingerprint();
			persisted = await this.readPersistedEntries(options);
			records = this.createHydrationRecords(persisted, now, options);
		}
		return {
			...records,
			fingerprint,
			revision: persisted.revision,
		};
	}

	readHydrationSnapshotIfChangedSync(
		previousFingerprint: string | null | undefined,
		now: number = Date.now(),
		options: UsageCacheHydrationOptions = {},
	): UsageCacheHydrationSnapshot | null {
		const fingerprint = this.readFingerprintSync();
		if (previousFingerprint !== undefined && fingerprint === previousFingerprint) {
			return null;
		}
		let content: string | undefined;
		try {
			content = fingerprint === null ? undefined : readFileSync(this.filePath, "utf-8");
		} catch (error: unknown) {
			multiAuthDebugLogger.log("usage_cache_live_read_failed", {
				cachePath: this.filePath,
				error: getErrorMessage(error),
			});
			return null;
		}
		const persisted = this.parsePersistedContent(content, options);
		return {
			...this.createHydrationRecords(persisted, now, options),
			fingerprint,
			revision: persisted.revision,
		};
	}

	async persistEntry(
		entry: UsageCacheRecord,
		now: number = Date.now(),
	): Promise<UsageCachePersistResult | null> {
		const isSuccess = Boolean(entry.result.snapshot && !entry.result.error);
		const isError = entry.result.snapshot === null && isNonEmptyString(entry.result.error);
		if (!isSuccess && !isError) {
			return null;
		}

		return this.withWriteLock(async () => {
			const persisted = await this.readPersistedEntries({}, true);
			const revision = this.nextRevision(persisted);
			let entries = this.pruneEntries(persisted.entries, now);
			let errorEntries = this.pruneErrorEntries(persisted.errorEntries, now);
			let displayEntries = this.pruneDisplayEntries(persisted.displayEntries, now);
			let displayEntry: PersistedUsageDisplayCacheEntry | null = null;
			let operationalEntry: UsageCacheRecord;

			if (isSuccess && entry.result.snapshot) {
				const persistedEntry: PersistedUsageCacheEntry = {
					provider: entry.providerId,
					credentialId: entry.credentialId,
					credentialCacheKey: entry.credentialCacheKey,
					fetchedAt: entry.result.fetchedAt,
					revision,
					freshUntil: entry.freshUntil,
					staleUntil: entry.staleUntil,
					snapshot: entry.result.snapshot,
				};
				displayEntry = {
					provider: entry.providerId,
					credentialId: entry.credentialId,
					credentialCacheKey: entry.credentialCacheKey,
					fetchedAt: entry.result.fetchedAt,
					revision,
					displayUntil: entry.result.fetchedAt + this.displayRetentionMs,
					snapshot: entry.result.snapshot,
				};
				entries = this.pruneEntries([...entries, persistedEntry], now);
				errorEntries = errorEntries.filter((candidate) => !this.isSameRecord(candidate, persistedEntry));
				displayEntries = this.pruneDisplayEntries([...displayEntries, displayEntry], now);
				operationalEntry = this.toUsageCacheRecord(persistedEntry);
			} else {
				const persistedErrorEntry: PersistedUsageCacheErrorEntry = {
					provider: entry.providerId,
					credentialId: entry.credentialId,
					credentialCacheKey: entry.credentialCacheKey,
					fetchedAt: entry.result.fetchedAt,
					revision,
					error: entry.result.error ?? "Usage unavailable",
					freshUntil: entry.freshUntil,
					staleUntil: entry.staleUntil,
				};
				errorEntries = this.pruneErrorEntries([...errorEntries, persistedErrorEntry], now);
				operationalEntry = this.toUsageErrorCacheRecord(persistedErrorEntry);
			}

			await this.writeEntries(entries, errorEntries, displayEntries, now, revision);
			return {
				operationalEntry,
				displayEntry: this.toDisplayCacheRecord(displayEntry),
			};
		});
	}

	async persistSuccessfulEntry(
		entry: UsageCacheRecord,
		now: number = Date.now(),
	): Promise<UsageDisplayCacheRecord | null> {
		if (!entry.result.snapshot || entry.result.error) {
			return null;
		}
		return (await this.persistEntry(entry, now))?.displayEntry ?? null;
	}

	private toUsageCacheRecord(entry: PersistedUsageCacheEntry): UsageCacheRecord {
		return {
			providerId: entry.provider,
			credentialId: entry.credentialId,
			credentialCacheKey: entry.credentialCacheKey,
			result: {
				snapshot: entry.snapshot,
				error: null,
				fetchedAt: entry.fetchedAt,
			},
			freshUntil: entry.freshUntil,
			staleUntil: entry.staleUntil,
			revision: entry.revision,
		};
	}

	private toUsageErrorCacheRecord(entry: PersistedUsageCacheErrorEntry): UsageCacheRecord {
		return {
			providerId: entry.provider,
			credentialId: entry.credentialId,
			credentialCacheKey: entry.credentialCacheKey,
			result: {
				snapshot: null,
				error: entry.error,
				fetchedAt: entry.fetchedAt,
			},
			freshUntil: entry.freshUntil,
			staleUntil: entry.staleUntil,
			revision: entry.revision,
		};
	}

	private toDisplayCacheRecord(entry: PersistedUsageDisplayCacheEntry): UsageDisplayCacheRecord;
	private toDisplayCacheRecord(entry: null): null;
	private toDisplayCacheRecord(entry: PersistedUsageDisplayCacheEntry | null): UsageDisplayCacheRecord | null;
	private toDisplayCacheRecord(entry: PersistedUsageDisplayCacheEntry | null): UsageDisplayCacheRecord | null {
		if (!entry) {
			return null;
		}
		return {
			providerId: entry.provider,
			credentialId: entry.credentialId,
			credentialCacheKey: entry.credentialCacheKey,
			result: {
				snapshot: entry.snapshot,
				error: null,
				fetchedAt: entry.fetchedAt,
			},
			displayUntil: entry.displayUntil,
			revision: entry.revision,
		};
	}

	private async readPersistedEntries(
		options: UsageCacheHydrationOptions = {},
		requireMergeSafe: boolean = false,
	): Promise<ParsedPersistedUsageCacheFile> {
		try {
			const persisted = await readTextSnapshotWithRetries({
				filePath: this.filePath,
				failureMessage: `Failed to read usage cache snapshot from '${this.filePath}'.`,
				read: async () => ((await pathExists(this.filePath)) ? readFile(this.filePath, "utf-8") : undefined),
				parse: (content) => this.parsePersistedContent(content, options),
				resolveOnFinalEmpty: () => createEmptyParsedUsageCache(),
				isRetryableError: isRetryableFileAccessError,
				onRetry: ({ attempt, maxAttempts, reason, delayMs }) => {
					multiAuthDebugLogger.log("usage_cache_read_retry", {
						cachePath: this.filePath,
						attempt,
						maxAttempts,
						reason,
						delayMs,
					});
				},
				onRecovered: ({ attempt, maxAttempts }) => {
					multiAuthDebugLogger.log("usage_cache_read_recovered", {
						cachePath: this.filePath,
						attempt,
						maxAttempts,
					});
				},
				onError: ({ attempt, maxAttempts, error }) => {
					multiAuthDebugLogger.log("usage_cache_read_error", {
						cachePath: this.filePath,
						attempt,
						maxAttempts,
						error,
					});
				},
			});
			if (requireMergeSafe && !persisted.mergeSafe) {
				throw new Error(`Usage cache '${this.filePath}' is not safe to merge; refusing to overwrite it.`);
			}
			return persisted;
		} catch (error: unknown) {
			multiAuthDebugLogger.log("usage_cache_read_failed", {
				cachePath: this.filePath,
				error: getErrorMessage(error),
			});
			if (requireMergeSafe) {
				throw error;
			}
			return createEmptyParsedUsageCache(false);
		}
	}

	private parsePersistedContent(
		content: string | undefined,
		options: UsageCacheHydrationOptions,
	): ParsedPersistedUsageCacheFile {
		if (content === undefined || content.trim() === "") {
			return createEmptyParsedUsageCache();
		}
		let parsed: unknown;
		try {
			parsed = JSON.parse(content);
		} catch (error: unknown) {
			multiAuthDebugLogger.log("usage_cache_malformed_json", {
				cachePath: this.filePath,
				error: getErrorMessage(error),
			});
			return createEmptyParsedUsageCache(false);
		}
		if (!isRecord(parsed)) {
			multiAuthDebugLogger.log("usage_cache_invalid_schema", { cachePath: this.filePath });
			return createEmptyParsedUsageCache(false);
		}
		const isCurrentSchema = parsed.schemaVersion === USAGE_CACHE_SCHEMA_VERSION;
		const isV2Schema = parsed.schemaVersion === USAGE_CACHE_V2_SCHEMA_VERSION;
		const isLegacySchema = parsed.schemaVersion === USAGE_CACHE_LEGACY_SCHEMA_VERSION;
		if (!isCurrentSchema && !isV2Schema && !isLegacySchema) {
			multiAuthDebugLogger.log("usage_cache_invalid_schema", { cachePath: this.filePath });
			return createEmptyParsedUsageCache(false);
		}
		if (!Array.isArray(parsed.entries)) {
			multiAuthDebugLogger.log("usage_cache_invalid_entries", { cachePath: this.filePath });
			return {
				...createEmptyParsedUsageCache(false),
				shouldRewrite: false,
			};
		}

		const entries: PersistedUsageCacheEntry[] = [];
		let discardedEntry = false;
		for (const rawEntry of parsed.entries) {
			const entry = isLegacySchema
				? parseLegacyPersistedEntry(rawEntry, options)
				: parsePersistedEntry(rawEntry);
			if (entry) {
				entries.push(entry);
			} else {
				discardedEntry = true;
			}
		}

		const errorEntries: PersistedUsageCacheErrorEntry[] = [];
		if (isCurrentSchema && parsed.errorEntries !== undefined) {
			if (Array.isArray(parsed.errorEntries)) {
				for (const rawEntry of parsed.errorEntries) {
					const entry = parsePersistedErrorEntry(rawEntry);
					if (entry) {
						errorEntries.push(entry);
					} else {
						discardedEntry = true;
					}
				}
			} else {
				discardedEntry = true;
			}
		}

		const entrySnapshots = new Map<string, UsageSnapshot>();
		for (const entry of entries) {
			entrySnapshots.set(createRecordKey(entry.provider, entry.credentialId, entry.credentialCacheKey), entry.snapshot);
		}
		const displayEntries: PersistedUsageDisplayCacheEntry[] = [];
		if ((isCurrentSchema || isV2Schema) && parsed.displayEntries !== undefined) {
			if (Array.isArray(parsed.displayEntries)) {
				for (const rawEntry of parsed.displayEntries) {
					const entry = parsePersistedDisplayEntry(
						rawEntry,
						(provider, credentialId, credentialCacheKey) =>
							entrySnapshots.get(createRecordKey(provider, credentialId, credentialCacheKey)) ?? null,
					);
					if (entry) {
						displayEntries.push(entry);
					} else {
						discardedEntry = true;
					}
				}
			} else {
				discardedEntry = true;
			}
		}

		return {
			mergeSafe: true,
			revision: parseRevision(parsed.revision),
			entries,
			errorEntries,
			displayEntries,
			shouldRewrite: isLegacySchema || isV2Schema || discardedEntry,
		};
	}

	private pruneEntries(
		entries: readonly PersistedUsageCacheEntry[],
		now: number,
		options: UsageCacheHydrationOptions = {},
	): PersistedUsageCacheEntry[] {
		const latestByCredential = new Map<string, PersistedUsageCacheEntry>();
		for (const entry of entries) {
			if (entry.staleUntil <= now || !isEntryAllowed(entry, options)) {
				continue;
			}
			const key = createRecordKey(entry.provider, entry.credentialId, entry.credentialCacheKey);
			const existing = latestByCredential.get(key);
			// <= so a later write wins an exact fetchedAt tie (same-millisecond
			// refetch); entries arrive in chronological append order.
			if (!existing || shouldReplaceSameIdentity(entry, existing)) {
				latestByCredential.set(key, entry);
			}
		}
		return [...latestByCredential.values()]
			.sort(compareEntriesForRetention)
			.slice(0, this.maxEntries);
	}

	private pruneDisplayEntries(
		entries: readonly PersistedUsageDisplayCacheEntry[],
		_now: number,
		options: UsageCacheHydrationOptions = {},
	): PersistedUsageDisplayCacheEntry[] {
		const latestByCredential = new Map<string, PersistedUsageDisplayCacheEntry>();
		for (const entry of entries) {
			if (!isDisplayEntryAllowed(entry, options)) {
				continue;
			}
			// Deduplicate by provider + credentialId only so newer fetches always
			// replace older ones regardless of credentialCacheKey (token) changes.
			const key = createRecordKey(entry.provider, entry.credentialId, "");
			const existing = latestByCredential.get(key);
			// <= so a later write wins an exact fetchedAt tie (same-millisecond
			// refetch); entries arrive in chronological append order.
			if (!existing || shouldReplaceSameIdentity(entry, existing)) {
				latestByCredential.set(key, entry);
			}
		}
		return [...latestByCredential.values()]
			.sort(compareEntriesForRetention)
			.slice(0, this.displayMaxEntries);
	}


	private pruneErrorEntries(
		entries: readonly PersistedUsageCacheErrorEntry[],
		now: number,
		options: UsageCacheHydrationOptions = {},
	): PersistedUsageCacheErrorEntry[] {
		const latestByCredential = new Map<string, PersistedUsageCacheErrorEntry>();
		for (const entry of entries) {
			if (entry.staleUntil <= now || !isEntryAllowed(entry, options)) {
				continue;
			}
			const key = createRecordKey(entry.provider, entry.credentialId, entry.credentialCacheKey);
			const existing = latestByCredential.get(key);
			if (!existing || shouldReplaceSameIdentity(entry, existing)) {
				latestByCredential.set(key, entry);
			}
		}
		return [...latestByCredential.values()]
			.sort(compareEntriesForRetention)
			.slice(0, this.maxEntries);
	}

	private createHydrationRecords(
		persisted: ParsedPersistedUsageCacheFile,
		now: number,
		options: UsageCacheHydrationOptions,
	): UsageCacheHydrationRecords {
		const successfulEntries = this.pruneEntries(persisted.entries, now, options);
		const errorEntries = this.pruneErrorEntries(persisted.errorEntries, now, options);
		const latestOperationalEntries = new Map<
			string,
			PersistedUsageCacheEntry | PersistedUsageCacheErrorEntry
		>();
		for (const entry of successfulEntries) {
			latestOperationalEntries.set(
				createRecordKey(entry.provider, entry.credentialId, entry.credentialCacheKey),
				entry,
			);
		}
		for (const entry of errorEntries) {
			const key = createRecordKey(entry.provider, entry.credentialId, entry.credentialCacheKey);
			const existing = latestOperationalEntries.get(key);
			if (!existing || shouldReplaceSameIdentity(entry, existing)) {
				latestOperationalEntries.set(key, entry);
			}
		}
		const operationalEntries = [...latestOperationalEntries.values()]
			.sort(compareEntriesForRetention)
			.slice(0, this.maxEntries)
			.map((entry) => "error" in entry
				? this.toUsageErrorCacheRecord(entry)
				: this.toUsageCacheRecord(entry));
		const displayEntries = this.pruneDisplayEntries(persisted.displayEntries, now, options)
			.map((entry) => this.toDisplayCacheRecord(entry));
		return { operationalEntries, displayEntries };
	}

	private shouldRewritePersistedEntries(
		persisted: ParsedPersistedUsageCacheFile,
		now: number,
		options: UsageCacheHydrationOptions,
	): boolean {
		return persisted.shouldRewrite ||
			this.haveEntriesChanged(persisted.entries, this.pruneEntries(persisted.entries, now, options)) ||
			this.haveEntriesChanged(persisted.errorEntries, this.pruneErrorEntries(persisted.errorEntries, now, options)) ||
			this.haveEntriesChanged(persisted.displayEntries, this.pruneDisplayEntries(persisted.displayEntries, now, options));
	}

	private async rewritePrunedEntries(
		now: number,
		options: UsageCacheHydrationOptions,
	): Promise<void> {
		await this.withWriteLock(async () => {
			const current = await this.readPersistedEntries(options, true);
			const entries = this.pruneEntries(current.entries, now, options);
			const errorEntries = this.pruneErrorEntries(current.errorEntries, now, options);
			const displayEntries = this.pruneDisplayEntries(current.displayEntries, now, options);
			if (
				!current.shouldRewrite &&
				!this.haveEntriesChanged(current.entries, entries) &&
				!this.haveEntriesChanged(current.errorEntries, errorEntries) &&
				!this.haveEntriesChanged(current.displayEntries, displayEntries)
			) {
				return;
			}
			const revision = this.nextRevision(current);
			await this.writeEntries(entries, errorEntries, displayEntries, now, revision);
		});
	}

	private async withWriteLock<T>(run: () => Promise<T>): Promise<T> {
		await ensureParentDir(this.filePath);
		let release: (() => Promise<void>) | undefined;
		try {
			release = await acquireFileLock(
				this.filePath,
				{
					realpath: false,
					retries: this.createLockRetryOptions(this.writeLockWaitMs),
					stale: this.writeLockStaleMs,
					timeoutMs: this.writeLockWaitMs,
					update: Math.max(1, Math.min(1_000, Math.floor(this.writeLockStaleMs / 3))),
					onCompromised: () => undefined,
				},
				{
					onStaleLockRemoved: ({ ageMs }) => {
						multiAuthDebugLogger.log("usage_cache_stale_write_lock_removed", {
							cachePath: this.filePath,
							ageMs,
						});
					},
				},
			);
			return await run();
		} finally {
			if (release) {
				await release().catch(() => undefined);
			}
		}
	}

	private createLockRetryOptions(waitMs: number): {
		retries: number;
		factor: number;
		minTimeout: number;
		maxTimeout: number;
		randomize: boolean;
	} {
		return {
			retries: Math.max(1, Math.ceil(waitMs / this.lockPollMs)),
			factor: 1,
			minTimeout: this.lockPollMs,
			maxTimeout: this.lockPollMs,
			randomize: false,
		};
	}

	private nextRevision(persisted: ParsedPersistedUsageCacheFile): number {
		let revision = persisted.revision;
		for (const entry of [...persisted.entries, ...persisted.errorEntries, ...persisted.displayEntries]) {
			revision = Math.max(revision, entry.revision);
		}
		return revision + 1;
	}

	private isSameRecord(
		left: CredentialScopedUsageCacheIdentity,
		right: CredentialScopedUsageCacheIdentity,
	): boolean {
		return left.provider === right.provider &&
			left.credentialId === right.credentialId &&
			left.credentialCacheKey === right.credentialCacheKey;
	}

	private async readFingerprint(): Promise<string | null> {
		try {
			return createFileFingerprint(await stat(this.filePath));
		} catch (error: unknown) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") {
				return null;
			}
			throw error;
		}
	}

	private readFingerprintSync(): string | null {
		try {
			return createFileFingerprint(statSync(this.filePath));
		} catch (error: unknown) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") {
				return null;
			}
			multiAuthDebugLogger.log("usage_cache_stat_failed", {
				cachePath: this.filePath,
				error: getErrorMessage(error),
			});
			return null;
		}
	}

	private haveEntriesChanged(
		previous: readonly CredentialScopedUsageCacheIdentity[],
		next: readonly CredentialScopedUsageCacheIdentity[],
	): boolean {
		if (previous.length !== next.length) {
			return true;
		}
		return JSON.stringify(previous) !== JSON.stringify(next);
	}

	private serialize(
		entries: readonly PersistedUsageCacheEntry[],
		errorEntries: readonly PersistedUsageCacheErrorEntry[],
		displayEntries: readonly PersistedUsageDisplayCacheEntry[],
		generatedAt: number,
		revision: number,
	): string {
		const sortedEntries = [...entries].sort(compareEntriesForRetention);
		const sortedErrorEntries = [...errorEntries].sort(compareEntriesForRetention);
		const entrySnapshots = new Map<string, string>();
		for (const entry of sortedEntries) {
			entrySnapshots.set(
				createRecordKey(entry.provider, entry.credentialId, entry.credentialCacheKey),
				JSON.stringify(entry.snapshot),
			);
		}
		const serializedDisplayEntries: SerializedUsageDisplayCacheEntry[] = [...displayEntries]
			.sort(compareEntriesForRetention)
			.map((entry) => {
				const baseEntry = {
					provider: entry.provider,
					credentialId: entry.credentialId,
					credentialCacheKey: entry.credentialCacheKey,
					fetchedAt: entry.fetchedAt,
					revision: entry.revision,
					displayUntil: entry.displayUntil,
				};
				const matchingSnapshot = entrySnapshots.get(
					createRecordKey(entry.provider, entry.credentialId, entry.credentialCacheKey),
				);
				return matchingSnapshot === JSON.stringify(entry.snapshot)
					? baseEntry
					: { ...baseEntry, snapshot: entry.snapshot };
			});
		const payload: PersistedUsageCacheFile = {
			schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
			revision,
			generatedAt,
			maxEntries: this.maxEntries,
			maxDisplayEntries: this.displayMaxEntries,
			displayRetentionMs: this.displayRetentionMs,
			entries: sortedEntries,
			errorEntries: sortedErrorEntries,
			displayEntries: serializedDisplayEntries,
		};
		return `${JSON.stringify(payload, null, 2)}\n`;
	}

	private async writeEntries(
		entries: readonly PersistedUsageCacheEntry[],
		errorEntries: readonly PersistedUsageCacheErrorEntry[],
		displayEntries: readonly PersistedUsageDisplayCacheEntry[],
		generatedAt: number,
		revision: number,
	): Promise<void> {
		try {
			const serialized = this.serialize(entries, errorEntries, displayEntries, generatedAt, revision);
			await ensureParentDir(this.filePath);
			await writeTextSnapshotWithRetries({
				filePath: this.filePath,
				failureMessage: `Failed to persist usage cache snapshot to '${this.filePath}'.`,
				write: async () => {
					await writeTextFileAtomically(this.filePath, serialized);
				},
				isRetryableError: isRetryableFileAccessError,
				onRetry: ({ attempt, maxAttempts, reason, delayMs }) => {
					multiAuthDebugLogger.log("usage_cache_write_retry", {
						cachePath: this.filePath,
						attempt,
						maxAttempts,
						reason,
						delayMs,
					});
				},
				onRecovered: ({ attempt, maxAttempts }) => {
					multiAuthDebugLogger.log("usage_cache_write_recovered", {
						cachePath: this.filePath,
						attempt,
						maxAttempts,
					});
				},
				onError: ({ attempt, maxAttempts, error }) => {
					multiAuthDebugLogger.log("usage_cache_write_error", {
						cachePath: this.filePath,
						attempt,
						maxAttempts,
						error,
					});
				},
			});
		} catch (error: unknown) {
			multiAuthDebugLogger.log("usage_cache_write_failed", {
				cachePath: this.filePath,
				error: getErrorMessage(error),
			});
			throw error;
		}
	}
}
