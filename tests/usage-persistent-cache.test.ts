import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AccountManager } from "../src/account-manager.js";
import { AuthWriter } from "../src/auth-writer.js";
import { ProviderRegistry } from "../src/provider-registry.js";
import { MultiAuthStorage } from "../src/storage.js";
import { createUsageCredentialCacheKey, UsageService } from "../src/usage/index.js";
import {
	USAGE_CACHE_SCHEMA_VERSION,
	UsageSnapshotCacheStore,
	type UsageCacheRecord,
} from "../src/usage/persistent-cache.js";
import type { UsageAuth, UsageSnapshot } from "../src/usage/types.js";

interface PersistedUsageCacheTestFile {
	schemaVersion: number;
	generatedAt: number;
	maxEntries: number;
	maxDisplayEntries?: number;
	displayRetentionMs?: number;
	entries: Array<{
		provider: string;
		credentialId: string;
		credentialCacheKey: string;
		fetchedAt: number;
		freshUntil: number;
		staleUntil: number;
		snapshot: UsageSnapshot;
	}>;
	displayEntries?: Array<{
		provider: string;
		credentialId: string;
		credentialCacheKey: string;
		fetchedAt: number;
		displayUntil: number;
		snapshot?: UsageSnapshot;
	}>;
}

interface LegacyPersistedUsageCacheTestFile {
	schemaVersion: 1;
	generatedAt: number;
	maxEntries: number;
	entries: Array<{
		provider: string;
		credentialId: string;
		fetchedAt: number;
		freshUntil: number;
		staleUntil: number;
		snapshot: UsageSnapshot;
	}>;
}

function createUsageSnapshot(provider: string, timestamp: number = Date.now()): UsageSnapshot {
	return {
		timestamp,
		provider,
		planType: null,
		primary: null,
		secondary: null,
		credits: null,
		copilotQuota: null,
		updatedAt: timestamp,
	};
}

function createBase64UrlJson(value: Record<string, unknown>): string {
	return Buffer.from(JSON.stringify(value), "utf-8")
		.toString("base64")
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
}

function createCodexIdentityJwt(options: {
	expiresAtSeconds: number;
	accountId: string;
	accountUserId: string;
	email: string;
}): string {
	return [
		createBase64UrlJson({ alg: "none", typ: "JWT" }),
		createBase64UrlJson({
			exp: options.expiresAtSeconds,
			"https://api.openai.com/auth": {
				chatgpt_account_id: options.accountId,
				chatgpt_account_user_id: options.accountUserId,
			},
			"https://api.openai.com/profile": {
				email: options.email,
			},
		}),
		"signature",
	].join(".");
}

function createUsageCacheRecord(
	providerId: string,
	credentialId: string,
	fetchedAt: number,
	credentialCacheKey: string = `cache:${credentialId}`,
): UsageCacheRecord {
	return {
		providerId,
		credentialId,
		credentialCacheKey,
		result: {
			snapshot: createUsageSnapshot(providerId, fetchedAt),
			error: null,
			fetchedAt,
		},
		freshUntil: fetchedAt + 30_000,
		staleUntil: fetchedAt + 300_000,
	};
}

async function createTempUsageCachePath(): Promise<{ tempRoot: string; cachePath: string }> {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-usage-cache-"));
	return { tempRoot, cachePath: join(tempRoot, "multi-auth-usage-cache.json") };
}

async function readPersistedCache(cachePath: string): Promise<PersistedUsageCacheTestFile> {
	return JSON.parse(await readFile(cachePath, "utf-8")) as PersistedUsageCacheTestFile;
}

test("usage service persists successful snapshots with bounded cache metadata", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const providerId = "persistent-provider";
	const credentialId = "credential-a";
	const snapshot = createUsageSnapshot(providerId);
	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 100 }),
	});
	usageService.register({
		id: providerId,
		displayName: providerId,
		fetchUsage: async (_auth: UsageAuth) => snapshot,
	});

	const result = await usageService.fetchUsage(
		providerId,
		credentialId,
		{ accessToken: "token" },
		{ forceRefresh: true },
	);
	const persisted = await readPersistedCache(cachePath);

	assert.equal(usageService.getPersistentCachePath(), cachePath);
	assert.equal(result.error, null);
	assert.equal(persisted.schemaVersion, USAGE_CACHE_SCHEMA_VERSION);
	assert.equal(persisted.maxEntries, 100);
	assert.equal(persisted.entries.length, 1);
	assert.equal(persisted.entries[0]?.provider, providerId);
	assert.equal(persisted.entries[0]?.credentialId, credentialId);
	assert.equal(persisted.entries[0]?.fetchedAt, result.fetchedAt);
	assert.equal((persisted.entries[0]?.freshUntil ?? 0) > result.fetchedAt, true);
	assert.equal((persisted.entries[0]?.staleUntil ?? 0) >= (persisted.entries[0]?.freshUntil ?? 0), true);
	assert.deepEqual(persisted.entries[0]?.snapshot, snapshot);
});

test("usage service hydrates valid non-expired entries and prunes expired or orphaned entries", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "hydrate-provider";
	const validCredentialId = "credential-valid";
	const expiredCredentialId = "credential-expired";
	const orphanCredentialId = "credential-orphan";
	const validSnapshot = createUsageSnapshot(providerId, now);
	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		entries: [
			{
				provider: providerId,
				credentialId: validCredentialId,
				credentialCacheKey: `cache:${validCredentialId}`,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: validSnapshot,
			},
			{
				provider: providerId,
				credentialId: expiredCredentialId,
				credentialCacheKey: `cache:${expiredCredentialId}`,
				fetchedAt: now - 600_000,
				freshUntil: now - 500_000,
				staleUntil: now - 1,
				snapshot: createUsageSnapshot(providerId, now - 600_000),
			},
			{
				provider: providerId,
				credentialId: orphanCredentialId,
				credentialCacheKey: `cache:${orphanCredentialId}`,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot(providerId, now),
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	await usageService.hydratePersistedCache({
		isCredentialValid: (_provider, credentialId) => credentialId === validCredentialId,
		pruneInvalidEntries: true,
	});

	const hydrated = usageService.readCachedUsage(providerId, validCredentialId);
	assert.deepEqual(hydrated?.snapshot, validSnapshot);
	assert.equal(hydrated?.fromCache, true);
	assert.equal(usageService.readCachedUsage(providerId, expiredCredentialId, { allowStale: true }), null);
	assert.equal(usageService.readCachedUsage(providerId, orphanCredentialId), null);

	const pruned = await readPersistedCache(cachePath);
	assert.deepEqual(
		pruned.entries.map((entry) => entry.credentialId),
		[validCredentialId],
	);
});

test("usage service hydrates display snapshots after operational entries expire", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "display-provider";
	const validCredentialId = "credential-valid";
	const orphanCredentialId = "credential-orphan";
	const validCredentialCacheKey = `cache:${validCredentialId}`;
	const validSnapshot = { ...createUsageSnapshot(providerId, now), planType: "pro" };
	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [
			{
				provider: providerId,
				credentialId: validCredentialId,
				credentialCacheKey: validCredentialCacheKey,
				fetchedAt: now - 600_000,
				freshUntil: now - 500_000,
				staleUntil: now - 1,
				snapshot: validSnapshot,
			},
		],
		displayEntries: [
			{
				provider: providerId,
				credentialId: validCredentialId,
				credentialCacheKey: validCredentialCacheKey,
				fetchedAt: now - 600_000,
				displayUntil: now + 86_400_000,
				snapshot: validSnapshot,
			},
			{
				provider: providerId,
				credentialId: orphanCredentialId,
				credentialCacheKey: `cache:${orphanCredentialId}`,
				fetchedAt: now - 600_000,
				displayUntil: now + 86_400_000,
				snapshot: createUsageSnapshot(providerId, now - 600_000),
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	await usageService.hydratePersistedCache({
		isCredentialValid: (_provider, credentialId, credentialCacheKey) =>
			credentialId === validCredentialId && credentialCacheKey === validCredentialCacheKey,
		pruneInvalidEntries: true,
	});

	const operational = usageService.readCachedUsage(providerId, validCredentialId, { allowStale: true });
	const display = usageService.readDisplayUsage(providerId, validCredentialId);
	const pruned = await readPersistedCache(cachePath);

	assert.equal(operational, null);
	assert.equal(display?.fromCache, true);
	assert.equal(display?.snapshot?.planType, "pro");
	assert.deepEqual(pruned.entries, []);
	assert.deepEqual(
		(pruned.displayEntries ?? []).map((entry) => entry.credentialId),
		[validCredentialId],
	);
});

test("usage cache schema v3 omits duplicate display snapshots on write", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	await store.persistSuccessfulEntry(createUsageCacheRecord("display-sparse-provider", "credential-a", 1_000), 1_000);

	const persisted = await readPersistedCache(cachePath);
	assert.equal(persisted.schemaVersion, USAGE_CACHE_SCHEMA_VERSION);
	assert.equal(persisted.entries.length, 1);
	assert.equal(persisted.displayEntries?.length, 1);
	assert.equal(persisted.displayEntries?.[0]?.snapshot, undefined);
});

test("usage cache schema v3 omits duplicate display snapshots and restores display-only retention on rewrite", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "display-sparse-provider";
	const credentialId = "credential-valid";
	const credentialCacheKey = `cache:${credentialId}`;
	const snapshot = { ...createUsageSnapshot(providerId, now - 600_000), planType: "pro" };
	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now - 600_000,
				freshUntil: now - 500_000,
				staleUntil: now - 1,
				snapshot,
			},
		],
		displayEntries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now - 600_000,
				displayUntil: now + 86_400_000,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isDisplayCredentialValid: (_provider, id) => id === credentialId,
		pruneInvalidEntries: true,
	});
	const rewritten = await readPersistedCache(cachePath);

	assert.deepEqual(hydrated.operationalEntries, []);
	assert.equal(hydrated.displayEntries[0]?.result.snapshot?.planType, "pro");
	assert.deepEqual(rewritten.entries, []);
	assert.deepEqual(rewritten.displayEntries?.[0]?.snapshot, snapshot);
});

test("usage service retains display snapshots past displayUntil", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "display-retention-provider";
	const credentialId = "credential-a";
	const credentialCacheKey = "cache:credential-a";
	const snapshot = { ...createUsageSnapshot(providerId, now - 86_400_000 * 60), planType: "pro" };
	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [],
		displayEntries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now - 86_400_000 * 60,
				displayUntil: now - 1,
				snapshot,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	await usageService.hydratePersistedCache({
		isDisplayCredentialValid: (_provider, id) => id === credentialId,
		pruneInvalidEntries: true,
	});

	const display = usageService.readDisplayUsage(providerId, credentialId);
	const pruned = await readPersistedCache(cachePath);

	assert.equal(display?.fromCache, true);
	assert.equal(display?.snapshot?.planType, "pro");
	assert.equal(pruned.displayEntries?.length, 1);
	assert.equal(pruned.displayEntries?.[0].credentialId, credentialId);
});

test("usage service replaces display snapshots for same credential regardless of cache key", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "display-dedup-provider";
	const credentialId = "credential-b";
	const oldCacheKey = "cache:old-token";
	const newCacheKey = "cache:new-token";
	const oldSnapshot = { ...createUsageSnapshot(providerId, now - 10_000), planType: "free" };
	const newSnapshot = { ...createUsageSnapshot(providerId, now), planType: "plus" };
	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [],
		displayEntries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey: oldCacheKey,
				fetchedAt: now - 10_000,
				displayUntil: now + 86_400_000,
				snapshot: oldSnapshot,
			},
			{
				provider: providerId,
				credentialId,
				credentialCacheKey: newCacheKey,
				fetchedAt: now,
				displayUntil: now + 86_400_000,
				snapshot: newSnapshot,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	await usageService.hydratePersistedCache({
		isDisplayCredentialValid: (_provider, id) => id === credentialId,
		pruneInvalidEntries: true,
	});

	const display = usageService.readDisplayUsage(providerId, credentialId);
	const pruned = await readPersistedCache(cachePath);

	assert.equal(display?.fromCache, true);
	assert.equal(display?.snapshot?.planType, "plus");
	assert.equal(pruned.displayEntries?.length, 1);
	assert.equal(pruned.displayEntries?.[0].credentialCacheKey, newCacheKey);
});

test("usage service migrates safely associated schema-v1 cache entries to the current credential-keyed schema", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "legacy-provider";
	const credentialId = "credential-a";
	const currentCredentialCacheKey = createUsageCredentialCacheKey(providerId, credentialId, {
		accessToken: "legacy-compatible-token",
		accountId: "legacy-compatible-account",
	});
	const legacySnapshot = createUsageSnapshot(providerId, now);
	const legacyCache: LegacyPersistedUsageCacheTestFile = {
		schemaVersion: 1,
		generatedAt: now,
		maxEntries: 10,
		entries: [
			{
				provider: providerId,
				credentialId,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: legacySnapshot,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(legacyCache, null, 2)}\n`, "utf-8");

	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	await usageService.hydratePersistedCache({
		isCredentialValid: (provider, credential, credentialCacheKey) =>
			provider === providerId && credential === credentialId && credentialCacheKey === currentCredentialCacheKey,
		resolveLegacyCredentialCacheKey: (provider, credential) =>
			provider === providerId && credential === credentialId ? currentCredentialCacheKey : null,
		pruneInvalidEntries: true,
	});

	const hydrated = usageService.readCachedUsage(providerId, credentialId);
	const migrated = await readPersistedCache(cachePath);

	assert.deepEqual(hydrated?.snapshot, legacySnapshot);
	assert.equal(hydrated?.fromCache, true);
	assert.equal(migrated.schemaVersion, USAGE_CACHE_SCHEMA_VERSION);
	assert.equal(migrated.entries.length, 1);
	assert.equal(migrated.entries[0]?.credentialCacheKey, currentCredentialCacheKey);
});

test("usage service prunes ambiguous or invalid schema-v1 cache entries during migration", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "legacy-prune-provider";
	const validCredentialId = "credential-valid";
	const ambiguousCredentialId = "credential-ambiguous";
	const invalidCredentialId = "credential-invalid";
	const validCredentialCacheKey = createUsageCredentialCacheKey(providerId, validCredentialId, {
		accessToken: "legacy-prune-token",
		accountId: "legacy-prune-account",
	});
	const validSnapshot = createUsageSnapshot(providerId, now);
	const legacyCache: LegacyPersistedUsageCacheTestFile = {
		schemaVersion: 1,
		generatedAt: now,
		maxEntries: 10,
		entries: [
			{
				provider: providerId,
				credentialId: validCredentialId,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: validSnapshot,
			},
			{
				provider: providerId,
				credentialId: ambiguousCredentialId,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot(providerId, now),
			},
			{
				provider: providerId,
				credentialId: invalidCredentialId,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot("different-provider", now),
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(legacyCache, null, 2)}\n`, "utf-8");

	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	await usageService.hydratePersistedCache({
		isCredentialValid: (_provider, credentialId, credentialCacheKey) =>
			credentialId === validCredentialId && credentialCacheKey === validCredentialCacheKey,
		resolveLegacyCredentialCacheKey: (_provider, credentialId) =>
			credentialId === validCredentialId ? validCredentialCacheKey : null,
		pruneInvalidEntries: true,
	});

	const migrated = await readPersistedCache(cachePath);

	assert.deepEqual(usageService.readCachedUsage(providerId, validCredentialId)?.snapshot, validSnapshot);
	assert.equal(usageService.readCachedUsage(providerId, ambiguousCredentialId), null);
	assert.equal(usageService.readCachedUsage(providerId, invalidCredentialId), null);
	assert.equal(migrated.schemaVersion, USAGE_CACHE_SCHEMA_VERSION);
	assert.deepEqual(
		migrated.entries.map((entry) => entry.credentialId),
		[validCredentialId],
	);
	assert.equal(migrated.entries[0]?.credentialCacheKey, validCredentialCacheKey);
});

test("usage cache store keeps one latest entry per provider credential within the hard entry bound", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 2 });
	await store.persistSuccessfulEntry(createUsageCacheRecord("bounded-provider", "credential-a", 1_000), 1_000);
	await store.persistSuccessfulEntry(createUsageCacheRecord("bounded-provider", "credential-b", 2_000), 1_000);
	await store.persistSuccessfulEntry(createUsageCacheRecord("bounded-provider", "credential-a", 3_000), 1_000);
	await store.persistSuccessfulEntry(createUsageCacheRecord("bounded-provider", "credential-c", 4_000), 1_000);

	const persisted = await readPersistedCache(cachePath);
	assert.equal(persisted.entries.length, 2);
	assert.deepEqual(
		persisted.entries.map((entry) => `${entry.credentialId}:${entry.fetchedAt}`),
		["credential-c:4000", "credential-a:3000"],
	);
	assert.equal(new Set(persisted.entries.map((entry) => entry.credentialId)).size, 2);
});

test("usage service ignores malformed persisted cache files during hydration", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	await writeFile(cachePath, "{ not valid json", "utf-8");
	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath }),
	});

	await assert.doesNotReject(() => usageService.hydratePersistedCache());
	assert.equal(usageService.readCachedUsage("missing-provider", "missing-credential"), null);
});

test("usage service does not overwrite last persisted successful snapshot with transient errors", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const providerId = "error-preserve-provider";
	const credentialId = "credential-a";
	const firstSnapshot = createUsageSnapshot(providerId);
	let shouldFail = false;
	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath }),
	});
	usageService.register({
		id: providerId,
		displayName: providerId,
		fetchUsage: async (_auth: UsageAuth) => {
			if (shouldFail) {
				throw new Error("transient upstream failure");
			}
			return firstSnapshot;
		},
	});

	await usageService.fetchUsage(providerId, credentialId, { accessToken: "token" }, { forceRefresh: true });
	const persistedAfterSuccess = await readPersistedCache(cachePath);
	shouldFail = true;

	const failedResult = await usageService.fetchUsage(
		providerId,
		credentialId,
		{ accessToken: "token" },
		{ forceRefresh: true },
	);
	const persistedAfterError = await readPersistedCache(cachePath);

	assert.match(failedResult.error ?? "", /transient upstream failure/);
	assert.deepEqual(persistedAfterError.entries, persistedAfterSuccess.entries);
	assert.deepEqual(persistedAfterError.entries[0]?.snapshot, firstSnapshot);
});


test("usage service separates cache records for reused credential ids with different credential material", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const providerId = "openai-codex";
	const credentialId = "openai-codex";
	const freeSnapshot = { ...createUsageSnapshot(providerId), planType: "free" };
	const teamSnapshot = { ...createUsageSnapshot(providerId), planType: "ChatGPT Team" };
	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	let activeSnapshot = freeSnapshot;
	usageService.register({
		id: providerId,
		displayName: providerId,
		fetchUsage: async () => activeSnapshot,
	});

	await usageService.fetchUsage(
		providerId,
		credentialId,
		{ accessToken: "free-token", accountId: "account-free", credential: { accountId: "account-free" } },
		{ forceRefresh: true },
	);
	activeSnapshot = teamSnapshot;
	await usageService.fetchUsage(
		providerId,
		credentialId,
		{ accessToken: "team-token", accountId: "account-team", credential: { accountId: "account-team" } },
		{ forceRefresh: true },
	);

	const ambiguousRead = usageService.readCachedUsage(providerId, credentialId, { allowStale: true });
	const persisted = await readPersistedCache(cachePath);

	assert.equal(ambiguousRead, null);
	assert.equal(persisted.entries.length, 2);
	assert.equal(new Set(persisted.entries.map((entry) => entry.credentialCacheKey)).size, 2);
	assert.deepEqual(
		persisted.entries.map((entry) => entry.snapshot.planType).sort(),
		["ChatGPT Team", "free"],
	);
});

test("usage service resolves ambiguous credential-id cache history when the current credential key is known", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const providerId = "openai-codex";
	const credentialId = "openai-codex";
	const freeAuth = { accessToken: "[REDACTED]", accountId: "account-free", credential: { accountId: "account-free" } };
	const teamAuth = { accessToken: "[REDACTED]", accountId: "account-team", credential: { accountId: "account-team" } };
	const freeSnapshot = { ...createUsageSnapshot(providerId), planType: "free" };
	const teamSnapshot = { ...createUsageSnapshot(providerId), planType: "ChatGPT Team" };
	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	let activeSnapshot = freeSnapshot;
	usageService.register({
		id: providerId,
		displayName: providerId,
		fetchUsage: async () => activeSnapshot,
	});

	await usageService.fetchUsage(providerId, credentialId, freeAuth, { forceRefresh: true });
	activeSnapshot = teamSnapshot;
	await usageService.fetchUsage(providerId, credentialId, teamAuth, { forceRefresh: true });

	assert.equal(usageService.readCachedUsage(providerId, credentialId, { allowStale: true }), null);
	assert.equal(usageService.readDisplayUsage(providerId, credentialId), null);

	usageService.setPreferredCredentialCacheKey(
		providerId,
		credentialId,
		createUsageCredentialCacheKey(providerId, credentialId, teamAuth),
	);

	assert.equal(
		usageService.readCachedUsage(providerId, credentialId, { allowStale: true })?.snapshot?.planType,
		"ChatGPT Team",
	);
	assert.equal(usageService.readDisplayUsage(providerId, credentialId)?.snapshot?.planType, "ChatGPT Team");

	usageService.setPreferredCredentialCacheKey(providerId, credentialId, null);
	assert.equal(usageService.readCachedUsage(providerId, credentialId, { allowStale: true }), null);
});

test("account manager hydrates persisted usage cache during initialization and serves warm-start reads", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-usage-cache-account-manager-"));
	const authPath = join(tempRoot, "auth.json");
	const storagePath = join(tempRoot, "multi-auth.json");
	const modelsPath = join(tempRoot, "models.json");
	const cachePath = join(tempRoot, "multi-auth-usage-cache.json");
	const providerId = "warm-start-provider";
	const credentialId = providerId;
	const now = Date.now();
	const hydratedSnapshot = createUsageSnapshot(providerId, now);
	const warmStartKey = "warm-start-key";
	let fetchCount = 0;

	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	await writeFile(
		authPath,
		JSON.stringify(
			{
				[credentialId]: { type: "api_key", key: warmStartKey },
			},
			null,
			2,
		),
		"utf-8",
	);
	await writeFile(modelsPath, JSON.stringify({ providers: {} }, null, 2), "utf-8");
	await writeFile(
		cachePath,
		`${JSON.stringify(
			{
				schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
				generatedAt: now,
				maxEntries: 10,
				entries: [
					{
						provider: providerId,
						credentialId,
						credentialCacheKey: createUsageCredentialCacheKey(providerId, credentialId, {
							accessToken: warmStartKey,
							credential: { type: "api_key", key: warmStartKey },
						}),
						fetchedAt: now,
						freshUntil: now + 30_000,
						staleUntil: now + 300_000,
						snapshot: hydratedSnapshot,
					},
					{
						provider: providerId,
						credentialId: "orphaned-credential",
						credentialCacheKey: "cache:orphaned-credential",
						fetchedAt: now,
						freshUntil: now + 30_000,
						staleUntil: now + 300_000,
						snapshot: createUsageSnapshot(providerId, now),
					},
				],
			},
			null,
			2,
		)}\n`,
		"utf-8",
	);

	const authWriter = new AuthWriter(authPath);
	const storage = new MultiAuthStorage(storagePath);
	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	usageService.register({
		id: providerId,
		displayName: providerId,
		fetchUsage: async () => {
			fetchCount += 1;
			return createUsageSnapshot(providerId);
		},
	});
	const providerRegistry = new ProviderRegistry(authWriter, modelsPath, [providerId]);
	const accountManager = new AccountManager(authWriter, storage, usageService, providerRegistry);

	t.after(async () => {
		await accountManager.shutdown();
	});

	await accountManager.ensureInitialized();
	Object.defineProperty(authWriter, "getCredential", {
		configurable: true,
		value: async () => {
			throw new Error("warm-started usage should not trigger an auth credential read");
		},
	});

	const result = await accountManager.getCredentialUsageSnapshot(providerId, credentialId, {
		maxAgeMs: 30_000,
	});
	const prunedCache = await readPersistedCache(cachePath);

	assert.equal(result.error, null);
	assert.equal(result.fromCache, true);
	assert.deepEqual(result.snapshot, hydratedSnapshot);
	assert.equal(fetchCount, 0);
	assert.deepEqual(
		prunedCache.entries.map((entry) => entry.credentialId),
		[credentialId],
	);
});

test("usage service keeps Codex usage snapshots separated for base and numbered credential ids", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	const providerId = "openai-codex";
	const baseCredentialId = "openai-codex";
	const numberedCredentialId = "openai-codex-17";
	const now = Date.now();
	const expiresAtSeconds = Math.floor(now / 1_000) + 3_600;
	const baseCredential = {
		type: "oauth" as const,
		["access"]: createCodexIdentityJwt({
			expiresAtSeconds,
			accountId: "acct-personal",
			accountUserId: "user-same",
			email: "same@example.com",
		}),
		refresh: "refresh-base",
		expires: now + 180_000,
		provider: providerId,
		accountId: "acct-personal",
	};
	const numberedCredential = {
		type: "oauth" as const,
		["access"]: createCodexIdentityJwt({
			expiresAtSeconds,
			accountId: "acct-team",
			accountUserId: "user-same",
			email: "same@example.com",
		}),
		refresh: "refresh-numbered",
		expires: now + 120_000,
		provider: providerId,
		accountId: "acct-team",
	};
	const baseSnapshot = { ...createUsageSnapshot(providerId, now), planType: "free" };
	const numberedSnapshot = {
		...createUsageSnapshot(providerId, now + 1),
		planType: "ChatGPT Team",
	};
	let nextSnapshot = baseSnapshot;

	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, {
		persistentCache: new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 }),
	});
	usageService.register({
		id: providerId,
		displayName: providerId,
		fetchUsage: async () => nextSnapshot,
	});

	nextSnapshot = baseSnapshot;
	await usageService.fetchUsage(
		providerId,
		baseCredentialId,
		{ accessToken: baseCredential.access, accountId: "acct-personal", credential: baseCredential },
		{ forceRefresh: true },
	);
	nextSnapshot = numberedSnapshot;
	await usageService.fetchUsage(
		providerId,
		numberedCredentialId,
		{ accessToken: numberedCredential.access, accountId: "acct-team", credential: numberedCredential },
		{ forceRefresh: true },
	);

	const baseUsage = usageService.readCachedUsage(providerId, baseCredentialId, { maxAgeMs: 30_000 });
	const numberedUsage = usageService.readCachedUsage(providerId, numberedCredentialId, {
		maxAgeMs: 30_000,
	});
	usageService.clearCredential(providerId, baseCredentialId);
	const baseUsageAfterClear = usageService.readCachedUsage(providerId, baseCredentialId, {
		allowStale: true,
	});
	const numberedUsageAfterClear = usageService.readCachedUsage(providerId, numberedCredentialId, {
		allowStale: true,
	});
	const persisted = await readPersistedCache(cachePath);

	assert.equal(baseUsage?.error, null);
	assert.equal(baseUsage?.fromCache, true);
	assert.equal(baseUsage?.snapshot?.planType, "free");
	assert.equal(numberedUsage?.error, null);
	assert.equal(numberedUsage?.fromCache, true);
	assert.equal(numberedUsage?.snapshot?.planType, "ChatGPT Team");
	assert.equal(baseUsageAfterClear, null);
	assert.equal(numberedUsageAfterClear?.snapshot?.planType, "ChatGPT Team");
	assert.deepEqual(
		persisted.entries.map((entry) => entry.credentialId).sort(),
		[baseCredentialId, numberedCredentialId].sort(),
	);
});

test("usage cache schema v3 includes display snapshot when it differs from operational snapshot", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "diff-snapshot-provider";
	const credentialId = "cred-a";
	const credentialCacheKey = `cache:${credentialId}`;

	// Operational entry has one snapshot
	const operationalSnapshot = createUsageSnapshot(providerId, now);
	// Display entry has a DIFFERENT snapshot (newer timestamp, different plan)
	const displaySnapshot = {
		...createUsageSnapshot(providerId, now + 1000),
		planType: "pro",
	};

	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: operationalSnapshot,
			},
		],
		displayEntries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now + 1000,
				displayUntil: now + 86_400_000,
				// Include the snapshot because it differs from operational
				snapshot: displaySnapshot,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isDisplayCredentialValid: () => true,
		pruneInvalidEntries: true,
	});

	assert.equal(hydrated.displayEntries.length, 1);
	assert.equal(hydrated.displayEntries[0]?.result.snapshot?.planType, "pro");
	assert.equal(hydrated.displayEntries[0]?.result.snapshot?.timestamp, now + 1000);

	// Read persisted file — display snapshot should be included since it differed
	const rewritten = await readPersistedCache(cachePath);
	assert.equal(rewritten.displayEntries?.length, 1);
	assert.equal(rewritten.displayEntries?.[0]?.snapshot?.planType, "pro");
	assert.equal(rewritten.displayEntries?.[0]?.snapshot?.timestamp, now + 1000);
});

test("usage cache schema v3 includes display snapshot when it differs from matching operational entry on serialize", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	// Test the serialize path specifically: persist an entry where the
	// display snapshot differs from the operational one at write time.
	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const entry = createUsageCacheRecord("diff-serialize-provider", "cred-a", 1_000);
	// The persistSuccessfulEntry creates both an operational and a display entry
	// with the SAME snapshot. They match, so the display snapshot is omitted.
	await store.persistSuccessfulEntry(entry, 1_000);

	let persisted = await readPersistedCache(cachePath);
	assert.equal(persisted.displayEntries?.[0]?.snapshot, undefined, "Matching snapshots should omit display snapshot");

	// Now simulate: operational entry is expired, but display still retained.
	// We'll manually write a display entry with a DIFFERENT snapshot to force inclusion.
	const operationalSnapshot = createUsageSnapshot("diff-serialize-provider", 1_000);
	const differingDisplaySnapshot = {
		...createUsageSnapshot("diff-serialize-provider", 2_000),
		planType: "enterprise",
	};
	const manualPersist: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: 2_000,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [
			{
				provider: "diff-serialize-provider",
				credentialId: "cred-a",
				credentialCacheKey: "cache:cred-a",
				fetchedAt: 1_000,
				freshUntil: 2_000,
				staleUntil: 300_000,
				snapshot: operationalSnapshot,
			},
		],
		displayEntries: [
			{
				provider: "diff-serialize-provider",
				credentialId: "cred-a",
				credentialCacheKey: "cache:cred-a",
				fetchedAt: 2_000,
				displayUntil: 86_400_000 + 2_000,
				// Different snapshot from operational — should be included
				snapshot: differingDisplaySnapshot,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(manualPersist, null, 2)}\n`, "utf-8");

	const hydrated = await store.readHydrationEntries(2_000, {
		isCredentialValid: () => true,
		isDisplayCredentialValid: () => true,
		pruneInvalidEntries: true,
	});
	const rewritten = await readPersistedCache(cachePath);

	assert.equal(hydrated.displayEntries.length, 1);
	assert.equal(hydrated.displayEntries[0]?.result.snapshot?.planType, "enterprise");

	// On serialize, since display snapshot doesn't match operational snapshot,
	// the display entry should include the full snapshot
	assert.equal(rewritten.displayEntries?.length, 1);
	assert.equal(rewritten.displayEntries?.[0]?.snapshot?.planType, "enterprise");
	assert.equal(rewritten.displayEntries?.[0]?.snapshot?.timestamp, 2_000);
});

test("usage cache discards non-array displayEntries in v3 schema and triggers rewrite", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "bad-display-entries-provider";
	const credentialId = "cred-a";

	// Write a v3 cache file where displayEntries is a string instead of an array
	const persisted: Record<string, unknown> = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey: `cache:${credentialId}`,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot(providerId, now),
			},
		],
		displayEntries: "this is not an array",
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isCredentialValid: () => true,
		pruneInvalidEntries: true,
	});

	// Display entries should be empty
	assert.equal(hydrated.displayEntries.length, 0);
	// Operational entries should still be valid
	assert.equal(hydrated.operationalEntries.length, 1);
	assert.equal(hydrated.operationalEntries[0]?.credentialId, credentialId);

	// File should be rewritten (discardedEntry caused shouldRewrite = true)
	const rewritten = await readPersistedCache(cachePath);
	assert.equal(rewritten.displayEntries?.length, 0);
	assert.equal(rewritten.entries.length, 1);
});

test("usage cache discards empty displayEntries and does not rewrite", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const persisted: Record<string, unknown> = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [
			{
				provider: "display-empty-provider",
				credentialId: "cred-a",
				credentialCacheKey: "cache:cred-a",
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot("display-empty-provider", now),
			},
		],
		displayEntries: [],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isCredentialValid: () => true,
		pruneInvalidEntries: true,
	});

	assert.equal(hydrated.displayEntries.length, 0);
	assert.equal(hydrated.operationalEntries.length, 1);

	// Empty displayEntries should not cause a rewrite (no discardedEntry)
	const rewritten = await readPersistedCache(cachePath);
	assert.equal(rewritten.displayEntries?.length, 0);
});

test("usage cache schema v2 entries without displayEntries field migrate to v3", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "v2-migrate-provider";
	const credentialId = "cred-a";
	const credentialCacheKey = `cache:${credentialId}`;

	// Write a schema-version-2 cache file without displayEntries field
	const persisted: Record<string, unknown> = {
		schemaVersion: 2,
		generatedAt: now,
		maxEntries: 10,
		entries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot(providerId, now),
			},
		],
		// Intentionally NO displayEntries field
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isCredentialValid: () => true,
		pruneInvalidEntries: true,
	});

	// Operational entry should be preserved
	assert.equal(hydrated.operationalEntries.length, 1);
	assert.equal(hydrated.operationalEntries[0]?.credentialId, credentialId);
	// Display entries should be empty (no displayEntries in v2 file)
	assert.equal(hydrated.displayEntries.length, 0);

	// File should be rewritten to v3 schema
	const rewritten = await readPersistedCache(cachePath);
	assert.equal(rewritten.schemaVersion, USAGE_CACHE_SCHEMA_VERSION);
	assert.equal(rewritten.entries.length, 1);
	assert.deepEqual(rewritten.displayEntries, []);
});

test("usage cache store returns null and does not persist when entry has null snapshot", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });

	// Entry with null snapshot
	const nullSnapshotEntry: UsageCacheRecord = {
		providerId: "null-snapshot-provider",
		credentialId: "cred-a",
		credentialCacheKey: "cache:cred-a",
		result: {
			snapshot: null,
			error: null,
			fetchedAt: Date.now(),
		},
		freshUntil: Date.now() + 30_000,
		staleUntil: Date.now() + 300_000,
	};
	const result = await store.persistSuccessfulEntry(nullSnapshotEntry);
	assert.equal(result, null);

	// Cache file should NOT be created (no entries to persist)
	await assert.rejects(
		readPersistedCache(cachePath),
		/ENOENT/,
	);

	// Entry with error
	const errorEntry: UsageCacheRecord = {
		providerId: "error-entry-provider",
		credentialId: "cred-a",
		credentialCacheKey: "cache:cred-a",
		result: {
			snapshot: createUsageSnapshot("error-entry-provider"),
			error: "transient failure",
			fetchedAt: Date.now(),
		},
		freshUntil: Date.now() + 30_000,
		staleUntil: Date.now() + 300_000,
	};
	const errorResult = await store.persistSuccessfulEntry(errorEntry);
	assert.equal(errorResult, null);

	// Cache file should still NOT exist
	await assert.rejects(
		readPersistedCache(cachePath),
		/ENOENT/,
	);
});

test("usage cache silently discards entries when credential validator throws", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "validator-throws-provider";
	const credentialId = "cred-a";

	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		entries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey: `cache:${credentialId}`,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot(providerId, now),
			},
		],
		displayEntries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey: `cache:${credentialId}`,
				fetchedAt: now,
				displayUntil: now + 86_400_000,
				snapshot: createUsageSnapshot(providerId, now),
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		// Validator that throws for all entries
		isCredentialValid: () => {
			throw new Error("validation database unavailable");
		},
		isDisplayCredentialValid: () => {
			throw new Error("display validation failed");
		},
		pruneInvalidEntries: true,
	});

	// All entries should be silently discarded
	assert.equal(hydrated.operationalEntries.length, 0);
	assert.equal(hydrated.displayEntries.length, 0);
});

test("usage cache round-trips snapshots with copilot quota and rate limit headers", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "rich-snapshot-provider";
	const credentialId = "cred-a";
	const credentialCacheKey = `cache:${credentialId}`;

	// Full-featured snapshot with copilot quota, rate limit headers, and credits
	const richSnapshot: UsageSnapshot = {
		timestamp: now,
		provider: providerId,
		planType: "pro",
		primary: { usedPercent: 75, windowMinutes: 60, resetsAt: now + 3_600_000 },
		secondary: { usedPercent: 50, windowMinutes: 60, resetsAt: now + 3_600_000 },
		monthly: { usedPercent: 36, windowMinutes: 30 * 24 * 60, resetsAt: now + 86_400_000 },
		credits: { hasCredits: true, unlimited: false, balance: "42.50" },
		copilotQuota: {
			chat: { used: 100, total: 200, remaining: 100, percentUsed: 50, unlimited: false },
			completions: { used: 50, total: 150, remaining: 100, percentUsed: 33, unlimited: false },
			resetAt: now + 86_400_000,
		},
		updatedAt: now,
		rateLimitHeaders: {
			limit: 100,
			remaining: 25,
			resetAt: now + 3_600,
			retryAfterSeconds: 3600,
			resetAtFormatted: new Date(now + 3_600).toISOString(),
			confidence: "high",
			source: "retry-after",
		},
		quotaClassification: "hourly",
		estimatedResetAt: now + 3_600_000,
	};

	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		entries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: richSnapshot,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isCredentialValid: () => true,
		pruneInvalidEntries: true,
	});

	assert.equal(hydrated.operationalEntries.length, 1);
	const entry = hydrated.operationalEntries[0];

	// Verify copilotQuota round-trips correctly
	assert.equal(entry?.result.snapshot?.copilotQuota?.chat.used, 100);
	assert.equal(entry?.result.snapshot?.copilotQuota?.chat.total, 200);
	assert.equal(entry?.result.snapshot?.copilotQuota?.completions?.used, 50);
	assert.equal(entry?.result.snapshot?.copilotQuota?.resetAt, now + 86_400_000);

	// Verify rate limit headers round-trip correctly
	assert.equal(entry?.result.snapshot?.rateLimitHeaders?.limit, 100);
	assert.equal(entry?.result.snapshot?.rateLimitHeaders?.remaining, 25);
	assert.equal(entry?.result.snapshot?.rateLimitHeaders?.confidence, "high");
	assert.equal(entry?.result.snapshot?.rateLimitHeaders?.source, "retry-after");

	// Verify the tertiary monthly window round-trips
	assert.equal(entry?.result.snapshot?.monthly?.usedPercent, 36);
	assert.equal(entry?.result.snapshot?.monthly?.windowMinutes, 30 * 24 * 60);
	assert.equal(entry?.result.snapshot?.monthly?.resetsAt, now + 86_400_000);

	// Verify credits
	assert.equal(entry?.result.snapshot?.credits?.hasCredits, true);
	assert.equal(entry?.result.snapshot?.credits?.balance, "42.50");

	// Verify plan type
	assert.equal(entry?.result.snapshot?.planType, "pro");

	// Verify quota classification
	assert.equal(entry?.result.snapshot?.quotaClassification, "hourly");
	assert.equal(entry?.result.snapshot?.estimatedResetAt, now + 3_600_000);

	// Verify it round-trips through re-serialize as well
	const rewritten = await readPersistedCache(cachePath);
	assert.equal(rewritten.entries.length, 1);
	assert.equal(rewritten.entries[0]?.snapshot?.copilotQuota?.chat.used, 100);
	assert.equal(rewritten.entries[0]?.snapshot?.rateLimitHeaders?.remaining, 25);
});

test("usage cache keeps only one entry when maxEntries is 1", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 1 });

	// Persist three entries — only the latest should be kept
	await store.persistSuccessfulEntry(
		createUsageCacheRecord("max-1-provider", "cred-a", 1_000),
		1_000,
	);
	await store.persistSuccessfulEntry(
		createUsageCacheRecord("max-1-provider", "cred-b", 2_000),
		1_000,
	);
	await store.persistSuccessfulEntry(
		createUsageCacheRecord("max-1-provider", "cred-c", 3_000),
		1_000,
	);

	const persisted = await readPersistedCache(cachePath);
	assert.equal(persisted.entries.length, 1);
	assert.equal(persisted.entries[0]?.credentialId, "cred-c");
	assert.equal(persisted.displayEntries?.length, 1);
});

test("usage cache hydration with pruneInvalidEntries:false reads valid entries but does not rewrite file", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "no-prune-provider";
	const validCredentialId = "cred-valid";
	const invalidCredentialId = "cred-invalid";

	const persisted: PersistedUsageCacheTestFile = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		entries: [
			{
				provider: providerId,
				credentialId: validCredentialId,
				credentialCacheKey: `cache:${validCredentialId}`,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot(providerId, now),
			},
			{
				provider: providerId,
				credentialId: invalidCredentialId,
				credentialCacheKey: `cache:${invalidCredentialId}`,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: createUsageSnapshot(providerId, now),
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");
	const originalContent = await readFile(cachePath, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isCredentialValid: (_provider, id) => id === validCredentialId,
		pruneInvalidEntries: false, // Do NOT rewrite
	});

	// Valid entries should be hydrated
	assert.equal(hydrated.operationalEntries.length, 1);
	assert.equal(hydrated.operationalEntries[0]?.credentialId, validCredentialId);

	// File on disk should be UNCHANGED
	const afterRead = await readFile(cachePath, "utf-8");
	assert.equal(afterRead, originalContent);
});

test("usage cache store writes with display retention and dedup keeps only per-credential display entries", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });

	// Multiple entries for same credential with different cache keys should dedup
	await store.persistSuccessfulEntry(
		createUsageCacheRecord("dedup-display-provider", "cred-a", 1_000, "cache:key-1"),
		1_000,
	);
	await store.persistSuccessfulEntry(
		createUsageCacheRecord("dedup-display-provider", "cred-a", 2_000, "cache:key-2"),
		1_000,
	);
	await store.persistSuccessfulEntry(
		createUsageCacheRecord("dedup-display-provider", "cred-b", 3_000, "cache:key-3"),
		1_000,
	);

	const persisted = await readPersistedCache(cachePath);
	// Display entries should only have one per credential (cred-a deduped by credentialId)
	assert.equal(persisted.displayEntries?.length, 2);
	assert.equal(persisted.entries.length, 3);
	// Latest display entry for cred-a should have the newest cache key
	const credADisplay = persisted.displayEntries?.find(
		(e) => e.credentialId === "cred-a",
	);
	assert.equal(credADisplay?.credentialCacheKey, "cache:key-2");
	assert.equal(credADisplay?.fetchedAt, 2_000);
});

test("usage cache display snapshot dedup handles different key insertion orders", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "key-order-provider";
	const credentialId = "cred-a";
	const credentialCacheKey = "cache:cred-a";

	// Build two snapshots with identical data but DIFFERENT key insertion orders.
	// operationalSnapshot is built with one key ordering.
	const operationalSnapshot: UsageSnapshot = {
		timestamp: now,
		provider: providerId,
		planType: "pro",
		primary: null,
		secondary: null,
		credits: null,
		copilotQuota: null,
		updatedAt: now,
	};

	// displayEntrySnapshot is built with REVERSED key ordering
	// (provider before timestamp, etc.)
	const displaySnapshot = JSON.parse(
		JSON.stringify({
			provider: providerId,
			timestamp: now,
			planType: "pro",
			secondary: null,
			primary: null,
			credits: null,
			copilotQuota: null,
			updatedAt: now,
		}),
	) as UsageSnapshot;

	// Write cache file with operational entry having one key order,
	// display entry having another key order
	const operationalJson = JSON.stringify(operationalSnapshot);
	const displayJson = JSON.stringify(displaySnapshot);
	// Verify they differ in stringified form due to key ordering
	if (operationalJson === displayJson) {
		// If by coincidence they serialize the same, force a different order
		// by constructing via alternative path
		displaySnapshot.planType = "pro";
	}

	const persisted = {
		schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: operationalSnapshot,
			},
		],
		displayEntries: [
			{
				provider: providerId,
				credentialId,
				credentialCacheKey,
				fetchedAt: now,
				displayUntil: now + 86_400_000,
				// Include the snapshot (JSON key ordering differs from operational)
				snapshot: displaySnapshot,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isCredentialValid: () => true,
		isDisplayCredentialValid: () => true,
		pruneInvalidEntries: true,
	});

	// Display entry should be hydrated with its snapshot preserved
	assert.equal(hydrated.displayEntries.length, 1, "Display entry should be hydrated");
	assert.equal(hydrated.displayEntries[0]?.result.snapshot?.planType, "pro");
	assert.equal(hydrated.displayEntries[0]?.result.snapshot?.timestamp, now);

	// Read persisted file after rewrite
	const rewritten = await readPersistedCache(cachePath);

	// The display entry should RETAIN its snapshot because the key ordering differs,
	// causing JSON.stringify to produce different strings -> dedup fails safe
	assert.equal(rewritten.displayEntries?.length, 1);
	// Snapshot must be present (even though data is semantically identical)
	assert.ok(
		rewritten.displayEntries?.[0]?.snapshot !== undefined,
		"Display snapshot should be retained when key orderings differ (safe no-data-loss dedup)",
	);
	assert.equal(rewritten.displayEntries?.[0]?.snapshot?.planType, "pro");
	assert.equal(rewritten.displayEntries?.[0]?.snapshot?.timestamp, now);
});

test("usage cache migrates schema-v2 entries with displayEntries present to v3", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "v2-with-display-provider";
	const operationalCredentialId = "cred-op";
	const displayCredentialId = "cred-disp";
	const opKey = "cache:cred-op";
	const dispKey = "cache:cred-disp";

	const operationalSnapshot = createUsageSnapshot(providerId, now);
	// Display snapshot is different from operational to verify it round-trips
	const displaySnapshot = {
		...createUsageSnapshot(providerId, now + 1000),
		planType: "team",
	};

	// Write a schema-version-2 cache file WITH displayEntries present
	const persisted: Record<string, unknown> = {
		schemaVersion: 2, // v2 schema
		generatedAt: now,
		maxEntries: 10,
		maxDisplayEntries: 10,
		displayRetentionMs: 86_400_000,
		entries: [
			{
				provider: providerId,
				credentialId: operationalCredentialId,
				credentialCacheKey: opKey,
				fetchedAt: now,
				freshUntil: now + 30_000,
				staleUntil: now + 300_000,
				snapshot: operationalSnapshot,
			},
		],
		// displayEntries IS present (different from existing test where it's absent)
		displayEntries: [
			{
				provider: providerId,
				credentialId: displayCredentialId,
				credentialCacheKey: dispKey,
				fetchedAt: now + 1000,
				displayUntil: now + 86_400_000,
				snapshot: displaySnapshot,
			},
		],
	};
	await writeFile(cachePath, `${JSON.stringify(persisted, null, 2)}\n`, "utf-8");

	const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
	const hydrated = await store.readHydrationEntries(now, {
		isCredentialValid: () => true,
		isDisplayCredentialValid: () => true,
		pruneInvalidEntries: true,
	});

	// Operational entries should be preserved
	assert.equal(hydrated.operationalEntries.length, 1);
	assert.equal(hydrated.operationalEntries[0]?.credentialId, operationalCredentialId);
	// Display entries should be preserved (the v2-with-displayEntries branch is exercised)
	assert.equal(hydrated.displayEntries.length, 1);
	assert.equal(hydrated.displayEntries[0]?.credentialId, displayCredentialId);
	assert.equal(hydrated.displayEntries[0]?.result.snapshot?.planType, "team");

	// File should be rewritten to v3 schema with entries preserved
	const rewritten = await readPersistedCache(cachePath);
	assert.equal(rewritten.schemaVersion, USAGE_CACHE_SCHEMA_VERSION);
	assert.equal(rewritten.entries.length, 1);
	assert.equal(rewritten.entries[0]?.credentialId, operationalCredentialId);
	assert.equal(rewritten.displayEntries?.length, 1);
	assert.equal(rewritten.displayEntries?.[0]?.credentialId, displayCredentialId);
	assert.equal(rewritten.displayEntries?.[0]?.snapshot?.planType, "team");
	assert.equal(rewritten.displayEntries?.[0]?.snapshot?.timestamp, now + 1000);
});

test("usage cache rejects snapshots with malformed copilot quota bucket fields", async (t) => {
	const { tempRoot, cachePath } = await createTempUsageCachePath();
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const now = Date.now();
	const providerId = "malformed-quota-provider";

	// Test 1: malformed chat.used (string instead of number)
	{
		const badSnapshot: Record<string, unknown> = {
			timestamp: now,
			provider: providerId,
			planType: null,
			primary: null,
			secondary: null,
			credits: null,
			copilotQuota: {
				chat: {
					used: "not-a-number",
					total: 200,
					remaining: 100,
					percentUsed: 50,
					unlimited: false,
				},
				completions: null,
				resetAt: now + 86_400_000,
			},
			updatedAt: now,
		};

		await writeFile(
			cachePath,
			JSON.stringify(
				{
					schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
					generatedAt: now,
					maxEntries: 10,
					entries: [
						{
							provider: providerId,
							credentialId: "cred-bad",
							credentialCacheKey: "cache:cred-bad",
							fetchedAt: now,
							freshUntil: now + 30_000,
							staleUntil: now + 300_000,
							snapshot: badSnapshot,
						},
					],
				},
				null,
				2,
			) + "\n",
			"utf-8",
		);

		const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
		const hydrated = await store.readHydrationEntries(now, {
			isCredentialValid: () => true,
			pruneInvalidEntries: true,
		});

		assert.equal(
			hydrated.operationalEntries.length,
			0,
			"Entry with malformed chat.used should be rejected",
		);
	}

	// Test 2: malformed completions.total (string instead of number)
	{
		const badSnapshot2: Record<string, unknown> = {
			timestamp: now,
			provider: providerId,
			planType: null,
			primary: null,
			secondary: null,
			credits: null,
			copilotQuota: {
				chat: { used: 100, total: 200, remaining: 100, percentUsed: 50, unlimited: false },
				completions: {
					used: 50,
					total: "not-a-number",
					remaining: 100,
					percentUsed: 33,
					unlimited: false,
				},
				resetAt: now + 86_400_000,
			},
			updatedAt: now,
		};

		await writeFile(
			cachePath,
			JSON.stringify(
				{
					schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
					generatedAt: now,
					maxEntries: 10,
					entries: [
						{
							provider: providerId + "-2",
							credentialId: "cred-bad-2",
							credentialCacheKey: "cache:cred-bad-2",
							fetchedAt: now,
							freshUntil: now + 30_000,
							staleUntil: now + 300_000,
							snapshot: badSnapshot2,
						},
					],
				},
				null,
				2,
			) + "\n",
			"utf-8",
		);

		const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
		const hydrated = await store.readHydrationEntries(now, {
			isCredentialValid: () => true,
			pruneInvalidEntries: true,
		});

		assert.equal(
			hydrated.operationalEntries.length,
			0,
			"Entry with malformed completions.total should be rejected",
		);
	}

	// Test 3: malformed chat.unlimited (boolean required, got string)
	{
		const badSnapshot3: Record<string, unknown> = {
			timestamp: now,
			provider: providerId,
			planType: null,
			primary: null,
			secondary: null,
			credits: null,
			copilotQuota: {
				chat: { used: 100, total: 200, remaining: 100, percentUsed: 50, unlimited: "yes" },
				completions: null,
				resetAt: now + 86_400_000,
			},
			updatedAt: now,
		};

		await writeFile(
			cachePath,
			JSON.stringify(
				{
					schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
					generatedAt: now,
					maxEntries: 10,
					entries: [
						{
							provider: providerId + "-3",
							credentialId: "cred-bad-3",
							credentialCacheKey: "cache:cred-bad-3",
							fetchedAt: now,
							freshUntil: now + 30_000,
							staleUntil: now + 300_000,
							snapshot: badSnapshot3,
						},
					],
				},
				null,
				2,
			) + "\n",
			"utf-8",
		);

		const store = new UsageSnapshotCacheStore({ filePath: cachePath, maxEntries: 10 });
		const hydrated = await store.readHydrationEntries(now, {
			isCredentialValid: () => true,
			pruneInvalidEntries: true,
		});

		assert.equal(
			hydrated.operationalEntries.length,
			0,
			"Entry with non-boolean unlimited should be rejected",
		);
	}

	// Test 4: malformed display entry with bad copilot quota should also be rejected
	{
		// Write separate temp cache for display entry test
		const { tempRoot: tempRoot2, cachePath: cachePath2 } = await createTempUsageCachePath();
		t.after(async () => {
			await rm(tempRoot2, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
		});

		// Valid operational entry + malformed display entry
		const validSnapshot = createUsageSnapshot(providerId, now);
		const badDisplaySnapshot: Record<string, unknown> = {
			timestamp: now,
			provider: providerId,
			planType: null,
			primary: null,
			secondary: null,
			credits: null,
			copilotQuota: {
				chat: { used: 100, total: "NaN", remaining: 100, percentUsed: 50, unlimited: false },
				completions: null,
				resetAt: now + 86_400_000,
			},
			updatedAt: now,
		};

		await writeFile(
			cachePath2,
			JSON.stringify(
				{
					schemaVersion: USAGE_CACHE_SCHEMA_VERSION,
					generatedAt: now,
					maxEntries: 10,
					maxDisplayEntries: 10,
					displayRetentionMs: 86_400_000,
					entries: [
						{
							provider: providerId,
							credentialId: "cred-valid",
							credentialCacheKey: "cache:cred-valid",
							fetchedAt: now,
							freshUntil: now + 30_000,
							staleUntil: now + 300_000,
							snapshot: validSnapshot,
						},
					],
					displayEntries: [
						{
							provider: providerId,
							credentialId: "cred-valid",
							credentialCacheKey: "cache:cred-valid",
							fetchedAt: now,
							displayUntil: now + 86_400_000,
							snapshot: badDisplaySnapshot,
						},
					],
				},
				null,
				2,
			) + "\n",
			"utf-8",
		);

		const store = new UsageSnapshotCacheStore({ filePath: cachePath2, maxEntries: 10 });
		const hydrated = await store.readHydrationEntries(now, {
			isCredentialValid: () => true,
			isDisplayCredentialValid: () => true,
			pruneInvalidEntries: true,
		});

		// Operational entry should be valid
		assert.equal(hydrated.operationalEntries.length, 1);
		// Display entry with malformed copilot quota should be rejected
		assert.equal(
			hydrated.displayEntries.length,
			0,
			"Display entry with malformed copilot quota should be rejected",
		);
	}
});
