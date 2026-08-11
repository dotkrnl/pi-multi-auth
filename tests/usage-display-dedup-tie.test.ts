import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { UsageSnapshotCacheStore, type UsageCacheRecord } from "../src/usage/persistent-cache.js";
import type { UsageSnapshot } from "../src/usage/types.js";

function createSnapshot(provider: string, planType: string, timestamp: number): UsageSnapshot {
	return {
		timestamp,
		provider,
		planType,
		primary: null,
		secondary: null,
		credits: null,
		copilotQuota: null,
		updatedAt: timestamp,
	};
}

function createRecord(
	provider: string,
	credentialId: string,
	credentialCacheKey: string,
	snapshot: UsageSnapshot,
	fetchedAt: number,
): UsageCacheRecord {
	return {
		providerId: provider,
		credentialId,
		credentialCacheKey,
		result: { snapshot, error: null, fetchedAt },
		freshUntil: fetchedAt + 30_000,
		staleUntil: fetchedAt + 300_000,
	};
}

test("display dedup lets the later write win an exact fetchedAt tie", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-display-tie-"));
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});
	const store = new UsageSnapshotCacheStore({
		filePath: join(tempRoot, "cache.json"),
		maxEntries: 10,
	});
	const fetchedAt = 1_786_000_000_000; // identical for both writes: same-ms refetch
	const older = createRecord("openai-codex", "openai-codex", "key-free", createSnapshot("openai-codex", "free", fetchedAt), fetchedAt);
	const newer = createRecord("openai-codex", "openai-codex", "key-team", createSnapshot("openai-codex", "ChatGPT Team", fetchedAt), fetchedAt);

	await store.persistSuccessfulEntry(older, fetchedAt);
	const display = await store.persistSuccessfulEntry(newer, fetchedAt);

	assert.equal(display?.result.snapshot?.planType, "ChatGPT Team");

	// The v3 file schema omits display snapshots identical to the operational
	// entry, so assert on the retained credential key instead of the payload.
	const persisted = JSON.parse(
		await readFile(join(tempRoot, "cache.json"), "utf-8"),
	) as { displayEntries?: Array<{ credentialCacheKey?: string }> };
	assert.equal(persisted.displayEntries?.length, 1);
	assert.equal(persisted.displayEntries?.[0]?.credentialCacheKey, "key-team");
});

test("operational dedup lets the later write win an exact fetchedAt tie for the same key", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-operational-tie-"));
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});
	const store = new UsageSnapshotCacheStore({
		filePath: join(tempRoot, "cache.json"),
		maxEntries: 10,
	});
	const fetchedAt = 1_786_000_000_000;
	const older = createRecord("kimi-coding", "kimi-coding", "key-a", createSnapshot("kimi-coding", "old", fetchedAt), fetchedAt);
	const newer = createRecord("kimi-coding", "kimi-coding", "key-a", createSnapshot("kimi-coding", "new", fetchedAt), fetchedAt);

	await store.persistSuccessfulEntry(older, fetchedAt);
	await store.persistSuccessfulEntry(newer, fetchedAt);

	const persisted = JSON.parse(
		await readFile(join(tempRoot, "cache.json"), "utf-8"),
	) as { entries?: Array<{ credentialCacheKey: string; snapshot?: UsageSnapshot }> };
	const entriesForKey = persisted.entries?.filter((entry) => entry.credentialCacheKey === "key-a") ?? [];
	assert.equal(entriesForKey.length, 1);
	assert.equal(entriesForKey[0]?.snapshot?.planType, "new");
});
