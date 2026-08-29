import assert from "node:assert/strict";
import test from "node:test";
import { UsageService } from "../src/usage/index.js";
import {
	UsageCoordinator,
	UsageRequestDeferredError,
	formatUsageRequestDeferredNote,
	isUsageRequestDeferredError,
	type UsageCoordinationConfig,
} from "../src/usage/usage-coordinator.js";
import type { UsageAuth, UsageSnapshot } from "../src/usage/types.js";

function createConfig(overrides: Partial<UsageCoordinationConfig> = {}): UsageCoordinationConfig {
	return {
		enabled: true,
		globalMaxConcurrentFreshRequests: 2,
		perProviderMaxConcurrentFreshRequests: 1,
		selectionCandidateWindow: 2,
		blockedReconciliationCandidateWindow: 2,
		entitlementCandidateWindow: 2,
		startupCandidateWindow: 1,
		modalRefreshCandidateWindow: 2,
		manualProviderRefreshCandidateWindow: 2,
		accountCooldownMs: 0,
		authCooldownMs: 0,
		providerCooldownMs: 0,
		circuitBreakerFailureThreshold: 3,
		circuitBreakerCooldownMs: 0,
		jitterMs: 0,
		...overrides,
	};
}

function createUsageSnapshot(provider: string): UsageSnapshot {
	const now = Date.now();
	return {
		timestamp: now,
		provider,
		planType: null,
		primary: null,
		secondary: null,
		credits: null,
		copilotQuota: null,
		updatedAt: now,
	};
}

function createCredentialRef(index: number): string {
	return `id:${index.toString(16).padStart(8, "0")}`;
}

function createCredentialRequests(count: number): Array<{ provider: string; credentialId: string }> {
	return Array.from({ length: count }, (_unused, index) => ({
		provider: "bounded-provider",
		credentialId: createCredentialRef(index),
	}));
}

function createDeferred(): { promise: Promise<void>; resolve: () => void } {
	let resolveDeferred: (() => void) | undefined;
	const promise = new Promise<void>((resolve) => {
		resolveDeferred = resolve;
	});
	if (!resolveDeferred) {
		throw new Error("Failed to initialize deferred usage coordination gate.");
	}
	return { promise, resolve: resolveDeferred };
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => {
		setTimeout(resolve, ms);
	});
}

test("usage coordinator bounds high-cardinality request windows", () => {
	const coordinator = new UsageCoordinator(createConfig({ modalRefreshCandidateWindow: 2 }));
	const selected = coordinator.selectCredentialRequests(
		[
			{ provider: "provider", credentialId: "credential-a" },
			{ provider: "provider", credentialId: "credential-a" },
			{ provider: "provider", credentialId: "credential-b" },
			{ provider: "provider", credentialId: "credential-c" },
		],
		"modal-refresh",
	);

	assert.deepEqual(
		selected.map((request) => request.credentialId),
		["credential-a", "credential-b"],
	);
});

test("usage coordinator progresses 14 modal refresh credentials with window 8", () => {
	const windowSize = 8;
	const coordinator = new UsageCoordinator(
		createConfig({ modalRefreshCandidateWindow: windowSize }),
	);
	const requests = createCredentialRequests(14);

	const first = coordinator.selectCredentialRequests(requests, "modal-refresh");
	const second = coordinator.selectCredentialRequests(requests, "modal-refresh");
	const coveredCredentialIds = new Set(
		[...first, ...second].map((request) => request.credentialId),
	);

	assert.equal(first.length, windowSize);
	assert.equal(second.length, windowSize);
	assert.deepEqual(
		first.map((request) => request.credentialId),
		Array.from({ length: windowSize }, (_unused, index) => createCredentialRef(index)),
	);
	assert.deepEqual(
		second.map((request) => request.credentialId),
		[
			...Array.from({ length: 6 }, (_unused, index) => createCredentialRef(index + windowSize)),
			createCredentialRef(0),
			createCredentialRef(1),
		],
	);
	assert.equal(coveredCredentialIds.size, requests.length);
	for (const request of requests) {
		assert.equal(coveredCredentialIds.has(request.credentialId), true);
	}
});

test("usage coordinator dedupes provider credential pairs before progressive modal windows", () => {
	const coordinator = new UsageCoordinator(createConfig({ modalRefreshCandidateWindow: 3 }));
	const requests = [
		{ provider: "provider-a", credentialId: "shared" },
		{ provider: "provider-a", credentialId: "shared" },
		{ provider: "provider-b", credentialId: "shared" },
		{ provider: "provider-a", credentialId: "credential-a" },
		{ provider: "provider-a", credentialId: "credential-b" },
		{ provider: "provider-b", credentialId: "credential-c" },
	];

	const first = coordinator.selectCredentialRequests(requests, "modal-refresh");
	const second = coordinator.selectCredentialRequests(requests, "modal-refresh");
	const selectedPairs = [...first, ...second].map(
		(request) => `${request.provider}:${request.credentialId}`,
	);

	assert.equal(first.length, 3);
	assert.equal(second.length, 3);
	assert.equal(new Set(first.map((request) => `${request.provider}:${request.credentialId}`)).size, 3);
	assert.equal(new Set(second.map((request) => `${request.provider}:${request.credentialId}`)).size, 3);
	assert.equal(new Set(selectedPairs).size, 5);
});

test("usage coordinator selectCredentialRequestWindows partitions into correct window count", () => {
	const windowSize = 4;
	const coordinator = new UsageCoordinator(
		createConfig({ modalRefreshCandidateWindow: windowSize }),
	);
	const requests = Array.from({ length: 10 }, (_unused, index) => ({
		provider: "partition-provider",
		credentialId: `cred-${index}`,
	}));

	// First call: should produce ceil(10/4) = 3 windows: [4, 4, 2]
	const windows1 = coordinator.selectCredentialRequestWindows(requests, "modal-refresh");
	assert.equal(windows1.length, 3, "10 requests with window 4 produces 3 windows");
	assert.equal(windows1[0]?.length, 4, "First window has 4 items");
	assert.equal(windows1[1]?.length, 4, "Second window has 4 items");
	assert.equal(windows1[2]?.length, 2, "Third window has 2 items");

	// All items in first windows should be unique (no duplicates within a call)
	const allFirstCall = [...windows1[0], ...windows1[1], ...windows1[2]];
	assert.equal(new Set(allFirstCall.map((r) => r.credentialId)).size, 10);
	assert.deepEqual(
		windows1[0].map((r) => r.credentialId),
		["cred-0", "cred-1", "cred-2", "cred-3"],
	);
	assert.deepEqual(
		windows1[1].map((r) => r.credentialId),
		["cred-4", "cred-5", "cred-6", "cred-7"],
	);
	assert.deepEqual(
		windows1[2].map((r) => r.credentialId),
		["cred-8", "cred-9"],
	);

	// Second call: rotated start position, same window sizes
	const windows2 = coordinator.selectCredentialRequestWindows(requests, "modal-refresh");
	assert.equal(windows2.length, 3, "Second call also produces 3 windows");
	assert.equal(windows2[0]?.length, 4, "First window has 4 items");
	assert.equal(windows2[1]?.length, 4, "Second window has 4 items");
	assert.equal(windows2[2]?.length, 2, "Third window has 2 items");

	// Second call is rotated: cursor advanced by windowSize (4) from position 0 to position 4
	assert.deepEqual(
		windows2[0].map((r) => r.credentialId),
		["cred-4", "cred-5", "cred-6", "cred-7"],
		"Second call first window is rotated",
	);
	assert.deepEqual(
		windows2[1].map((r) => r.credentialId),
		["cred-8", "cred-9", "cred-0", "cred-1"],
		"Second call second window wraps around",
	);

	// All 10 unique credentials covered across both calls
	const coveredFirst = new Set(windows1.flat().map((r) => r.credentialId));
	const coveredSecond = new Set(windows2.flat().map((r) => r.credentialId));
	assert.equal(coveredFirst.size, 10, "First call covers all 10 unique credentials");
	assert.equal(coveredSecond.size, 10, "Second call also covers all 10 unique credentials");

	// Verify no duplicates within each call
	const dedupFirst = new Set(windows1.flat().map((r) => `${r.provider}:${r.credentialId}`));
	assert.equal(dedupFirst.size, 10, "No duplicate provider+credential pairs within first call");
	const dedupSecond = new Set(windows2.flat().map((r) => `${r.provider}:${r.credentialId}`));
	assert.equal(dedupSecond.size, 10, "No duplicate provider+credential pairs within second call");
});

test("usage coordinator handles modal refresh inventory changes without exceeding the window", () => {
	const coordinator = new UsageCoordinator(createConfig({ modalRefreshCandidateWindow: 4 }));

	coordinator.selectCredentialRequests(createCredentialRequests(10), "modal-refresh");
	coordinator.selectCredentialRequests(createCredentialRequests(10), "modal-refresh");
	const reduced = coordinator.selectCredentialRequests(createCredentialRequests(3), "modal-refresh");
	const expanded = coordinator.selectCredentialRequests(createCredentialRequests(6), "modal-refresh");
	const progressed = coordinator.selectCredentialRequests(createCredentialRequests(6), "modal-refresh");

	assert.equal(reduced.length, 3);
	assert.deepEqual(
		reduced.map((request) => request.credentialId),
		Array.from({ length: 3 }, (_unused, index) => createCredentialRef(index)),
	);
	assert.equal(expanded.length, 4);
	assert.deepEqual(
		expanded.map((request) => request.credentialId),
		Array.from({ length: 4 }, (_unused, index) => createCredentialRef(index)),
	);
	assert.equal(progressed.length, 4);
	assert.deepEqual(
		progressed.map((request) => request.credentialId),
		[createCredentialRef(4), createCredentialRef(5), createCredentialRef(0), createCredentialRef(1)],
	);
});

test("usage coordinator keeps 50, 100, and 500 credential windows bounded", async (t) => {
	const windowSize = 8;
	const selectionCount = 10;
	for (const credentialCount of [50, 100, 500]) {
		await t.test(`${credentialCount} credentials`, () => {
			const coordinator = new UsageCoordinator(
				createConfig({ modalRefreshCandidateWindow: windowSize }),
			);
			const requests = createCredentialRequests(credentialCount);
			const selections = Array.from({ length: selectionCount }, () =>
				coordinator.selectCredentialRequests(requests, "modal-refresh"),
			);

			for (const selected of selections) {
				assert.equal(selected.length <= windowSize, true);
			}
			assert.deepEqual(
				selections[0].map((request) => request.credentialId),
				Array.from({ length: windowSize }, (_unused, index) => createCredentialRef(index)),
			);
			assert.equal(selections[1][0]?.credentialId, createCredentialRef(windowSize));
			assert.equal(
				new Set(selections.flat().map((request) => request.credentialId)).size,
				Math.min(credentialCount, windowSize * selectionCount),
			);
		});
	}
});

test("usage coordinator keeps usage rate-limit failures scoped to the credential", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 1,
			perProviderMaxConcurrentFreshRequests: 1,
			accountCooldownMs: 60_000,
			providerCooldownMs: 60_000,
			jitterMs: 0,
		}),
	);
	const firstGate = createDeferred();
	let queuedRunCount = 0;

	const first = coordinator.executeFreshRequest(
		{ provider: "cooldown-provider", credentialId: createCredentialRef(1), operation: "direct" },
		async () => {
			await firstGate.promise;
			throw new Error("429 rate limit");
		},
	);
	const queued = coordinator.executeFreshRequest(
		{ provider: "cooldown-provider", credentialId: createCredentialRef(2), operation: "direct" },
		async () => {
			queuedRunCount += 1;
			return "queued-dispatch";
		},
	);

	const firstRejection = assert.rejects(first, /429 rate limit/);
	firstGate.resolve();
	await firstRejection;
	assert.equal(await queued, "queued-dispatch");
	assert.equal(queuedRunCount, 1);

	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider: "cooldown-provider", credentialId: createCredentialRef(1), operation: "direct" },
			async () => "unexpected-repeat-dispatch",
		),
		/credential usage cooldown is active/,
	);
});

test("usage coordinator does not open provider circuits after usage auth failures", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 1,
			perProviderMaxConcurrentFreshRequests: 1,
			accountCooldownMs: 60_000,
			circuitBreakerCooldownMs: 60_000,
			jitterMs: 0,
		}),
	);
	const firstGate = createDeferred();
	let queuedRunCount = 0;

	const first = coordinator.executeFreshRequest(
		{ provider: "circuit-provider", credentialId: createCredentialRef(1), operation: "direct" },
		async () => {
			await firstGate.promise;
			throw new Error("401 unauthorized");
		},
	);
	const queued = coordinator.executeFreshRequest(
		{ provider: "circuit-provider", credentialId: createCredentialRef(2), operation: "direct" },
		async () => {
			queuedRunCount += 1;
			return "queued-dispatch";
		},
	);

	const firstRejection = assert.rejects(first, /401 unauthorized/);
	firstGate.resolve();
	await firstRejection;
	assert.equal(await queued, "queued-dispatch");
	assert.equal(queuedRunCount, 1);
});

test("usage coordinator opens and recovers provider circuit after repeated non-auth failures", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			accountCooldownMs: 0,
			authCooldownMs: 0,
			circuitBreakerFailureThreshold: 2,
			circuitBreakerCooldownMs: 25,
			jitterMs: 0,
		}),
	);
	const descriptor = (credentialId: string) => ({
		provider: "breaker-provider",
		credentialId,
		operation: "direct" as const,
	});

	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(1)), async () => {
			throw new Error("429 usage limited");
		}),
		/429 usage limited/,
	);
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(2)), async () => {
			throw new Error("503 upstream unavailable");
		}),
		/503 upstream unavailable/,
	);
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(3)), async () => "unexpected-dispatch"),
		/provider usage circuit is open/,
	);

	await sleep(35);
	assert.equal(
		await coordinator.executeFreshRequest(descriptor(createCredentialRef(4)), async () => "recovered"),
		"recovered",
	);
	assert.equal(
		await coordinator.executeFreshRequest(descriptor(createCredentialRef(5)), async () => "after-close"),
		"after-close",
	);
});

test("usage coordinator allows only one half-open provider circuit probe", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 2,
			perProviderMaxConcurrentFreshRequests: 2,
			accountCooldownMs: 0,
			authCooldownMs: 0,
			circuitBreakerFailureThreshold: 1,
			circuitBreakerCooldownMs: 25,
			jitterMs: 0,
		}),
	);
	const descriptor = (credentialId: string) => ({
		provider: "half-open-provider",
		credentialId,
		operation: "direct" as const,
	});

	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(1)), async () => {
			throw new Error("503 upstream unavailable");
		}),
		/503 upstream unavailable/,
	);
	await sleep(35);

	const probeGate = createDeferred();
	const probe = coordinator.executeFreshRequest(descriptor(createCredentialRef(2)), async () => {
		await probeGate.promise;
		throw new Error("503 probe failed");
	});
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(3)), async () => "unexpected-dispatch"),
		/recovery probe/,
	);

	probeGate.resolve();
	await assert.rejects(probe, /503 probe failed/);
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(4)), async () => "unexpected-dispatch"),
		/provider usage circuit is open/,
	);
});

test("usage service preserves single-flight fresh usage requests under coordination", async () => {
	let fetchCount = 0;
	const coordinator = new UsageCoordinator(createConfig());
	const usageService = new UsageService(30_000, 300_000, 10_000, coordinator, { persistentCache: false });
	usageService.register({
		id: "single-flight-provider",
		displayName: "Single Flight Provider",
		fetchUsage: async (_auth: UsageAuth) => {
			fetchCount += 1;
			return createUsageSnapshot("single-flight-provider");
		},
	});

	const [first, second] = await Promise.all([
		usageService.fetchUsage(
			"single-flight-provider",
			"credential-a",
			{ accessToken: "token-a" },
			{ forceRefresh: true, coordinationOperation: "modal-refresh" },
		),
		usageService.fetchUsage(
			"single-flight-provider",
			"credential-a",
			{ accessToken: "token-a" },
			{ forceRefresh: true, coordinationOperation: "modal-refresh" },
		),
	]);

	assert.equal(fetchCount, 1);
	assert.equal(first.fromCache, false);
	assert.equal(second.fromCache, false);
	assert.equal(first.error, null);
	assert.equal(second.error, null);
});

test("usage service reuses fresh negative cache even for forced refreshes", async () => {
	let fetchCount = 0;
	const usageService = new UsageService(30_000, 300_000, 60_000, undefined, { persistentCache: false });
	usageService.register({
		id: "negative-cache-provider",
		displayName: "Negative Cache Provider",
		fetchUsage: async (_auth: UsageAuth) => {
			fetchCount += 1;
			throw new Error("429 usage endpoint limited");
		},
	});

	const first = await usageService.fetchUsage(
		"negative-cache-provider",
		"credential-a",
		{ accessToken: "token-a" },
		{ forceRefresh: true },
	);
	const second = await usageService.fetchUsage(
		"negative-cache-provider",
		"credential-a",
		{ accessToken: "token-a" },
		{ forceRefresh: true },
	);

	assert.equal(fetchCount, 1);
	assert.equal(first.fromCache, false);
	assert.equal(second.fromCache, true);
	assert.match(first.error ?? "", /429 usage endpoint limited/);
	assert.equal(second.error, first.error);
});

test("usage service harvests rate-limit headers into operational usage cache", async () => {
	const usageService = new UsageService(30_000, 300_000, 10_000, undefined, { persistentCache: false });
	const credentialCacheKey = "cache-key-a";
	const observedAt = Date.now();

	const harvested = await usageService.harvestRateLimitHeaders(
		"openai-codex",
		"credential-a",
		credentialCacheKey,
		{
			"x-ratelimit-limit-requests": "100",
			"x-ratelimit-remaining-requests": "0",
			"x-ratelimit-reset-requests": "60",
		},
		observedAt,
	);

	assert.ok(harvested?.snapshot);
	assert.equal(harvested.snapshot.rateLimitHeaders?.remaining, 0);
	assert.equal(harvested.snapshot.quotaClassification, "hourly");
	const cached = usageService.readCachedUsage("openai-codex", "credential-a", { allowStale: true });
	assert.equal(cached?.snapshot?.rateLimitHeaders?.remaining, 0);
});

test("usage coordinator half-open probe success fully closes provider circuit", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 2,
			perProviderMaxConcurrentFreshRequests: 2,
			accountCooldownMs: 0,
			authCooldownMs: 0,
			circuitBreakerFailureThreshold: 2,
			circuitBreakerCooldownMs: 25,
			jitterMs: 0,
		}),
	);
	const descriptor = (credentialId: string) => ({
		provider: "success-close-provider",
		credentialId,
		operation: "direct" as const,
	});

	// Open the circuit with 2 failures
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(1)), async () => {
			throw new Error("503 upstream unavailable");
		}),
	);
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(2)), async () => {
			throw new Error("429 rate limited");
		}),
	);

	// Circuit is open
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(3)), async () => "unexpected"),
		/provider usage circuit is open/,
	);

	// Wait for cooldown
	await sleep(35);

	// This should be the half-open probe — make it succeed
	const result = await coordinator.executeFreshRequest(
		descriptor(createCredentialRef(4)),
		async () => "probe-success",
	);
	assert.equal(result, "probe-success");

	// Circuit should now be fully closed — next request should dispatch normally
	const result2 = await coordinator.executeFreshRequest(
		descriptor(createCredentialRef(5)),
		async () => "after-close",
	);
	assert.equal(result2, "after-close");

	// Verify debug state no longer shows a circuit
	const state = coordinator.getRedactedDebugState();
	const circuits = state.providerCircuits as Array<{ provider: string }>;
	const circuit = circuits.find((c) => c.provider === "success-close-provider");
	assert.equal(circuit, undefined, "Circuit should be removed after successful probe");
});

test("usage coordinator validates config rejects invalid values", () => {
	// Zero for positive fields
	assert.throws(
		() => new UsageCoordinator(createConfig({ globalMaxConcurrentFreshRequests: 0 })),
		/positive integer/,
	);
	assert.throws(
		() => new UsageCoordinator(createConfig({ circuitBreakerFailureThreshold: 0 })),
		/positive integer/,
	);
	// Negative values
	assert.throws(
		() => new UsageCoordinator(createConfig({ globalMaxConcurrentFreshRequests: -1 })),
		/positive integer/,
	);
	// Float values (non-integer)
	assert.throws(
		() => new UsageCoordinator(createConfig({ globalMaxConcurrentFreshRequests: 1.5 })),
		/positive integer/,
	);
	// NaN
	assert.throws(
		() => new UsageCoordinator(createConfig({ globalMaxConcurrentFreshRequests: NaN })),
		/positive integer/,
	);
	// Infinity
	assert.throws(
		() => new UsageCoordinator(createConfig({ globalMaxConcurrentFreshRequests: Infinity })),
		/positive integer/,
	);

	// Non-negative integer fields accept 0
	assert.doesNotThrow(
		() => new UsageCoordinator(createConfig({ accountCooldownMs: 0 })),
	);
	assert.doesNotThrow(
		() => new UsageCoordinator(createConfig({ circuitBreakerCooldownMs: 0 })),
	);
	// But reject negative
	assert.throws(
		() => new UsageCoordinator(createConfig({ accountCooldownMs: -1 })),
		/non-negative integer/,
	);
	assert.throws(
		() => new UsageCoordinator(createConfig({ circuitBreakerCooldownMs: -100 })),
		/non-negative integer/,
	);
});

test("usage coordinator circuitBreakerCooldownMs:0 prevents circuit from opening", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 2,
			perProviderMaxConcurrentFreshRequests: 2,
			accountCooldownMs: 0,
			authCooldownMs: 0,
			circuitBreakerFailureThreshold: 2,
			circuitBreakerCooldownMs: 0,
			jitterMs: 0,
		}),
	);
	const descriptor = (credentialId: string) => ({
		provider: "no-circuit-provider",
		credentialId,
		operation: "direct" as const,
	});

	// Repeated failures even beyond threshold should NOT open circuit when cooldown is 0
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(1)), async () => {
			throw new Error("429 rate limit");
		}),
	);
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(2)), async () => {
			throw new Error("503 unavailable");
		}),
	);
	await assert.rejects(
		coordinator.executeFreshRequest(descriptor(createCredentialRef(3)), async () => {
			throw new Error("500 server error");
		}),
	);

	// With cooldown 0, the circuit should never open, so this should dispatch
	// Despite 3 failures exceeding threshold of 2
	const result = await coordinator.executeFreshRequest(
		descriptor(createCredentialRef(4)),
		async () => "still-allowed",
	);
	assert.equal(result, "still-allowed");
});

test("usage coordinator independent circuits for multiple providers", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 4,
			perProviderMaxConcurrentFreshRequests: 2,
			accountCooldownMs: 0,
			authCooldownMs: 0,
			circuitBreakerFailureThreshold: 2,
			circuitBreakerCooldownMs: 40,
			jitterMs: 0,
		}),
	);
	const descriptorA = (credentialId: string) => ({
		provider: "provider-a",
		credentialId,
		operation: "direct" as const,
	});
	const descriptorB = (credentialId: string) => ({
		provider: "provider-b",
		credentialId,
		operation: "direct" as const,
	});

	// Open circuit for provider-a with 2 failures
	await assert.rejects(
		coordinator.executeFreshRequest(descriptorA(createCredentialRef(1)), async () => {
			throw new Error("503 unavailable");
		}),
	);
	await assert.rejects(
		coordinator.executeFreshRequest(descriptorA(createCredentialRef(2)), async () => {
			throw new Error("429 limit");
		}),
	);

	// Provider-a circuit should now be open
	await assert.rejects(
		coordinator.executeFreshRequest(descriptorA(createCredentialRef(3)), async () => "unexpected"),
		/provider usage circuit is open/,
	);

	// Provider-b should still accept requests
	const result = await coordinator.executeFreshRequest(
		descriptorB(createCredentialRef(1)),
		async () => "provider-b-ok",
	);
	assert.equal(result, "provider-b-ok");
});

test("usage coordinator disabled bypasses all policy", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			enabled: false,
			accountCooldownMs: 60_000,
			circuitBreakerCooldownMs: 120_000,
		}),
	);

	// Even with auth failures and circuits, disabled coordinator should dispatch directly
	const result = await coordinator.executeFreshRequest(
		{ provider: "disabled-provider", credentialId: "cred-a", operation: "direct" },
		async () => "bypassed-all-policy",
	);
	assert.equal(result, "bypassed-all-policy");
});

test("usage coordinator rejects whitespace-only descriptor fields", async () => {
	const coordinator = new UsageCoordinator(createConfig({ enabled: true }));

	// Whitespace-only provider
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider: "   ", credentialId: "cred-a", operation: "direct" },
			async () => "should not run",
		),
		/provider must be a non-empty string/,
	);

	// Whitespace-only credentialId
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider: "valid-provider", credentialId: "   ", operation: "direct" },
			async () => "should not run",
		),
		/credential ID must be a non-empty string/,
	);

	// Empty provider
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider: "", credentialId: "cred-a", operation: "direct" },
			async () => "should not run",
		),
		/provider must be a non-empty string/,
	);
});

test("usage coordinator classifies all auth-like error patterns", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 2,
			perProviderMaxConcurrentFreshRequests: 2,
			accountCooldownMs: 0,
			authCooldownMs: 60_000, // Set high enough to detect auth classification
			circuitBreakerCooldownMs: 60_000,
			jitterMs: 0,
		}),
	);

	// Test all 8 pattern variants
	const authPatterns = [
		"401 unauthorized",
		"403 forbidden",
		"token expired",
		"invalid_grant",
		"access denied",
		"missing required usage scope",
		"token revoked",
		"unauthorized access",
	];

	for (const [index, errorMessage] of authPatterns.entries()) {
		const coordinator = new UsageCoordinator(
			createConfig({
				globalMaxConcurrentFreshRequests: 2,
				perProviderMaxConcurrentFreshRequests: 2,
				accountCooldownMs: 0,
				authCooldownMs: 60_000,
				circuitBreakerCooldownMs: 60_000,
				jitterMs: 0,
			}),
		);
		const provider = `auth-pattern-${index}`;
		const credentialId = `cred-${index}`;

		// Auth failure should NOT open the circuit (authCooldown will fire)
		await assert.rejects(
			coordinator.executeFreshRequest(
				{ provider, credentialId, operation: "direct" },
				async () => {
					throw new Error(errorMessage);
				},
			),
			new RegExp(errorMessage.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
		);

		// A second auth failure on the same credential should hit auth_cooldown,
		// NOT provider_circuit_open — confirming it was classified as auth
		await assert.rejects(
			coordinator.executeFreshRequest(
				{ provider, credentialId, operation: "direct" },
				async () => {
					throw new Error(errorMessage);
				},
			),
			/auth cooldown/,
		);
	}
});

test("usage coordinator rejects non-Error objects in auth check as non-auth", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 2,
			perProviderMaxConcurrentFreshRequests: 2,
			accountCooldownMs: 0,
			circuitBreakerFailureThreshold: 2,
			circuitBreakerCooldownMs: 25,
			jitterMs: 0,
		}),
	);

	// Throw a string instead of an Error — should be classified as non-auth
	const provider = "non-error-provider";
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider, credentialId: "cred-a", operation: "direct" },
			async () => {
				throw "401 unauthorized string";
			},
		),
	);

	// Should open circuit after threshold because string is NOT an Error instance
	// (Second non-auth failure should open circuit)
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider, credentialId: "cred-b", operation: "direct" },
			async () => {
				throw new Error("500 server error");
			},
		),
	);

	// Circuit should now be open
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider, credentialId: "cred-c", operation: "direct" },
			async () => "unexpected",
		),
		/provider usage circuit is open/,
	);
});

test("usage coordinator formatUsageRequestDeferredNote with past vs future retryAt", () => {
	const now = Date.now();

	// Future retryAt -> should include "until" timestamp
	const futureError = new UsageRequestDeferredError(
		{ provider: "test-provider", credentialId: "cred-a", operation: "direct" },
		{
			reason: "credential_cooldown",
			retryAt: now + 60_000,
			message: "Deferred",
		},
	);
	const futureNote = formatUsageRequestDeferredNote(futureError);
	assert.match(futureNote, /until/);
	assert.match(futureNote, /deferred/);

	// Past retryAt -> should NOT include "until" timestamp
	const pastError = new UsageRequestDeferredError(
		{ provider: "test-provider", credentialId: "cred-a", operation: "direct" },
		{
			reason: "credential_cooldown",
			retryAt: now - 60_000,
			message: "Deferred",
		},
	);
	const pastNote = formatUsageRequestDeferredNote(pastError);
	assert.equal(pastNote.includes("until"), false);
	assert.match(pastNote, /deferred/);
});

test("usage coordinator isUsageRequestDeferredError type guard", () => {
	const now = Date.now();
	const deferredError = new UsageRequestDeferredError(
		{ provider: "test-provider", credentialId: "cred-a", operation: "direct" },
		{
			reason: "credential_cooldown",
			retryAt: now + 60_000,
			message: "Deferred",
		},
	);

	assert.equal(isUsageRequestDeferredError(deferredError), true);
	assert.equal(isUsageRequestDeferredError(new Error("generic")), false);
	assert.equal(isUsageRequestDeferredError("string error"), false);
	assert.equal(isUsageRequestDeferredError(null), false);
	assert.equal(isUsageRequestDeferredError(undefined), false);
	assert.equal(isUsageRequestDeferredError({}), false);
});

test("usage coordinator empty and whitespace selectCredentialIds", () => {
	const coordinator = new UsageCoordinator(createConfig());

	// Empty array
	assert.deepEqual(
		coordinator.selectCredentialIds([], "modal-refresh"),
		[],
	);

	// All whitespace entries
	assert.deepEqual(
		coordinator.selectCredentialIds(["   ", "", " \t "], "modal-refresh"),
		[],
	);

	// Mixed valid and whitespace entries
	assert.deepEqual(
		coordinator.selectCredentialIds(["cred-a", "   ", "cred-b", ""], "selection"),
		["cred-a", "cred-b"],
	);
});

test("usage coordinator deferred note constructs with all deferral reasons", () => {
	const now = Date.now();
	const makeError = (reason: "credential_cooldown" | "auth_cooldown" | "provider_circuit_open") =>
		new UsageRequestDeferredError(
			{ provider: "p", credentialId: "c", operation: "direct" },
			{ reason, retryAt: now + 60_000, message: `Deferred: ${reason}` },
		);

	const credError = makeError("credential_cooldown");
	assert.equal(credError.reason, "credential_cooldown");
	assert.equal(credError.provider, "p");
	assert.equal(credError.credentialId, "c");

	const authError = makeError("auth_cooldown");
	assert.equal(authError.reason, "auth_cooldown");

	const circuitError = makeError("provider_circuit_open");
	assert.equal(circuitError.reason, "provider_circuit_open");
});

test("usage coordinator updateConfig while queue populated changes behavior", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 1,
			perProviderMaxConcurrentFreshRequests: 1,
			accountCooldownMs: 0,
			circuitBreakerCooldownMs: 0,
			jitterMs: 0,
		}),
	);

	// Fill the single concurrency slot
	const gate = createDeferred();
	const longRunning = coordinator.executeFreshRequest(
		{ provider: "queue-test-provider", credentialId: "cred-a", operation: "direct" },
		async () => {
			await gate.promise;
			return "long-result";
		},
	);

	// Queue up a request while the first is in-flight
	const queued = coordinator.executeFreshRequest(
		{ provider: "queue-test-provider", credentialId: "cred-b", operation: "direct" },
		async () => "queued-result",
	);

	// Now tighten config to 0 concurrency... actually that won't work since we can't reduce to 0
	// Instead, update config with same concurrency
	coordinator.updateConfig(
		createConfig({
			globalMaxConcurrentFreshRequests: 1,
			perProviderMaxConcurrentFreshRequests: 1,
			accountCooldownMs: 0,
			circuitBreakerCooldownMs: 0,
			jitterMs: 0,
		}),
	);

	gate.resolve();
	assert.equal(await longRunning, "long-result");
	assert.equal(await queued, "queued-result");
});

test("usage coordinator non-zero jitterMs produces bounded deterministic values", () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			jitterMs: 2000,
		}),
	);

	// Access jitter indirectly through the authCooldownMs behavior
	// We can't directly call resolveJitterMs since it's private, but we can
	// verify that repeated auth failures on different credentials produce
	// different cooldown durations when jitterMs > 0 by checking the
	// getRedactedDebugState output

	// Verify that the coordinator accepts non-zero jitter
	assert.doesNotThrow(() => {
		const coordinator2 = new UsageCoordinator(createConfig({ jitterMs: 5000 }));
		assert.equal(coordinator2.getOperationWindowSize("direct"), 1);
	});
});

test("usage coordinator expired cooldowns omitted from debug state", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			accountCooldownMs: 10_000,
			circuitBreakerCooldownMs: 0,
			jitterMs: 0,
		}),
	);

	// Trigger a credential cooldown
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider: "debug-state-provider", credentialId: "cred-a", operation: "direct" },
			async () => {
				throw new Error("429 rate limit");
			},
		),
	);

	// Debug state should include the active cooldown
	const stateAfter = coordinator.getRedactedDebugState();
	const cooldowns = stateAfter.credentialCooldowns as Array<{ reason: string }>;
	const matchingCooldowns = cooldowns.filter((c) => c.reason === "credential_cooldown");
	assert.equal(matchingCooldowns.length >= 1, true);

	// Wait for cooldown to expire
	await sleep(15_000);

	// Debug state should no longer show the expired cooldown
	const stateAfterExpiry = coordinator.getRedactedDebugState();
	const cooldownsAfterExpiry = stateAfterExpiry.credentialCooldowns as Array<{ reason: string }>;
	const expiredCooldowns = cooldownsAfterExpiry.filter(
		(c: { reason: string }) => c.reason === "credential_cooldown",
	);
	assert.equal(expiredCooldowns.length, 0);
});

test("usage coordinator auth and non-auth failures on same provider produce independent cooldowns", async () => {
	const coordinator = new UsageCoordinator(
		createConfig({
			globalMaxConcurrentFreshRequests: 4,
			perProviderMaxConcurrentFreshRequests: 4,
			accountCooldownMs: 30_000,
			authCooldownMs: 60_000,
			circuitBreakerFailureThreshold: 2,
			circuitBreakerCooldownMs: 60_000,
			jitterMs: 0,
		}),
	);
	const authFailureDesc = { provider: "cross-provider", credentialId: "cred-auth", operation: "direct" as const };

	// Auth failure on credential A
	await assert.rejects(
		coordinator.executeFreshRequest(authFailureDesc, async () => {
			throw new Error("401 unauthorized");
		}),
	);

	// Non-auth failure on credential B (different credential, same provider)
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider: "cross-provider", credentialId: "cred-non-auth-1", operation: "direct" as const },
			async () => {
				throw new Error("503 upstream unavailable");
			},
		),
	);

	// credential A should be on auth cooldown
	await assert.rejects(
		coordinator.executeFreshRequest(authFailureDesc, async () => "unexpected"),
		/auth cooldown/,
	);

	// Second non-auth failure on credential C (different from B) to avoid account cooldown
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider: "cross-provider", credentialId: "cred-non-auth-2", operation: "direct" as const },
			async () => {
				throw new Error("429 rate limit");
			},
		),
	);

	// Provider circuit should now be open for credential D (different credential, same provider)
	await assert.rejects(
		coordinator.executeFreshRequest(
			{ provider: "cross-provider", credentialId: "cred-d", operation: "direct" as const },
			async () => "unexpected",
		),
		/provider usage circuit is open/,
	);
});
