import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";

import { AccountManager } from "../src/account-manager.js";
import { AuthWriter } from "../src/auth-writer.js";
import { KeyDistributor } from "../src/balancer/index.js";
import { DEFAULT_MULTI_AUTH_CONFIG } from "../src/config.js";
import { multiAuthDebugLogger } from "../src/debug-logger.js";
import { acquireFileLock, lockDirPath, pathExists } from "../src/file-utils.js";
import {
	registerOAuthProvider,
	resetOAuthProviders,
} from "../src/oauth-compat.js";
import {
	getOAuthRefreshLockTargetPath,
	OAUTH_REFRESH_LOCK_STALE_MS,
} from "../src/oauth-refresh-lock.js";
import { ProviderRegistry } from "../src/provider-registry.js";
import { MultiAuthStorage } from "../src/storage.js";
import type { StoredAuthCredential } from "../src/types.js";
import { OAuthRefreshFailureError } from "../src/types-oauth.js";
import { UsageService } from "../src/usage/index.js";

interface Deferred<T> {
	promise: Promise<T>;
	resolve: (value: T | PromiseLike<T>) => void;
	reject: (reason?: unknown) => void;
}

function createDeferred<T>(): Deferred<T> {
	let resolve!: Deferred<T>["resolve"];
	let reject!: Deferred<T>["reject"];
	const promise = new Promise<T>((resolvePromise, rejectPromise) => {
		resolve = resolvePromise;
		reject = rejectPromise;
	});
	return { promise, resolve, reject };
}

async function createProcessLikeManagers(
	t: TestContext,
	providerId: string,
	authData: Record<string, unknown>,
): Promise<{
	managers: [AccountManager, AccountManager];
	authPath: string;
	storagePath: string;
}> {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-oauth-xproc-"));
	const authPath = join(tempRoot, "auth.json");
	const storagePath = join(tempRoot, "multi-auth.json");
	const modelsPath = join(tempRoot, "models.json");
	await writeFile(authPath, JSON.stringify(authData, null, 2), "utf-8");
	await writeFile(modelsPath, JSON.stringify({ providers: {} }), "utf-8");

	const createManager = (): AccountManager => {
		const authWriter = new AuthWriter(authPath);
		const storage = new MultiAuthStorage(storagePath);
		const usageService = new UsageService(
			undefined,
			undefined,
			undefined,
			undefined,
			{ persistentCache: false },
		);
		const providerRegistry = new ProviderRegistry(authWriter, modelsPath, [providerId]);
		const keyDistributor = new KeyDistributor(storage, authWriter);
		return new AccountManager(
			authWriter,
			storage,
			usageService,
			providerRegistry,
			keyDistributor,
			DEFAULT_MULTI_AUTH_CONFIG,
			{
				startOAuthRefreshScheduler: false,
				configPath: join(tempRoot, "config.json"),
			},
		);
	};

	const managers: [AccountManager, AccountManager] = [createManager(), createManager()];
	t.after(async () => {
		await Promise.all(managers.map((manager) => manager.shutdown()));
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});
	await managers[0].ensureInitialized();
	await managers[1].ensureInitialized();
	return { managers, authPath, storagePath };
}

async function readStoredCredential(
	authPath: string,
	credentialId: string,
): Promise<StoredAuthCredential | undefined> {
	const data = JSON.parse(await readFile(authPath, "utf-8")) as Record<
		string,
		StoredAuthCredential
	>;
	return data[credentialId];
}

async function readDisabledCredentialIds(
	storagePath: string,
	providerId: string,
): Promise<string[]> {
	const data = JSON.parse(await readFile(storagePath, "utf-8")) as {
		providers?: Record<
			string,
			{ disabledCredentials?: Record<string, { error: string; disabledAt: number }> }
		>;
	};
	return Object.keys(data.providers?.[providerId]?.disabledCredentials ?? {});
}

test(
	"process-like account managers serialize rotating OAuth refreshes and the waiter reuses auth.json",
	{ timeout: 5_000 },
	async (t) => {
		resetOAuthProviders();
		t.after(() => resetOAuthProviders());
		const providerId = "rotating-race-provider";
		const credentialId = providerId;
		const networkStarted = createDeferred<void>();
		const releaseNetwork = createDeferred<void>();
		const waiterReachedLock = createDeferred<void>();
		const refreshTokensSeen: string[] = [];
		let activeNetworkRefreshes = 0;
		let maxActiveNetworkRefreshes = 0;

		registerOAuthProvider({
			id: providerId,
			name: "Rotating Race Provider",
			usesCallbackServer: false,
			login: async () => {
				throw new Error("Login is not used in this test.");
			},
			refreshToken: async (credential) => {
				refreshTokensSeen.push(credential.refresh);
				activeNetworkRefreshes += 1;
				maxActiveNetworkRefreshes = Math.max(maxActiveNetworkRefreshes, activeNetworkRefreshes);
				try {
					if (refreshTokensSeen.length === 1) {
						networkStarted.resolve();
						await releaseNetwork.promise;
					}
					return {
						...credential,
						access: `access-${refreshTokensSeen.length}`,
						refresh: `refresh-${refreshTokensSeen.length}`,
						expires: Date.now() + 3_600_000,
					};
				} finally {
					activeNetworkRefreshes -= 1;
				}
			},
			getApiKey: () => "unused",
		});

		const { managers, authPath, storagePath } = await createProcessLikeManagers(
			t,
			providerId,
			{
				[credentialId]: {
					type: "oauth",
					access: "access-0",
					refresh: "refresh-0",
					expires: Date.now() - 60_000,
				},
			},
		);

		const originalDebugLog = multiAuthDebugLogger.log.bind(multiAuthDebugLogger);
		multiAuthDebugLogger.log = (event, payload = {}) => {
			if (event === "oauth_refresh_lock_wait" && payload.provider === providerId) {
				waiterReachedLock.resolve();
			}
		};
		t.after(() => {
			multiAuthDebugLogger.log = originalDebugLog;
		});

		const firstRefresh = managers[0].refreshCredential(providerId, credentialId);
		await networkStarted.promise;
		const secondRefresh = managers[1].refreshCredential(providerId, credentialId);
		await waiterReachedLock.promise;
		releaseNetwork.resolve();

		const [firstResult, secondResult] = await Promise.all([firstRefresh, secondRefresh]);
		const storedCredential = await readStoredCredential(authPath, credentialId);

		assert.deepEqual(refreshTokensSeen, ["refresh-0"]);
		assert.equal(maxActiveNetworkRefreshes, 1);
		assert.equal(firstResult.disposition, "refreshed");
		assert.equal(secondResult.disposition, "reused_current_token");
		assert.equal(firstResult.credential.refresh, "refresh-1");
		assert.equal(secondResult.credential.refresh, "refresh-1");
		assert.equal(storedCredential?.type, "oauth");
		assert.equal(storedCredential?.type === "oauth" ? storedCredential.refresh : undefined, "refresh-1");
		assert.deepEqual(await readDisabledCredentialIds(storagePath, providerId), []);
	},
);

test(
	"a permanent OAuth failure is shared with cross-process waiters without another token request",
	{ timeout: 5_000 },
	async (t) => {
		resetOAuthProviders();
		t.after(() => resetOAuthProviders());
		const providerId = "permanent-refresh-failure-provider";
		const credentialId = providerId;
		const networkStarted = createDeferred<void>();
		const releaseNetwork = createDeferred<void>();
		const waiterReachedLock = createDeferred<void>();
		let refreshCalls = 0;

		registerOAuthProvider({
			id: providerId,
			name: "Permanent Refresh Failure Provider",
			usesCallbackServer: false,
			login: async () => {
				throw new Error("Login is not used in this test.");
			},
			refreshToken: async () => {
				refreshCalls += 1;
				networkStarted.resolve();
				await releaseNetwork.promise;
				throw new OAuthRefreshFailureError("The rotating refresh token was rejected.", {
					providerId,
					status: 400,
					reason: "token_rejected",
					permanent: true,
					source: "extension",
				});
			},
			getApiKey: () => "unused",
		});

		const { managers, storagePath } = await createProcessLikeManagers(t, providerId, {
			[credentialId]: {
				type: "oauth",
				access: "access-invalid",
				refresh: "refresh-invalid",
				expires: Date.now() - 60_000,
			},
		});

		const originalDebugLog = multiAuthDebugLogger.log.bind(multiAuthDebugLogger);
		multiAuthDebugLogger.log = (event, payload = {}) => {
			if (event === "oauth_refresh_lock_wait" && payload.provider === providerId) {
				waiterReachedLock.resolve();
			}
		};
		t.after(() => {
			multiAuthDebugLogger.log = originalDebugLog;
		});

		const firstRefresh = managers[0].refreshCredential(providerId, credentialId);
		await networkStarted.promise;
		const secondRefresh = managers[1].refreshCredential(providerId, credentialId);
		await waiterReachedLock.promise;
		releaseNetwork.resolve();

		const results = await Promise.allSettled([firstRefresh, secondRefresh]);
		assert.equal(refreshCalls, 1);
		assert.equal(results[0]?.status, "rejected");
		assert.equal(results[1]?.status, "rejected");
		assert.deepEqual(await readDisabledCredentialIds(storagePath, providerId), [credentialId]);
	},
);

test(
	"generic permanent refresh failure recovers a credential rotated during provider I/O",
	{ timeout: 5_000 },
	async (t) => {
		resetOAuthProviders();
		t.after(() => resetOAuthProviders());
		const providerId = "kimi-coding";
		const credentialId = providerId;
		let authPathForRefresh = "";
		let refreshCalls = 0;

		registerOAuthProvider({
			id: providerId,
			name: "Kimi Coding Race Test",
			usesCallbackServer: false,
			login: async () => {
				throw new Error("Login is not used in this test.");
			},
			refreshToken: async () => {
				refreshCalls += 1;
				// This independent auth.json transaction proves the refresh critical
				// section does not hold auth.json's write lock across provider I/O.
				await new AuthWriter(authPathForRefresh).setOAuthCredential(credentialId, {
					access: "access-rotated-elsewhere",
					refresh: "refresh-rotated-elsewhere",
					expires: Date.now() + 3_600_000,
				});
				throw new OAuthRefreshFailureError("Kimi rejected the stale rotating token.", {
					providerId,
					status: 401,
					errorCode: "invalid_grant",
					reason: "token_rejected",
					permanent: true,
					source: "extension",
				});
			},
			getApiKey: () => "unused",
		});

		const { managers, authPath, storagePath } = await createProcessLikeManagers(
			t,
			providerId,
			{
				[credentialId]: {
					type: "oauth",
					access: "access-stale",
					refresh: "refresh-stale",
					expires: Date.now() - 60_000,
				},
			},
		);
		authPathForRefresh = authPath;

		const result = await managers[0].refreshCredential(providerId, credentialId);
		const storedCredential = await readStoredCredential(authPath, credentialId);

		assert.equal(refreshCalls, 1);
		assert.equal(result.disposition, "reused_current_token");
		assert.equal(result.credential.refresh, "refresh-rotated-elsewhere");
		assert.equal(storedCredential?.type, "oauth");
		assert.equal(
			storedCredential?.type === "oauth" ? storedCredential.refresh : undefined,
			"refresh-rotated-elsewhere",
		);
		assert.deepEqual(await readDisabledCredentialIds(storagePath, providerId), []);
	},
);

test("OAuth refresh removes a crashed process's stale credential lock", async (t) => {
	resetOAuthProviders();
	t.after(() => resetOAuthProviders());
	const providerId = "stale-refresh-lock-provider";
	const credentialId = providerId;
	let refreshCalls = 0;
	registerOAuthProvider({
		id: providerId,
		name: "Stale Refresh Lock Provider",
		usesCallbackServer: false,
		login: async () => {
			throw new Error("Login is not used in this test.");
		},
		refreshToken: async (credential) => {
			refreshCalls += 1;
			return {
				...credential,
				access: "access-after-stale-lock",
				refresh: "refresh-after-stale-lock",
				expires: Date.now() + 3_600_000,
			};
		},
		getApiKey: () => "unused",
	});

	const { managers, authPath } = await createProcessLikeManagers(t, providerId, {
		[credentialId]: {
			type: "oauth",
			access: "access-before-stale-lock",
			refresh: "refresh-before-stale-lock",
			expires: Date.now() - 60_000,
		},
	});
	const lockPath = lockDirPath(
		getOAuthRefreshLockTargetPath(authPath, providerId, credentialId),
	);
	await mkdir(lockPath, { mode: 0o700 });
	const staleTime = new Date(Date.now() - OAUTH_REFRESH_LOCK_STALE_MS - 5_000);
	await utimes(lockPath, staleTime, staleTime);

	const result = await managers[0].refreshCredential(providerId, credentialId);

	assert.equal(refreshCalls, 1);
	assert.equal(result.credential.refresh, "refresh-after-stale-lock");
	assert.equal(await pathExists(lockPath), false);
});

test("shared file lock waiting supports deterministic abort and timeout", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-oauth-lock-control-"));
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});
	const targetPath = join(tempRoot, "refresh-scope");
	const baseOptions = {
		realpath: false,
		retries: {
			retries: 20,
			factor: 1,
			minTimeout: 5,
			maxTimeout: 5,
			randomize: false,
		},
		stale: 30_000,
	};
	const release = await acquireFileLock(targetPath, baseOptions);

	const controller = new AbortController();
	await assert.rejects(
		acquireFileLock(
			targetPath,
			{ ...baseOptions, signal: controller.signal },
			{
				onRetry: () => controller.abort(),
			},
		),
		(error: unknown) => error instanceof Error && error.name === "AbortError",
	);
	await assert.rejects(
		acquireFileLock(targetPath, { ...baseOptions, timeoutMs: 10 }),
		/Timed out acquiring lock/,
	);
	await release();
	assert.equal(await pathExists(lockDirPath(targetPath)), false);
});
