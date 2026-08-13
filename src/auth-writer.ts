import { writeFile } from "node:fs/promises";
import {
	getErrorMessage,
	isRecord,
} from "./auth-error-utils.js";
import type { OAuthCredentials } from "./oauth-compat.js";
import { resolveAgentRuntimePath } from "./runtime-paths.js";
import { multiAuthDebugLogger } from "./debug-logger.js";
import {
	acquireFileLock,
	backupBeforeOverwrite,
	ensureFileExists,
	ensureParentDir,
	hardenCredentialFilePermissions,
	readTextSnapshotWithBackupRecovery,
} from "./file-utils.js";
import {
	isRetryableFileAccessError,
	writeTextSnapshotWithRetries,
} from "./file-retry.js";
import type {
	BackupAndStoreResult,
	CredentialRequestOverrides,
	OpenCodeGoQuotaConfig,
	StoredApiKeyCredential,
	StoredAuthCredential,
	StoredOAuthCredential,
	SupportedProviderId,
} from "./types.js";

type RawAuthFileData = Record<string, unknown>;

type LockResult<T> = {
	result: T;
	next?: RawAuthFileData;
};

export interface AuthCredentialEntry {
	credentialId: string;
	credential: StoredAuthCredential;
}

export interface ApiKeyProviderNormalizationResult {
	provider: SupportedProviderId;
	removedDuplicateCount: number;
	renumberedCredentialIds: boolean;
	credentialIds: string[];
	credentialIdMap: Record<string, string>;
}

export type CredentialIdentityKeyResolver = (
	provider: SupportedProviderId,
	credential: StoredAuthCredential,
) => string | undefined;

function getDefaultAuthPath(): string {
	return resolveAgentRuntimePath("auth.json");
}

function parseAuthData(content: string | undefined): RawAuthFileData {
	if (!content || content.trim() === "") {
		return {};
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(content);
	} catch (error) {
		throw new Error(`Invalid JSON in auth.json: ${getErrorMessage(error)}`);
	}

	if (!isRecord(parsed)) {
		throw new Error("Invalid auth.json format: expected a JSON object");
	}

	return parsed;
}

async function readAuthDataSnapshot(authPath: string): Promise<RawAuthFileData> {
	await ensureParentDir(authPath);
	await ensureFileExists(authPath, "{}");

	return readTextSnapshotWithBackupRecovery({
		filePath: authPath,
		parse: parseAuthData,
		createDefault: () => ({}),
	});
}

function serializeAuthData(data: RawAuthFileData): string {
	return JSON.stringify(data, null, 2);
}

async function writeAuthDataSnapshot(authPath: string, data: RawAuthFileData): Promise<void> {
	const serialized = serializeAuthData(data);
	await writeTextSnapshotWithRetries({
		filePath: authPath,
		failureMessage: `Failed to persist auth.json to '${authPath}'.`,
		write: async () => {
			await backupBeforeOverwrite(authPath);
			await writeFile(authPath, serialized, "utf-8");
			await hardenCredentialFilePermissions(authPath);
		},
		isRetryableError: isRetryableFileAccessError,
		onRetry: ({ attempt, maxAttempts, reason, delayMs }) => {
			multiAuthDebugLogger.log("auth_snapshot_write_retry", {
				authPath,
				attempt,
				maxAttempts,
				reason,
				delayMs,
			});
		},
		onRecovered: ({ attempt, maxAttempts }) => {
			multiAuthDebugLogger.log("auth_snapshot_write_recovered", {
				authPath,
				attempt,
				maxAttempts,
			});
		},
		onError: ({ attempt, maxAttempts, error }) => {
			multiAuthDebugLogger.log("auth_snapshot_write_error", {
				authPath,
				attempt,
				maxAttempts,
				error,
			});
		},
	});
}

function cloneAuthData(data: RawAuthFileData): RawAuthFileData {
	return { ...data };
}

function isOAuthCredential(value: unknown): value is StoredOAuthCredential {
	if (!isRecord(value)) {
		return false;
	}

	if (value.type !== "oauth") {
		return false;
	}

	return (
		typeof value.access === "string" &&
		typeof value.refresh === "string" &&
		typeof value.expires === "number" &&
		Number.isFinite(value.expires)
	);
}

function isApiKeyCredential(value: unknown): value is StoredApiKeyCredential {
	if (!isRecord(value)) {
		return false;
	}

	if (value.type !== "api_key") {
		return false;
	}

	return typeof value.key === "string";
}

function isStoredCredential(value: unknown): value is StoredAuthCredential {
	return isOAuthCredential(value) || isApiKeyCredential(value);
}

function escapeRegex(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function getFirstAvailableBackupSuffix(provider: SupportedProviderId, data: RawAuthFileData): number {
	const expression = new RegExp(`^${escapeRegex(provider)}-(\\d+)$`);
	const usedSuffixes = new Set<number>();
	for (const key of Object.keys(data)) {
		const match = expression.exec(key);
		if (!match) {
			continue;
		}
		const suffix = Number.parseInt(match[1], 10);
		if (Number.isInteger(suffix) && suffix > 0) {
			usedSuffixes.add(suffix);
		}
	}

	let suffix = 1;
	while (usedSuffixes.has(suffix)) {
		suffix += 1;
	}
	return suffix;
}

function cloneStoredCredential(credential: StoredAuthCredential): StoredAuthCredential {
	if (credential.type === "oauth") {
		return { ...credential };
	}
	return { ...credential };
}

function hasBackupCredentialSibling(
	provider: string,
	data: RawAuthFileData,
	excludeCredentialId?: string,
): boolean {
	const expression = new RegExp(`^${escapeRegex(provider)}-(\\d+)$`);
	for (const credentialId of Object.keys(data)) {
		if (credentialId === excludeCredentialId) {
			continue;
		}
		if (!expression.test(credentialId)) {
			continue;
		}
		if (isStoredCredential(data[credentialId])) {
			return true;
		}
	}
	return false;
}

function maybeResolveBackupBaseProvider(
	credentialId: string,
	data: RawAuthFileData,
	knownProviders: ReadonlySet<string>,
): string | null {
	const match = /^(.*)-(\d+)$/.exec(credentialId);
	if (!match) {
		return null;
	}

	const maybeProvider = match[1]?.trim();
	if (!maybeProvider) {
		return null;
	}

	const primaryCredential = data[maybeProvider];
	if (
		isStoredCredential(primaryCredential) ||
		knownProviders.has(maybeProvider) ||
		hasBackupCredentialSibling(maybeProvider, data, credentialId)
	) {
		return maybeProvider;
	}

	return null;
}

function getExpectedProviderCredentialId(provider: SupportedProviderId, index: number): string {
	return index === 0 ? provider : `${provider}-${index}`;
}

function normalizeCredentialIdentityKey(identityKey: string | undefined): string | undefined {
	const normalized = identityKey?.trim();
	return normalized ? normalized : undefined;
}

/**
 * Writes the active agent runtime auth.json under the same lock path as AuthStorage.
 * Read-only access uses optimistic snapshots so provider selection is not blocked by long-lived core auth locks.
 */
export class AuthWriter {
	constructor(private readonly authPath: string = getDefaultAuthPath()) {}

	/**
	 * Returns the configured auth.json path.
	 */
	getPath(): string {
		return this.authPath;
	}

	private async readSnapshot(): Promise<RawAuthFileData> {
		return readAuthDataSnapshot(this.authPath);
	}

	/**
	 * Lists provider IDs found in auth.json.
	 */
	async listProviderIds(seedProviders: readonly string[] = []): Promise<string[]> {
		const data = await this.readSnapshot();
		return this.listProviderIdsFromData(data, new Set(seedProviders));
	}

	/**
	 * Reads the credential IDs for a provider in deterministic order.
	 */
	async listProviderCredentialIds(provider: SupportedProviderId): Promise<string[]> {
		const data = await this.readSnapshot();
		return this.listProviderCredentialIdsFromData(provider, data);
	}

	/**
	 * Reads any stored credential by credential ID.
	 */
	async getCredential(credentialId: string): Promise<StoredAuthCredential | undefined> {
		const credentials = await this.getCredentials([credentialId]);
		return credentials.get(credentialId);
	}

	/**
	 * Reads a deterministic credential snapshot for the provided credential IDs.
	 */
	async getCredentials(credentialIds: readonly string[]): Promise<Map<string, StoredAuthCredential>> {
		const uniqueCredentialIds = [...new Set(credentialIds.map((credentialId) => credentialId.trim()))].filter(
			(credentialId) => credentialId.length > 0,
		);
		if (uniqueCredentialIds.length === 0) {
			return new Map<string, StoredAuthCredential>();
		}

		const data = await this.readSnapshot();
		const credentials = new Map<string, StoredAuthCredential>();
		for (const credentialId of uniqueCredentialIds) {
			const credential = data[credentialId];
			if (!isStoredCredential(credential)) {
				continue;
			}
			credentials.set(credentialId, cloneStoredCredential(credential));
		}
		return credentials;
	}

	/**
	 * Reads a provider's credentials in deterministic order from a single auth.json snapshot.
	 */
	async getProviderCredentialEntries(provider: SupportedProviderId): Promise<AuthCredentialEntry[]> {
		const data = await this.readSnapshot();
		return this.getProviderCredentialEntriesFromData(provider, data);
	}

	/**
	 * Reads an OAuth credential by credential ID.
	 */
	async getOAuthCredential(credentialId: string): Promise<StoredOAuthCredential | undefined> {
		const credential = await this.getCredential(credentialId);
		return credential?.type === "oauth" ? credential : undefined;
	}

	/**
	 * Persists an OAuth credential at the given credential ID.
	 */
	async setOAuthCredential(credentialId: string, credential: OAuthCredentials): Promise<void> {
		await this.withLock((data) => {
			const next = cloneAuthData(data);
			next[credentialId] = {
				type: "oauth",
				...credential,
			};
			return { result: undefined, next };
		});
	}

	/**
	 * Persists an API-key credential at the given credential ID.
	 */
	async setApiKeyCredential(credentialId: string, key: string): Promise<void> {
		const normalized = key.trim();
		if (!normalized) {
			throw new Error("API key cannot be empty.");
		}

		await this.withLock((data) => {
			const next = cloneAuthData(data);
			next[credentialId] = {
				type: "api_key",
				key: normalized,
			};
			return { result: undefined, next };
		});
	}

	/**
	 * Persists credential-scoped request overrides, preserving the credential secret.
	 */
	async setCredentialRequestOverrides(
		credentialId: string,
		request: CredentialRequestOverrides,
	): Promise<StoredAuthCredential> {
		const normalizedCredentialId = credentialId.trim();
		if (!normalizedCredentialId) {
			throw new Error("Credential ID cannot be empty.");
		}

		return this.withLock((data) => {
			const existing = data[normalizedCredentialId];
			if (!isStoredCredential(existing)) {
				throw new Error(
					`Credential ${normalizedCredentialId} is missing from auth.json. Open /multi-auth and add the account again if needed.`,
				);
			}

			const nextCredential: StoredAuthCredential = {
				...cloneStoredCredential(existing),
				request: {
					...existing.request,
					...request,
				},
			};
			const next = cloneAuthData(data);
			next[normalizedCredentialId] = nextCredential;
			return {
				result: cloneStoredCredential(nextCredential),
				next,
			};
		});
	}

	/**
	 * Persists the cookie-based OpenCode Go quota lookup config on a credential,
	 * preserving the credential secret and any sibling request overrides. Pass
	 * `null` to clear the stored workspace id and cookie.
	 */
	async setOpenCodeGoQuotaConfig(
		credentialId: string,
		config: OpenCodeGoQuotaConfig | null,
	): Promise<StoredAuthCredential> {
		const normalizedCredentialId = credentialId.trim();
		if (!normalizedCredentialId) {
			throw new Error("Credential ID cannot be empty.");
		}
		if (config !== null) {
			const workspaceId = config.workspaceId.trim();
			const cookie = config.cookie.trim();
			if (!workspaceId || !cookie) {
				throw new Error("OpenCode Go workspace id and cookie are both required.");
			}
			config = { workspaceId, cookie };
		}

		return this.withLock((data) => {
			const existing = data[normalizedCredentialId];
			if (!isStoredCredential(existing)) {
				throw new Error(
					`Credential ${normalizedCredentialId} is missing from auth.json. Open /multi-auth and add the account again if needed.`,
				);
			}

			const base = cloneStoredCredential(existing);
			if (config === null) {
				delete base.opencodeGo;
			} else {
				base.opencodeGo = config;
			}
			const nextCredential: StoredAuthCredential = base;
			const next = cloneAuthData(data);
			next[normalizedCredentialId] = nextCredential;
			return {
				result: cloneStoredCredential(nextCredential),
				next,
			};
		});
	}

	/**
	 * Stores OAuth credentials in provider slot (first account) or provider-N backup slot.
	 */
	async setOAuthCredentialAsBackup(
		provider: SupportedProviderId,
		credential: OAuthCredentials,
	): Promise<BackupAndStoreResult> {
		return this.withLock((data) => {
			const next = cloneAuthData(data);
			const destination = this.getBackupDestinationCredentialId(provider, next);
			next[destination.credentialId] = {
				type: "oauth",
				...credential,
			};

			const credentialIds = this.listProviderCredentialIdsFromData(provider, next);
			return {
				result: {
					credentialId: destination.credentialId,
					isBackupCredential: destination.isBackup,
					credentialIds,
				},
				next,
			};
		});
	}

	/**
	 * Stores API-key credentials in provider slot (first account) or provider-N backup slot.
	 */
	async setApiKeyCredentialAsBackup(
		provider: SupportedProviderId,
		key: string,
		request?: CredentialRequestOverrides,
		identityKeyResolver?: CredentialIdentityKeyResolver,
	): Promise<BackupAndStoreResult> {
		const normalized = key.trim();
		if (!normalized) {
			throw new Error("API key cannot be empty.");
		}

		return this.withLock((data) => {
			const existingEntries = this.getProviderCredentialEntriesFromData(provider, data);
			const uniqueCredentials: StoredAuthCredential[] = [];
			const firstIndexByApiKey = new Map<string, number>();
			const firstIndexByIdentityKey = new Map<string, number>();
			const newCredential: StoredAuthCredential = {
				type: "api_key",
				key: normalized,
				...(request && { request }),
			};
			const targetIdentityKey = normalizeCredentialIdentityKey(
				identityKeyResolver?.(provider, newCredential),
			);
			let deduplicatedCount = 0;

			for (const entry of existingEntries) {
				const credential = cloneStoredCredential(entry.credential);
				if (credential.type === "api_key") {
					const normalizedExistingKey = credential.key.trim();
					if (!normalizedExistingKey) {
						deduplicatedCount += 1;
						continue;
					}
					const existingIdentityKey = normalizeCredentialIdentityKey(
						identityKeyResolver?.(provider, credential),
					);
					if (
						firstIndexByApiKey.has(normalizedExistingKey) ||
						(existingIdentityKey !== undefined && firstIndexByIdentityKey.has(existingIdentityKey))
					) {
						deduplicatedCount += 1;
						continue;
					}
					credential.key = normalizedExistingKey;
					const nextIndex = uniqueCredentials.length;
					firstIndexByApiKey.set(normalizedExistingKey, nextIndex);
					if (existingIdentityKey !== undefined) {
						firstIndexByIdentityKey.set(existingIdentityKey, nextIndex);
					}
				}
				uniqueCredentials.push(credential);
			}

			let targetIndex = targetIdentityKey === undefined
				? undefined
				: firstIndexByIdentityKey.get(targetIdentityKey);
			targetIndex ??= firstIndexByApiKey.get(normalized);
			let didAddCredential = false;
			if (targetIndex === undefined) {
				didAddCredential = true;
				targetIndex = uniqueCredentials.length;
				uniqueCredentials.push(newCredential);
				firstIndexByApiKey.set(normalized, targetIndex);
				if (targetIdentityKey !== undefined) {
					firstIndexByIdentityKey.set(targetIdentityKey, targetIndex);
				}
			} else {
				const existingIndex = targetIndex;
				const existingCredential = uniqueCredentials[existingIndex];
				if (existingCredential?.type === "api_key") {
					uniqueCredentials[existingIndex] = {
						...existingCredential,
						key: normalized,
						...(request
							? {
									request: {
										...existingCredential.request,
										...request,
									},
								}
							: {}),
					};
				}
			}

			const existingCredentialIds = existingEntries.map((entry) => entry.credentialId);
			const next = cloneAuthData(data);
			for (const credentialId of existingCredentialIds) {
				delete next[credentialId];
			}

			const credentialIds: string[] = [];
			for (const [index, credential] of uniqueCredentials.entries()) {
				const credentialId = index === 0 ? provider : `${provider}-${index}`;
				next[credentialId] = credential;
				credentialIds.push(credentialId);
			}

			const renumberedCredentialIds = existingCredentialIds.some((credentialId, index) => {
				const expectedCredentialId = index === 0 ? provider : `${provider}-${index}`;
				return credentialId !== expectedCredentialId;
			});
			const resolvedIndex = targetIndex ?? 0;
			const resolvedCredentialId = credentialIds[resolvedIndex] ?? provider;
			return {
				result: {
					credentialId: resolvedCredentialId,
					isBackupCredential: resolvedIndex > 0,
					credentialIds,
					didAddCredential,
					duplicateOfCredentialId: didAddCredential ? undefined : resolvedCredentialId,
					deduplicatedCount,
					renumberedCredentialIds,
				},
				next,
			};
		});
	}

	private normalizeProviderCredentialsFromData(
		data: RawAuthFileData,
		seedProviders: readonly string[] = [],
		identityKeyResolver?: CredentialIdentityKeyResolver,
	): {
		hasChanges: boolean;
		next: RawAuthFileData;
		changedProviders: ApiKeyProviderNormalizationResult[];
	} {
		const next = cloneAuthData(data);
		const providers = this.listProviderIdsFromData(next, new Set(seedProviders));
		const changedProviders: ApiKeyProviderNormalizationResult[] = [];
		let hasChanges = false;

		for (const provider of providers) {
			const entries = this.getProviderCredentialEntriesFromData(provider, next);
			if (entries.length === 0) {
				continue;
			}

			const existingCredentialIds = entries.map((entry) => entry.credentialId);
			const retainedEntries: Array<{
				credentialId: string;
				credential: StoredAuthCredential;
			}> = [];
			const seenApiKeys = new Set<string>();
			const seenIdentityKeys = new Set<string>();
			let removedDuplicateCount = 0;

			for (const entry of entries) {
				const credential = cloneStoredCredential(entry.credential);
				if (credential.type === "api_key") {
					const normalizedKey = credential.key.trim();
					if (!normalizedKey) {
						removedDuplicateCount += 1;
						continue;
					}
					const identityKey = normalizeCredentialIdentityKey(
						identityKeyResolver?.(provider, credential),
					);
					if (
						seenApiKeys.has(normalizedKey) ||
						(identityKey !== undefined && seenIdentityKeys.has(identityKey))
					) {
						removedDuplicateCount += 1;
						continue;
					}
					credential.key = normalizedKey;
					seenApiKeys.add(normalizedKey);
					if (identityKey !== undefined) {
						seenIdentityKeys.add(identityKey);
					}
				}
				retainedEntries.push({
					credentialId: entry.credentialId,
					credential,
				});
			}

			for (const credentialId of existingCredentialIds) {
				delete next[credentialId];
			}

			const shouldRenumberCredentialIds = retainedEntries.every(
				(entry) => entry.credential.type === "api_key",
			);
			const normalizedCredentialIds: string[] = [];
			const credentialIdMap: Record<string, string> = {};
			for (const [index, entry] of retainedEntries.entries()) {
				const credentialId = shouldRenumberCredentialIds
					? getExpectedProviderCredentialId(provider, index)
					: entry.credentialId;
				next[credentialId] = entry.credential;
				normalizedCredentialIds.push(credentialId);
				credentialIdMap[entry.credentialId] = credentialId;
			}

			const renumberedCredentialIds = shouldRenumberCredentialIds && retainedEntries.some(
				(entry, index) => entry.credentialId !== getExpectedProviderCredentialId(provider, index),
			);

			const providerChanged = removedDuplicateCount > 0 || renumberedCredentialIds;
			if (providerChanged) {
				hasChanges = true;
				changedProviders.push({
					provider,
					removedDuplicateCount,
					renumberedCredentialIds,
					credentialIds: normalizedCredentialIds,
					credentialIdMap,
				});
			}
		}

		return {
			hasChanges,
			next,
			changedProviders,
		};
	}

	/**
	 * Deduplicates API-key entries and renumbers only API-key-only provider slots.
	 */
	async normalizeProviderCredentials(
		seedProviders: readonly string[] = [],
		options: { identityKeyResolver?: CredentialIdentityKeyResolver } = {},
	): Promise<ApiKeyProviderNormalizationResult[]> {
		const snapshot = await this.readSnapshot();
		const analyzedSnapshot = this.normalizeProviderCredentialsFromData(
			snapshot,
			seedProviders,
			options.identityKeyResolver,
		);
		if (!analyzedSnapshot.hasChanges) {
			return analyzedSnapshot.changedProviders;
		}

		return this.withLock((data) => {
			const normalized = this.normalizeProviderCredentialsFromData(
				data,
				seedProviders,
				options.identityKeyResolver,
			);
			return normalized.hasChanges
				? { result: normalized.changedProviders, next: normalized.next }
				: { result: normalized.changedProviders };
		});
	}

	/**
	 * Backward-compatible wrapper retained for existing normalization flows.
	 */
	async normalizeApiKeyProviders(
		seedProviders: readonly string[] = [],
	): Promise<ApiKeyProviderNormalizationResult[]> {
		return this.normalizeProviderCredentials(seedProviders);
	}

	/**
	 * Backward-compatible method retained for existing OAuth flows.
	 */
	async backupAndStorePrimaryCredential(
		provider: SupportedProviderId,
		credential: OAuthCredentials,
	): Promise<BackupAndStoreResult> {
		return this.setOAuthCredentialAsBackup(provider, credential);
	}

	/**
	 * Executes an auth.json transaction under file lock.
	 */
	async withLock<T>(
		fn: (data: RawAuthFileData) => Promise<LockResult<T>> | LockResult<T>,
	): Promise<T> {
		await ensureParentDir(this.authPath);
		await ensureFileExists(this.authPath, "{}");

		let release: (() => Promise<void>) | undefined;

		try {
			release = await acquireFileLock(
				this.authPath,
				{
					realpath: false,
					retries: {
						retries: 10,
						factor: 2,
						minTimeout: 100,
						maxTimeout: 10_000,
						randomize: true,
					},
					stale: 30_000,
					onCompromised: () => {
						// Stale lock cleanup happened; continue transaction under the new lock.
					},
				},
				{
					onAcquired: (_latencyMs, details) => {
						if (details.attempt > 1) {
							multiAuthDebugLogger.log("auth_lock_acquired_after_retry", {
								authPath: details.filePath,
								lockPath: details.lockPath,
								attempt: details.attempt,
								maxAttempts: details.maxAttempts,
							});
						}
					},
					onError: (details) => {
						multiAuthDebugLogger.log("auth_lock_error", {
							authPath: details.filePath,
							lockPath: details.lockPath,
							attempt: details.attempt,
							maxAttempts: details.maxAttempts,
							error: details.error,
						});
					},
					onRetryableAccessError: (details) => {
						multiAuthDebugLogger.log("auth_lock_retryable_access_error", {
							authPath: details.filePath,
							lockPath: details.lockPath,
							attempt: details.attempt,
							maxAttempts: details.maxAttempts,
							error: details.error,
						});
					},
					onStaleLockRemoved: (details) => {
						multiAuthDebugLogger.log("auth_lock_removed_stale", {
							authPath: details.filePath,
							lockPath: details.lockPath,
							attempt: details.attempt,
							maxAttempts: details.maxAttempts,
							staleMs: details.staleMs,
							ageMs: details.ageMs,
						});
					},
					onTimeout: (details) => {
						multiAuthDebugLogger.log("auth_lock_timeout", {
							authPath: details.filePath,
							lockPath: details.lockPath,
							attempt: details.attempt,
							maxAttempts: details.maxAttempts,
							staleMs: details.staleMs,
							error: details.error,
						});
					},
					onRetry: (delayMs, details) => {
						multiAuthDebugLogger.log("auth_lock_wait", {
							authPath: details.filePath,
							lockPath: details.lockPath,
							attempt: details.attempt,
							maxAttempts: details.maxAttempts,
							staleMs: details.staleMs,
							delayMs,
						});
					},
				},
			);

			const parsed = await readAuthDataSnapshot(this.authPath);
			const lockResult = await fn(cloneAuthData(parsed));

			if (lockResult.next) {
				const serializedCurrent = serializeAuthData(parsed);
				const serializedNext = serializeAuthData(lockResult.next);
				if (serializedNext !== serializedCurrent) {
					await writeAuthDataSnapshot(this.authPath, lockResult.next);
				}
			}
			return lockResult.result;
		} finally {
			if (release) {
				try {
					await release();
				} catch {
					// Ignore unlock failures when lock is compromised.
				}
			}
		}
	}

	private getProviderCredentialEntriesFromData(
		provider: SupportedProviderId,
		data: RawAuthFileData,
	): AuthCredentialEntry[] {
		const credentialIds = this.listProviderCredentialIdsFromData(provider, data);
		const entries: AuthCredentialEntry[] = [];
		for (const credentialId of credentialIds) {
			const credential = data[credentialId];
			if (!isStoredCredential(credential)) {
				continue;
			}
			entries.push({
				credentialId,
				credential: cloneStoredCredential(credential),
			});
		}
		return entries;
	}

	private listProviderIdsFromData(data: RawAuthFileData, knownProviders: ReadonlySet<string>): string[] {
		const providers: string[] = [];
		const seen = new Set<string>();

		for (const [credentialId, value] of Object.entries(data)) {
			if (!isStoredCredential(value)) {
				continue;
			}

			const backupBase = maybeResolveBackupBaseProvider(credentialId, data, knownProviders);
			const provider = backupBase ?? credentialId;
			if (seen.has(provider)) {
				continue;
			}
			seen.add(provider);
			providers.push(provider);
		}

		return providers;
	}

	private listProviderCredentialIdsFromData(
		provider: SupportedProviderId,
		data: RawAuthFileData,
	): string[] {
		const credentialIds: string[] = [];

		if (isStoredCredential(data[provider])) {
			credentialIds.push(provider);
		}

		const expression = new RegExp(`^${escapeRegex(provider)}-(\\d+)$`);
		const suffixEntries = Object.keys(data)
			.map((credentialId) => {
				const match = expression.exec(credentialId);
				if (!match) {
					return undefined;
				}
				const suffix = Number.parseInt(match[1], 10);
				if (!Number.isInteger(suffix) || !isStoredCredential(data[credentialId])) {
					return undefined;
				}
				return { credentialId, suffix };
			})
			.filter((entry): entry is { credentialId: string; suffix: number } => entry !== undefined)
			.sort((left, right) => left.suffix - right.suffix);

		for (const entry of suffixEntries) {
			credentialIds.push(entry.credentialId);
		}

		return credentialIds;
	}

	private getBackupDestinationCredentialId(
		provider: SupportedProviderId,
		data: RawAuthFileData,
	): { credentialId: string; isBackup: boolean } {
		if (!isStoredCredential(data[provider])) {
			return {
				credentialId: provider,
				isBackup: false,
			};
		}

		const nextSuffix = getFirstAvailableBackupSuffix(provider, data);
		return {
			credentialId: `${provider}-${nextSuffix}`,
			isBackup: true,
		};
	}
}
