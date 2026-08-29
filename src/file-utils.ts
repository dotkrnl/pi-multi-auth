import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { access, chmod, copyFile, mkdir, readFile, rename, rm, stat, utimes, writeFile } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { abortableSleep } from "./async-utils.js";
import { getErrorMessage, throwIfAborted, toError } from "./auth-error-utils.js";
import { multiAuthDebugLogger } from "./debug-logger.js";
import { isRetryableFileAccessError, readTextSnapshotWithRetries } from "./file-retry.js";

const execFileAsync = promisify(execFile);
const DEFAULT_BACKUP_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

type AtomicWriteOptions = {
	createBackup?: boolean;
};

type BackupRecoveryOptions<T> = {
	filePath: string;
	backupPath?: string;
	parse: (content: string | undefined) => T;
	createDefault: () => T;
	maxAgeMs?: number;
};

export type LockRetryOptions = {
	retries: number;
	factor: number;
	minTimeout: number;
	maxTimeout: number;
	randomize: boolean;
};

export type FileLockOptions = {
	realpath?: boolean;
	retries: LockRetryOptions;
	stale: number;
	/** Optional absolute acquisition timeout in addition to the retry limit. */
	timeoutMs?: number;
	/** Stops a caller that is waiting for the lock. */
	signal?: AbortSignal;
	/** Optional lock-directory mtime heartbeat for long-lived critical sections. */
	update?: number;
	onCompromised?: (error: Error) => void;
};

type FileLockAttemptDetails = {
	filePath: string;
	lockPath: string;
	attempt: number;
	maxAttempts: number;
	staleMs: number;
};

export type FileLockRetryDetails = FileLockAttemptDetails & {
	delayMs: number;
	error: string;
};

export type FileLockErrorDetails = FileLockAttemptDetails & {
	error: string;
};

export type FileLockStaleDetails = FileLockAttemptDetails & {
	ageMs: number;
};

export type FileLockObserver = {
	onRetry?: (delayMs: number, details: FileLockRetryDetails) => void;
	onAcquired?: (latencyMs: number, details: FileLockAttemptDetails) => void;
	onRetryableAccessError?: (details: FileLockErrorDetails) => void;
	onError?: (details: FileLockErrorDetails) => void;
	onStaleLockRemoved?: (details: FileLockStaleDetails) => void;
	onTimeout?: (details: FileLockErrorDetails) => void;
};

export function lockDirPath(filePath: string): string {
	return `${filePath}.lock`;
}

export async function pathExists(filePath: string): Promise<boolean> {
	try {
		await access(filePath, fsConstants.F_OK);
		return true;
	} catch {
		return false;
	}
}

export async function ensureParentDir(filePath: string): Promise<void> {
	const parentDir = dirname(filePath);
	if (!(await pathExists(parentDir))) {
		await mkdir(parentDir, { recursive: true, mode: 0o700 });
	}
}

function wrapPermissionHardeningError(filePath: string, error: unknown): Error & { code?: string } {
	const maybeCode = (error as Error & { code?: unknown }).code;
	const hardenedError = new Error(
		`Failed to harden credential file permissions for '${filePath}': ${getErrorMessage(error)}`,
		{ cause: error },
	) as Error & { code?: string };
	if (typeof maybeCode === "string") {
		hardenedError.code = maybeCode;
	}
	return hardenedError;
}

async function hardenWindowsCredentialFilePermissions(filePath: string): Promise<void> {
	const currentUser = userInfo().username.trim() || process.env.USERNAME?.trim();
	if (!currentUser) {
		throw new Error("Unable to resolve current Windows user for credential ACL hardening.");
	}

	await execFileAsync("icacls", [
		filePath,
		"/inheritance:r",
		"/grant:r",
		`${currentUser}:F`,
		"*S-1-5-18:F",
		"*S-1-5-32-544:F",
	], { windowsHide: true });
}

export async function hardenCredentialFilePermissions(filePath: string): Promise<void> {
	try {
		if (process.platform === "win32") {
			await hardenWindowsCredentialFilePermissions(filePath);
			return;
		}

		await chmod(filePath, 0o600);
	} catch (error: unknown) {
		throw wrapPermissionHardeningError(filePath, error);
	}
}

export async function backupBeforeOverwrite(filePath: string, backupPath: string = `${filePath}.bak`): Promise<void> {
	if (!(await pathExists(filePath))) {
		return;
	}

	try {
		await copyFile(filePath, backupPath);
		await hardenCredentialFilePermissions(backupPath);
	} catch (error: unknown) {
		const maybeCode = (error as Error & { code?: unknown }).code;
		if (maybeCode === "ENOENT") {
			return;
		}
		throw error;
	}
}

export async function writeTextFileAtomically(
	filePath: string,
	content: string,
	options: AtomicWriteOptions = {},
): Promise<void> {
	const tempPath = `${filePath}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
	let tempCreated = false;
	try {
		await writeFile(tempPath, content, { encoding: "utf-8", mode: 0o600 });
		tempCreated = true;
		await hardenCredentialFilePermissions(tempPath);
		if (options.createBackup !== false) {
			await backupBeforeOverwrite(filePath);
		}
		await rename(tempPath, filePath);
		tempCreated = false;
		await hardenCredentialFilePermissions(filePath);
	} catch (error: unknown) {
		if (tempCreated) {
			await rm(tempPath, { force: true }).catch(() => undefined);
		}
		throw error;
	}
}

export async function readTextSnapshotWithBackupRecovery<T>(
	options: BackupRecoveryOptions<T>,
): Promise<T> {
	const backupPath = options.backupPath ?? `${options.filePath}.bak`;
	const maxAgeMs = Math.max(0, options.maxAgeMs ?? DEFAULT_BACKUP_MAX_AGE_MS);
	const primaryContent = await readTextSnapshotWithRetries<string | undefined>({
		filePath: options.filePath,
		failureMessage: `Failed to read snapshot from '${options.filePath}'.`,
		read: async () => ((await pathExists(options.filePath)) ? readFile(options.filePath, "utf-8") : undefined),
		parse: (content) => content,
		resolveOnFinalEmpty: () => undefined,
		isRetryableError: isRetryableFileAccessError,
	});

	if (primaryContent === undefined || primaryContent.trim() === "") {
		return options.createDefault();
	}

	try {
		return options.parse(primaryContent);
	} catch (primaryError: unknown) {
		multiAuthDebugLogger.log("primary_snapshot_corrupted", {
			filePath: options.filePath,
			backupPath,
			error: getErrorMessage(primaryError),
		});
	}

	try {
		if (!(await pathExists(backupPath))) {
			multiAuthDebugLogger.log("snapshot_backup_unavailable", {
				filePath: options.filePath,
				backupPath,
				reason: "missing",
			});
			return options.createDefault();
		}

		const backupStats = await stat(backupPath);
		const backupAgeMs = Date.now() - backupStats.mtimeMs;
		if (maxAgeMs > 0 && backupAgeMs > maxAgeMs) {
			multiAuthDebugLogger.log("snapshot_backup_unavailable", {
				filePath: options.filePath,
				backupPath,
				reason: "stale",
				backupAgeMs: Math.round(backupAgeMs),
				maxAgeMs,
			});
			return options.createDefault();
		}

		const backupContent = await readTextSnapshotWithRetries<string | undefined>({
			filePath: backupPath,
			failureMessage: `Failed to read backup snapshot from '${backupPath}'.`,
			read: async () => readFile(backupPath, "utf-8"),
			parse: (content) => content,
			resolveOnFinalEmpty: () => undefined,
			isRetryableError: isRetryableFileAccessError,
		});
		if (backupContent === undefined || backupContent.trim() === "") {
			return options.createDefault();
		}

		const parsedBackup = options.parse(backupContent);
		await writeTextFileAtomically(options.filePath, backupContent, { createBackup: false });
		multiAuthDebugLogger.log("snapshot_backup_recovered", {
			filePath: options.filePath,
			backupPath,
		});
		return parsedBackup;
	} catch (backupError: unknown) {
		multiAuthDebugLogger.log("snapshot_backup_recovery_failed", {
			filePath: options.filePath,
			backupPath,
			error: getErrorMessage(backupError),
		});
		return options.createDefault();
	}
}

export async function ensureFileExists(filePath: string, content: string): Promise<void> {
	if (!(await pathExists(filePath))) {
		await writeTextFileAtomically(filePath, content);
	}
}

export async function acquireFileLock(
	filePath: string,
	options: FileLockOptions,
	observer: FileLockObserver = {},
): Promise<() => Promise<void>> {
	const lockPath = lockDirPath(filePath);
	const ownerPath = join(lockPath, ".owner");
	const ownerToken = `${process.pid}:${randomUUID()}`;
	const maxAttempts = Math.max(0, options.retries.retries) + 1;
	const timeoutMs =
		typeof options.timeoutMs === "number" && Number.isFinite(options.timeoutMs)
			? Math.max(0, options.timeoutMs)
			: undefined;
	const updateMs =
		typeof options.update === "number" && Number.isFinite(options.update) && options.update > 0
			? Math.max(1, Math.floor(options.update))
			: undefined;
	const startedAt = Date.now();
	const abortMessage = `Lock acquisition aborted for '${filePath}'.`;

	throwIfAborted(options.signal, abortMessage);

	for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
		const details: FileLockAttemptDetails = {
			filePath,
			lockPath,
			attempt,
			maxAttempts,
			staleMs: options.stale,
		};
		try {
			await mkdir(lockPath, { mode: 0o700 });
			try {
				await writeFile(ownerPath, ownerToken, { encoding: "utf-8", flag: "wx", mode: 0o600 });
				throwIfAborted(options.signal, abortMessage);
			} catch (setupError) {
				await rm(lockPath, { recursive: true, force: true }).catch(() => undefined);
				throw setupError;
			}

			observer.onAcquired?.(Date.now() - startedAt, details);
			let released = false;
			let heartbeatPromise: Promise<void> | null = null;
			let heartbeatTimer: ReturnType<typeof setInterval> | undefined;

			const reportCompromised = (error: Error): void => {
				if (released) {
					return;
				}
				options.onCompromised?.(error);
			};

			if (updateMs !== undefined) {
				heartbeatTimer = setInterval(() => {
					if (released || heartbeatPromise) {
						return;
					}
					heartbeatPromise = (async () => {
						try {
							const currentOwner = await readFile(ownerPath, "utf-8");
							if (currentOwner !== ownerToken) {
								throw new Error(`Lock ownership changed for '${lockPath}'.`);
							}
							const now = new Date();
							await utimes(lockPath, now, now);
						} catch (error) {
							reportCompromised(toError(error));
						}
					})().finally(() => {
						heartbeatPromise = null;
					});
					void heartbeatPromise;
				}, updateMs);
				heartbeatTimer.unref?.();
			}

			return async () => {
				if (released) {
					return;
				}
				released = true;
				if (heartbeatTimer) {
					clearInterval(heartbeatTimer);
				}
				await heartbeatPromise?.catch(() => undefined);

				let currentOwner: string;
				try {
					currentOwner = await readFile(ownerPath, "utf-8");
				} catch {
					// A stale-lock recovery may already have replaced this lock.
					return;
				}
				if (currentOwner !== ownerToken) {
					// Never remove a replacement lock owned by another process.
					return;
				}
				await rm(lockPath, { recursive: true, force: true });
			};
		} catch (error) {
			const lockError = toError(error);
			if (options.signal?.aborted) {
				throwIfAborted(options.signal, abortMessage);
			}
			const maybeCode = (lockError as Error & { code?: unknown }).code;
			const isExistingLockError = maybeCode === "EEXIST";
			const isRetryableAccessError = isRetryableFileAccessError(lockError);

			if (!isExistingLockError && !isRetryableAccessError) {
				observer.onError?.({ ...details, error: lockError.message });
				throw lockError;
			}

			if (!isExistingLockError) {
				observer.onRetryableAccessError?.({ ...details, error: lockError.message });
			}

			try {
				const lockStats = await stat(lockPath);
				let ageMs = Date.now() - lockStats.mtimeMs;
				if (ageMs > options.stale) {
					// Confirm the age once more so a heartbeat racing the first stat wins.
					const confirmedStats = await stat(lockPath);
					ageMs = Date.now() - confirmedStats.mtimeMs;
					if (ageMs > options.stale) {
						await rm(lockPath, { recursive: true, force: true });
						observer.onStaleLockRemoved?.({ ...details, ageMs: Math.round(ageMs) });
						options.onCompromised?.(
							new Error(`Removed stale lock '${lockPath}' older than ${Math.round(ageMs)}ms.`),
						);
						// Retry mkdir immediately after removing the stale lock.
						attempt -= 1;
						continue;
					}
				}
			} catch {
				// Lock may be released while checking staleness; retry.
			}

			const elapsedMs = Date.now() - startedAt;
			const didTimeOut = timeoutMs !== undefined && elapsedMs >= timeoutMs;
			if (attempt >= maxAttempts || didTimeOut) {
				observer.onTimeout?.({ ...details, error: lockError.message });
				const timeoutDescription = timeoutMs === undefined
					? `${maxAttempts} attempt(s)`
					: `${Math.round(elapsedMs)}ms`;
				throw new Error(
					`Timed out acquiring lock for '${filePath}' after ${timeoutDescription}: ${lockError.message}`,
				);
			}

			const baseDelay = Math.min(
				options.retries.maxTimeout,
				Math.max(
					options.retries.minTimeout,
					Math.round(options.retries.minTimeout * Math.pow(options.retries.factor, attempt - 1)),
				),
			);
			let delay = options.retries.randomize
				? Math.round(baseDelay * (0.5 + Math.random()))
				: baseDelay;
			if (timeoutMs !== undefined) {
				delay = Math.min(delay, Math.max(0, timeoutMs - elapsedMs));
			}
			if (delay <= 0) {
				observer.onTimeout?.({ ...details, error: lockError.message });
				throw new Error(
					`Timed out acquiring lock for '${filePath}' after ${Math.round(elapsedMs)}ms: ${lockError.message}`,
				);
			}
			observer.onRetry?.(delay, { ...details, delayMs: delay, error: lockError.message });
			try {
				await abortableSleep(delay, options.signal);
			} catch (sleepError) {
				if (options.signal?.aborted) {
					throwIfAborted(options.signal, abortMessage);
				}
				throw sleepError;
			}
		}
	}

	throw new Error(`Failed to acquire lock for '${filePath}'.`);
}
