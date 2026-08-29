import { createHash } from "node:crypto";
import {
	acquireFileLock,
	type FileLockObserver,
} from "./file-utils.js";

/**
 * Refresh locks are heartbeated while provider I/O is active. A dead process is
 * reclaimable after the stale window, while a live but slow refresh retains
 * ownership until it finishes or waiters hit their own acquisition timeout.
 */
export const OAUTH_REFRESH_LOCK_STALE_MS = 30_000;
export const OAUTH_REFRESH_LOCK_UPDATE_MS = 5_000;
export const OAUTH_REFRESH_LOCK_TIMEOUT_MS = 45_000;

export function getOAuthRefreshLockTargetPath(
	authPath: string,
	provider: string,
	credentialId: string,
): string {
	const scopeHash = createHash("sha256")
		.update(provider)
		.update("\0")
		.update(credentialId)
		.digest("hex")
		.slice(0, 32);
	return `${authPath}.oauth-refresh.${scopeHash}`;
}

export async function acquireOAuthRefreshLock(
	authPath: string,
	provider: string,
	credentialId: string,
	signal?: AbortSignal,
	observer: FileLockObserver = {},
): Promise<() => Promise<void>> {
	return acquireFileLock(
		getOAuthRefreshLockTargetPath(authPath, provider, credentialId),
		{
			realpath: false,
			retries: {
				retries: 300,
				factor: 1,
				minTimeout: 250,
				maxTimeout: 250,
				randomize: true,
			},
			stale: OAUTH_REFRESH_LOCK_STALE_MS,
			timeoutMs: OAUTH_REFRESH_LOCK_TIMEOUT_MS,
			update: OAUTH_REFRESH_LOCK_UPDATE_MS,
			signal,
		},
		observer,
	);
}
