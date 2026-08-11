import { watch, type FSWatcher } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import type { ExtensionAPI, ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { AccountManager } from "./account-manager.js";
import {
	registerGlobalKeyDistributor,
	unregisterGlobalKeyDistributor,
} from "./balancer/index.js";
import { getErrorMessage, isRecord } from "./auth-error-utils.js";
import { loadMultiAuthConfig } from "./config.js";
import { multiAuthDebugLogger } from "./debug-logger.js";
import {
	registerDelegatedAuthBroker,
	unregisterDelegatedAuthBroker,
} from "./delegated-auth-broker.js";
import {
	registerMultiAuthProviders,
	registerRuntimeProviderOverride,
	type RuntimeProviderRegistrationPayload,
} from "./provider.js";
import { registerClineOAuthProvider } from "./oauth-cline.js";
import { registerKiloOAuthProvider } from "./oauth-kilo.js";
import { registerKimiCodingOAuthProvider } from "./oauth-kimi-coding.js";
import { registerQwenOAuthProvider } from "./oauth-qwen.js";
import {
	isDelegatedSubagentRuntime,
	resolveRequestedProviderFromArgv,
} from "./runtime-context.js";
import { resolveAgentRuntimePath } from "./runtime-paths.js";
import {
	formatQuotaStatusLine,
	formatStatusReport,
	summarizeProviderStatuses,
} from "./status-summary.js";

const STARTUP_WARMUP_DELAY_MS = 0;
const STARTUP_REFINEMENT_DELAY_MS = 1_500;
const RUNTIME_PROVIDER_REGISTRATION_EVENT = "pi-multi-auth:runtime-provider-registration";
const PROVIDERS_REGISTERED_EVENT = "pi-multi-auth:providers-registered";
const FOOTER_STATUS_KEY = "multi-auth";
const FOOTER_REFRESH_INTERVAL_MS = 30_000;
const AUTH_FILE_WATCH_DEBOUNCE_MS = 300;
const FIRST_CLASS_OAUTH_PROVIDER_REGISTRARS: Readonly<Record<string, () => void>> = {
	cline: registerClineOAuthProvider,
	kilo: registerKiloOAuthProvider,
	"kimi-coding": registerKimiCodingOAuthProvider,
	qwen: registerQwenOAuthProvider,
};

/**
 * Session start event payload.
 * The reason indicates the cause of the session start.
 */
interface SessionStartEvent {
	reason?: "new" | "resume" | "fork" | "reload";
	previousSessionFile?: string;
}

function isRuntimeProviderRegistrationPayload(
	value: unknown,
): value is RuntimeProviderRegistrationPayload {
	return (
		isRecord(value) &&
		typeof value.provider === "string" &&
		typeof value.baseUrl === "string" &&
		typeof value.api === "string" &&
		Array.isArray(value.models) &&
		typeof value.streamSimple === "function" &&
		(value.displayName === undefined || typeof value.displayName === "string") &&
		(value.headers === undefined || isRecord(value.headers))
	);
}

function registerEnabledOAuthProviders(hiddenProviders: ReadonlySet<string>): void {
	for (const [provider, registerProvider] of Object.entries(FIRST_CLASS_OAUTH_PROVIDER_REGISTRARS)) {
		if (!hiddenProviders.has(provider)) {
			registerProvider();
		}
	}
}

function registerLazyMultiAuthCommands(
	pi: ExtensionAPI,
	accountManager: AccountManager,
): void {
	pi.registerCommand("multi-auth", {
		description: "Open unified multi-auth account manager modal (or '/multi-auth status' for an inline report)",
		handler: async (args: string, ctx: ExtensionCommandContext): Promise<void> => {
			const trimmedArgs = args.trim();
			if (trimmedArgs === "status") {
				try {
					const statuses = await accountManager.getStatus();
					ctx.ui.notify(formatStatusReport(statuses), "info");
				} catch (error) {
					ctx.ui.notify(`/multi-auth status failed: ${getErrorMessage(error)}`, "error");
				}
				return;
			}

			if (trimmedArgs) {
				ctx.ui.notify("Usage: /multi-auth [status]", "warning");
				return;
			}

			if (!ctx.hasUI) {
				ctx.ui.notify("/multi-auth requires interactive TUI mode.", "warning");
				return;
			}

			try {
				const { openMultiAuthModal } = await import("./commands.js");
				await openMultiAuthModal(ctx, accountManager);
			} catch (error) {
				ctx.ui.notify(`/multi-auth failed: ${getErrorMessage(error)}`, "error");
			}
		},
	});
}

/**
 * pi-multi-auth extension entry point for multi-account OAuth credential management and rotation.
 */
export default async function multiAuthExtension(pi: ExtensionAPI): Promise<void> {
	const configLoadResult = loadMultiAuthConfig();
	const isSubagentRuntime = isDelegatedSubagentRuntime();
	const requestedSubagentProvider = isSubagentRuntime
		? resolveRequestedProviderFromArgv()
		: undefined;
	const startupWarnings = new Set<string>();
	const recordStartupWarning = (
		message: string,
		context: string,
		error?: unknown,
		onError?: (message: string) => void,
	): void => {
		const normalizedMessage = message.trim();
		if (!normalizedMessage) {
			return;
		}
		startupWarnings.add(normalizedMessage);
		multiAuthDebugLogger.log("startup_warning", {
			context,
			message: normalizedMessage,
			error: error ? getErrorMessage(error) : undefined,
		});
		onError?.(normalizedMessage);
	};
	if (configLoadResult.warning) {
		recordStartupWarning(configLoadResult.warning, "config_load");
	}

	const accountManager = new AccountManager(
		undefined,
		undefined,
		undefined,
		undefined,
		undefined,
		configLoadResult.config,
		{
			startOAuthRefreshScheduler: !isSubagentRuntime,
		},
	);
	let hiddenProvidersAtStartup: ReadonlySet<string> = new Set();
	try {
		hiddenProvidersAtStartup = new Set(await accountManager.getHiddenProviders());
	} catch (error) {
		recordStartupWarning(
			`Failed to read hidden providers: ${getErrorMessage(error)}`,
			"hidden_providers_load",
			error,
		);
	}
	registerEnabledOAuthProviders(hiddenProvidersAtStartup);

	const keyDistributor = accountManager.getKeyDistributor();
	registerGlobalKeyDistributor(keyDistributor);
	const delegatedAuthBroker = registerDelegatedAuthBroker(accountManager);
	const excludedProviders = new Set(hiddenProvidersAtStartup);
	const isRuntimeProviderAllowed = (provider: string): boolean => {
		if (excludedProviders.has(provider)) {
			return false;
		}
		if (isSubagentRuntime && requestedSubagentProvider) {
			return provider === requestedSubagentProvider;
		}
		return true;
	};
	const applyRuntimeProviderRegistration = (
		payload: RuntimeProviderRegistrationPayload,
		onError?: (message: string) => void,
	): void => {
		if (!isRuntimeProviderAllowed(payload.provider)) {
			return;
		}
		try {
			registerRuntimeProviderOverride(pi, accountManager, payload);
		} catch (error) {
			recordStartupWarning(
				`Failed to register runtime provider override for ${payload.provider}: ${getErrorMessage(error)}`,
				"runtime_provider_override",
				error,
				onError,
			);
		}
	};

	let warmupInFlight: Promise<void> | null = null;
	let warmupTimer: ReturnType<typeof setTimeout> | null = null;
	let warmupCompleted = false;
	let refinementInFlight: Promise<void> | null = null;
	let refinementTimer: ReturnType<typeof setTimeout> | null = null;
	let startupWorkGeneration = 0;
	let shutdownPromise: Promise<void> | null = null;

	const beginStartupWorkGeneration = (): number => {
		startupWorkGeneration += 1;
		return startupWorkGeneration;
	};

	const isStartupWorkCurrent = (generation: number): boolean => {
		return generation === startupWorkGeneration;
	};

	const clearStartupTimers = (): void => {
		if (warmupTimer !== null) {
			clearTimeout(warmupTimer);
			warmupTimer = null;
		}
		if (refinementTimer !== null) {
			clearTimeout(refinementTimer);
			refinementTimer = null;
		}
	};

	const scheduleRefinement = (
		generation: number,
		onError?: (message: string) => void,
	): void => {
		if (!isStartupWorkCurrent(generation) || refinementInFlight || refinementTimer) {
			return;
		}

		refinementTimer = setTimeout(() => {
			refinementTimer = null;
			if (!isStartupWorkCurrent(generation)) {
				return;
			}
			if (warmupInFlight) {
				scheduleRefinement(generation, onError);
				return;
			}

			let nextRefinement: Promise<void>;
			nextRefinement = accountManager
				.autoActivatePreferredCredentials()
				.catch((error: unknown) => {
					if (!isStartupWorkCurrent(generation)) {
						return;
					}
					recordStartupWarning(
						getErrorMessage(error),
						"startup_refinement",
						error,
						onError,
					);
				})
				.finally(() => {
					if (refinementInFlight === nextRefinement) {
						refinementInFlight = null;
					}
				});
			refinementInFlight = nextRefinement;
		}, STARTUP_REFINEMENT_DELAY_MS);
	};

	const startWarmup = (
		generation: number,
		onError?: (message: string) => void,
	): void => {
		if (!isStartupWorkCurrent(generation) || warmupInFlight) {
			return;
		}

		let nextWarmup: Promise<void>;
		nextWarmup = (async () => {
			await accountManager.ensureInitialized();
			await accountManager.autoActivatePreferredCredentials({ avoidUsageApi: true });
			await accountManager.warmupOperationalUsageCaches();
		})()
			.then(() => {
				if (!isStartupWorkCurrent(generation)) {
					return;
				}
				warmupCompleted = true;
				scheduleRefinement(generation, onError);
			})
			.catch((error: unknown) => {
				if (!isStartupWorkCurrent(generation)) {
					return;
				}
				recordStartupWarning(
					getErrorMessage(error),
					"startup_warmup",
					error,
					onError,
				);
			})
			.finally(() => {
				if (warmupInFlight === nextWarmup) {
					warmupInFlight = null;
				}
			});
		warmupInFlight = nextWarmup;
	};

	const scheduleWarmup = (
		generation: number,
		onError?: (message: string) => void,
	): void => {
		if (!isStartupWorkCurrent(generation) || warmupInFlight || warmupTimer) {
			return;
		}

		warmupTimer = setTimeout(() => {
			warmupTimer = null;
			if (!isStartupWorkCurrent(generation)) {
				return;
			}
			startWarmup(generation, onError);
		}, STARTUP_WARMUP_DELAY_MS);
	};

	const scheduleStartupWork = (
		generation: number,
		onError?: (message: string) => void,
	): void => {
		if (!isStartupWorkCurrent(generation)) {
			return;
		}
		if (!warmupCompleted) {
			scheduleWarmup(generation, onError);
			return;
		}
		scheduleRefinement(generation, onError);
	};

	// --- Footer quota indicator + live auth.json discovery (interactive runtimes) ---

	type FooterUiContext = {
		hasUI: boolean;
		ui: { setStatus(key: string, text: string | undefined): void };
	};

	let footerCtx: FooterUiContext | null = null;
	let footerRefreshTimer: ReturnType<typeof setInterval> | null = null;
	let footerInitialTimer: ReturnType<typeof setTimeout> | null = null;
	let footerRefreshInFlight: Promise<void> | null = null;
	let authWatcher: FSWatcher | null = null;
	let authWatchDebounceTimer: ReturnType<typeof setTimeout> | null = null;
	let lastAuthFileFingerprint: string | null = null;

	const refreshFooterStatus = async (): Promise<void> => {
		const ctx = footerCtx;
		if (!ctx?.hasUI) {
			return;
		}
		if (footerRefreshInFlight) {
			return footerRefreshInFlight;
		}
		footerRefreshInFlight = (async () => {
			try {
				const statuses = await accountManager.getStatus();
				const line = formatQuotaStatusLine(summarizeProviderStatuses(statuses));
				if (footerCtx === ctx) {
					ctx.ui.setStatus(FOOTER_STATUS_KEY, line);
				}
			} catch (error) {
				multiAuthDebugLogger.log("footer_status_refresh_failed", {
					error: getErrorMessage(error),
				});
			}
		})();
		try {
			await footerRefreshInFlight;
		} finally {
			footerRefreshInFlight = null;
		}
	};

	const stopFooterStatus = (): void => {
		if (footerRefreshTimer !== null) {
			clearInterval(footerRefreshTimer);
			footerRefreshTimer = null;
		}
		if (footerInitialTimer !== null) {
			clearTimeout(footerInitialTimer);
			footerInitialTimer = null;
		}
		if (footerCtx?.hasUI) {
			footerCtx.ui.setStatus(FOOTER_STATUS_KEY, undefined);
		}
		footerCtx = null;
	};

	const startFooterStatus = (ctx: FooterUiContext): void => {
		stopFooterStatus();
		if (!ctx.hasUI) {
			return;
		}
		footerCtx = ctx;
		// Initial refresh once warmup has had a chance to populate usage caches;
		// afterwards the interval re-reads cached snapshots (cheap, no network).
		footerInitialTimer = setTimeout(() => {
			footerInitialTimer = null;
			void refreshFooterStatus();
		}, STARTUP_REFINEMENT_DELAY_MS + 500);
		footerRefreshTimer = setInterval(() => {
			void refreshFooterStatus();
		}, FOOTER_REFRESH_INTERVAL_MS);
		footerRefreshTimer.unref?.();
	};

	const readAuthFileFingerprint = async (): Promise<string | null> => {
		try {
			const parsed: unknown = JSON.parse(await readFile(resolveAgentRuntimePath("auth.json"), "utf8"));
			if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
				return null;
			}
			// Only the credential-id set matters: token refreshes rewrite values
			// without changing keys and must not trigger re-registration.
			return Object.keys(parsed).sort().join("\n");
		} catch {
			return null;
		}
	};

	const handleAuthFileChange = (): void => {
		if (authWatchDebounceTimer !== null) {
			clearTimeout(authWatchDebounceTimer);
		}
		authWatchDebounceTimer = setTimeout(() => {
			authWatchDebounceTimer = null;
			void (async () => {
				const fingerprint = await readAuthFileFingerprint();
				if (fingerprint === null || fingerprint === lastAuthFileFingerprint) {
					return;
				}
				lastAuthFileFingerprint = fingerprint;
				multiAuthDebugLogger.log("auth_file_credential_set_changed");
				try {
					await registerMultiAuthProviders(pi, accountManager, {
						excludeProviders: [...excludedProviders],
					});
				} catch (error) {
					multiAuthDebugLogger.log("auth_change_reregistration_failed", {
						error: getErrorMessage(error),
					});
				}
				await refreshFooterStatus();
			})();
		}, AUTH_FILE_WATCH_DEBOUNCE_MS);
		authWatchDebounceTimer.unref?.();
	};

	const startAuthFileWatcher = (): void => {
		if (authWatcher) {
			return;
		}
		void (async () => {
			lastAuthFileFingerprint = await readAuthFileFingerprint();
		})();
		try {
			// Watch the directory: auth.json writes are atomic renames, which
			// invalidate file-level watchers.
			authWatcher = watch(resolveAgentRuntimePath(), (eventType, filename) => {
				if (filename && basename(filename.toString()) === "auth.json") {
					handleAuthFileChange();
				}
			});
			authWatcher.on("error", (error) => {
				multiAuthDebugLogger.log("auth_file_watch_error", {
					error: getErrorMessage(error),
				});
			});
			authWatcher.unref?.();
		} catch (error) {
			authWatcher = null;
			multiAuthDebugLogger.log("auth_file_watch_start_failed", {
				error: getErrorMessage(error),
			});
		}
	};

	const stopAuthFileWatcher = (): void => {
		if (authWatchDebounceTimer !== null) {
			clearTimeout(authWatchDebounceTimer);
			authWatchDebounceTimer = null;
		}
		if (authWatcher) {
			authWatcher.close();
			authWatcher = null;
		}
	};

	const shutdownExtension = async (onWarning?: (message: string) => void): Promise<void> => {
		if (shutdownPromise) {
			return shutdownPromise;
		}

		const generation = beginStartupWorkGeneration();
		clearStartupTimers();
		stopFooterStatus();
		stopAuthFileWatcher();
		shutdownPromise = (async () => {
			try {
				await accountManager.shutdown();
			} catch (error) {
				const message = `Failed to stop multi-auth background services: ${getErrorMessage(error)}`;
				multiAuthDebugLogger.log("session_shutdown_warning", {
					message,
					generation,
					error: getErrorMessage(error),
				});
				onWarning?.(message);
			} finally {
				unregisterGlobalKeyDistributor(keyDistributor);
				unregisterDelegatedAuthBroker(delegatedAuthBroker);
				await multiAuthDebugLogger.dispose();
			}
		})();
		return shutdownPromise;
	};

	const flushStartupWarnings = (notify?: (message: string) => void): void => {
		if (!notify) {
			return;
		}
		for (const warning of startupWarnings) {
			notify(warning);
		}
	};

	pi.events?.on(RUNTIME_PROVIDER_REGISTRATION_EVENT, (payload) => {
		if (!isRuntimeProviderRegistrationPayload(payload)) {
			return;
		}
		applyRuntimeProviderRegistration(payload);
	});

	if (!isSubagentRuntime) {
		registerLazyMultiAuthCommands(pi, accountManager);
	}

	try {
		await registerMultiAuthProviders(pi, accountManager, {
			excludeProviders: [...excludedProviders],
			includeProviders:
				isSubagentRuntime && requestedSubagentProvider
					? [requestedSubagentProvider]
					: undefined,
		});
		pi.events?.emit(PROVIDERS_REGISTERED_EVENT, {
			generation: startupWorkGeneration,
		});
	} catch (error) {
		recordStartupWarning(
			`Failed to register provider wrappers: ${getErrorMessage(error)}`,
			"provider_registration",
			error,
		);
	}

	pi.on("session_start", (_event, ctx) => {
		const event = _event as SessionStartEvent;
		shutdownPromise = null;
		const startupGeneration = beginStartupWorkGeneration();
		clearStartupTimers();
		registerGlobalKeyDistributor(keyDistributor);
		registerDelegatedAuthBroker(accountManager);
		flushStartupWarnings((message) => {
			ctx.ui.notify(`multi-auth startup warning: ${message}`, "warning");
		});

		// Refresh config on reload
		if (event.reason === "reload") {
			const reloadResult = loadMultiAuthConfig();
			if (reloadResult.warning) {
				ctx.ui.notify(`multi-auth reload warning: ${reloadResult.warning}`, "warning");
			}
			accountManager.refreshExtensionConfig(reloadResult.config);
			multiAuthDebugLogger.log("config_refreshed", { reason: event.reason });
		}

		if (!isSubagentRuntime) {
			startFooterStatus(ctx);
			startAuthFileWatcher();
			scheduleStartupWork(startupGeneration, (message) => {
				ctx.ui.notify(`multi-auth initialization warning: ${message}`, "warning");
			});
		}
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		await shutdownExtension((message) => {
			if (ctx.hasUI) {
				ctx.ui.notify(`multi-auth shutdown warning: ${message}`, "warning");
			}
		});
	});
}
