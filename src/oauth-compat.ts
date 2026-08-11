import type {
	Api,
	AuthEvent,
	AuthPrompt,
	Model,
	OAuthCredential,
	Provider,
	ProviderAuthInteraction,
} from "@earendil-works/pi-ai";
import {
	type OAuthCredentials,
	type OAuthDeviceCodeInfo,
	type OAuthLoginCallbacks,
} from "@earendil-works/pi-ai/oauth";
import { builtinProviders } from "@earendil-works/pi-ai/providers/all";
import {
	formatOAuthRefreshFailureSummary,
	isRecord,
} from "./auth-error-utils.js";
import { extractCodexCredentialIdentity } from "./openai-codex-identity.js";
import { determineTokenExpiration } from "./oauth-refresh-scheduler.js";
import { isRemovedLegacyGoogleProvider } from "./removed-google-providers.js";
import {
	OAuthRefreshFailureError,
	UNSUPPORTED_OAUTH_REFRESH_PROVIDER_ERROR_CODE,
} from "./types-oauth.js";

const OPENAI_CODEX_PROVIDER_ID = "openai-codex";
const OPENAI_CODEX_PROVIDER_LABEL = "OpenAI Codex";
const OPENAI_CODEX_TOKEN_URL = "https://auth.openai.com/oauth/token";
const OPENAI_CODEX_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const DEFAULT_OAUTH_REFRESH_TIMEOUT_MS = 15_000;
const OAUTH_REFRESH_TIMEOUT_ERROR_CODE = "request_timeout";

function asNonEmptyString(value: unknown): string | undefined {
	if (typeof value !== "string") {
		return undefined;
	}

	const normalized = value.trim();
	return normalized.length > 0 ? normalized : undefined;
}


function parseJsonRecord(value: string): Record<string, unknown> | null {
	if (!value.trim()) {
		return null;
	}

	try {
		const parsed = JSON.parse(value) as unknown;
		return isRecord(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

function extractCodexRefreshErrorDetails(
	parsedBody: Record<string, unknown> | null,
): { errorCode?: string; errorDescription?: string } {
	const nestedError = isRecord(parsedBody?.error) ? parsedBody.error : null;
	return {
		errorCode:
			asNonEmptyString(nestedError?.code) ??
			asNonEmptyString(parsedBody?.error) ??
			asNonEmptyString(nestedError?.type),
		errorDescription:
			asNonEmptyString(nestedError?.message) ??
			asNonEmptyString(parsedBody?.error_description) ??
			asNonEmptyString(parsedBody?.message),
	};
}

function isPermanentCodexRefreshFailure(
	status: number,
	errorCode: string | undefined,
	errorDescription: string | undefined,
	responseBody: string | undefined,
): boolean {
	const combined = [errorCode, errorDescription, responseBody]
		.filter((value): value is string => typeof value === "string" && value.length > 0)
		.join(" ");

	if (errorCode === "invalid_grant" || errorCode === "refresh_token_reused") {
		return true;
	}

	if (status !== 400 && status !== 401) {
		return false;
	}

	return (
		/invalid[_-]?grant/i.test(combined) ||
		(/refresh token/i.test(combined) &&
			/(expired|revoked|invalid|not found|already(?:\s+been)?\s+used|reused)/i.test(combined))
	);
}

async function fetchCodexRefreshResponse(
	refreshToken: string,
	timeoutMs: number,
): Promise<Response> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

	try {
		return await fetch(OPENAI_CODEX_TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				client_id: OPENAI_CODEX_CLIENT_ID,
			}),
			signal: controller.signal,
		});
	} catch (error) {
		if (error instanceof Error && error.name === "AbortError") {
			throw new OAuthRefreshFailureError(
				`OpenAI Codex token refresh request timed out after ${timeoutMs}ms.`,
				{
					providerId: OPENAI_CODEX_PROVIDER_ID,
					permanent: false,
					source: "extension",
					errorCode: OAUTH_REFRESH_TIMEOUT_ERROR_CODE,
				},
				{ cause: error },
			);
		}
		throw new OAuthRefreshFailureError(
			formatOAuthRefreshFailureSummary({
				providerLabel: OPENAI_CODEX_PROVIDER_LABEL,
				reason: "request_failed",
				permanent: false,
				source: "extension",
			}),
			{
				providerId: OPENAI_CODEX_PROVIDER_ID,
				reason: "request_failed",
				permanent: false,
				source: "extension",
			},
			{ cause: error },
		);
	} finally {
		clearTimeout(timeoutId);
	}
}

function createCodexRefreshFailureMessage(
	status: number,
	errorCode: string | undefined,
	permanent: boolean,
): string {
	return formatOAuthRefreshFailureSummary({
		providerLabel: OPENAI_CODEX_PROVIDER_LABEL,
		status,
		errorCode,
		reason: permanent ? "token_rejected" : "http_error",
		permanent,
		source: "extension",
	});
}

async function refreshOpenAICodexCredential(
	credentials: OAuthCredentials,
	requestTimeoutMs: number,
): Promise<OAuthCredentials> {
	const refreshToken = asNonEmptyString(credentials.refresh);
	if (!refreshToken) {
		throw new OAuthRefreshFailureError(
			formatOAuthRefreshFailureSummary({
				providerLabel: OPENAI_CODEX_PROVIDER_LABEL,
				reason: "missing_refresh_token",
				permanent: true,
				source: "extension",
			}),
			{
				providerId: OPENAI_CODEX_PROVIDER_ID,
				reason: "missing_refresh_token",
				permanent: true,
				source: "extension",
			},
		);
	}

	const response = await fetchCodexRefreshResponse(refreshToken, requestTimeoutMs);
	const responseText = await response.text().catch(() => "");
	const parsedBody = parseJsonRecord(responseText);
	const { errorCode, errorDescription } = extractCodexRefreshErrorDetails(parsedBody);

	if (!response.ok) {
		const permanent = isPermanentCodexRefreshFailure(
			response.status,
			errorCode,
			errorDescription,
			responseText,
		);
		throw new OAuthRefreshFailureError(
			createCodexRefreshFailureMessage(response.status, errorCode, permanent),
			{
				providerId: OPENAI_CODEX_PROVIDER_ID,
				status: response.status,
				errorCode,
				reason: permanent ? "token_rejected" : "http_error",
				permanent,
				source: "extension",
			},
		);
	}

	const accessToken = asNonEmptyString(parsedBody?.access_token);
	const nextRefreshToken = asNonEmptyString(parsedBody?.refresh_token);
	const expiresIn =
		typeof parsedBody?.expires_in === "number" && Number.isFinite(parsedBody.expires_in)
			? parsedBody.expires_in
			: undefined;

	if (!accessToken || !nextRefreshToken || expiresIn === undefined) {
		throw new OAuthRefreshFailureError(
			formatOAuthRefreshFailureSummary({
				providerLabel: OPENAI_CODEX_PROVIDER_LABEL,
				reason: "missing_required_fields",
				permanent: false,
				source: "extension",
			}),
			{
				providerId: OPENAI_CODEX_PROVIDER_ID,
				reason: "missing_required_fields",
				permanent: false,
				source: "extension",
			},
		);
	}

	const identity = extractCodexCredentialIdentity({
		access: accessToken,
		accountId: credentials.accountId,
		idToken: credentials.idToken,
	});
	if (!identity.accountId) {
		throw new OAuthRefreshFailureError(
			formatOAuthRefreshFailureSummary({
				providerLabel: OPENAI_CODEX_PROVIDER_LABEL,
				reason: "missing_account_identity",
				permanent: false,
				source: "extension",
			}),
			{
				providerId: OPENAI_CODEX_PROVIDER_ID,
				reason: "missing_account_identity",
				permanent: false,
				source: "extension",
			},
		);
	}

	const expiration = determineTokenExpiration(accessToken, undefined, expiresIn);
	return {
		...credentials,
		access: accessToken,
		refresh: nextRefreshToken,
		expires: expiration.expiresAt,
		accountId: identity.accountId,
	};
}

export type OAuthProviderId = string;

/**
 * Legacy OAuth provider surface used throughout this extension.
 *
 * pi-ai >= 0.80 removed the global OAuth provider registry; OAuth now lives
 * behind provider factories (`provider.auth.oauth`) with an AuthInteraction
 * login API. This module keeps the extension's legacy shape and bridges it
 * to the provider-factory world: built-in providers are adapted on demand,
 * while providers registered by this extension (kimi-coding, qwen, cline,
 * kilo, test doubles) live in a local registry that shadows the built-ins.
 */
export interface OAuthProviderInterface {
	readonly id: OAuthProviderId;
	readonly name: string;
	/** Run the login flow, return credentials to persist */
	login(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials>;
	/** Whether login uses a local callback server and supports manual code input. */
	usesCallbackServer?: boolean;
	/** Refresh expired credentials, return updated credentials to persist */
	refreshToken(credentials: OAuthCredentials): Promise<OAuthCredentials>;
	/** Convert credentials to API key string for the provider */
	getApiKey(credentials: OAuthCredentials): string;
	/** Optional: modify models for this provider (e.g., update baseUrl) */
	modifyModels?(models: Model<Api>[], credentials: OAuthCredentials): Model<Api>[];
}

const extensionOAuthProviders = new Map<OAuthProviderId, OAuthProviderInterface>();
const builtinOAuthAdapters = new Map<OAuthProviderId, OAuthProviderInterface>();
let builtinOAuthProvidersCache: ReadonlyMap<OAuthProviderId, Provider> | null = null;

function getBuiltinOAuthProviders(): ReadonlyMap<OAuthProviderId, Provider> {
	if (!builtinOAuthProvidersCache) {
		const providers = new Map<OAuthProviderId, Provider>();
		for (const provider of builtinProviders()) {
			if (provider.auth.oauth) {
				providers.set(provider.id, provider);
			}
		}
		builtinOAuthProvidersCache = providers;
	}
	return builtinOAuthProvidersCache;
}

function stripCredentialType(credential: OAuthCredential): OAuthCredentials {
	const { type: _type, ...credentials } = credential;
	return credentials;
}

const OAUTH_LOGIN_CANCELLED_MESSAGE = "OAuth login cancelled.";

/**
 * Translate legacy login callbacks into the provider-factory AuthInteraction
 * API. Built-in provider login flows call `prompt()`/`notify()`; this routes
 * those calls back to the extension's callback surface.
 */
function adaptLoginCallbacks(callbacks: OAuthLoginCallbacks): ProviderAuthInteraction {
	return {
		signal: callbacks.signal ?? new AbortController().signal,
		prompt: async (prompt: AuthPrompt): Promise<string> => {
			switch (prompt.type) {
				case "select": {
					const selected = await callbacks.onSelect({
						message: prompt.message,
						options: prompt.options.map((option) => ({
							id: option.id,
							label: option.label,
						})),
					});
					if (selected === undefined) {
						throw new Error(OAUTH_LOGIN_CANCELLED_MESSAGE);
					}
					return selected;
				}
				case "manual_code": {
					if (callbacks.onManualCodeInput) {
						return callbacks.onManualCodeInput();
					}
					return callbacks.onPrompt({
						message: prompt.message,
						placeholder: prompt.placeholder,
					});
				}
				default:
					return callbacks.onPrompt({
						message: prompt.message,
						placeholder: prompt.placeholder,
					});
			}
		},
		notify: (event: AuthEvent): void => {
			switch (event.type) {
				case "auth_url":
					callbacks.onAuth({ url: event.url, instructions: event.instructions });
					break;
				case "device_code":
					callbacks.onDeviceCode({
						userCode: event.userCode,
						verificationUri: event.verificationUri,
						intervalSeconds: event.intervalSeconds,
						expiresInSeconds: event.expiresInSeconds,
					});
					break;
				case "info":
				case "progress":
					callbacks.onProgress?.(event.message);
					break;
			}
		},
	};
}

function adaptBuiltinOAuthProvider(provider: Provider): OAuthProviderInterface {
	const oauth = provider.auth.oauth;
	if (!oauth) {
		throw new Error(`Provider has no OAuth auth: ${provider.id}`);
	}
	return {
		id: provider.id,
		name: oauth.name || provider.name,
		usesCallbackServer: false,
		login: async (callbacks) =>
			stripCredentialType(await oauth.login(adaptLoginCallbacks(callbacks))),
		refreshToken: async (credentials) =>
			stripCredentialType(
				await oauth.refresh(
					{ type: "oauth", ...credentials },
					new AbortController().signal,
				),
			),
		getApiKey: (credentials) => credentials.access,
	};
}

function getBuiltinOAuthAdapter(id: OAuthProviderId): OAuthProviderInterface | undefined {
	const cached = builtinOAuthAdapters.get(id);
	if (cached) {
		return cached;
	}
	const provider = getBuiltinOAuthProviders().get(id);
	if (!provider) {
		return undefined;
	}
	const adapter = adaptBuiltinOAuthProvider(provider);
	builtinOAuthAdapters.set(id, adapter);
	return adapter;
}

export function getOAuthProvider(
	id: OAuthProviderId,
): OAuthProviderInterface | undefined {
	if (isRemovedLegacyGoogleProvider(id)) {
		return undefined;
	}
	return extensionOAuthProviders.get(id) ?? getBuiltinOAuthAdapter(id);
}

export function getOAuthProviders(): OAuthProviderInterface[] {
	const providers = new Map<OAuthProviderId, OAuthProviderInterface>();
	for (const id of getBuiltinOAuthProviders().keys()) {
		if (isRemovedLegacyGoogleProvider(id)) {
			continue;
		}
		const adapter = getBuiltinOAuthAdapter(id);
		if (adapter) {
			providers.set(id, adapter);
		}
	}
	for (const [id, provider] of extensionOAuthProviders) {
		if (!isRemovedLegacyGoogleProvider(id)) {
			providers.set(id, provider);
		}
	}
	return [...providers.values()];
}

export function registerOAuthProvider(provider: OAuthProviderInterface): void {
	extensionOAuthProviders.set(provider.id, provider);
}

export function unregisterOAuthProvider(id: OAuthProviderId): void {
	extensionOAuthProviders.delete(id);
}

export function resetOAuthProviders(): void {
	extensionOAuthProviders.clear();
}

export interface OAuthRefreshExecutionOptions {
	requestTimeoutMs?: number;
}

export async function refreshOAuthCredential(
	providerId: OAuthProviderId,
	credentials: OAuthCredentials,
	options: OAuthRefreshExecutionOptions = {},
): Promise<OAuthCredentials> {
	if (isRemovedLegacyGoogleProvider(providerId)) {
		throw new OAuthRefreshFailureError(
			"Legacy Google OAuth providers are no longer supported for token refresh.",
			{
				providerId,
				permanent: true,
				source: "extension",
				errorCode: UNSUPPORTED_OAUTH_REFRESH_PROVIDER_ERROR_CODE,
			},
		);
	}

	if (providerId === OPENAI_CODEX_PROVIDER_ID) {
		const requestTimeoutMs =
			typeof options.requestTimeoutMs === "number" &&
			Number.isFinite(options.requestTimeoutMs) &&
			options.requestTimeoutMs > 0
				? Math.floor(options.requestTimeoutMs)
				: DEFAULT_OAUTH_REFRESH_TIMEOUT_MS;
		return refreshOpenAICodexCredential(credentials, requestTimeoutMs);
	}

	const provider = getOAuthProvider(providerId);
	if (!provider) {
		throw new OAuthRefreshFailureError(
			`OAuth provider is not available for token refresh: ${providerId}`,
			{
				providerId,
				permanent: true,
				source: "extension",
				errorCode: UNSUPPORTED_OAUTH_REFRESH_PROVIDER_ERROR_CODE,
			},
		);
	}

	return provider.refreshToken(credentials);
}

export type {
	OAuthCredentials,
	OAuthDeviceCodeInfo,
	OAuthLoginCallbacks,
};
