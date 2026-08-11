import {
	type Api,
	type AssistantMessage,
	type AssistantMessageEvent,
	type AssistantMessageEventStream,
	type Context,
	createAssistantMessageEventStream,
	type Model,
	type SimpleStreamOptions,
} from "@earendil-works/pi-ai";
import {
	getApiProvider,
	registerApiProvider,
} from "@earendil-works/pi-ai/compat";
import type {
	ExtensionAPI,
	ProviderModelConfig,
} from "@earendil-works/pi-coding-agent";
import {
	AccountManager,
	createCredentialSelectionCache,
} from "./account-manager.js";
import { getErrorMessage, isAbortError } from "./auth-error-utils.js";
import {
	classifyCredentialError,
	isCredentialModelIncompatibilityError,
	isRetryableModelAvailabilityError,
	type CredentialErrorKind,
} from "./error-classifier.js";
import { buildClineClientHeaders } from "./cline-compat.js";
import { isCloudflareCredentialManagedAuthProvider } from "./cloudflare-provider.js";
import { buildKiloRequestHeaders } from "./kilo-compat.js";
import { describeCredentialErrorAction } from "./credential-error-formatting.js";
import { applyCredentialRequestOverrides } from "./credential-request-overrides.js";
import { getCredentialRequestSecret } from "./credential-display.js";
import { abortableSleep } from "./async-utils.js";
import { multiAuthDebugLogger } from "./debug-logger.js";
import { modelRequiresEntitlement } from "./model-entitlements.js";
import {
	enrichProviderStatusOnlyErrorMessage,
	formatEnrichedProviderResponseBrief,
	parseEnrichedProviderResponse,
} from "./provider-error-details.js";
import { ProviderRegistry } from "./provider-registry.js";
import { resolveDelegatedCredentialOverride } from "./runtime-context.js";
import { computeExponentialBackoffMs } from "./balancer/credential-backoff.js";
import { RetryBudget } from "./balancer/retry-budget.js";
import type {
	ProviderRegistrationMetadata,
	SelectedCredential,
	SupportedProviderId,
} from "./types.js";

const MIN_ROTATION_ATTEMPT_LIMIT = 11;
const MAX_TRANSIENT_RETRIES_PER_CREDENTIAL = 2;
const PROVIDER_REGISTRATION_CHURN_WINDOW_MS = 100;
// Cap how long we wait between transient retries when no alternate credential
// is available to rotate to. The cooldown returned by the account manager can
// grow up to TRANSIENT_COOLDOWN_MAX_MS (~15 minutes); for sole-credential
// providers we keep the wait short so auto-retry stays responsive.
const SOLE_CREDENTIAL_TRANSIENT_RETRY_WAIT_MS = 30_000;
const MIN_SOLE_CREDENTIAL_TRANSIENT_RETRY_WAIT_MS = 25;
const BLAZEAPI_PROVIDER_ID = "blazeapi";
const BLAZEAPI_REQUEST_LIMIT_MESSAGE_PATTERN = /request limit reached for your current plan/i;
const PROVIDER_RETRY_BUDGET_WINDOW_MS = 60_000;
const PROVIDER_RETRY_BUDGET_MAX_RETRIES = 100;
const providerRetryBudget = new RetryBudget({
	maxRetriesPerWindow: PROVIDER_RETRY_BUDGET_MAX_RETRIES,
	windowMs: PROVIDER_RETRY_BUDGET_WINDOW_MS,
});

type ApiProviderRef = NonNullable<ReturnType<typeof getApiProvider>>;

type ProviderRegistrationMetricState = {
	discoveryCount: number;
	registrationCount: number;
	duplicateRegistrationCount: number;
	lastDiscoveredAt?: number;
	lastRegisteredAt?: number;
	lastRegistrationDeltaMs?: number;
};

export interface ProviderRegistrationMetricsSnapshot {
	discoveryCount: number;
	registrationCount: number;
	duplicateRegistrationCount: number;
	providers: Record<string, ProviderRegistrationMetricState>;
}

const providerRegistrationMetrics = {
	discoveryCount: 0,
	registrationCount: 0,
	duplicateRegistrationCount: 0,
	providers: new Map<string, ProviderRegistrationMetricState>(),
};

const STRUCTURED_ERROR_MESSAGE_OPTIONS = {
	preserveStructuredData: true,
} as const;

interface RuntimeAuthFailureMetadata {
	status?: number;
	code?: string;
	message?: string;
	refreshable?: boolean;
	authExpired?: boolean;
	permanent?: boolean;
}

const STRUCTURED_AUTH_STATUS_KEYS = [
	"status",
	"statusCode",
	"httpStatus",
	"http_status",
] as const;
const STRUCTURED_AUTH_CODE_KEYS = [
	"code",
	"errorCode",
	"error_code",
	"reason",
	"type",
] as const;
const STRUCTURED_AUTH_MESSAGE_KEYS = [
	"message",
	"detail",
	"description",
	"error_description",
] as const;
const STRUCTURED_AUTH_REFRESHABLE_KEYS = [
	"refreshable",
	"authRefreshable",
	"auth_refreshable",
	"shouldRefreshAuth",
	"should_refresh_auth",
] as const;
const STRUCTURED_AUTH_EXPIRED_KEYS = [
	"authExpired",
	"auth_expired",
	"tokenExpired",
	"token_expired",
	"accessTokenExpired",
	"access_token_expired",
] as const;
const STRUCTURED_AUTH_PERMANENT_KEYS = [
	"permanent",
	"fatal",
	"requiresRelogin",
	"requires_relogin",
	"reloginRequired",
	"relogin_required",
] as const;

function getAssistantErrorMessage(error: AssistantMessage): string {
	if (typeof error.errorMessage === "string" && error.errorMessage.trim().length > 0) {
		return error.errorMessage;
	}
	return getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS);
}

function isCallerAbort(parentSignal: AbortSignal | undefined, error?: unknown): boolean {
	if (!parentSignal?.aborted) {
		return false;
	}
	if (error === undefined) {
		return true;
	}
	return isAbortError(error);
}

function isCallerAbortMessage(parentSignal: AbortSignal | undefined, message: string): boolean {
	return Boolean(parentSignal?.aborted) && isAbortError(message);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeMetadataString(value: unknown): string | undefined {
	if (typeof value === "string") {
		const normalized = value.trim();
		return normalized.length > 0 ? normalized : undefined;
	}
	if (typeof value === "number" || typeof value === "boolean") {
		return String(value);
	}
	return undefined;
}

function normalizeMetadataBoolean(value: unknown): boolean | undefined {
	if (typeof value === "boolean") {
		return value;
	}
	if (typeof value !== "string") {
		return undefined;
	}
	const normalized = value.trim().toLowerCase();
	if (["true", "1", "yes"].includes(normalized)) {
		return true;
	}
	if (["false", "0", "no"].includes(normalized)) {
		return false;
	}
	return undefined;
}

function normalizeMetadataStatus(value: unknown): number | undefined {
	if (typeof value === "number" && Number.isFinite(value)) {
		return Math.trunc(value);
	}
	if (typeof value === "string") {
		const parsed = Number.parseInt(value.trim(), 10);
		return Number.isInteger(parsed) ? parsed : undefined;
	}
	return undefined;
}

function firstMetadataValue(
	record: Record<string, unknown>,
	keys: readonly string[],
): unknown {
	for (const key of keys) {
		if (record[key] !== undefined) {
			return record[key];
		}
	}
	return undefined;
}

function mergeRuntimeAuthMetadata(
	left: RuntimeAuthFailureMetadata,
	right: RuntimeAuthFailureMetadata,
): RuntimeAuthFailureMetadata {
	return {
		status: left.status ?? right.status,
		code: left.code ?? right.code,
		message: left.message ?? right.message,
		refreshable: left.refreshable ?? right.refreshable,
		authExpired: left.authExpired ?? right.authExpired,
		permanent: left.permanent ?? right.permanent,
	};
}

function extractStructuredRuntimeAuthMetadata(
	value: unknown,
	depth: number = 0,
): RuntimeAuthFailureMetadata {
	if (depth > 3) {
		return {};
	}

	if (typeof value === "string") {
		const trimmed = value.trim();
		if (!trimmed || (!trimmed.startsWith("{") && !trimmed.startsWith("["))) {
			return {};
		}
		try {
			return extractStructuredRuntimeAuthMetadata(JSON.parse(trimmed) as unknown, depth + 1);
		} catch {
			return {};
		}
	}

	if (Array.isArray(value)) {
		return value.reduce<RuntimeAuthFailureMetadata>(
			(metadata, entry) => mergeRuntimeAuthMetadata(metadata, extractStructuredRuntimeAuthMetadata(entry, depth + 1)),
			{},
		);
	}

	if (!isPlainRecord(value)) {
		return {};
	}

	let metadata: RuntimeAuthFailureMetadata = {
		status: normalizeMetadataStatus(firstMetadataValue(value, STRUCTURED_AUTH_STATUS_KEYS)),
		code: normalizeMetadataString(firstMetadataValue(value, STRUCTURED_AUTH_CODE_KEYS)),
		message: normalizeMetadataString(firstMetadataValue(value, STRUCTURED_AUTH_MESSAGE_KEYS)),
		refreshable: normalizeMetadataBoolean(firstMetadataValue(value, STRUCTURED_AUTH_REFRESHABLE_KEYS)),
		authExpired: normalizeMetadataBoolean(firstMetadataValue(value, STRUCTURED_AUTH_EXPIRED_KEYS)),
		permanent: normalizeMetadataBoolean(firstMetadataValue(value, STRUCTURED_AUTH_PERMANENT_KEYS)),
	};

	const nestedError = value.error;
	if (nestedError !== undefined) {
		if (typeof nestedError === "string") {
			metadata.message ??= normalizeMetadataString(nestedError);
		} else {
			metadata = mergeRuntimeAuthMetadata(
				metadata,
				extractStructuredRuntimeAuthMetadata(nestedError, depth + 1),
			);
		}
	}

	return metadata;
}

function extractHttpStatusFromMessage(message: string): number | undefined {
	const httpMatch = /\bHTTP\s+([1-5]\d{2})\b/i.exec(message);
	if (httpMatch?.[1]) {
		return Number.parseInt(httpMatch[1], 10);
	}
	const statusCodeMatch = /\b([1-5]\d{2})\s+status code\b/i.exec(message);
	if (statusCodeMatch?.[1]) {
		return Number.parseInt(statusCodeMatch[1], 10);
	}
	return undefined;
}

function hasRefreshableAuthExpiredSignal(text: string): boolean {
	return /\b(?:access[_\s-]?token|auth(?:entication)?|oauth|session|credential)s?[_\s-]*(?:expired|expir(?:e|ation)|invalid_token|unauthorized)\b/i.test(text) ||
		/\b(?:token|session|credential)[_\s-]*(?:expired|invalid_token)\b/i.test(text) ||
		/\b(?:auth|token|session)[_\s-]?expired\b/i.test(text);
}

function hasPermanentAuthFailureSignal(text: string): boolean {
	return /\b(?:invalid[_\s-]?grant|refresh[_\s-]?token[_\s-]?(?:reused|revoked|expired|invalid)|token[_\s-]?revoked|invalid[_\s-]?api[_\s-]?key|permission[_\s-]?denied|model[_\s-]?access[_\s-]?denied|insufficient[_\s-]?scope|requires[_\s-]?relogin|relogin[_\s-]?required)\b/i.test(text);
}

function isRefreshableRuntimeAuthFailure(message: string): boolean {
	const providerResponse = parseEnrichedProviderResponse(message);
	const structuredMetadata = extractStructuredRuntimeAuthMetadata(message);
	const status = structuredMetadata.status ?? providerResponse.status ?? extractHttpStatusFromMessage(message);
	if (status !== 401 && status !== 403) {
		return false;
	}

	const combinedMetadataText = [
		structuredMetadata.code,
		structuredMetadata.message,
		providerResponse.code,
		providerResponse.message,
		message,
	]
		.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
		.join(" ");

	if (structuredMetadata.permanent === true || hasPermanentAuthFailureSignal(combinedMetadataText)) {
		return false;
	}
	if (structuredMetadata.refreshable === true || structuredMetadata.authExpired === true) {
		return true;
	}
	if (status === 403) {
		return hasRefreshableAuthExpiredSignal(combinedMetadataText);
	}
	return structuredMetadata.refreshable !== false &&
		(/\bunauthorized\b/i.test(combinedMetadataText) || hasRefreshableAuthExpiredSignal(combinedMetadataText));
}

function getOrCreateProviderRegistrationMetricState(
	provider: SupportedProviderId,
): ProviderRegistrationMetricState {
	const existing = providerRegistrationMetrics.providers.get(provider);
	if (existing) {
		return existing;
	}

	const created: ProviderRegistrationMetricState = {
		discoveryCount: 0,
		registrationCount: 0,
		duplicateRegistrationCount: 0,
	};
	providerRegistrationMetrics.providers.set(provider, created);
	return created;
}

function recordProviderDiscovery(provider: SupportedProviderId): void {
	const metrics = getOrCreateProviderRegistrationMetricState(provider);
	metrics.discoveryCount += 1;
	metrics.lastDiscoveredAt = Date.now();
	providerRegistrationMetrics.discoveryCount += 1;
}

function recordProviderRegistration(provider: SupportedProviderId): ProviderRegistrationMetricState {
	const metrics = getOrCreateProviderRegistrationMetricState(provider);
	const now = Date.now();
	const lastRegisteredAt = metrics.lastRegisteredAt;
	const deltaMs = typeof lastRegisteredAt === "number" ? now - lastRegisteredAt : undefined;
	metrics.registrationCount += 1;
	metrics.lastRegisteredAt = now;
	metrics.lastRegistrationDeltaMs = deltaMs;
	providerRegistrationMetrics.registrationCount += 1;
	if (
		typeof deltaMs === "number" &&
		deltaMs >= 0 &&
		deltaMs <= PROVIDER_REGISTRATION_CHURN_WINDOW_MS
	) {
		metrics.duplicateRegistrationCount += 1;
		providerRegistrationMetrics.duplicateRegistrationCount += 1;
	}
	return metrics;
}

export function getProviderRegistrationMetrics(): ProviderRegistrationMetricsSnapshot {
	return {
		discoveryCount: providerRegistrationMetrics.discoveryCount,
		registrationCount: providerRegistrationMetrics.registrationCount,
		duplicateRegistrationCount: providerRegistrationMetrics.duplicateRegistrationCount,
		providers: Object.fromEntries(
			[...providerRegistrationMetrics.providers.entries()].map(([provider, metrics]) => [
				provider,
				{ ...metrics },
			]),
		),
	};
}

function isSubstantiveEvent(event: AssistantMessageEvent): boolean {
	switch (event.type) {
		case "text_delta":
		case "text_end":
		case "thinking_delta":
		case "thinking_end":
		case "toolcall_delta":
		case "toolcall_end":
		case "done":
			return true;
		default:
			return false;
	}
}

const ANSI_PATTERN = /\x1b\[[0-9;]*m/g;
const LETTER_OR_NUMBER_PATTERN = /[\p{L}\p{N}]/u;
const WHITESPACE_PATTERN = /\s/u;
const STRUCTURAL_SYMBOL_PATTERN = /[\[\]{}<>|^_=+*\\/~】》■•]/u;
const LONG_STRUCTURAL_RUN_PATTERN = /(?:[\[\]{}<>|^_=+*\\/~-]{12,}|[】》■•]{4,})/u;
const MALFORMED_THINKING_DECISION_MIN_CHARS = 96;
const MALFORMED_THINKING_MIN_CHARS = 128;
const MALFORMED_THINKING_MAX_LETTER_RATIO = 0.25;
const MALFORMED_THINKING_MIN_PUNCTUATION_RATIO = 0.45;
const MALFORMED_THINKING_MIN_STRUCTURAL_RATIO = 0.2;

type BufferedThinkingStartEvent = Extract<AssistantMessageEvent, { type: "thinking_start" }>;
type BufferedThinkingDeltaEvent = Extract<AssistantMessageEvent, { type: "thinking_delta" }>;
type BufferedThinkingGuardState = {
	pendingStartEvent: BufferedThinkingStartEvent | null;
	pendingDeltaEvents: BufferedThinkingDeltaEvent[];
	pendingText: string;
	forwardedCurrentThinking: boolean;
	isDroppingCurrentThinking: boolean;
};

function stripAnsi(text: string): string {
	return text.replace(ANSI_PATTERN, "");
}

function isOllamaProvider(provider: SupportedProviderId): boolean {
	return provider.trim().toLowerCase() === "ollama";
}

const CREDENTIAL_MANAGED_AUTH_HEADER_NAMES = new Set([
	"authorization",
	"x-api-key",
	"api-key",
]);

function shouldStripCallerAuthHeaders(provider: SupportedProviderId): boolean {
	return isCloudflareCredentialManagedAuthProvider(provider);
}

function stripCallerAuthHeaders(
	provider: SupportedProviderId,
	headers: SimpleStreamOptions["headers"],
): SimpleStreamOptions["headers"] {
	if (!headers || !shouldStripCallerAuthHeaders(provider)) {
		return headers;
	}

	const sanitizedHeaders: Record<string, string | null> = {};
	const strippedHeaderNames: string[] = [];
	for (const [headerName, headerValue] of Object.entries(headers)) {
		const normalizedHeaderName = headerName.trim().toLowerCase();
		if (
			typeof headerValue === "string" &&
			CREDENTIAL_MANAGED_AUTH_HEADER_NAMES.has(normalizedHeaderName)
		) {
			strippedHeaderNames.push(headerName);
			continue;
		}
		sanitizedHeaders[headerName] = headerValue;
	}

	if (strippedHeaderNames.length === 0) {
		return headers;
	}

	multiAuthDebugLogger.log("caller_auth_headers_stripped", {
		provider,
		headers: strippedHeaderNames,
	});
	return sanitizedHeaders;
}

function resolveProviderRequestHeaders(
	provider: SupportedProviderId,
	headers: SimpleStreamOptions["headers"],
): SimpleStreamOptions["headers"] {
	const credentialSafeHeaders = stripCallerAuthHeaders(provider, headers);
	if (provider === "cline") {
		return {
			...credentialSafeHeaders,
			...buildClineClientHeaders({ includeRequestTracking: true }),
		};
	}
	if (provider === "kilo") {
		return {
			...credentialSafeHeaders,
			...buildKiloRequestHeaders(),
		};
	}
	return credentialSafeHeaders;
}

function isMalformedThinkingText(text: string): boolean {
	const normalized = stripAnsi(text).trim();
	if (normalized.length < MALFORMED_THINKING_MIN_CHARS) {
		return false;
	}

	let letterOrNumberCount = 0;
	let punctuationCount = 0;
	let structuralSymbolCount = 0;

	for (const char of normalized) {
		if (LETTER_OR_NUMBER_PATTERN.test(char)) {
			letterOrNumberCount += 1;
			continue;
		}
		if (WHITESPACE_PATTERN.test(char)) {
			continue;
		}

		punctuationCount += 1;
		if (STRUCTURAL_SYMBOL_PATTERN.test(char)) {
			structuralSymbolCount += 1;
		}
	}

	if (letterOrNumberCount === 0) {
		return true;
	}

	const totalLength = normalized.length;
	const letterRatio = letterOrNumberCount / totalLength;
	const punctuationRatio = punctuationCount / totalLength;
	const structuralRatio = structuralSymbolCount / totalLength;

	return (
		LONG_STRUCTURAL_RUN_PATTERN.test(normalized) ||
		(letterRatio < MALFORMED_THINKING_MAX_LETTER_RATIO &&
			punctuationRatio > MALFORMED_THINKING_MIN_PUNCTUATION_RATIO &&
			structuralRatio > MALFORMED_THINKING_MIN_STRUCTURAL_RATIO)
	);
}

function sanitizeAssistantThinkingBlocks(
	message: AssistantMessage,
	provider: SupportedProviderId,
): AssistantMessage {
	if (!isOllamaProvider(provider) || !Array.isArray(message.content)) {
		return message;
	}

	let changed = false;
	const nextContent = message.content.filter((block) => {
		if (block.type !== "thinking") {
			return true;
		}
		if (!isMalformedThinkingText(block.thinking)) {
			return true;
		}

		changed = true;
		return false;
	});

	return changed ? { ...message, content: nextContent } : message;
}

function sanitizeAssistantPayloadsInEvent(
	event: AssistantMessageEvent,
	provider: SupportedProviderId,
): AssistantMessageEvent {
	switch (event.type) {
		case "start":
		case "text_start":
		case "text_delta":
		case "text_end":
		case "thinking_start":
		case "thinking_delta":
		case "thinking_end":
		case "toolcall_start":
		case "toolcall_delta":
		case "toolcall_end":
			return {
				...event,
				partial: sanitizeAssistantThinkingBlocks(event.partial, provider),
			};
		case "done":
			return {
				...event,
				message: sanitizeAssistantThinkingBlocks(event.message, provider),
			};
		case "error":
			return {
				...event,
				error: sanitizeAssistantThinkingBlocks(event.error, provider),
			};
		default:
			return event;
	}
}

function resetBufferedThinkingState(state: BufferedThinkingGuardState): void {
	state.pendingStartEvent = null;
	state.pendingDeltaEvents = [];
	state.pendingText = "";
	state.forwardedCurrentThinking = false;
	state.isDroppingCurrentThinking = false;
}

function createBufferedThinkingState(): BufferedThinkingGuardState {
	return {
		pendingStartEvent: null,
		pendingDeltaEvents: [],
		pendingText: "",
		forwardedCurrentThinking: false,
		isDroppingCurrentThinking: false,
	};
}

function hasMeaningfulAssistantContent(message: AssistantMessage): boolean {
	return message.content.some((block) => {
		switch (block.type) {
			case "text":
				return block.text.trim().length > 0;
			case "thinking":
				return block.thinking.trim().length > 0;
			case "toolCall":
				return true;
			default:
				return true;
		}
	});
}

function getAssistantOutputTokens(message: AssistantMessage): number | null {
	return typeof message.usage.output === "number" && Number.isFinite(message.usage.output)
		? message.usage.output
		: null;
}

function getAssistantTokenEstimate(message: AssistantMessage): number | undefined {
	const totalTokens = message.usage.totalTokens;
	if (typeof totalTokens === "number" && Number.isFinite(totalTokens) && totalTokens > 0) {
		return totalTokens;
	}

	const components = [
		message.usage.input,
		message.usage.output,
		message.usage.cacheRead,
		message.usage.cacheWrite,
	].filter((value): value is number => typeof value === "number" && Number.isFinite(value) && value > 0);
	const sum = components.reduce((total, value) => total + value, 0);
	return sum > 0 ? sum : undefined;
}

function isRetryableEmptyCompletion(
	event: Extract<AssistantMessageEvent, { type: "done" }>,
	hasForwardedSubstantiveEvent: boolean,
): boolean {
	return (
		!hasForwardedSubstantiveEvent &&
		event.reason === "stop" &&
		event.message.stopReason === "stop" &&
		!hasMeaningfulAssistantContent(event.message)
	);
}

function createEmptyCompletionErrorMessage(
	provider: SupportedProviderId,
	credentialId: string,
	message: AssistantMessage,
): string {
	const metadata: string[] = [];
	if (typeof message.responseId === "string" && message.responseId.trim().length > 0) {
		metadata.push(`responseId=${message.responseId.trim()}`);
	}
	const outputTokens = getAssistantOutputTokens(message);
	if (outputTokens !== null) {
		metadata.push(`outputTokens=${outputTokens}`);
	}

	return `Provider stream ended unexpectedly with empty completion for ${provider} (credential ${credentialId}, model ${message.model})${metadata.length > 0 ? ` [${metadata.join(", ")}]` : ""}.`;
}

function flushBufferedThinkingEvents(
	state: BufferedThinkingGuardState,
	provider: SupportedProviderId,
): AssistantMessageEvent[] {
	if (!state.pendingStartEvent) {
		return [];
	}

	state.forwardedCurrentThinking = true;
	return [state.pendingStartEvent, ...state.pendingDeltaEvents].map((event) =>
		sanitizeAssistantPayloadsInEvent(event, provider),
	);
}

function sanitizeOllamaThinkingEvent(
	event: AssistantMessageEvent,
	provider: SupportedProviderId,
	state: BufferedThinkingGuardState,
): AssistantMessageEvent[] {
	if (!isOllamaProvider(provider)) {
		return [sanitizeAssistantPayloadsInEvent(event, provider)];
	}

	switch (event.type) {
		case "thinking_start": {
			resetBufferedThinkingState(state);
			state.pendingStartEvent = event;
			return [];
		}
		case "thinking_delta": {
			if (!state.pendingStartEvent) {
				return [sanitizeAssistantPayloadsInEvent(event, provider)];
			}
			if (state.isDroppingCurrentThinking) {
				return [];
			}
			if (state.forwardedCurrentThinking) {
				return [sanitizeAssistantPayloadsInEvent(event, provider)];
			}

			state.pendingDeltaEvents.push(event);
			state.pendingText += event.delta;
			if (state.pendingText.trim().length < MALFORMED_THINKING_DECISION_MIN_CHARS) {
				return [];
			}
			if (isMalformedThinkingText(state.pendingText)) {
				state.isDroppingCurrentThinking = true;
				return [];
			}

			return flushBufferedThinkingEvents(state, provider);
		}
		case "thinking_end": {
			if (!state.pendingStartEvent) {
				return [sanitizeAssistantPayloadsInEvent(event, provider)];
			}
			if (state.isDroppingCurrentThinking) {
				resetBufferedThinkingState(state);
				return [];
			}
			if (state.forwardedCurrentThinking) {
				resetBufferedThinkingState(state);
				return [sanitizeAssistantPayloadsInEvent(event, provider)];
			}

			const completeThinking = state.pendingText || event.content;
			if (isMalformedThinkingText(completeThinking)) {
				resetBufferedThinkingState(state);
				return [];
			}

			const forwardedEvents = [
				...flushBufferedThinkingEvents(state, provider),
				sanitizeAssistantPayloadsInEvent(event, provider),
			];
			resetBufferedThinkingState(state);
			return forwardedEvents;
		}
		case "done":
		case "error":
			resetBufferedThinkingState(state);
			return [sanitizeAssistantPayloadsInEvent(event, provider)];
		default:
			return [sanitizeAssistantPayloadsInEvent(event, provider)];
	}
}

function createErrorAssistantMessage(model: Model<Api>, message: string): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: model.api,
		provider: model.provider,
		model: model.id,
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: {
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				total: 0,
			},
		},
		stopReason: "error",
		errorMessage: message,
		timestamp: Date.now(),
	};
}

function createAbortedAssistantMessage(model: Model<Api>, message: string): AssistantMessage {
	return {
		...createErrorAssistantMessage(model, message),
		stopReason: "aborted",
	};
}

interface RotationFailureDetails {
	credentialCount?: number;
	lastCredentialError?: string;
	providerStatus?: number;
	providerCode?: string;
	providerMessage?: string;
}

function parseRotationFailureDetails(errorMessage: string): RotationFailureDetails {
	const details: RotationFailureDetails = {};
	const credentialCountMatch = /All\s+(\d+)\s+rotated credential\(s\)/i.exec(errorMessage);
	if (credentialCountMatch?.[1]) {
		details.credentialCount = Number.parseInt(credentialCountMatch[1], 10);
	}

	const lastCredentialErrorMatch = /Last (?:credential )?error:\s*([^]*?)(?:;\s*provider response:|$)/i.exec(errorMessage);
	if (lastCredentialErrorMatch?.[1]?.trim()) {
		details.lastCredentialError = lastCredentialErrorMatch[1].trim();
	}

	const providerResponse = parseEnrichedProviderResponse(errorMessage);
	details.providerStatus = providerResponse.status;
	details.providerCode = providerResponse.code;
	details.providerMessage = providerResponse.message;

	return details;
}

function formatMultiAuthRotationFailureMessage(
	providerId: SupportedProviderId,
	model: Model<Api>,
	errorMessage: string,
): string {
	if (/^(?:All credentials are unavailable|Delegated credential)\b/i.test(errorMessage.trim())) {
		return errorMessage;
	}

	const details = parseRotationFailureDetails(errorMessage);
	const classifiedMessage = details.providerMessage ?? details.lastCredentialError ?? errorMessage;
	const classification = classifyCredentialError(classifiedMessage, {
		providerId,
		modelId: model.id,
	});
	const reason =
		formatEnrichedProviderResponseBrief({
			status: details.providerStatus,
			code: details.providerCode,
			message: details.providerMessage,
		}) ??
		details.lastCredentialError ??
		"Provider request failed after credential rotation was exhausted.";
	const lines = [
		"Multi-auth rotation failed",
		`Provider: ${providerId}`,
		`Model: ${model.id}`,
	];
	if (typeof details.credentialCount === "number" && Number.isFinite(details.credentialCount)) {
		lines.push(`Credentials tried: ${details.credentialCount}`);
	}
	lines.push(
		`Reason: ${reason}`,
		`Action: ${describeCredentialErrorAction(classification.kind)}`,
	);
	return lines.join("\n");
}

function resolveCredentialProviderId(
	model: Model<Api>,
	fallbackProvider: SupportedProviderId,
): SupportedProviderId {
	const providerFromModel =
		typeof model.provider === "string" ? model.provider.trim() : "";
	return providerFromModel.length > 0 ? providerFromModel : fallbackProvider;
}

function getJitteredBackoffMs(baseMs: number): number {
	if (baseMs <= 0) {
		return 0;
	}
	return Math.max(1, Math.round(baseMs * (0.5 + Math.random() * 0.5)));
}

function usageWindowHasRemainingCapacity(
	window: { usedPercent: number } | null | undefined,
): boolean | null {
	if (!window || typeof window.usedPercent !== "number" || !Number.isFinite(window.usedPercent)) {
		return null;
	}
	return window.usedPercent < 100;
}

async function shouldRetryBlazeApiRequestLimitWithLiveCapacity(
	accountManager: AccountManager,
	providerId: SupportedProviderId,
	credentialId: string,
	modelId: string,
	message: string,
): Promise<boolean> {
	if (providerId !== BLAZEAPI_PROVIDER_ID || !BLAZEAPI_REQUEST_LIMIT_MESSAGE_PATTERN.test(message)) {
		return false;
	}

	try {
		const usage = await accountManager.getCredentialUsageSnapshot(providerId, credentialId, {
			forceRefresh: true,
			coordinationOperation: "selection",
		});
		const snapshot = usage.snapshot;
		if (!snapshot) {
			return false;
		}

		const requiresPremiumCredits = modelRequiresEntitlement(providerId, modelId);
		const windowCapacities = [
			usageWindowHasRemainingCapacity(snapshot.primary),
			...(requiresPremiumCredits ? [usageWindowHasRemainingCapacity(snapshot.secondary)] : []),
		].filter((value): value is boolean => value !== null);
		if (windowCapacities.length > 0) {
			return windowCapacities.every(Boolean);
		}

		const remaining = snapshot.rateLimitHeaders?.remaining;
		return typeof remaining === "number" && Number.isFinite(remaining) && remaining > 0;
	} catch (error: unknown) {
		multiAuthDebugLogger.log("blazeapi_request_limit_usage_probe_failed", {
			provider: providerId,
			credentialId,
			error: getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS),
		});
		return false;
	}
}

async function resolveRotationAttemptLimit(
	accountManager: AccountManager,
	providerId: SupportedProviderId,
): Promise<number> {
	try {
		const credentialIds = await accountManager.listProviderCredentialIds(providerId);
		return Math.max(MIN_ROTATION_ATTEMPT_LIMIT, credentialIds.length);
	} catch (error: unknown) {
		multiAuthDebugLogger.log("rotation_attempt_limit_fallback", {
			provider: providerId,
			minimumAttemptLimit: MIN_ROTATION_ATTEMPT_LIMIT,
			error: getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS),
		});
		return MIN_ROTATION_ATTEMPT_LIMIT;
	}
}

/**
 * Builds an API wrapper that injects rotated credentials and retries on quota/rate-limit errors.
 * Credential namespace is resolved from model.provider at request time.
 */
export function createRotatingStreamWrapper(
	fallbackProvider: SupportedProviderId,
	accountManager: AccountManager,
	baseProvider: ApiProviderRef,
	baseProvidersByApi: ReadonlyMap<Api, ApiProviderRef> = new Map(),
	excludedProviders?: ReadonlySet<string>,
): (
	model: Model<Api>,
	context: Context,
	options?: SimpleStreamOptions,
) => AssistantMessageEventStream {
	return (
		model: Model<Api>,
		context: Context,
		options?: SimpleStreamOptions,
	): AssistantMessageEventStream => {
		const stream = createAssistantMessageEventStream();
		let activeProviderId = resolveCredentialProviderId(model, fallbackProvider);
		let activeModel = model;
		let activeBaseProvider = baseProvider;

		multiAuthDebugLogger.log("stream_invoked", {
			provider: model.provider,
			credentialProvider: activeProviderId,
			model: model.id,
		});

		(async () => {
			let excludedCredentialIds = new Set<string>();
			let lastCredentialErrorMessage: string | null = null;
			let lastFailoverTrigger: CredentialErrorKind | null = null;
			const selectionCache = createCredentialSelectionCache();
			const bufferedThinkingState = createBufferedThinkingState();
			const emitAbortedTermination = (reason?: unknown): void => {
				const fallbackMessage = `multi-auth request aborted for ${activeProviderId}.`;
				const message = reason === undefined
					? fallbackMessage
					: getErrorMessage(reason, STRUCTURED_ERROR_MESSAGE_OPTIONS) || fallbackMessage;
				const assistantAbort: AssistantMessageEvent = {
					type: "error",
					reason: "aborted",
					error: createAbortedAssistantMessage(activeModel, message),
				};
				stream.push(assistantAbort);
				stream.end(assistantAbort.error);
			};

			// Providers explicitly excluded from multi-auth rotation should pass
			// through to the base API provider without credential management.
			if (excludedProviders?.has(activeProviderId)) {
				multiAuthDebugLogger.log("provider_excluded_passthrough", {
					provider: activeProviderId,
					model: activeModel.id,
					api: activeModel.api,
				});
				try {
					const innerStream = activeBaseProvider.streamSimple(activeModel, context, {
						...options,
						signal: options?.signal,
					});
					for await (const rawEvent of innerStream) {
						stream.push(rawEvent);
					}
					stream.end();
				} catch (error: unknown) {
					if (isCallerAbort(options?.signal, error)) {
						emitAbortedTermination(options?.signal?.reason ?? error);
						return;
					}
					const message = getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS);
					const assistantError: AssistantMessageEvent = {
						type: "error",
						reason: "error",
						error: createErrorAssistantMessage(activeModel, message),
					};
					stream.push(assistantError);
					stream.end();
				}
				return;
			}

			let rotationAttemptLimit = MIN_ROTATION_ATTEMPT_LIMIT;
			const refreshRotationAttemptLimit = async (): Promise<void> => {
				rotationAttemptLimit = await resolveRotationAttemptLimit(
					accountManager,
					activeProviderId,
				);
			};

			const switchToFailoverProvider = async (): Promise<boolean> => {
				if (!lastFailoverTrigger) {
					return false;
				}

				const target = await accountManager.resolveFailoverTarget(
					activeProviderId,
					lastFailoverTrigger,
					activeModel.id,
				);
				if (!target) {
					return false;
				}

				const failoverBaseProvider = baseProvidersByApi.get(target.api);
				if (!failoverBaseProvider) {
					throw new Error(
						`No base provider is registered for failover API '${target.api}' (${target.providerId}/${target.modelId}).`,
					);
				}

				multiAuthDebugLogger.log("chain_failover_activated", {
					fromProvider: activeProviderId,
					toProvider: target.providerId,
					modelId: target.modelId,
					api: target.api,
					chainId: target.chainId,
					position: target.position,
				});
				activeProviderId = target.providerId;
				activeModel = {
					...activeModel,
					provider: target.providerId,
					id: target.modelId,
					api: target.api,
				};
				activeBaseProvider = failoverBaseProvider;
				excludedCredentialIds = new Set<string>();
				lastCredentialErrorMessage = null;
				lastFailoverTrigger = null;
				await refreshRotationAttemptLimit();
				return true;
			};

			await refreshRotationAttemptLimit();
			for (let attempt = 0; attempt < rotationAttemptLimit; attempt += 1) {
				if (!providerRetryBudget.tryAcquire(activeProviderId)) {
					throw new Error(
						`Retry budget exhausted for ${activeProviderId}: ${PROVIDER_RETRY_BUDGET_MAX_RETRIES} rotation attempt(s) per ${Math.round(PROVIDER_RETRY_BUDGET_WINDOW_MS / 1000)}s window.`,
					);
				}
				const delegatedCredentialOverride = resolveDelegatedCredentialOverride(activeProviderId);
				const useDelegatedCredentialOverride = delegatedCredentialOverride !== undefined;
				let selected: SelectedCredential;
				try {
					if (delegatedCredentialOverride) {
						const providerCredentialIds = await accountManager.listProviderCredentialIds(
							activeProviderId,
						);
						if (!providerCredentialIds.includes(delegatedCredentialOverride.credentialId)) {
							throw new Error(
								`Delegated credential '${delegatedCredentialOverride.credentialId}' is not available for ${activeProviderId}.`,
							);
						}

						const pinnedExcludedCredentialIds = new Set(excludedCredentialIds);
						for (const credentialId of providerCredentialIds) {
							if (credentialId !== delegatedCredentialOverride.credentialId) {
								pinnedExcludedCredentialIds.add(credentialId);
							}
						}

						selected = await accountManager.acquireCredential(activeProviderId, {
							excludedCredentialIds: pinnedExcludedCredentialIds,
							pinnedCredentialId: delegatedCredentialOverride.credentialId,
							modelId: activeModel.id,
							selectionCache,
							signal: options?.signal,
						});
						multiAuthDebugLogger.log("delegated_credential_override_applied", {
							provider: activeProviderId,
							credentialId: delegatedCredentialOverride.credentialId,
							model: activeModel.id,
						});
					} else {
						selected = await accountManager.acquireCredential(activeProviderId, {
							excludedCredentialIds,
							modelId: activeModel.id,
							selectionCache,
							signal: options?.signal,
						});
					}
				} catch (error: unknown) {
					if (options?.signal?.aborted && isAbortError(error)) {
						emitAbortedTermination(options.signal.reason ?? error);
						return;
					}
					if (excludedCredentialIds.size > 0 && (await switchToFailoverProvider())) {
						continue;
					}
					if (excludedCredentialIds.size > 0) {
						const lastDetail = lastCredentialErrorMessage
							? ` Last credential error: ${lastCredentialErrorMessage}`
							: ` Credential acquisition error: ${getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS)}`;
						throw new Error(
							`All ${excludedCredentialIds.size} rotated credential(s) for ${activeProviderId} failed.${lastDetail}`,
						);
					}
					throw error;
				}

				let authRefreshRetryAttempted = false;
				const enrichProviderErrorMessage = async (
					rawMessage: string,
					requestModel: Model<Api>,
					requestHeaders: SimpleStreamOptions["headers"],
				): Promise<string> => {
					const message = await enrichProviderStatusOnlyErrorMessage(rawMessage, {
						model: requestModel,
						apiKey: selected.secret,
						headers: requestHeaders,
						signal: options?.signal,
						onResponseHeaders: (headers, status) => accountManager.harvestProviderRateLimitHeaders(
							activeProviderId,
							selected.credentialId,
							selected.credential,
							headers,
							status,
						),
					});
					if (message !== rawMessage) {
						multiAuthDebugLogger.log("provider_error_body_enriched", {
							provider: activeProviderId,
							credentialId: selected.credentialId,
							model: requestModel.id,
							errorMessage: message.slice(0, 200),
						});
					}
					return message;
				};

				const tryRefreshOAuthCredentialForAuthFailure = async (
					rawMessage: string,
					hasForwardedSubstantiveEvent: boolean,
					requestModel: Model<Api>,
					requestHeaders: SimpleStreamOptions["headers"],
				): Promise<boolean> => {
					if (authRefreshRetryAttempted || hasForwardedSubstantiveEvent) {
						return false;
					}
					if (selected.credential?.type !== "oauth") {
						return false;
					}

					const message = await enrichProviderErrorMessage(rawMessage, requestModel, requestHeaders);
					if (!isRefreshableRuntimeAuthFailure(message)) {
						return false;
					}

					authRefreshRetryAttempted = true;
					lastCredentialErrorMessage = message;
					try {
						const failedCredential = selected.credential;
						const refreshResult = await accountManager.refreshCredentialForAuthFailure(
							activeProviderId,
							selected.credentialId,
							failedCredential,
						);
						selected = {
							...selected,
							credential: refreshResult.credential,
							secret: getCredentialRequestSecret(activeProviderId, refreshResult.credential),
						};
						multiAuthDebugLogger.log("runtime_auth_refresh_replay", {
							provider: activeProviderId,
							credentialId: selected.credentialId,
							model: requestModel.id,
							disposition: refreshResult.disposition,
							errorMessage: message.slice(0, 200),
						});
						return true;
					} catch (error: unknown) {
						multiAuthDebugLogger.log("runtime_auth_refresh_failed", {
							provider: activeProviderId,
							credentialId: selected.credentialId,
							model: requestModel.id,
							error: getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS),
						});
						return false;
					}
				};

				const resolveRetryDecision = async (
					rawMessage: string,
					hasForwardedSubstantiveEvent: boolean,
					transientAttempt: number,
					requestModel: Model<Api>,
					requestHeaders: SimpleStreamOptions["headers"],
				): Promise<"fail" | "retry_same_credential" | "rotate_credential"> => {
					const message = await enrichProviderErrorMessage(rawMessage, requestModel, requestHeaders);
					const classification = classifyCredentialError(message, {
						providerId: activeProviderId,
						modelId: requestModel.id,
					});
					multiAuthDebugLogger.log("error_classified", {
						provider: activeProviderId,
						credentialId: selected.credentialId,
						kind: classification.kind,
						shouldDisable: classification.shouldDisableCredential,
						shouldRotate: classification.shouldRotateCredential,
						shouldCooldown: classification.shouldApplyCooldown,
						errorMessage: message.slice(0, 200),
					});

					if (classification.shouldDisableCredential) {
						try {
							await accountManager.disableApiKeyCredential(
								activeProviderId,
								selected.credentialId,
								message,
								classification.kind,
							);
							multiAuthDebugLogger.log("credential_disabled", {
								provider: activeProviderId,
								credentialId: selected.credentialId,
								kind: classification.kind,
								reason: message.slice(0, 200),
							});
						} catch (error: unknown) {
							multiAuthDebugLogger.log("credential_disable_failed", {
								provider: activeProviderId,
								credentialId: selected.credentialId,
								error: getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS),
							});
						}
					}

					if (hasForwardedSubstantiveEvent) {
						return "fail";
					}

					const blazeApiRequestLimitHasLiveCapacity =
						await shouldRetryBlazeApiRequestLimitWithLiveCapacity(
							accountManager,
							activeProviderId,
							selected.credentialId,
							requestModel.id,
							message,
						);
					if (blazeApiRequestLimitHasLiveCapacity) {
						lastCredentialErrorMessage = message;
						if (transientAttempt < MAX_TRANSIENT_RETRIES_PER_CREDENTIAL) {
							multiAuthDebugLogger.log("blazeapi_request_limit_treated_as_transient", {
								provider: activeProviderId,
								credentialId: selected.credentialId,
								model: requestModel.id,
								transientAttempt,
							});
							return "retry_same_credential";
						}

						const cooldownMs = await accountManager.markTransientProviderError(
							activeProviderId,
							selected.credentialId,
							message,
						);
						multiAuthDebugLogger.log("blazeapi_request_limit_retry_budget_exhausted", {
							provider: activeProviderId,
							credentialId: selected.credentialId,
							model: requestModel.id,
							transientAttempt,
							cooldownMs,
						});
						return "fail";
					}

					if (
						classification.shouldRetrySameCredential &&
						transientAttempt < MAX_TRANSIENT_RETRIES_PER_CREDENTIAL
					) {
						lastCredentialErrorMessage = message;
						return "retry_same_credential";
					}

					if (
						(classification.kind === "provider_transient" ||
							classification.kind === "request_timeout") &&
						!hasForwardedSubstantiveEvent &&
						attempt + 1 < rotationAttemptLimit
					) {
						lastCredentialErrorMessage = message;
						if (useDelegatedCredentialOverride) {
							return "fail";
						}
						const cooldownMs = await accountManager.markTransientProviderError(
							activeProviderId,
							selected.credentialId,
							message,
						);
						multiAuthDebugLogger.log("credential_transient_cooldown_recorded", {
							provider: activeProviderId,
							credentialId: selected.credentialId,
							cooldownMs,
							reason: message.slice(0, 200),
						});

						// Detect whether rotation has anywhere actually usable for this request.
						// A provider can have other stored credentials that are disabled, quota-locked,
						// or ineligible for the requested model (for example Kiro Free credentials
						// on a Kiro Opus request). In that case, excluding the current credential
						// would exhaust rotation and abort even though the error is transient.
						let hasAlternateCredential = false;
						let alternateLookupFailed = false;
						try {
							if (typeof accountManager.hasUsableAlternateCredential === "function") {
								hasAlternateCredential = await accountManager.hasUsableAlternateCredential(
									activeProviderId,
									{
										currentCredentialId: selected.credentialId,
										excludedCredentialIds,
										modelId: requestModel.id,
										selectionCache,
										signal: options?.signal,
									},
								);
							} else {
								const providerCredentialIds = await accountManager.listProviderCredentialIds(
									activeProviderId,
								);
								hasAlternateCredential = providerCredentialIds.some(
									(credentialId) =>
										credentialId !== selected.credentialId &&
										!excludedCredentialIds.has(credentialId),
								);
							}
						} catch (error: unknown) {
							alternateLookupFailed = true;
							multiAuthDebugLogger.log("transient_alternate_lookup_failed", {
								provider: activeProviderId,
								credentialId: selected.credentialId,
								error: getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS),
							});
						}

						if (!alternateLookupFailed && !hasAlternateCredential) {
							// No alternate credential is available, so excluding this
							// one would fail acquisition on the next outer iteration.
							// Wait past the recorded cooldown (capped) and re-acquire
							// the same credential without marking it excluded so that
							// transient errors auto-retry instead of bubbling up.
							const backoffBaseMs = cooldownMs > 0
								? Math.min(cooldownMs, SOLE_CREDENTIAL_TRANSIENT_RETRY_WAIT_MS)
								: MIN_SOLE_CREDENTIAL_TRANSIENT_RETRY_WAIT_MS;
							const backoffMs = computeExponentialBackoffMs(
								backoffBaseMs,
								transientAttempt + 1,
								SOLE_CREDENTIAL_TRANSIENT_RETRY_WAIT_MS,
							);
							const waitMs = getJitteredBackoffMs(backoffMs);
							multiAuthDebugLogger.log("transient_retry_without_rotation", {
								provider: activeProviderId,
								credentialId: selected.credentialId,
								cooldownMs,
								backoffMs,
								waitMs,
								attempt,
								rotationAttemptLimit,
								reason: message.slice(0, 200),
							});
							if (waitMs > 0) {
								try {
									await abortableSleep(waitMs, options?.signal);
								} catch (error: unknown) {
									if (isCallerAbort(options?.signal, error)) {
										return "fail";
									}
									throw error;
								}
							}
							if (options?.signal?.aborted) {
								return "fail";
							}
							if (typeof accountManager.releaseTransientProviderRetryBlock === "function") {
								try {
									await accountManager.releaseTransientProviderRetryBlock(
										activeProviderId,
										selected.credentialId,
									);
									multiAuthDebugLogger.log("transient_retry_block_released", {
										provider: activeProviderId,
										credentialId: selected.credentialId,
										reason: message.slice(0, 200),
									});
								} catch (error: unknown) {
									multiAuthDebugLogger.log("transient_retry_block_release_failed", {
										provider: activeProviderId,
										credentialId: selected.credentialId,
										error: getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS),
									});
									return "fail";
								}
							}
							return "rotate_credential";
						}

						excludedCredentialIds.add(selected.credentialId);
						return "rotate_credential";
					}

					if (
						classification.shouldRotateCredential &&
						attempt + 1 < rotationAttemptLimit
					) {
						lastCredentialErrorMessage = message;
						if (useDelegatedCredentialOverride) {
							return "fail";
						}
						if (classification.shouldApplyCooldown) {
							await accountManager.markQuotaExceeded(
								activeProviderId,
								selected.credentialId,
								{
									errorMessage: message,
									isWeekly: classification.kind === "quota_weekly",
									quotaClassification: classification.quotaClassification,
									recommendedCooldownMs: classification.recommendedCooldownMs,
									errorKind: classification.kind,
								},
							);
						} else if (
							isCredentialModelIncompatibilityError(message, {
								providerId: activeProviderId,
								modelId: requestModel.id,
							})
						) {
							const blockedUntil = await accountManager.markCredentialModelIncompatible(
								activeProviderId,
								selected.credentialId,
								requestModel.id,
								message,
							);
							multiAuthDebugLogger.log("credential_model_incompatibility_recorded", {
								provider: activeProviderId,
								credentialId: selected.credentialId,
								modelId: requestModel.id,
								blockedUntil,
								reason: message.slice(0, 200),
							});
						} else if (
							isRetryableModelAvailabilityError(message, {
								providerId: activeProviderId,
								modelId: activeModel.id,
							})
						) {
							const cooldownMs = await accountManager.markTransientProviderError(
								activeProviderId,
								selected.credentialId,
								message,
							);
							multiAuthDebugLogger.log("credential_transient_cooldown_recorded", {
								provider: activeProviderId,
								credentialId: selected.credentialId,
								cooldownMs,
								reason: message.slice(0, 200),
							});
						}
						lastFailoverTrigger = classification.kind;
						excludedCredentialIds.add(selected.credentialId);
						return "rotate_credential";
					}

					return "fail";
				};

				for (
					let transientAttempt = 0;
					transientAttempt <= MAX_TRANSIENT_RETRIES_PER_CREDENTIAL;
					transientAttempt += 1
				) {
					resetBufferedThinkingState(bufferedThinkingState);
					const requestStartedAt = Date.now();
					const providerRequestHeaders = resolveProviderRequestHeaders(
						activeProviderId,
						options?.headers,
					);
					const {
						model: requestModel,
						headers: requestHeaders,
					} = applyCredentialRequestOverrides({
						provider: activeProviderId,
						credentialId: selected.credentialId,
						credential: selected.credential,
						model: activeModel,
						headers: providerRequestHeaders,
					});
					let innerStream: AssistantMessageEventStream;
					try {
						const credentialType = useDelegatedCredentialOverride
							? "delegated"
							: selected.credential?.type ?? "unknown";
						const secretKind = selected.secret.startsWith("workos:")
							? "workos"
							: credentialType;
						multiAuthDebugLogger.log("stream_request_auth", {
							provider: activeProviderId,
							credentialId: selected.credentialId,
							credentialType,
							secretKind,
							hasSecret: selected.secret.length > 0,
							model: requestModel.id,
							baseUrl: requestModel.baseUrl,
							api: requestModel.api,
						});
						innerStream = activeBaseProvider.streamSimple(requestModel, context, {
							...options,
							apiKey: selected.secret,
							headers: requestHeaders,
							signal: options?.signal,
						});
					} catch (error: unknown) {
						if (isCallerAbort(options?.signal, error)) {
							emitAbortedTermination(options?.signal?.reason ?? error);
							return;
						}
						const message = getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS);
						if (
							await tryRefreshOAuthCredentialForAuthFailure(
								message,
								false,
								requestModel,
								requestHeaders,
							)
						) {
							continue;
						}
						const decision = await resolveRetryDecision(
							message,
							false,
							transientAttempt,
							requestModel,
							requestHeaders,
						);
						if (decision === "retry_same_credential") {
							continue;
						}
						if (decision === "rotate_credential") {
							break;
						}
						throw error;
					}

					let forwardedAnyEvent = false;
					let hasForwardedSubstantiveEvent = false;
					let sawDoneEvent = false;
					let shouldRetrySameCredential = false;
					let shouldRotateCredential = false;

					try {
						for await (const rawEvent of innerStream) {
							const forwardedEvents = sanitizeOllamaThinkingEvent(
								rawEvent,
								activeProviderId,
								bufferedThinkingState,
							);
							for (const event of forwardedEvents) {
								if (event.type === "error") {
									const assistantErrorMessage = getAssistantErrorMessage(event.error);
									if (isCallerAbortMessage(options?.signal, assistantErrorMessage)) {
										emitAbortedTermination(options?.signal?.reason ?? event.error.errorMessage);
										return;
									}
									const message = assistantErrorMessage;
									if (
										await tryRefreshOAuthCredentialForAuthFailure(
											message,
											hasForwardedSubstantiveEvent,
											requestModel,
											requestHeaders,
										)
									) {
										shouldRetrySameCredential = true;
										break;
									}
									const decision = await resolveRetryDecision(
										message,
										hasForwardedSubstantiveEvent,
										transientAttempt,
										requestModel,
										requestHeaders,
									);
									if (decision === "retry_same_credential") {
										shouldRetrySameCredential = true;
										break;
									}
									if (decision === "rotate_credential") {
										shouldRotateCredential = true;
										break;
									}

									stream.push(event);
									stream.end();
									return;
								}

								if (
									event.type === "done" &&
									isRetryableEmptyCompletion(
										event,
										hasForwardedSubstantiveEvent,
									)
								) {
									const message = createEmptyCompletionErrorMessage(
										activeProviderId,
										selected.credentialId,
										event.message,
									);
									multiAuthDebugLogger.log("empty_completion_detected", {
										provider: activeProviderId,
										credentialId: selected.credentialId,
										model: event.message.model,
										responseId: event.message.responseId,
										outputTokens: getAssistantOutputTokens(event.message),
										contentBlockCount: event.message.content.length,
										stopReason: event.message.stopReason,
									});
									const decision = await resolveRetryDecision(
										message,
										hasForwardedSubstantiveEvent,
										transientAttempt,
										requestModel,
										requestHeaders,
									);
									if (decision === "retry_same_credential") {
										shouldRetrySameCredential = true;
										break;
									}
									if (decision === "rotate_credential") {
										shouldRotateCredential = true;
										break;
									}
									throw new Error(message);
								}

								forwardedAnyEvent = true;
								hasForwardedSubstantiveEvent ||= isSubstantiveEvent(event);
								stream.push(event);
								if (event.type === "done") {
									sawDoneEvent = true;
									providerRetryBudget.recordSuccess(activeProviderId);
									await accountManager.recordCredentialSuccess(
										activeProviderId,
										selected.credentialId,
										Date.now() - requestStartedAt,
										requestModel.id,
										getAssistantTokenEstimate(event.message),
									);
									stream.end();
									return;
								}
							}

							if (shouldRetrySameCredential || shouldRotateCredential) {
								break;
							}
						}
					} catch (error: unknown) {
						if (isCallerAbort(options?.signal, error)) {
							emitAbortedTermination(options?.signal?.reason ?? error);
							return;
						}
						const message = getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS);
						if (
							await tryRefreshOAuthCredentialForAuthFailure(
								message,
								hasForwardedSubstantiveEvent,
								requestModel,
								requestHeaders,
							)
						) {
							shouldRetrySameCredential = true;
						} else {
							const decision = await resolveRetryDecision(
								message,
								hasForwardedSubstantiveEvent,
								transientAttempt,
								requestModel,
								requestHeaders,
							);
							if (decision === "retry_same_credential") {
								shouldRetrySameCredential = true;
							} else if (decision === "rotate_credential") {
								shouldRotateCredential = true;
							} else {
								throw error;
							}
						}
					}

					if (shouldRetrySameCredential) {
						continue;
					}

					if (shouldRotateCredential) {
						break;
					}

					if (!sawDoneEvent) {
						if (options?.signal?.aborted) {
							emitAbortedTermination(options.signal.reason);
							return;
						}
						const message = !forwardedAnyEvent
							? `Provider stream ended before completion event for ${activeProviderId} (credential ${selected.credentialId}) without emitting any events.`
							: `Provider stream ended before completion event for ${activeProviderId} (credential ${selected.credentialId}).`;
						const decision = await resolveRetryDecision(
							message,
							hasForwardedSubstantiveEvent,
							transientAttempt,
							requestModel,
							requestHeaders,
						);
						if (decision === "retry_same_credential") {
							continue;
						}
						if (decision === "rotate_credential") {
							break;
						}
						throw new Error(message);
					}

					stream.end();
					return;
				}
			}

			const triedCount = excludedCredentialIds.size;
			const lastDetail = lastCredentialErrorMessage
				? ` Last error: ${lastCredentialErrorMessage}`
				: "";
			throw new Error(
				`Rotation exhausted for ${activeProviderId}: ${triedCount} credential(s) tried across ${rotationAttemptLimit} attempt budget, all produced rotation-triggering errors.${lastDetail}`,
			);
		})().catch((error: unknown) => {
			const errorMessage = getErrorMessage(error, STRUCTURED_ERROR_MESSAGE_OPTIONS);
			const assistantError: AssistantMessageEvent = {
				type: "error",
				reason: "error",
				error: createErrorAssistantMessage(
					activeModel,
					formatMultiAuthRotationFailureMessage(activeProviderId, activeModel, errorMessage),
				),
			};
			stream.push(assistantError);
			stream.end();
		});

		return stream;
	};
}

/**
 * Resolves provider metadata required for registerProvider().
 */
export async function resolveProviderRegistrationMetadata(
	provider: SupportedProviderId,
	registry: ProviderRegistry = new ProviderRegistry(),
): Promise<ProviderRegistrationMetadata | null> {
	return registry.resolveProviderRegistrationMetadata(provider);
}

export interface RuntimeProviderRegistrationPayload {
	provider: SupportedProviderId;
	displayName?: string;
	baseUrl: string;
	api: Api;
	models: ProviderModelConfig[];
	streamSimple: (
		model: Model<Api>,
		context: Context,
		options?: SimpleStreamOptions,
	) => AssistantMessageEventStream;
	headers?: Record<string, string>;
}

export function registerRuntimeProviderOverride(
	pi: ExtensionAPI,
	accountManager: AccountManager,
	payload: RuntimeProviderRegistrationPayload,
): void {
	const baseProvider: ApiProviderRef = {
		api: payload.api,
		stream: (model, context, options) => payload.streamSimple(model, context, options),
		streamSimple: payload.streamSimple,
	};
	const streamSimple = createRotatingStreamWrapper(
		payload.provider,
		accountManager,
		baseProvider,
		new Map([[payload.api, baseProvider]]),
	);

	multiAuthDebugLogger.log("runtime_provider_override_registering", {
		provider: payload.provider,
		api: payload.api,
		modelCount: payload.models.length,
	});

	pi.registerProvider(payload.provider, {
		name: payload.displayName,
		baseUrl: payload.baseUrl,
		apiKey: "managed-by-multi-auth",
		api: payload.api,
		headers: payload.headers,
		models: payload.models,
		streamSimple,
	});
}

/**
 * Registers stream wrappers for all discovered providers with model metadata.
 */
export async function registerMultiAuthProviders(
	pi: ExtensionAPI,
	accountManager: AccountManager,
	options?: {
		excludeProviders?: string[];
		includeProviders?: string[];
	},
): Promise<void> {
	const excludeSet = new Set(options?.excludeProviders ?? []);
	const includeSet =
		options?.includeProviders && options.includeProviders.length > 0
			? new Set(options.includeProviders)
			: null;
	const registry = accountManager.getProviderRegistry();
	const providers = includeSet
		? ([...includeSet] as SupportedProviderId[])
		: await registry.discoverProviderIds();
	const metadataToRegister = (
		await Promise.all(
			providers.map(async (provider) => {
				if (excludeSet.has(provider)) {
					return null;
				}
				if (includeSet && !includeSet.has(provider)) {
					return null;
				}

				const metadata = await resolveProviderRegistrationMetadata(provider, registry);
				if (!metadata) {
					const isCredentialOnlyOAuthProvider = await registry.isCredentialOnlyOAuthProvider(provider);
					if (!isCredentialOnlyOAuthProvider) {
						multiAuthDebugLogger.log("provider_registration_skipped", {
							provider,
							reason: "no_model_metadata",
						});
					}
					return null;
				}

				if (metadata.models.length === 0) {
					multiAuthDebugLogger.log("provider_registration_skipped", {
						provider,
						reason: "no_models",
					});
					return null;
				}

				return metadata;
			}),
		)
	).filter((metadata): metadata is ProviderRegistrationMetadata => metadata !== null);

	for (const metadata of metadataToRegister) {
		recordProviderDiscovery(metadata.provider);
	}

	multiAuthDebugLogger.log("providers_discovered", {
		count: metadataToRegister.length,
		providers: metadataToRegister.map((metadata) => metadata.provider),
		metrics: getProviderRegistrationMetrics(),
	});

	const allApis = new Set<Api>();
	const fallbackProvidersByApi = new Map<Api, SupportedProviderId>();
	for (const metadata of metadataToRegister) {
		for (const model of metadata.models) {
			if (!model.api) {
				continue;
			}
			allApis.add(model.api);
			if (!fallbackProvidersByApi.has(model.api)) {
				fallbackProvidersByApi.set(model.api, metadata.provider);
			}
		}
		allApis.add(metadata.api);
		if (!fallbackProvidersByApi.has(metadata.api)) {
			fallbackProvidersByApi.set(metadata.api, metadata.provider);
		}
	}

	const wrappersByApi = new Map<Api, ReturnType<typeof createRotatingStreamWrapper>>();
	const baseProvidersByApi = new Map<Api, ApiProviderRef>();

	for (const api of allApis) {
		const baseProvider = getApiProvider(api);
		if (!baseProvider) {
			multiAuthDebugLogger.log("api_wrapper_unavailable", {
				api,
				reason: "no_base_api_provider",
			});
			continue;
		}

		baseProvidersByApi.set(api, baseProvider);
		const fallbackProvider = fallbackProvidersByApi.get(api) ?? (api as SupportedProviderId);
		const streamSimple = createRotatingStreamWrapper(
			fallbackProvider,
			accountManager,
			baseProvider,
			baseProvidersByApi,
			excludeSet,
		);
		wrappersByApi.set(api, streamSimple);
		multiAuthDebugLogger.log("stream_wrapper_created", {
			api,
			fallbackProvider,
		});
	}

	for (const metadata of metadataToRegister) {
		const primaryApi = metadata.api;
		const primaryWrapper = wrappersByApi.get(primaryApi);
		if (!primaryWrapper) {
			multiAuthDebugLogger.log("provider_registration_skipped", {
				provider: metadata.provider,
				api: primaryApi,
				reason: "no_wrapper_for_api",
			});
			continue;
		}

		const providerApis = new Set<Api>();
		for (const model of metadata.models) {
			if (model.api) {
				providerApis.add(model.api);
			}
		}
		if (providerApis.size === 0) {
			providerApis.add(primaryApi);
		}

		for (const api of providerApis) {
			const wrapper = wrappersByApi.get(api);
			if (!wrapper) {
				multiAuthDebugLogger.log("provider_api_registration_skipped", {
					provider: metadata.provider,
					api,
					reason: "no_wrapper_for_api",
				});
				continue;
			}

			multiAuthDebugLogger.log("api_provider_registering", {
				provider: metadata.provider,
				api,
				sourceId: `provider:${metadata.provider}:${api}`,
			});

			registerApiProvider(
				{
					api,
					stream: (model, context, options) => wrapper(model, context, options as SimpleStreamOptions),
					streamSimple: wrapper,
				},
				`provider:${metadata.provider}:${api}`,
			);
		}

		const registrationMetrics = recordProviderRegistration(metadata.provider);
		multiAuthDebugLogger.log("provider_registered", {
			provider: metadata.provider,
			primaryApi,
			providerApis: [...providerApis],
			modelCount: metadata.models.filter((model) => (model.api ? providerApis.has(model.api) : true)).length,
			registrationCount: registrationMetrics.registrationCount,
			duplicateRegistrationCount: registrationMetrics.duplicateRegistrationCount,
			lastRegistrationDeltaMs: registrationMetrics.lastRegistrationDeltaMs,
		});

		pi.registerProvider(metadata.provider, {
			baseUrl: metadata.baseUrl,
			apiKey: "managed-by-multi-auth",
			api: primaryApi,
			models: metadata.models,
			streamSimple: primaryWrapper,
		});
	}
}
