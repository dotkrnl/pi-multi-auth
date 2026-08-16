import { fetchWithTimeout } from "../async-utils.js";
import { isRecord, normalizeNonEmptyString } from "../auth-error-utils.js";
import { quotaClassifier } from "../quota-classifier.js";
import type { OpenCodeGoQuotaConfig } from "../types.js";
import type { RateLimitWindow, UsageAuth, UsageCredits, UsageProvider, UsageSnapshot } from "./types.js";

/**
 * Cookie-based OpenCode Go (opencode.ai) usage provider.
 *
 * OpenCode Go does not expose a public quota API keyed on the model access key.
 * The Go plan dashboard (`https://opencode.ai/workspace/<workspaceId>/go`)
 * instead renders quota server-side into SolidStart hydration state using the
 * browser `auth` session cookie. This provider reads that dashboard HTML and
 * parses the serialized `lite.subscription.get` payload, which reports three
 * usage windows plus an account credit balance:
 *
 * - `rollingUsage` — the rolling 5-hour request window (primary).
 * - `weeklyUsage` — the weekly request window (secondary).
 * - `monthlyUsage` — the monthly request window (tertiary `monthly` gauge).
 * - `balance` — remaining prepaid credit balance, reported as `credits`.
 *
 * The workspace id and cookie are stored per-credential on the OpenCode Go
 * account (`opencodeGo.workspaceId` / `opencodeGo.cookie`) and configured
 * through the `/multi-auth` modal's `[c]` action. When a credential has no
 * `opencodeGo` config the provider reports no quota for it.
 */
const OPENCODE_GO_PROVIDER_ID = "opencode-go";
const OPENCODE_GO_DASHBOARD_ORIGIN = "https://opencode.ai";
const OPENCODE_GO_PLAN_TYPE = "Go";
const REQUEST_TIMEOUT_MS = 6_000;

/** Rolling OpenCode Go request window length, in minutes. */
const ROLLING_WINDOW_MINUTES = 5 * 60;
/** Weekly OpenCode Go request window length, in minutes. */
const WEEKLY_WINDOW_MINUTES = 7 * 24 * 60;
/** Monthly OpenCode Go request window length, in minutes. */
const MONTHLY_WINDOW_MINUTES = 30 * 24 * 60;

interface ParsedUsageWindow {
	status: string | null;
	resetInSec: number | null;
	usagePercent: number | null;
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Resolves the per-credential OpenCode Go quota config from the credential
 * record carried on {@link UsageAuth}.
 */
function resolveOpenCodeGoConfig(auth: UsageAuth): OpenCodeGoQuotaConfig | null {
	const raw = auth.credential?.opencodeGo;
	if (!isRecord(raw)) {
		return null;
	}
	const workspaceId = normalizeNonEmptyString(raw.workspaceId);
	const cookie = normalizeNonEmptyString(raw.cookie);
	if (!workspaceId || !cookie) {
		return null;
	}
	return { workspaceId, cookie };
}

/**
 * Extracts a serialized usage-window object (e.g. `rollingUsage:$R[34]={...}`).
 * The SolidStart serializer emits unquoted identifier keys and may prefix the
 * object literal with an intermediate reference assignment (`$R[34]=`), so we
 * tolerate that prefix and parse the inner `key:value` pairs.
 */
function extractUsageObject(html: string, key: string): ParsedUsageWindow | null {
	const keyPattern = escapeRegExp(key);
	const objectMatch = new RegExp(
		`${keyPattern}\\s*:\\s*(?:\\$[A-Za-z_$][\\w$]*\\[\\d+\\]\\s*=\\s*)?\\{([^}]*)\\}`,
	).exec(html);
	if (!objectMatch?.[1]) {
		return null;
	}
	const body = objectMatch[1];
	return {
		status: extractStringValue(body, "status"),
		resetInSec: extractNumberValue(body, "resetInSec"),
		usagePercent: extractNumberValue(body, "usagePercent"),
	};
}

function extractStringValue(body: string, key: string): string | null {
	const match = new RegExp(`${escapeRegExp(key)}\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)"`).exec(body);
	return match?.[1] ?? null;
}

function extractNumberValue(body: string, key: string): number | null {
	const match = new RegExp(`${escapeRegExp(key)}\\s*:\\s*(-?\\d+(?:\\.\\d+)?)`).exec(body);
	if (!match?.[1]) {
		return null;
	}
	const parsed = Number(match[1]);
	return Number.isFinite(parsed) ? parsed : null;
}

function extractBalanceCents(html: string): number | null {
	const match = /\bbalance\s*:\s*(-?\d+(?:\.\d+)?)/.exec(html);
	if (!match?.[1]) {
		return null;
	}
	const parsed = Number(match[1]);
	return Number.isFinite(parsed) ? parsed : null;
}

function clampPercent(value: number): number {
	return Math.max(0, Math.min(100, Math.round(value)));
}

function toRateLimitWindow(
	parsed: ParsedUsageWindow | null,
	windowMinutes: number,
	now: number,
): RateLimitWindow | null {
	if (!parsed) {
		return null;
	}
	if (parsed.usagePercent === null) {
		return null;
	}
	const resetsAt =
		parsed.resetInSec !== null && parsed.resetInSec >= 0 ? now + parsed.resetInSec * 1000 : null;
	return {
		usedPercent: clampPercent(parsed.usagePercent),
		windowMinutes,
		resetsAt,
	};
}

function buildUsageCredits(balanceCents: number | null): UsageCredits | null {
	if (balanceCents === null || balanceCents <= 0) {
		return null;
	}
	const dollars = (balanceCents / 100).toFixed(2);
	return {
		hasCredits: true,
		unlimited: false,
		balance: `$${dollars} credit`,
	};
}

function getEstimatedResetAt(
	primary: RateLimitWindow | null,
	secondary: RateLimitWindow | null,
	monthly: RateLimitWindow | null,
): number | undefined {
	const resets = [primary?.resetsAt, secondary?.resetsAt, monthly?.resetsAt].filter(
		(value): value is number => typeof value === "number" && Number.isFinite(value),
	);
	return resets.length > 0 ? Math.min(...resets) : undefined;
}

function buildDashboardUrl(workspaceId: string): string {
	return `${OPENCODE_GO_DASHBOARD_ORIGIN}/workspace/${workspaceId}/go`;
}

/**
 * Sanitizes the `auth` cookie value for use in a `Cookie` header. The OpenCode
 * session cookie is an opaque `Fe26.2**…` string, but defensively trim at the
 * first `;`/whitespace so a malformed pasted value cannot inject extra cookie
 * pairs or header fields.
 */
function sanitizeCookieValue(cookie: string): string {
	const trimmed = cookie.trim();
	const cutoff = trimmed.search(/[;\s]/);
	return cutoff === -1 ? trimmed : trimmed.slice(0, cutoff);
}

function looksLikeAuthRedirect(html: string, responseUrl: string): boolean {
	if (/auth\.opencode\.ai|\/auth\/(?:authorize|callback|login)|\/authorize\b/i.test(responseUrl)) {
		return true;
	}
	return /auth\.opencode\.ai\/authorize|\/auth\/(?:authorize|callback|login)\b|sign\s*in\b/i.test(html);
}

function hasUsagePayload(html: string): boolean {
	return html.includes("rollingUsage") || html.includes("lite.subscription.get");
}

export const opencodeGoUsageProvider: UsageProvider<UsageAuth> = {
	id: OPENCODE_GO_PROVIDER_ID,
	displayName: "OpenCode Go",
	fetchUsage: async (auth: UsageAuth): Promise<UsageSnapshot | null> => {
		const config = resolveOpenCodeGoConfig(auth);
		if (!config) {
			return null;
		}

		const response = await fetchWithTimeout(
			buildDashboardUrl(config.workspaceId),
			{
				method: "GET",
				redirect: "follow",
				headers: {
					Accept: "text/html,application/xhtml+xml",
					Cookie: `auth=${sanitizeCookieValue(config.cookie)}`,
					"User-Agent": "pi-multi-auth",
				},
			},
			{
				timeoutMs: REQUEST_TIMEOUT_MS,
				timeoutMessage: `OpenCode Go quota request timed out after ${REQUEST_TIMEOUT_MS}ms`,
			},
		);

		if (response.status === 401 || response.status === 403) {
			throw new Error("OpenCode Go session cookie expired or invalid");
		}
		if (!response.ok) {
			throw new Error(`OpenCode Go quota request failed with status ${response.status}`);
		}

		const html = await response.text();
		if (!hasUsagePayload(html)) {
			if (looksLikeAuthRedirect(html, response.url)) {
				throw new Error("OpenCode Go session cookie expired or invalid");
			}
			throw new Error("OpenCode Go quota response format was invalid");
		}

		const now = Date.now();
		const rolling = extractUsageObject(html, "rollingUsage");
		const weekly = extractUsageObject(html, "weeklyUsage");
		const monthlyRaw = extractUsageObject(html, "monthlyUsage");
		const primary = toRateLimitWindow(rolling, ROLLING_WINDOW_MINUTES, now);
		const secondary = toRateLimitWindow(weekly, WEEKLY_WINDOW_MINUTES, now);
		const monthly = toRateLimitWindow(monthlyRaw, MONTHLY_WINDOW_MINUTES, now);
		if (!primary && !secondary && !monthly) {
			throw new Error("OpenCode Go quota response format was invalid");
		}

		const balanceCents = extractBalanceCents(html);
		const credits = buildUsageCredits(balanceCents);
		const quotaClassification = quotaClassifier.classifyFromUsage(primary, secondary, undefined, monthly).classification;

		return {
			timestamp: now,
			provider: OPENCODE_GO_PROVIDER_ID,
			planType: OPENCODE_GO_PLAN_TYPE,
			primary,
			secondary,
			monthly,
			credits,
			copilotQuota: null,
			updatedAt: now,
			estimatedResetAt: getEstimatedResetAt(primary, secondary, monthly),
			quotaClassification,
		};
	},
};

// Internal parser helpers exported for unit testing.
export const __opencodeGoParser = {
	resolveOpenCodeGoConfig,
	extractUsageObject,
	extractBalanceCents,
	toRateLimitWindow,
	looksLikeAuthRedirect,
};
