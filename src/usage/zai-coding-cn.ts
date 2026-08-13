import { fetchWithTimeout } from "../async-utils.js";
import { isRecord, normalizeNonEmptyString } from "../auth-error-utils.js";
import { quotaClassifier } from "../quota-classifier.js";
import type { RateLimitWindow, UsageAuth, UsageProvider, UsageSnapshot } from "./types.js";

const ZAI_CODING_CN_PROVIDER_ID = "zai-coding-cn";
/**
 * GLM China (bigmodel.cn) API origin. The coding-plan chat endpoint lives at
 * `https://open.bigmodel.cn/api/coding/paas/v4` and the quota monitor is served
 * from the same origin at `/api/monitor/usage/quota/limit`.
 */
const ZAI_CODING_CN_API_ORIGIN = "https://open.bigmodel.cn";
const ZAI_CODING_CN_QUOTA_PATH = "/api/monitor/usage/quota/limit";
const REQUEST_TIMEOUT_MS = 3_000;

/** GLM coding-plan model token/credit budget for the rolling 5-hour window. */
const FIVE_HOUR_WINDOW_MINUTES = 5 * 60;
/** GLM coding-plan model token/credit budget for the weekly window. */
const WEEKLY_WINDOW_MINUTES = 7 * 24 * 60;

type ZaiQuotaLimitType = "TIME_LIMIT" | "TOKENS_LIMIT";

interface ZaiQuotaLimitRow {
	type: ZaiQuotaLimitType;
	unit: number | null;
	number: number | null;
	usedPercent: number;
	resetsAt: number | null;
}

function asNumber(value: unknown): number | null {
	if (typeof value === "number" && Number.isFinite(value)) {
		return value;
	}
	if (typeof value !== "string") {
		return null;
	}
	const normalized = value.trim();
	if (!normalized) {
		return null;
	}
	const parsed = Number(normalized);
	return Number.isFinite(parsed) ? parsed : null;
}

function clampPercent(value: number): number {
	return Math.max(0, Math.min(100, Math.round(value)));
}

/**
 * Resolves the quota monitor URL from the credential's configured base URL when
 * available (the monitor shares the chat API origin), falling back to the
 * default bigmodel.cn API origin.
 */
function normalizeQuotaUrl(auth: UsageAuth): string {
	const requestConfig = isRecord(auth.credential?.request) ? auth.credential.request : null;
	const configuredBaseUrl = normalizeNonEmptyString(requestConfig?.baseUrl);
	if (configuredBaseUrl) {
		try {
			const origin = new URL(configuredBaseUrl).origin;
			if (origin.startsWith("https://") || origin.startsWith("http://")) {
				return `${origin}${ZAI_CODING_CN_QUOTA_PATH}`;
			}
		} catch {
			// Fall through to the default origin on malformed overrides.
		}
	}
	return `${ZAI_CODING_CN_API_ORIGIN}${ZAI_CODING_CN_QUOTA_PATH}`;
}

function parseResetAt(value: unknown): number | null {
	const timestamp = asNumber(value);
	if (timestamp === null || timestamp <= 0) {
		return null;
	}
	return timestamp > 1_000_000_000_000 ? timestamp : timestamp * 1000;
}

function parseLimitRow(value: unknown): ZaiQuotaLimitRow | null {
	if (!isRecord(value)) {
		return null;
	}

	const type = normalizeNonEmptyString(value.type)?.toUpperCase();
	if (type !== "TIME_LIMIT" && type !== "TOKENS_LIMIT") {
		return null;
	}

	const total = asNumber(value.usage);
	const used = asNumber(value.currentValue);
	const remaining = asNumber(value.remaining);
	let usedPercent = asNumber(value.percentage);
	if (usedPercent === null && total !== null && total > 0) {
		if (used !== null) {
			usedPercent = (used / total) * 100;
		} else if (remaining !== null) {
			usedPercent = ((total - remaining) / total) * 100;
		}
	}
	if (usedPercent === null) {
		return null;
	}

	return {
		type,
		unit: asNumber(value.unit),
		number: asNumber(value.number),
		usedPercent: clampPercent(usedPercent),
		resetsAt: parseResetAt(value.nextResetTime),
	};
}

function parseQuotaLimits(payload: unknown): { rows: ZaiQuotaLimitRow[]; level: string | null } {
	if (!isRecord(payload)) {
		return { rows: [], level: null };
	}
	const data = isRecord(payload.data) ? payload.data : null;
	if (!data || !Array.isArray(data.limits)) {
		return { rows: [], level: null };
	}
	const rows: ZaiQuotaLimitRow[] = [];
	for (const item of data.limits) {
		const row = parseLimitRow(item);
		if (row) {
			rows.push(row);
		}
	}
	return { rows, level: normalizeNonEmptyString(data.level) ?? null };
}

/**
 * Maps a `TOKENS_LIMIT` row to its window length. The GLM quota API encodes the
 * window in the undocumented `unit`/`number` pair; the two buckets observed in
 * practice (and used by other coding-plan quota tools) are `(3, 5)` for the
 * rolling 5-hour budget and `(6, 1)` for the weekly budget. Unrecognized
 * buckets fall back to the reset horizon when the row carries one.
 */
function resolveTokenWindowMinutes(row: ZaiQuotaLimitRow, now: number): number | null {
	if (row.unit === 3 && row.number === 5) {
		return FIVE_HOUR_WINDOW_MINUTES;
	}
	if (row.unit === 6 && row.number === 1) {
		return WEEKLY_WINDOW_MINUTES;
	}
	if (row.resetsAt !== null) {
		const spanMinutes = (row.resetsAt - now) / 60_000;
		if (spanMinutes > 0 && spanMinutes <= 6 * 60) {
			return FIVE_HOUR_WINDOW_MINUTES;
		}
		if (spanMinutes >= 5 * 24 * 60) {
			return WEEKLY_WINDOW_MINUTES;
		}
	}
	return null;
}

function toWindow(row: ZaiQuotaLimitRow | undefined, windowMinutes: number | null): RateLimitWindow | null {
	if (!row) {
		return null;
	}
	return {
		usedPercent: row.usedPercent,
		windowMinutes,
		resetsAt: row.resetsAt,
	};
}

function getEstimatedResetAt(primary: RateLimitWindow | null, secondary: RateLimitWindow | null): number | undefined {
	const resets = [primary?.resetsAt, secondary?.resetsAt].filter(
		(value): value is number => typeof value === "number" && Number.isFinite(value),
	);
	if (resets.length === 0) {
		return undefined;
	}
	return Math.min(...resets);
}

/**
 * Fetches GLM China (Z.AI Coding CN) coding-plan quota from the bigmodel.cn
 * monitor endpoint `GET /api/monitor/usage/quota/limit` using the account's API
 * key as a Bearer token.
 *
 * The endpoint reports two kinds of limit buckets, distinguished by `type` and
 * the `unit`/`number` pair:
 *
 * - `TOKENS_LIMIT` with `unit: 3, number: 5` — the model token/credit budget
 *   for the rolling 5-hour window (primary window).
 * - `TOKENS_LIMIT` with `unit: 6, number: 1` — the model token/credit budget
 *   for the weekly window (secondary window, with an explicit `nextResetTime`).
 * - `TIME_LIMIT` — the MCP tool pool (web-search / web-reader / zread, per the
 *   row's `usageDetails` model codes). Coding traffic does not consume this
 *   pool, so it is deliberately excluded from the reported quota windows;
 *   surfacing it as the primary window would show a permanently-zero gauge.
 *
 * Each entry carries a `percentage` of the budget already consumed plus, when
 * active, raw `usage`/`currentValue`/`remaining` counters, which we normalize
 * into the shared `RateLimitWindow` shape. The account plan tier (`level`,
 * e.g. "pro") is reported as the snapshot's plan type.
 */
export const zaiCodingCnUsageProvider: UsageProvider<UsageAuth> = {
	id: ZAI_CODING_CN_PROVIDER_ID,
	displayName: "Z.AI Coding CN",
	fetchUsage: async (auth: UsageAuth): Promise<UsageSnapshot | null> => {
		if (!auth.accessToken) {
			return null;
		}

		const response = await fetchWithTimeout(
			normalizeQuotaUrl(auth),
			{
				method: "GET",
				headers: {
					Accept: "application/json",
					Authorization: `Bearer ${auth.accessToken}`,
					"User-Agent": "pi-multi-auth",
				},
			},
			{
				timeoutMs: REQUEST_TIMEOUT_MS,
				timeoutMessage: `Z.AI Coding CN quota request timed out after ${REQUEST_TIMEOUT_MS}ms`,
			},
		);

		if (response.status === 401) {
			throw new Error("Z.AI Coding CN token expired or invalid");
		}
		if (response.status === 403) {
			throw new Error("Z.AI Coding CN quota access was denied for this account");
		}
		if (!response.ok) {
			throw new Error(`Z.AI Coding CN quota request failed with status ${response.status}`);
		}

		const payload = (await response.json()) as unknown;
		if (isRecord(payload) && payload.success === false) {
			const message = normalizeNonEmptyString(payload.msg) ?? normalizeNonEmptyString(payload.message);
			throw new Error(message ? `Z.AI Coding CN quota request failed: ${message}` : "Z.AI Coding CN quota request failed");
		}

		const now = Date.now();
		const { rows, level } = parseQuotaLimits(payload);
		// Only TOKENS_LIMIT rows track model consumption. TIME_LIMIT rows are the
		// MCP tool pool (web-search / web-reader / zread) and are excluded.
		const tokenWindows = rows
			.filter((row) => row.type === "TOKENS_LIMIT")
			.map((row) => ({ row, windowMinutes: resolveTokenWindowMinutes(row, now) }))
			.sort(
				(left, right) =>
					(left.windowMinutes ?? Number.MAX_SAFE_INTEGER) - (right.windowMinutes ?? Number.MAX_SAFE_INTEGER),
			);
		if (tokenWindows.length === 0) {
			throw new Error("Z.AI Coding CN quota response format was invalid");
		}

		// The short 5-hour budget is the primary window, the weekly budget the
		// secondary window, matching other providers.
		const primary = toWindow(tokenWindows[0]?.row, tokenWindows[0]?.windowMinutes ?? null);
		const secondary = toWindow(tokenWindows[1]?.row, tokenWindows[1]?.windowMinutes ?? null);
		const quotaClassification = quotaClassifier.classifyFromUsage(primary, secondary).classification;

		return {
			timestamp: now,
			provider: ZAI_CODING_CN_PROVIDER_ID,
			planType: level,
			primary,
			secondary,
			credits: null,
			copilotQuota: null,
			updatedAt: now,
			estimatedResetAt: getEstimatedResetAt(primary, secondary),
			quotaClassification,
		};
	},
};
