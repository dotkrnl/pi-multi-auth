import type { RateLimitWindow } from "./usage/types.js";
import type { CredentialStatus, ProviderStatus } from "./types.js";

/**
 * Read-only formatting helpers over AccountManager.getStatus() results: the
 * compact footer quota indicator and the `/multi-auth status` inline report.
 */

function formatWindowMinutes(windowMinutes: number | null): string | null {
	if (windowMinutes === null || !Number.isFinite(windowMinutes) || windowMinutes <= 0) {
		return null;
	}
	if (windowMinutes % (60 * 24 * 7) === 0) {
		const weeks = windowMinutes / (60 * 24 * 7);
		return weeks === 1 ? "weekly" : `${weeks}w`;
	}
	if (windowMinutes % (60 * 24) === 0) {
		const days = windowMinutes / (60 * 24);
		return days === 1 ? "daily" : `${days}d`;
	}
	if (windowMinutes % 60 === 0) {
		return `${windowMinutes / 60}h`;
	}
	return `${windowMinutes}m`;
}

function credentialLabel(credential: CredentialStatus): string {
	return credential.friendlyName ?? credential.identityEmail ?? credential.credentialId;
}

/**
 * Single-letter statusline suffix for a window length: `h`ourly, `d`aily,
 * `w`eekly, `m`onthly. Returns an empty string for unknown/short windows so the
 * primary (short) window renders bare (e.g. `54`, not `54h`).
 */
function formatWindowSuffix(windowMinutes: number | null | undefined): string {
	if (windowMinutes === null || typeof windowMinutes !== "number" || !Number.isFinite(windowMinutes) || windowMinutes <= 0) {
		return "";
	}
	if (windowMinutes >= 25 * 24 * 60) {
		return "m";
	}
	if (windowMinutes >= 5 * 24 * 60) {
		return "w";
	}
	if (windowMinutes >= 20 * 60) {
		return "d";
	}
	return "h";
}

/**
 * Short statusline aliases for known provider IDs, keeping the compact footer
 * readable (e.g. `openai-codex` renders as `gpt`). Unknown providers fall back
 * to their full provider ID.
 */
const PROVIDER_STATUSLINE_ALIASES: Readonly<Record<string, string>> = {
	anthropic: "claude",
	blazeapi: "blaze",
	"command-code": "cmdcode",
	"github-copilot": "copilot",
	google: "gemini",
	"google-vertex": "vertex",
	"kimi-coding": "kimi",
	"minimax-cn": "minimax",
	"opencode-go": "go",
	"moonshotai-cn": "moonshot",
	openai: "gpt",
	"openai-codex": "gpt",
	"qwen-token-plan-cn": "qwen",
	"xiaomi-token-plan-cn": "xiaomi",
	zai: "zai",
	"zai-coding-cn": "glm",
};

/**
 * Resolves the compact statusline alias for a provider ID.
 */
export function formatProviderStatuslineAlias(provider: string): string {
	return PROVIDER_STATUSLINE_ALIASES[provider] ?? provider;
}

/**
 * One statusline cell for a single account + window: the used percent rounded
 * to an integer with the window suffix (bare for the primary window). Returns
 * `–` when the account has no usage data for that window.
 */
function formatWindowCell(window: RateLimitWindow | null | undefined, suffix: string): string {
	if (!window || typeof window.usedPercent !== "number" || !Number.isFinite(window.usedPercent)) {
		return "–";
	}
	return `${Math.round(window.usedPercent)}${suffix}`;
}

/**
 * Compact single-line footer text listing every account's quota, grouped by
 * quota window instead of by account, e.g.
 * "kimi|54|12|85w|27w  go|12|24w|36m".
 *
 * Grammar: `<alias>|<primary: acct1>|<primary: acct2>|...  <weekly: acct1>|<weekly: acct2>|...w  <monthly...>m`
 *
 * - Accounts appear in stored credential index order (the same order as the
 *   `/multi-auth` modal account list), so within each `|`-separated run the
 *   n-th value belongs to the n-th account.
 * - The primary (short) window is bare; secondary/weekly and monthly windows
 *   carry a size suffix (`w`/`m`).
 * - `–` marks an account without data for that window; a whole window run is
 *   dropped when no account has data for it.
 * Returns undefined when no provider has usage data.
 */
export function formatAllAccountsQuotaStatusLine(
	statuses: readonly ProviderStatus[],
): string | undefined {
	const segments: string[] = [];
	for (const status of statuses) {
		const credentials = [...status.credentials].sort((a, b) => a.index - b.index);
		if (credentials.length === 0) {
			continue;
		}
		const groups: string[][] = [[], [], []];
		for (const credential of credentials) {
			const snapshot = credential.usageSnapshot;
			groups[0].push(formatWindowCell(snapshot?.primary, ""));
			groups[1].push(
				formatWindowCell(
					snapshot?.secondary,
					formatWindowSuffix(snapshot?.secondary?.windowMinutes) || "w",
				),
			);
			groups[2].push(
				formatWindowCell(
					snapshot?.monthly,
					formatWindowSuffix(snapshot?.monthly?.windowMinutes) || "m",
				),
			);
		}
		const runs: string[] = [];
		for (const values of groups) {
			if (values.some((value) => value !== "–")) {
				runs.push(values.join("|"));
			}
		}
		if (runs.length === 0) {
			continue;
		}
		segments.push(`${formatProviderStatuslineAlias(status.provider)}|${runs.join("|")}`);
	}
	return segments.length > 0 ? segments.join("  ") : undefined;
}

function formatCredentialReportLine(credential: CredentialStatus, now: number): string {
	const markers: string[] = [];
	if (credential.isActive) {
		markers.push("active");
	}
	if (credential.isExpired) {
		markers.push("expired");
	}
	if (typeof credential.quotaExhaustedUntil === "number" && credential.quotaExhaustedUntil > now) {
		markers.push("quota exhausted");
	}
	if (credential.disabledError) {
		markers.push("disabled");
	}
	const usage = credential.usageSnapshot;
	const usageParts: string[] = [];
	if (usage?.primary) {
		const windowLabel = formatWindowMinutes(usage.primary.windowMinutes);
		usageParts.push(`${Math.round(usage.primary.usedPercent)}%${windowLabel ? ` ${windowLabel}` : ""}`);
	}
	if (usage?.secondary) {
		const windowLabel = formatWindowMinutes(usage.secondary.windowMinutes) ?? "secondary";
		usageParts.push(`${Math.round(usage.secondary.usedPercent)}% ${windowLabel}`);
	}
	const plan = usage?.planType ?? credential.identityPlanType;
	const columns = [
		`    ${credentialLabel(credential)}`,
		usageParts.length > 0 ? usageParts.join(", ") : "no usage data",
		plan ?? null,
		markers.length > 0 ? `[${markers.join(", ")}]` : null,
	].filter((column): column is string => typeof column === "string" && column.length > 0);
	return columns.join(" — ");
}

/**
 * Verbose multi-line report for `/multi-auth status`.
 */
export function formatStatusReport(
	statuses: readonly ProviderStatus[],
	now: number = Date.now(),
): string {
	if (statuses.length === 0) {
		return "multi-auth: no credentials configured.";
	}
	const lines: string[] = [];
	for (const status of statuses) {
		const accountWord = status.credentials.length === 1 ? "account" : "accounts";
		lines.push(
			`${status.provider} (${status.rotationMode}, ${status.credentials.length} ${accountWord})`,
		);
		for (const credential of status.credentials) {
			lines.push(formatCredentialReportLine(credential, now));
		}
	}
	return lines.join("\n");
}
