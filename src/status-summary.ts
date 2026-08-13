import type { CredentialStatus, ProviderStatus } from "./types.js";

/**
 * Shared, read-only projection of AccountManager.getStatus() used by the
 * footer quota indicator and the `/multi-auth status` inline report.
 */

export interface ProviderUsageSummary {
	provider: string;
	rotationMode: string;
	accountCount: number;
	/** Label for the active credential: friendly name, identity email, or id. */
	activeLabel?: string;
	/** Active credential's primary (short) window usage, 0-100. */
	primaryPercent?: number;
	/** Active credential's secondary (long/weekly) window usage, 0-100. */
	secondaryPercent?: number;
	/** Active credential's tertiary (monthly) window usage, 0-100. */
	monthlyPercent?: number;
	/** Active credential's primary window length in minutes (for statusline suffixes). */
	primaryWindowMinutes?: number;
	/** Active credential's secondary window length in minutes (for statusline suffixes). */
	secondaryWindowMinutes?: number;
	/** Active credential's monthly window length in minutes (for statusline suffixes). */
	monthlyWindowMinutes?: number;
	planType?: string;
	/** True when the active credential is in a quota cooldown. */
	activeQuotaExhausted: boolean;
	/** True when the active credential's usage data is stale/unavailable. */
	activeUsageUnavailable: boolean;
}

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

export function summarizeProviderStatuses(
	statuses: readonly ProviderStatus[],
	now: number = Date.now(),
): ProviderUsageSummary[] {
	const summaries: ProviderUsageSummary[] = [];
	for (const status of statuses) {
		if (status.credentials.length === 0) {
			continue;
		}
		const active =
			status.credentials.find((credential) => credential.isActive) ?? status.credentials[0];
		const snapshot = active.usageSnapshot ?? null;
		summaries.push({
			provider: status.provider,
			rotationMode: status.rotationMode,
			accountCount: status.credentials.length,
			activeLabel: credentialLabel(active),
			primaryPercent: snapshot?.primary?.usedPercent,
			secondaryPercent: snapshot?.secondary?.usedPercent,
			monthlyPercent: snapshot?.monthly?.usedPercent,
			primaryWindowMinutes: snapshot?.primary?.windowMinutes ?? undefined,
			secondaryWindowMinutes: snapshot?.secondary?.windowMinutes ?? undefined,
			monthlyWindowMinutes: snapshot?.monthly?.windowMinutes ?? undefined,
			planType: snapshot?.planType ?? active.identityPlanType,
			activeQuotaExhausted:
				typeof active.quotaExhaustedUntil === "number" && active.quotaExhaustedUntil > now,
			activeUsageUnavailable: !snapshot,
		});
	}
	return summaries;
}

/**
 * Single-letter statusline suffix for a window length: `h`ourly, `d`aily,
 * `w`eekly, `m`onthly. Returns an empty string for unknown/short windows so the
 * primary (short) window renders bare (e.g. `54`, not `54h`).
 */
function formatWindowSuffix(windowMinutes?: number): string {
	if (typeof windowMinutes !== "number" || !Number.isFinite(windowMinutes) || windowMinutes <= 0) {
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

function formatUsageGroup(summary: ProviderUsageSummary): string | null {
	const parts: string[] = [];
	if (typeof summary.primaryPercent === "number") {
		parts.push(`${Math.round(summary.primaryPercent)}`);
	}
	if (typeof summary.secondaryPercent === "number") {
		parts.push(`${Math.round(summary.secondaryPercent)}${formatWindowSuffix(summary.secondaryWindowMinutes)}`);
	}
	if (typeof summary.monthlyPercent === "number") {
		parts.push(`${Math.round(summary.monthlyPercent)}${formatWindowSuffix(summary.monthlyWindowMinutes)}`);
	}
	return parts.length > 0 ? parts.join("/") : null;
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
 * Compact single-line footer text, e.g. "kimi|54/85w  go|12/24w/36m  gpt|7".
 * The primary (short) window is bare; secondary and monthly windows carry a
 * size suffix (`w`/`m`). Returns undefined when no provider has usage data.
 */
export function formatQuotaStatusLine(
	summaries: readonly ProviderUsageSummary[],
): string | undefined {
	const segments: string[] = [];
	for (const summary of summaries) {
		const usage = formatUsageGroup(summary);
		if (!usage) {
			continue;
		}
		const exhaustedMarker = summary.activeQuotaExhausted ? "!" : "";
		segments.push(`${formatProviderStatuslineAlias(summary.provider)}|${usage}${exhaustedMarker}`);
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
