import type {
	ExtensionAPI,
	ExtensionCommandContext,
} from "@earendil-works/pi-coding-agent";
import { Input, matchesKey, truncateToWidth, visibleWidth, type OverlayOptions } from "@earendil-works/pi-tui";
import { AccountManager, type CloudflareCredentialIdentityRefreshResult } from "./account-manager.js";
import {
	resolveBatchDeleteSelection,
	pruneBatchSelection,
	toggleBatchSelection,
} from "./account-batch-selection.js";
import { parseCloudflareCredentialBatchInput } from "./cloudflare-credential-input.js";
import { isCloudflareWorkersAiProvider } from "./cloudflare-provider.js";
import { runOAuthLoginDialog } from "./oauth-login-flow.js";
import {
	OPENAI_CODEX_IMPORT_PROVIDER_ID,
	parseOpenAICodexCredentialImportInput,
} from "./openai-codex-import.js";
import { runProviderConfigurationDialog } from "./provider-configuration-dialog.js";
import { getErrorMessage } from "./auth-error-utils.js";
import { formatStatusReport } from "./status-summary.js";
import { parseApiKeyBatchInput } from "./credential-display.js";
import { ModalVisibilityController } from "./modal-visibility.js";
import { isRemovedLegacyGoogleProvider } from "./removed-google-providers.js";
import { formatResetCountdown } from "./formatters/bar.js";
import { resolveBorderGlyphs } from "./formatters/charset.js";
import {
	clampRenderedRows,
	renderWrappedFooterActions,
	RESPONSIVE_MODAL_DEFAULT_SCALE,
	resolveBodyRowBudget,
	resolveResponsiveOverlayOptions,
	resolveResponsiveOverlayRuntimeOptions,
	wrapTextToWidth,
	type ModalOverlayOptions,
} from "./formatters/responsive-modal.js";
import {
	formatProviderBadge,
	normalizeInlineText,
	truncateAccountIdentifier,
} from "./formatters/multi-auth-display.js";
import {
	formatHiddenProviderHint,
	resolveFooterActions,
	summarizeProviderVisibility,
	type FocusPane,
	type ProviderVisibilitySummary,
	type SelectedEntryKind,
} from "./formatters/modal-ui.js";
import { renderZellijFrameWithRenderer } from "./formatters/zellij-frame.js";
import {
	formatRotationModeLabel,
	resolveDefaultRotationMode,
	resolveSelectableRotationModes,
} from "./rotation-modes.js";
import { normalizeCodexPlanType } from "./model-entitlements.js";
import {
	LEGACY_SUPPORTED_PROVIDERS,
	type CredentialRequestOverrides,
	type CredentialStatus,
	type ProviderStatus,
	type SupportedProviderId,
} from "./types.js";
import type { UsageSnapshot } from "./usage/types.js";

interface ThemeLike {
	fg(color: string, text: string): string;
	bold(text: string): string;
}

interface RenameEditorState {
	provider: SupportedProviderId;
	credentialId: string;
	input: Input;
}

type SelectedProviderEntry =
	| {
		kind: "account";
		credential: CredentialStatus;
		entryIndex: number;
	}
	| {
		kind: "add";
		entryIndex: number;
	};

type SelectionAnchor =
	| {
		provider: SupportedProviderId;
		kind: "account";
		credentialId: string;
	}
	| {
		provider: SupportedProviderId;
		kind: "add";
	};

type PlanHighlightColor = "accent" | "mdLink" | "success" | "text" | "toolTitle" | "warning";

interface DuplicateAccountIndicator {
	email: string;
	planLabel: string;
	credentialIds: string[];
}

interface AccountColumnWidths {
	alias: number;
	account: number;
}

const ACCOUNT_ROW_PREFIX_WIDTH = 8;
const ACCOUNT_TABLE_MIN_WIDTH = 30;
const GRID_CELL_HORIZONTAL_PADDING = 2;
const ACCOUNT_PANE_MIN_WIDTH = visibleWidth("Accounts: github-copilot (1)") + GRID_CELL_HORIZONTAL_PADDING * 2;
const NEUTRAL_PLAN_LABELS = new Set(["", "free", "n/a", "na", "no plan", "none", "null", "unknown"]);

const THREE_PANE_MIN_WIDTH = 96;
const GRID_BODY_ROW_COUNT = Math.ceil(22 * RESPONSIVE_MODAL_DEFAULT_SCALE);
const MIN_BODY_ROW_COUNT = 4;
const GRID_VERTICAL_SEPARATOR_COLUMNS = 2;
const MODAL_TITLE_LEFT_MARGIN = 2;
const MODAL_TITLE_BOTTOM_MARGIN_ROWS = 1;
export type ModalRefreshAction = "none" | "provider" | "selected-account";

export function resolveModalRefreshAction(
	data: string,
	focusedPane: FocusPane,
	selectedEntryKind: SelectedEntryKind,
): ModalRefreshAction {
	if (data === "T" || matchesKey(data, "shift+t")) {
		return selectedEntryKind === "account" ? "selected-account" : "none";
	}

	if (data === "t" || matchesKey(data, "t")) {
		return focusedPane === "accounts" && selectedEntryKind === "account"
			? "selected-account"
			: "provider";
	}

	return "none";
}
const BORDER_GLYPHS = resolveBorderGlyphs();
export const CUSTOM_PROVIDER_NAME_OPTION = "__custom_provider__" as const;

type AddProviderMethod = "api_key" | "oauth" | "import";

function providerSupportsCredentialImport(provider: SupportedProviderId): boolean {
	return provider === OPENAI_CODEX_IMPORT_PROVIDER_ID;
}
type ProviderStatusSummary = Pick<ProviderStatus, "provider" | "credentials">;

type ProviderChoiceCandidate = {
	provider: SupportedProviderId;
	displayName: string;
	credentialCount: number;
	isConfigured: boolean;
	isSelected: boolean;
};

type SupportedApiKeyProviderSummary = Readonly<{
	provider: SupportedProviderId;
	name?: string;
}>;

export interface SmartApiKeyProviderOption {
	provider: SupportedProviderId | typeof CUSTOM_PROVIDER_NAME_OPTION;
	name: string;
	isConfigured: boolean;
	isSelected: boolean;
	credentialCount: number;
}

export interface SmartOAuthProviderOption {
	provider: SupportedProviderId;
	name: string;
	isConfigured: boolean;
	isSelected: boolean;
	credentialCount: number;
}

function compareProviderChoiceCandidates(
	a: ProviderChoiceCandidate,
	b: ProviderChoiceCandidate,
): number {
	if (a.isSelected !== b.isSelected) {
		return a.isSelected ? -1 : 1;
	}
	if (a.isConfigured !== b.isConfigured) {
		return a.isConfigured ? -1 : 1;
	}
	const nameCompare = a.displayName.localeCompare(b.displayName, undefined, {
		sensitivity: "base",
	});
	if (nameCompare !== 0) {
		return nameCompare;
	}
	return a.provider.localeCompare(b.provider, undefined, { sensitivity: "base" });
}

function getCredentialCountsByProvider(
	providerStatuses: readonly ProviderStatusSummary[],
): Map<SupportedProviderId, number> {
	const counts = new Map<SupportedProviderId, number>();
	for (const status of providerStatuses) {
		counts.set(status.provider, status.credentials.length);
	}
	return counts;
}

export function buildSmartApiKeyProviderOptions(
	providerStatuses: readonly ProviderStatusSummary[],
	selectedProviderId: SupportedProviderId | null,
	supportedProviders: readonly SupportedApiKeyProviderSummary[] = [],
): SmartApiKeyProviderOption[] {
	const credentialCounts = getCredentialCountsByProvider(providerStatuses);
	const seenProviders = new Set<SupportedProviderId>();
	const candidates: ProviderChoiceCandidate[] = [];
	const pushCandidate = (providerId: string, displayName: string): void => {
		const provider = providerId.trim();
		if (!provider || seenProviders.has(provider)) {
			return;
		}
		const credentialCount = credentialCounts.get(provider) ?? 0;
		seenProviders.add(provider);
		candidates.push({
			provider,
			displayName: displayName.trim() || provider,
			credentialCount,
			isConfigured: credentialCount > 0,
			isSelected: provider === selectedProviderId,
		});
	};

	for (const supportedProvider of supportedProviders) {
		pushCandidate(supportedProvider.provider, supportedProvider.name ?? supportedProvider.provider);
	}
	for (const status of providerStatuses) {
		pushCandidate(status.provider, status.provider);
	}

	const options = candidates
		.sort(compareProviderChoiceCandidates)
		.map<SmartApiKeyProviderOption>((candidate) => ({
			provider: candidate.provider,
			name: candidate.displayName,
			isConfigured: candidate.isConfigured,
			isSelected: candidate.isSelected,
			credentialCount: candidate.credentialCount,
		}));

	options.push({
		provider: CUSTOM_PROVIDER_NAME_OPTION,
		name: "Use custom provider name…",
		isConfigured: false,
		isSelected: false,
		credentialCount: 0,
	});
	return options;
}

export function buildSmartOAuthProviderOptions(
	oauthProviders: readonly Readonly<{ provider: SupportedProviderId; name: string }>[],
	providerStatuses: readonly ProviderStatusSummary[],
	selectedProviderId: SupportedProviderId | null,
): SmartOAuthProviderOption[] {
	const credentialCounts = getCredentialCountsByProvider(providerStatuses);
	const seenProviders = new Set<SupportedProviderId>();
	const candidates: ProviderChoiceCandidate[] = [];
	const names = new Map<SupportedProviderId, string>();

	for (const oauthProvider of oauthProviders) {
		const provider = oauthProvider.provider.trim();
		if (!provider || seenProviders.has(provider)) {
			continue;
		}
		seenProviders.add(provider);
		const displayName = oauthProvider.name.trim() || provider;
		names.set(provider, displayName);
		candidates.push({
			provider,
			displayName,
			credentialCount: credentialCounts.get(provider) ?? 0,
			isConfigured: (credentialCounts.get(provider) ?? 0) > 0,
			isSelected: provider === selectedProviderId,
		});
	}

	return candidates
		.sort(compareProviderChoiceCandidates)
		.map<SmartOAuthProviderOption>((candidate) => ({
			provider: candidate.provider,
			name: names.get(candidate.provider) ?? candidate.provider,
			isConfigured: candidate.isConfigured,
			isSelected: candidate.isSelected,
			credentialCount: candidate.credentialCount,
		}));
}

export function normalizeProviderSelectionInput(
	input: string,
	knownProviderIds: readonly SupportedProviderId[],
): { ok: true; value: SupportedProviderId } | { ok: false; message: string } {
	const normalizedInput = input.trim();
	if (!normalizedInput) {
		return { ok: false, message: "Provider name is required." };
	}
	if (/\s/.test(normalizedInput)) {
		return {
			ok: false,
			message: "Provider name cannot contain spaces. Use IDs like 'openrouter' or 'my-provider'.",
		};
	}
	if (isRemovedLegacyGoogleProvider(normalizedInput)) {
		return {
			ok: false,
			message: "Legacy Google providers are no longer supported.",
		};
	}

	const canonicalProvider = knownProviderIds.find(
		(providerId) => providerId.trim().toLowerCase() === normalizedInput.toLowerCase(),
	);
	return {
		ok: true,
		value: canonicalProvider ?? normalizedInput,
	};
}

export type ProviderPaneEntry =
	| {
		kind: "provider";
		provider: SupportedProviderId;
		entryIndex: number;
	}
	| {
		kind: "add";
		entryIndex: number;
	};

export function buildProviderPaneEntries(
	statuses: readonly Pick<ProviderStatus, "provider">[],
): ProviderPaneEntry[] {
	return [
		...statuses.map<ProviderPaneEntry>((status, entryIndex) => ({
			kind: "provider",
			provider: status.provider,
			entryIndex,
		})),
		{ kind: "add", entryIndex: statuses.length },
	];
}

export function wrapAccountDisplayNameLines(displayName: string, maxWidth: number): string[] {
	const safeWidth = Math.max(1, Math.floor(maxWidth));
	const normalized = normalizeInlineText(displayName).trim();
	if (!normalized) {
		return [""];
	}
	const wrapped = wrapTextToWidth(normalized, safeWidth);
	return wrapped.length > 0 ? wrapped : [normalized];
}

function wrapDetailMessageLines(message: string, maxWidth: number): string[] {
	const safeWidth = Math.max(1, Math.floor(maxWidth));
	const normalized = normalizeInlineText(message).trim();
	if (!normalized) {
		return [];
	}
	const wrapped = wrapTextToWidth(normalized, safeWidth);
	return wrapped.length > 0 ? wrapped : [normalized];
}

export function buildMissingUsageDetailLines(maxWidth: number): string[] {
	return wrapDetailMessageLines("No cached usage data. Press [T] to refresh this account.", maxWidth);
}

function buildUsageUnavailableLines(error: string | undefined, maxWidth: number): string[] {
	const normalizedError = normalizeInlineText(error ?? "").trim();
	if (!normalizedError) {
		return ["Usage unavailable"];
	}

	const lowerError = normalizedError.toLowerCase();
	const message = lowerError.startsWith("usage unavailable")
		? normalizedError
		: `Usage unavailable (${normalizedError})`;
	return wrapDetailMessageLines(message, maxWidth);
}

function clamp(value: number, min: number, max: number): number {
	return Math.max(min, Math.min(max, value));
}

function padRight(value: string, width: number): string {
	if (width <= 0) {
		return "";
	}
	const fitted = truncateToWidth(normalizeInlineText(value), width, "…", true);
	const usedWidth = visibleWidth(fitted);
	return `${fitted}${" ".repeat(Math.max(0, width - usedWidth))}`;
}

function getPaneContentWidth(columnWidth: number): number {
	return Math.max(1, columnWidth - GRID_CELL_HORIZONTAL_PADDING * 2);
}

function getScrollableWindow(
	lines: string[],
	selectedIndex: number,
	visibleRowCount: number,
): string[] {
	if (visibleRowCount <= 0 || lines.length <= visibleRowCount) {
		return lines;
	}

	const clampedSelection = clamp(selectedIndex, 0, lines.length - 1);
	const halfWindow = Math.floor(visibleRowCount / 2);
	const maxStart = Math.max(0, lines.length - visibleRowCount);
	const start = clamp(clampedSelection - halfWindow, 0, maxStart);
	return lines.slice(start, start + visibleRowCount);
}

function formatProviderLabel(provider: SupportedProviderId): string {
	switch (provider) {
		case "openai-codex":
			return "openai-codex";
		case "github-copilot":
			return "github-copilot";
		default:
			return provider;
	}
}

function normalizePlanLabel(planType: string | null | undefined): string {
	const normalized = normalizeInlineText(planType ?? "").trim();
	return normalized || "unknown";
}

function normalizeDuplicateEmailKey(email: string | undefined): string | null {
	const normalized = normalizeInlineText(email ?? "").trim().toLowerCase();
	return normalized && normalized.includes("@") ? normalized : null;
}

function normalizeDuplicatePlanKey(
	provider: SupportedProviderId,
	planType: string | null | undefined,
): string | null {
	if (provider === "openai-codex") {
		const normalized = normalizeCodexPlanType(planType);
		return normalized === "unknown" ? null : normalized;
	}

	const normalized = normalizePlanLabel(planType).toLowerCase();
	return NEUTRAL_PLAN_LABELS.has(normalized) ? null : normalized;
}

function getPlanHighlightColor(planType: string | null | undefined): PlanHighlightColor {
	const normalized = normalizePlanLabel(planType).toLowerCase();
	if (NEUTRAL_PLAN_LABELS.has(normalized)) {
		return "text";
	}
	if (normalized.includes("enterprise") || normalized.includes("business")) {
		return "toolTitle";
	}
	if (normalized.includes("team")) {
		return "warning";
	}
	if (
		normalized.includes("pro") ||
		normalized.includes("max") ||
		normalized.includes("unlimited") ||
		normalized.includes("advanced")
	) {
		return "accent";
	}
	if (
		normalized.includes("plus") ||
		normalized.includes("premium") ||
		normalized.includes("paid") ||
		normalized.includes("code assist") ||
		normalized.includes("copilot")
	) {
		return "success";
	}
	return "mdLink";
}

function formatPlanDetailLabel(planType: string | null | undefined, displayOnly: boolean): string {
	const label = normalizePlanLabel(planType);
	return displayOnly ? `${label} (last known)` : label;
}

function resolveAccountColumnWidths(contentWidth: number): AccountColumnWidths | null {
	const safeWidth = Math.max(1, Math.floor(contentWidth));
	if (safeWidth < ACCOUNT_TABLE_MIN_WIDTH) {
		return null;
	}

	const availableColumns = safeWidth - ACCOUNT_ROW_PREFIX_WIDTH;
	const alias = clamp(Math.floor(safeWidth * 0.28), 8, Math.min(16, availableColumns - 9));
	const account = availableColumns - alias - 1;
	if (account < 8) {
		return null;
	}
	return { alias, account };
}

function getCredentialAlias(credential: CredentialStatus): string {
	return normalizeInlineText(credential.credentialId).trim() || "account";
}

function getCredentialAccountLabel(credential: CredentialStatus): string {
	const credentialId = normalizeInlineText(credential.credentialId).trim();
	const friendlyName = normalizeInlineText(credential.friendlyName ?? "").trim();
	return friendlyName && friendlyName !== credentialId ? friendlyName : "";
}

type AccountPlanTextFormatter = (text: string, planType: string | null | undefined) => string;

export interface AccountEntryLineOptions {
	credential: CredentialStatus;
	contentWidth: number;
	isSelected: boolean;
	isMarked: boolean;
	statusCell: string;
	formatPlanText?: AccountPlanTextFormatter;
	singleLine?: boolean;
}

function renderUnlabeledAccountEntryLines(
	credential: CredentialStatus,
	contentWidth: number,
	isSelected: boolean,
	isMarked: boolean,
	statusCell: string,
	formatPlanText: AccountPlanTextFormatter,
): string[] {
	const cursor = isSelected ? "▶" : " ";
	const activeMarker = isMarked || credential.isManualActive ? "*" : " ";
	const prefix = `${cursor} ${activeMarker} ${statusCell} `;
	const accountWidth = Math.max(1, contentWidth - visibleWidth(prefix));
	const accountLines = wrapAccountDisplayNameLines(getCredentialAlias(credential), accountWidth);
	const continuationPrefix = " ".repeat(visibleWidth(prefix));
	return accountLines.map((accountLine, lineIndex) => {
		const formattedAccountLine = formatPlanText(accountLine, credential.usageSnapshot?.planType);
		if (lineIndex === 0) {
			return padRight(`${prefix}${formattedAccountLine}`, contentWidth);
		}
		return padRight(`${continuationPrefix}${formattedAccountLine}`, contentWidth);
	});
}

function renderSingleLineAccountEntry(
	credential: CredentialStatus,
	contentWidth: number,
	isSelected: boolean,
	isMarked: boolean,
	statusCell: string,
	formatPlanText: AccountPlanTextFormatter,
): string[] {
	const safeContentWidth = Math.max(1, Math.floor(contentWidth));
	const cursor = isSelected ? "▶" : " ";
	const activeMarker = isMarked || credential.isManualActive ? "*" : " ";
	const prefix = `${cursor} ${activeMarker} ${statusCell} `;
	const bodyWidth = Math.max(1, safeContentWidth - visibleWidth(prefix));
	const alias = getCredentialAlias(credential);
	const accountLabel = getCredentialAccountLabel(credential);

	if (accountLabel && bodyWidth >= 18) {
		const aliasWidth = clamp(Math.floor(bodyWidth * 0.46), 8, Math.max(8, bodyWidth - 7));
		const labelWidth = Math.max(1, bodyWidth - aliasWidth - 1);
		const aliasText = truncateAccountIdentifier(alias, aliasWidth);
		const labelText = truncateAccountIdentifier(accountLabel, labelWidth);
		const formattedAlias = formatPlanText(padRight(aliasText, aliasWidth), credential.usageSnapshot?.planType);
		return [padRight(`${prefix}${formattedAlias} ${labelText}`, safeContentWidth)];
	}

	const body = formatPlanText(
		truncateAccountIdentifier(accountLabel || alias, bodyWidth),
		credential.usageSnapshot?.planType,
	);
	return [padRight(`${prefix}${body}`, safeContentWidth)];
}

export function renderAccountEntryLines(options: AccountEntryLineOptions): string[] {
	const safeContentWidth = Math.max(1, Math.floor(options.contentWidth));
	const formatPlanText = options.formatPlanText ?? ((text: string) => text);
	if (options.singleLine) {
		return renderSingleLineAccountEntry(
			options.credential,
			safeContentWidth,
			options.isSelected,
			options.isMarked,
			options.statusCell,
			formatPlanText,
		);
	}

	const accountLabel = getCredentialAccountLabel(options.credential);
	if (!accountLabel) {
		return renderUnlabeledAccountEntryLines(
			options.credential,
			safeContentWidth,
			options.isSelected,
			options.isMarked,
			options.statusCell,
			formatPlanText,
		);
	}

	const columnWidths = resolveAccountColumnWidths(safeContentWidth);
	if (!columnWidths) {
		const cursor = options.isSelected ? "▶" : " ";
		const activeMarker = options.isMarked || options.credential.isManualActive ? "*" : " ";
		const alias = formatPlanText(getCredentialAlias(options.credential), options.credential.usageSnapshot?.planType);
		const prefix = `${cursor} ${activeMarker} ${options.statusCell} ${alias}`;
		const accountWidth = Math.max(1, safeContentWidth - visibleWidth(prefix) - 1);
		const accountLines = wrapAccountDisplayNameLines(accountLabel, accountWidth);
		const continuationPrefix = " ".repeat(visibleWidth(prefix) + 1);
		return accountLines.map((accountLine, lineIndex) => {
			if (lineIndex === 0) {
				const accountSuffix = accountLine ? ` ${accountLine}` : "";
				return padRight(`${prefix}${accountSuffix}`, safeContentWidth);
			}
			return padRight(`${continuationPrefix}${accountLine}`, safeContentWidth);
		});
	}

	const cursor = options.isSelected ? "▶" : " ";
	const activeMarker = options.isMarked || options.credential.isManualActive ? "*" : " ";
	const alias = formatPlanText(
		padRight(getCredentialAlias(options.credential), columnWidths.alias),
		options.credential.usageSnapshot?.planType,
	);
	const accountLines = wrapAccountDisplayNameLines(accountLabel, columnWidths.account);
	const firstPrefix = `${cursor} ${activeMarker} ${options.statusCell} `;
	const continuationPrefix = `${" ".repeat(ACCOUNT_ROW_PREFIX_WIDTH + columnWidths.alias)} `;
	return accountLines.map((accountLine, lineIndex) => {
		if (lineIndex === 0) {
			const accountSuffix = accountLine ? ` ${accountLine}` : "";
			return padRight(`${firstPrefix}${alias}${accountSuffix}`, safeContentWidth);
		}
		return padRight(`${continuationPrefix}${accountLine}`, safeContentWidth);
	});
}

function renderProgressBar(percentUsed: number | null, width: number): string {
	if (percentUsed === null || !Number.isFinite(percentUsed)) {
		return `[${"░".repeat(Math.max(4, width))}] n/a`;
	}

	const safeWidth = Math.max(4, width);
	const clampedPercent = clamp(Math.round(percentUsed), 0, 100);
	const filled = Math.round((clampedPercent / 100) * safeWidth);
	const bar = `${"█".repeat(filled)}${"░".repeat(Math.max(0, safeWidth - filled))}`;
	return `[${bar}] ${clampedPercent}%`;
}

interface PaneWidths {
	providers: number;
	accounts: number;
	details: number;
}

export function splitPaneWidths(totalWidth: number): PaneWidths {
	const minimumProviders = 16;
	const minimumAccounts = ACCOUNT_PANE_MIN_WIDTH;
	const minimumDetails = 30;
	const usable = Math.max(
		minimumProviders + minimumAccounts + minimumDetails,
		totalWidth - GRID_VERTICAL_SEPARATOR_COLUMNS,
	);

	let providers = Math.floor(usable * 0.18);
	let accounts = Math.floor(usable * 0.46);
	let details = usable - providers - accounts;

	if (providers < minimumProviders) {
		const delta = minimumProviders - providers;
		providers += delta;
		details -= delta;
	}
	if (accounts < minimumAccounts) {
		const delta = minimumAccounts - accounts;
		accounts += delta;
		details -= delta;
	}
	if (details < minimumDetails) {
		const delta = minimumDetails - details;
		details += delta;
		if (accounts - delta >= minimumAccounts) {
			accounts -= delta;
		} else {
			const accountShrink = Math.max(0, accounts - minimumAccounts);
			accounts -= accountShrink;
			providers = Math.max(minimumProviders, providers - (delta - accountShrink));
		}
	}

	return { providers, accounts, details };
}

function renderGridCell(content: string, width: number): string {
	const padding = " ".repeat(GRID_CELL_HORIZONTAL_PADDING);
	const inner = getPaneContentWidth(width);
	return `${padding}${padRight(content, inner)}${padding}`;
}

function horizontalRule(width: number): string {
	return BORDER_GLYPHS.horizontal.repeat(Math.max(1, width));
}

function formatCredentialDisplayName(credentialId: string, friendlyName: string | undefined): string {
	const safeCredentialId = normalizeInlineText(credentialId).trim();
	const normalized = normalizeInlineText(friendlyName ?? "").trim();
	if (!normalized || normalized === safeCredentialId) {
		return safeCredentialId;
	}
	return `${normalized} (${safeCredentialId})`;
}

function formatCloudflareIdentityRefreshMessage(
	result: CloudflareCredentialIdentityRefreshResult,
	displayName: string,
): string {
	if (result.status === "unsupported") {
		return `Cloudflare identity unavailable for ${displayName}: ${result.message}`;
	}
	if (result.status === "unchanged") {
		return `Cloudflare identity checked for ${displayName}: ${result.friendlyName ?? "saved identity"} is already saved.`;
	}
	return `Cloudflare identity refreshed for ${displayName}: ${result.friendlyName ?? "resolved identity"} saved.`;
}

function formatWindowDurationLabel(windowMinutes: number | null): string | null {
	if (typeof windowMinutes !== "number" || !Number.isFinite(windowMinutes) || windowMinutes <= 0) {
		return null;
	}

	if (windowMinutes % (24 * 60) === 0) {
		const days = windowMinutes / (24 * 60);
		if (days === 1) {
			return "24-hour window";
		}
		return `${days}-day window`;
	}

	if (windowMinutes % 60 === 0) {
		const hours = windowMinutes / 60;
		if (hours === 1) {
			return "1-hour window";
		}
		return `${hours}-hour window`;
	}

	return `${windowMinutes}-minute window`;
}

export function resolveUsageWindowLabel(
	snapshot: UsageSnapshot,
	slot: "primary" | "secondary",
): string {
	if (snapshot.provider === "blazeapi") {
		return slot === "primary" ? "Daily requests" : "Premium credits";
	}

	const window = slot === "primary" ? snapshot.primary : snapshot.secondary;
	const durationLabel = formatWindowDurationLabel(window?.windowMinutes ?? null);
	if (!durationLabel) {
		return slot === "primary" ? "Primary window" : "Secondary window";
	}

	const sameDuration =
		snapshot.primary?.windowMinutes !== null &&
		snapshot.primary?.windowMinutes !== undefined &&
		snapshot.primary?.windowMinutes === snapshot.secondary?.windowMinutes;
	if (sameDuration) {
		return slot === "primary"
			? `${durationLabel} (window 1)`
			: `${durationLabel} (window 2)`;
	}

	return durationLabel;
}

async function loginProviderFromModal(
	ctx: ExtensionCommandContext,
	accountManager: AccountManager,
	provider: SupportedProviderId,
): Promise<{ message: string; credentialId: string }> {
	return runOAuthLoginDialog(ctx, accountManager, provider);
}

interface ParsedProviderApiKeyInputEntry {
	apiKey: string;
	request?: CredentialRequestOverrides;
}

interface ParsedProviderApiKeyInput {
	entries: ParsedProviderApiKeyInputEntry[];
	duplicateCount: number;
	ignoredLineCount: number;
	requestOverrideCount?: number;
}

function parseProviderApiKeyInput(
	provider: SupportedProviderId,
	apiKeyInput: string,
	allowBatch: boolean,
): { ok: true; parsed: ParsedProviderApiKeyInput } | { ok: false; message: string } {
	if (isCloudflareWorkersAiProvider(provider)) {
		const parsed = parseCloudflareCredentialBatchInput(apiKeyInput, {
			allowMultiple: allowBatch,
		});
		if (!parsed.ok) {
			return parsed;
		}
		return {
			ok: true,
			parsed: {
				entries: parsed.entries.map((entry) => ({
					apiKey: entry.apiToken,
					...(entry.request && { request: entry.request }),
				})),
				duplicateCount: parsed.duplicateCount,
				ignoredLineCount: parsed.ignoredLineCount,
				requestOverrideCount: parsed.requestOverrideCount,
			},
		};
	}

	const parsed = parseApiKeyBatchInput(apiKeyInput, {
		allowMultiple: allowBatch,
	});
	if (!parsed.ok) {
		return parsed;
	}
	return {
		ok: true,
		parsed: {
			entries: parsed.keys.map((apiKey) => ({ apiKey })),
			duplicateCount: parsed.duplicateCount,
			ignoredLineCount: parsed.ignoredLineCount,
		},
	};
}

async function addApiKeysFromModal(
	accountManager: AccountManager,
	provider: SupportedProviderId,
	apiKeyInput: string,
	allowBatch: boolean,
): Promise<{ message: string; credentialId: string }> {
	const parsedResult = parseProviderApiKeyInput(provider, apiKeyInput, allowBatch);
	if (!parsedResult.ok) {
		throw new Error(parsedResult.message);
	}
	const parsedInput = parsedResult.parsed;

	const successfulAdds: Array<{
		credentialId: string;
		isBackupCredential: boolean;
		credentialIds: string[];
	}> = [];
	const duplicateExistingCredentialIds: string[] = [];
	const failedAdds: Array<{ ordinal: number; message: string }> = [];
	let deduplicatedCount = 0;
	let renumberedCredentialIds = false;
	let latestCredentialIds: string[] = [];
	let lastTouchedCredentialId: string | null = null;

	for (const [index, entry] of parsedInput.entries.entries()) {
		try {
			const added = await accountManager.addApiKeyCredential(
				provider,
				entry.apiKey,
				entry.request ? { request: entry.request } : undefined,
			);
			latestCredentialIds = added.credentialIds;
			lastTouchedCredentialId = added.credentialId;
			deduplicatedCount += added.deduplicatedCount ?? 0;
			renumberedCredentialIds = renumberedCredentialIds || Boolean(added.renumberedCredentialIds);

			if (added.didAddCredential === false) {
				duplicateExistingCredentialIds.push(added.duplicateOfCredentialId ?? added.credentialId);
				continue;
			}

			successfulAdds.push(added);
		} catch (error: unknown) {
			failedAdds.push({
				ordinal: index + 1,
				message: getErrorMessage(error),
			});
		}
	}

	if (successfulAdds.length === 0 && duplicateExistingCredentialIds.length === 0) {
		const firstError = failedAdds[0]?.message ?? "No API keys were saved.";
		throw new Error(firstError);
	}

	const fallbackCredentialId =
		successfulAdds[successfulAdds.length - 1]?.credentialId ??
		duplicateExistingCredentialIds[0] ??
		lastTouchedCredentialId ??
		latestCredentialIds[0] ??
		provider;
	const totalCredentials = latestCredentialIds.length;

	const addSummary =
		successfulAdds.length > 0
			? successfulAdds.length === 1
				? `API key saved for ${provider}. ${successfulAdds[0]?.isBackupCredential ? `Stored as backup credential ${successfulAdds[0].credentialId}.` : `Stored as primary credential ${successfulAdds[0]?.credentialId}.`} Total credentials: ${totalCredentials}`
				: `Saved ${successfulAdds.length} API keys for ${provider}. Added credentials: ${successfulAdds.map((result) => result.credentialId).join(", ")}. Total credentials: ${totalCredentials}`
			: `No new API keys were added for ${provider}. Total credentials: ${totalCredentials}`;

	const detailParts: string[] = [];
	if (duplicateExistingCredentialIds.length > 0) {
		detailParts.push(
			`Skipped ${duplicateExistingCredentialIds.length} key${duplicateExistingCredentialIds.length === 1 ? "" : "s"} already present in ${provider}.`,
		);
	}
	if (parsedInput.duplicateCount > 0) {
		detailParts.push(
			`Skipped ${parsedInput.duplicateCount} duplicate line${parsedInput.duplicateCount === 1 ? "" : "s"}.`,
		);
	}
	if (parsedInput.requestOverrideCount && parsedInput.requestOverrideCount > 0) {
		detailParts.push(
			`Applied Cloudflare account-scoped base URL to ${parsedInput.requestOverrideCount} key${parsedInput.requestOverrideCount === 1 ? "" : "s"}.`,
		);
	}
	if (deduplicatedCount > 0) {
		detailParts.push(
			`Removed ${deduplicatedCount} existing duplicate credential${deduplicatedCount === 1 ? "" : "s"} from auth.json.`,
		);
	}
	if (renumberedCredentialIds) {
		detailParts.push("Renumbered credential IDs sequentially for this provider.");
	}
	if (parsedInput.ignoredLineCount > 0) {
		detailParts.push(
			`Ignored ${parsedInput.ignoredLineCount} empty/fence line${parsedInput.ignoredLineCount === 1 ? "" : "s"}.`,
		);
	}
	if (failedAdds.length > 0) {
		const failedOrdinals = failedAdds.map((entry) => `#${entry.ordinal}`).join(", ");
		detailParts.push(
			`Failed to save ${failedAdds.length} key${failedAdds.length === 1 ? "" : "s"} (${failedOrdinals}).`,
		);
	}

	return {
		message: detailParts.length > 0 ? `${addSummary} ${detailParts.join(" ")}` : addSummary,
		credentialId: fallbackCredentialId,
	};
}

async function addOpenAICodexImportsFromModal(
	accountManager: AccountManager,
	importInput: string,
): Promise<{ message: string; credentialId: string }> {
	const parsedResult = await parseOpenAICodexCredentialImportInput(importInput);
	if (!parsedResult.ok) {
		throw new Error(parsedResult.message);
	}

	const parsedInput = parsedResult.parsed;
	const successfulAdds: Array<{ credentialId: string; isBackupCredential: boolean; credentialIds: string[] }> = [];
	const updatedExistingCredentialIds: string[] = [];
	const failedAdds: Array<{ ordinal: number; message: string }> = [];
	let latestCredentialIds: string[] = [];
	let lastTouchedCredentialId: string | null = null;

	for (const [index, credential] of parsedInput.credentials.entries()) {
		try {
			const missingRefreshToken = credential.refresh.trim().length === 0;
			const added = await accountManager.addOAuthCredential(
				OPENAI_CODEX_IMPORT_PROVIDER_ID,
				credential,
				{
					backgroundExclusionReason: missingRefreshToken
						? "missing_refresh_token_on_import"
						: undefined,
				},
			);
			latestCredentialIds = added.credentialIds;
			lastTouchedCredentialId = added.credentialId;

			if (added.didAddCredential === false) {
				updatedExistingCredentialIds.push(added.duplicateOfCredentialId ?? added.credentialId);
				continue;
			}

			successfulAdds.push(added);
		} catch (error: unknown) {
			failedAdds.push({
				ordinal: index + 1,
				message: getErrorMessage(error),
			});
		}
	}

	if (successfulAdds.length === 0 && updatedExistingCredentialIds.length === 0) {
		const firstError = failedAdds[0]?.message ?? "No OpenAI Codex credentials were imported.";
		throw new Error(firstError);
	}

	const fallbackCredentialId =
		successfulAdds[successfulAdds.length - 1]?.credentialId ??
		updatedExistingCredentialIds[updatedExistingCredentialIds.length - 1] ??
		lastTouchedCredentialId ??
		latestCredentialIds[0] ??
		OPENAI_CODEX_IMPORT_PROVIDER_ID;
	const totalCredentials = latestCredentialIds.length;
	const importedCount = successfulAdds.length;
	const updatedCount = updatedExistingCredentialIds.length;
	const summaryParts: string[] = [];
	if (importedCount > 0) {
		summaryParts.push(
			importedCount === 1
				? `Imported OpenAI Codex credential ${successfulAdds[0]?.credentialId}.`
				: `Imported ${importedCount} OpenAI Codex credentials: ${successfulAdds.map((result) => result.credentialId).join(", ")}.`,
		);
	}
	if (updatedCount > 0) {
		summaryParts.push(
			`Updated ${updatedCount} existing OpenAI Codex credential${updatedCount === 1 ? "" : "s"}: ${updatedExistingCredentialIds.join(", ")}.`,
		);
	}
	summaryParts.push(`Total credentials: ${totalCredentials}`);

	const detailParts: string[] = [];
	if (parsedInput.duplicateCount > 0) {
		detailParts.push(
			`Skipped ${parsedInput.duplicateCount} duplicate import record${parsedInput.duplicateCount === 1 ? "" : "s"}.`,
		);
	}
	if (parsedInput.invalidRecordCount > 0) {
		const firstInvalid = parsedInput.invalidRecordMessages[0];
		detailParts.push(
			firstInvalid
				? `Skipped ${parsedInput.invalidRecordCount} invalid import record${parsedInput.invalidRecordCount === 1 ? "" : "s"}. First issue: ${firstInvalid}`
				: `Skipped ${parsedInput.invalidRecordCount} invalid import record${parsedInput.invalidRecordCount === 1 ? "" : "s"}.`,
		);
	}
	if (parsedInput.ignoredLineCount > 0) {
		detailParts.push(
			`Ignored ${parsedInput.ignoredLineCount} empty/fence line${parsedInput.ignoredLineCount === 1 ? "" : "s"}.`,
		);
	}
	if (failedAdds.length > 0) {
		const failedOrdinals = failedAdds.map((entry) => `#${entry.ordinal}`).join(", ");
		detailParts.push(
			`Failed to import ${failedAdds.length} credential${failedAdds.length === 1 ? "" : "s"} (${failedOrdinals}).`,
		);
	}

	return {
		message: detailParts.length > 0
			? `${summaryParts.join(" ")} ${detailParts.join(" ")}`
			: summaryParts.join(" "),
		credentialId: fallbackCredentialId,
	};
}

function createEmptyProviderStatus(provider: SupportedProviderId): ProviderStatus {
	return {
		provider,
		rotationMode: resolveDefaultRotationMode(provider),
		activeIndex: 0,
		manualActiveCredentialId: undefined,
		credentials: [],
	};
}

interface CachedUsageDisplayReader {
	hasUsageProvider?(provider: SupportedProviderId): boolean;
	getCachedCredentialUsageDisplaySnapshot(
		provider: SupportedProviderId,
		credentialId: string,
	): {
		snapshot: CredentialStatus["usageSnapshot"];
		error: string | null;
		displayOnly?: boolean;
	} | null;
}

export function hydrateStatusWithCachedUsage(
	accountManager: CachedUsageDisplayReader,
	status: ProviderStatus,
): ProviderStatus {
	if (accountManager.hasUsageProvider && !accountManager.hasUsageProvider(status.provider)) {
		return status;
	}

	let hasCachedUsage = false;
	const credentials = status.credentials.map((credential) => {
		const usage = accountManager.getCachedCredentialUsageDisplaySnapshot(
			status.provider,
			credential.credentialId,
		);
		if (!usage) {
			return credential;
		}

		hasCachedUsage = true;
		return {
			...credential,
			usageSnapshot: usage.snapshot,
			usageSnapshotDisplayOnly: usage.displayOnly,
			usageFetchError: usage.error ?? undefined,
		};
	});

	return hasCachedUsage ? { ...status, credentials } : status;
}

async function loadAllProviderStatuses(accountManager: AccountManager): Promise<ProviderStatus[]> {
	const providers = await accountManager.getSupportedProviders();
	const settled = await Promise.allSettled(
		providers.map(async (provider) => accountManager.getProviderStatus(provider, {
			allowExternalIdentityLookups: false,
		})),
	);

	return settled.map((result, index) => {
		const provider = providers[index];
		if (result?.status === "fulfilled") {
			return hydrateStatusWithCachedUsage(accountManager, result.value);
		}
		return createEmptyProviderStatus(provider);
	});
}

const FRAME_BORDER_ROWS = 2;
const THREE_PANE_CHROME_ROWS = 3;

export function resolveMultiAuthOverlayOptions(
	terminal?: { terminalColumns?: number | null; terminalRows?: number | null },
): ModalOverlayOptions {
	return resolveResponsiveOverlayOptions({
		...terminal,
		minimumWidth: 48,
		minimumHeight: 14,
		widthRatio: 0.98,
		heightRatio: 0.92,
	});
}

function resolveMultiAuthRuntimeOverlayOptions(): OverlayOptions {
	return resolveResponsiveOverlayRuntimeOptions({
		minimumWidth: 48,
		widthRatio: 0.98,
		heightRatio: 0.92,
	});
}

export function resolveMultiAuthContentRows(overlayOptions: Pick<ModalOverlayOptions, "maxHeight">): number {
	return Math.max(1, overlayOptions.maxHeight - FRAME_BORDER_ROWS);
}

class MultiAuthManagerModal {
	private statuses: ProviderStatus[];
	private selectedProviderId: SupportedProviderId | null = null;
	private selectedProviderPaneIndex = 0;
	private selectedEntryByProvider = new Map<SupportedProviderId, number>();
	private batchSelectedCredentialIdsByProvider = new Map<SupportedProviderId, Set<string>>();
	private focusedPane: FocusPane = "providers";
	private renameEditor: RenameEditorState | null = null;
	private busyMessage: string | null = null;
	private infoMessage: string | null = null;
	private isBusy = false;
	private readonly hiddenProviders: Set<SupportedProviderId>;
	private showHiddenProviders = false;
	private showDisabledAccounts = false;

	constructor(
		private readonly ctx: ExtensionCommandContext,
		private readonly accountManager: AccountManager,
		private readonly theme: ThemeLike,
		private readonly done: () => void,
		private readonly requestRender: () => void,
		private readonly modalVisibility: ModalVisibilityController,
		private readonly resolveMaxContentRows: () => number | null,
		initialStatuses: ProviderStatus[],
		initialHiddenProviders: SupportedProviderId[],
	) {
		this.statuses = initialStatuses;
		this.hiddenProviders = new Set(initialHiddenProviders);
		this.syncSelectionState(this.statuses[0]?.provider);
		if (this.statuses.length === 0) {
			this.isBusy = true;
			this.busyMessage = "Loading provider statuses...";
			void this.loadInitialState();
		}
	}

	private async loadInitialState(): Promise<void> {
		try {
			const [statuses, hiddenProviders] = await Promise.all([
				loadAllProviderStatuses(this.accountManager),
				this.accountManager.getHiddenProviders(),
			]);
			this.statuses = statuses;
			this.hiddenProviders.clear();
			for (const provider of hiddenProviders) {
				this.hiddenProviders.add(provider);
			}
			this.syncSelectionState(this.statuses[0]?.provider);
			this.infoMessage = "Provider statuses loaded.";
		} catch (error: unknown) {
			this.infoMessage = `Failed to load provider statuses: ${getErrorMessage(error)}`;
			this.ctx.ui.notify(this.infoMessage, "error");
		} finally {
			this.isBusy = false;
			this.busyMessage = null;
			this.requestRender();
		}
	}

	private getProviderVisibilitySummary(): ProviderVisibilitySummary<ProviderStatus> {
		return summarizeProviderVisibility(this.statuses, this.hiddenProviders, this.showHiddenProviders);
	}

	private hasAnyDisabledAccounts(): boolean {
		return this.statuses.some((status) =>
			status.credentials.some((credential) => Boolean(credential.disabledError)),
		);
	}

	private getDuplicateAccountIndicators(status: ProviderStatus): Map<string, DuplicateAccountIndicator> {
		const groups = new Map<string, DuplicateAccountIndicator>();
		for (const credential of status.credentials) {
			const email = normalizeDuplicateEmailKey(credential.identityEmail);
			let planType = credential.usageSnapshot?.planType;
			let planKey = normalizeDuplicatePlanKey(status.provider, planType);
			if (!planKey && credential.identityPlanType) {
				planType = credential.identityPlanType;
				planKey = normalizeDuplicatePlanKey(status.provider, planType);
			}
			if (!email || !planKey) {
				continue;
			}

			const groupKey = `${email}\u0000${planKey}`;
			const group = groups.get(groupKey);
			if (group) {
				group.credentialIds.push(credential.credentialId);
				continue;
			}

			groups.set(groupKey, {
				email,
				planLabel: normalizePlanLabel(planType),
				credentialIds: [credential.credentialId],
			});
		}

		const indicators = new Map<string, DuplicateAccountIndicator>();
		for (const group of groups.values()) {
			if (group.credentialIds.length <= 1) {
				continue;
			}
			for (const credentialId of group.credentialIds) {
				indicators.set(credentialId, group);
			}
		}
		return indicators;
	}

	private resolveNoProviderSelectedLines(): string[] {
		if (this.statuses.length === 0) {
			return ["No providers detected."];
		}

		const hiddenHint = formatHiddenProviderHint(this.getProviderVisibilitySummary());
		if (hiddenHint) {
			return ["No providers shown in the cleaner view.", hiddenHint];
		}

		return ["No provider selected."];
	}

	private getSelectedEntryKind(status: ProviderStatus | null): SelectedEntryKind {
		if (!status) {
			return "none";
		}
		return this.getSelectedEntry(status).kind;
	}

	private isSelectedAccountCookieQuotaCapable(status: ProviderStatus | null): boolean {
		if (!status || status.provider !== "opencode-go") {
			return false;
		}
		return this.getSelectedEntry(status).kind === "account";
	}

	render(width: number): string[] {
		const safeWidth = Math.max(1, Math.floor(width));
		const lines: string[] = [];
		const modalTitle = this.theme.fg(
			"accent",
			this.theme.bold(`${" ".repeat(MODAL_TITLE_LEFT_MARGIN)}Pi Multi Auth`),
		);
		const focusedPaneLabel = this.focusedPane === "providers" ? "Providers" : "Accounts";
		const runtimeStatus = this.busyMessage ?? this.infoMessage ?? `Focused pane: ${focusedPaneLabel}.`;
		const statusLines = this.buildStatusLines(runtimeStatus, safeWidth);
		const footerLines = this.buildFooterLines(safeWidth);
		const dashboardChromeRows = safeWidth >= THREE_PANE_MIN_WIDTH ? THREE_PANE_CHROME_ROWS : 0;
		const reservedRows =
			statusLines.length + footerLines.length + dashboardChromeRows + 3 + MODAL_TITLE_BOTTOM_MARGIN_ROWS;
		const bodyRowCount = resolveBodyRowBudget({
			defaultRows: GRID_BODY_ROW_COUNT,
			terminalRows: this.resolveMaxContentRows(),
			reservedRows,
			minimumRows: MIN_BODY_ROW_COUNT,
			fitAvailableRows: true,
		});
		const dashboardRows = this.renderDashboardRows(safeWidth, bodyRowCount);

		lines.push(normalizeInlineText(modalTitle));
		for (let index = 0; index < MODAL_TITLE_BOTTOM_MARGIN_ROWS; index += 1) {
			lines.push("");
		}
		for (const row of dashboardRows) {
			lines.push(normalizeInlineText(row));
		}
		lines.push("");
		for (const line of statusLines) {
			const safeLine = normalizeInlineText(line);
			lines.push(this.busyMessage ? this.theme.fg("warning", safeLine) : safeLine);
		}
		lines.push(horizontalRule(safeWidth));
		for (const line of footerLines) {
			lines.push(normalizeInlineText(line));
		}

		return lines;
	}

	private buildStatusLines(runtimeStatus: string, width: number): string[] {
		const lineWidth = Math.max(1, width);
		const wrapped = wrapTextToWidth(`Status: ${runtimeStatus}`, lineWidth);
		const lines = wrapped.length === 0 ? ["Status: idle."] : wrapped;
		const hiddenHint = formatHiddenProviderHint(this.getProviderVisibilitySummary());
		if (hiddenHint && !this.showHiddenProviders) {
			lines.push(...wrapTextToWidth(hiddenHint, lineWidth));
		}
		return lines;
	}

	private buildFooterLines(width: number): string[] {
		const lineWidth = Math.max(1, width);
		const selectedProviderStatus = this.getSelectedProviderStatus();
		const visibilitySummary = this.getProviderVisibilitySummary();
		const actions = resolveFooterActions({
			focusedPane: this.focusedPane,
			renameMode: this.renameEditor !== null,
			hasProviderSelection: selectedProviderStatus !== null,
			hasProviderCredentials: (selectedProviderStatus?.credentials.length ?? 0) > 0,
			selectedEntryKind: this.getSelectedEntryKind(selectedProviderStatus),
			selectedProviderPaneEntryKind: this.getSelectedProviderPaneEntryKind(),
			selectedProviderHidden:
				selectedProviderStatus !== null && this.hiddenProviders.has(selectedProviderStatus.provider),
			hasHiddenProviders: visibilitySummary.hiddenStatusCount > 0,
			showHiddenProviders: this.showHiddenProviders,
			hasDisabledAccounts: this.hasAnyDisabledAccounts(),
			showDisabledAccounts: this.showDisabledAccounts,
			hasBatchSelection:
				selectedProviderStatus !== null && this.getBatchSelectedCredentialIds(selectedProviderStatus).length > 0,
			selectedAccountMarked:
				selectedProviderStatus !== null && this.isSelectedAccountMarked(selectedProviderStatus),
			selectedAccountSupportsCookieQuota: this.isSelectedAccountCookieQuotaCapable(selectedProviderStatus),
		});
		const wrapped = renderWrappedFooterActions(actions, lineWidth);
		if (wrapped.length === 0) {
			return ["[Esc] Close"];
		}
		return wrapped;
	}

	invalidate(): void {
		// no-op; render is fully state driven.
	}

	handleInput(data: string): void {
		if (this.renameEditor) {
			this.renameEditor.input.handleInput(data);
			this.requestRender();
			return;
		}

		if (matchesKey(data, "escape") || matchesKey(data, "ctrl+c")) {
			this.done();
			return;
		}

		if (matchesKey(data, "left")) {
			this.switchPane(-1);
			this.requestRender();
			return;
		}

		if (matchesKey(data, "right")) {
			this.switchPane(1);
			this.requestRender();
			return;
		}

		if (matchesKey(data, "up")) {
			this.moveSelectionInFocusedPane(-1);
			this.requestRender();
			return;
		}

		if (matchesKey(data, "down")) {
			this.moveSelectionInFocusedPane(1);
			this.requestRender();
			return;
		}

		if (matchesKey(data, "return")) {
			this.activateSelectedEntry();
			return;
		}

		if (matchesKey(data, "a")) {
			this.addForSelectedProvider();
			return;
		}

		if ((data === " " || matchesKey(data, "space")) && this.focusedPane === "accounts") {
			this.toggleSelectedAccountBatchSelection();
			return;
		}

		if (matchesKey(data, "m") && this.focusedPane === "providers") {
			this.changeSelectedProviderRotationMode();
			return;
		}

		if (matchesKey(data, "r")) {
			this.renameSelectedAccount();
			return;
		}

		if (matchesKey(data, "d")) {
			this.deleteSelectedAccount();
			return;
		}

		if (matchesKey(data, "h")) {
			this.toggleSelectedProviderHidden();
			return;
		}

		if (matchesKey(data, "v")) {
			this.toggleShowHiddenProviders();
			return;
		}

		if (matchesKey(data, "x")) {
			this.toggleShowDisabledAccounts();
			return;
		}

		if (matchesKey(data, "e")) {
			this.reenableSelectedAccount();
			return;
		}

		if (matchesKey(data, "c")) {
			void this.configureSelectedOpenCodeGoQuota();
			return;
		}

		const refreshAction = resolveModalRefreshAction(
			data,
			this.focusedPane,
			this.getSelectedEntryKind(this.getSelectedProviderStatus()),
		);
		if (refreshAction === "selected-account") {
			this.refreshSelectedAccount();
			return;
		}
		if (refreshAction === "provider") {
			this.refreshSelectedProviderAccounts();
			return;
		}
	}

	private renderDashboardRows(availableWidth: number, bodyRowCount: number): string[] {
		if (availableWidth < THREE_PANE_MIN_WIDTH) {
			return this.renderStackedDashboardRows(availableWidth, bodyRowCount);
		}
		return this.renderThreePaneDashboardRows(availableWidth, bodyRowCount);
	}

	private renderThreePaneDashboardRows(availableWidth: number, bodyRowCount: number): string[] {
		const widths = splitPaneWidths(availableWidth);
		const selectedProviderStatus = this.getSelectedProviderStatus();
		const providerLines = this.buildProvidersPaneLines(widths.providers);
		const accountLines = this.buildAccountsPaneLines(selectedProviderStatus, widths.accounts);
		const selectedAccountLineIndex = selectedProviderStatus
			? this.getSelectedAccountLineIndex(selectedProviderStatus, widths.accounts)
			: 0;
		const visibleBodyRowCount = Math.max(0, bodyRowCount);
		const visibleAccountLines = getScrollableWindow(
			accountLines,
			selectedAccountLineIndex,
			visibleBodyRowCount,
		);
		const detailsContentWidth = getPaneContentWidth(widths.details);
		const detailsLines = this.buildDetailsPaneLines(selectedProviderStatus, detailsContentWidth);

		const providerHeaderCell = renderGridCell("Providers", widths.providers);
		const accountProviderLabel = selectedProviderStatus
			? formatProviderLabel(selectedProviderStatus.provider)
			: "none";
		const accountCountLabel = selectedProviderStatus
			? this.getVisibleCredentials(selectedProviderStatus).length.toString()
			: "0";
		const accountTitleText = `Accounts: ${accountProviderLabel} (${accountCountLabel})`;
		const accountHeaderCell = renderGridCell(accountTitleText, widths.accounts);
		const detailsHeaderCell = renderGridCell("Account Details", widths.details);
		const providerTitle =
			this.focusedPane === "providers"
				? this.theme.fg("accent", this.theme.bold(providerHeaderCell))
				: this.theme.fg("dim", providerHeaderCell);
		const accountTitle =
			this.focusedPane === "accounts"
				? this.theme.fg("accent", this.theme.bold(accountHeaderCell))
				: this.theme.fg("dim", accountHeaderCell);
		const detailsTitle = this.theme.fg("dim", detailsHeaderCell);

		const rows: string[] = [];
		rows.push(`${providerTitle}${BORDER_GLYPHS.vertical}${accountTitle}${BORDER_GLYPHS.vertical}${detailsTitle}`);
		rows.push(this.renderThreePaneDivider(widths, BORDER_GLYPHS.cross));

		for (let index = 0; index < visibleBodyRowCount; index += 1) {
			rows.push(
				this.renderThreePaneRow(
					widths,
					providerLines[index] ?? "",
					visibleAccountLines[index] ?? "",
					detailsLines[index] ?? "",
				),
			);
		}

		rows.push(this.renderThreePaneDivider(widths, BORDER_GLYPHS.teeUp));
		return rows;
	}

	private renderThreePaneRow(
		widths: PaneWidths,
		providerCell: string,
		accountCell: string,
		detailsCell: string,
	): string {
		return `${renderGridCell(providerCell, widths.providers)}${BORDER_GLYPHS.vertical}${renderGridCell(accountCell, widths.accounts)}${BORDER_GLYPHS.vertical}${renderGridCell(detailsCell, widths.details)}`;
	}

	private renderThreePaneDivider(widths: PaneWidths, centerJoint: string): string {
		const leftSegment = horizontalRule(widths.providers);
		const middleSegment = horizontalRule(widths.accounts);
		const rightSegment = horizontalRule(widths.details);
		return `${leftSegment}${centerJoint}${middleSegment}${centerJoint}${rightSegment}`;
	}

	private renderStackedDashboardRows(availableWidth: number, bodyRowCount: number): string[] {
		const selectedProviderStatus = this.getSelectedProviderStatus();
		const width = Math.max(1, availableWidth);
		const rows: string[] = [];
		rows.push(this.theme.fg("dim", "Providers"));
		for (const line of this.buildProvidersPaneLines(width)) {
			rows.push(line);
		}
		rows.push("");
		const providerLabel = selectedProviderStatus
			? formatProviderLabel(selectedProviderStatus.provider)
			: "none";
		const accountCountLabel = selectedProviderStatus
			? this.getVisibleCredentials(selectedProviderStatus).length.toString()
			: "0";
		rows.push(this.theme.fg("dim", `Accounts: ${providerLabel} (${accountCountLabel})`));
		for (const line of this.buildAccountsPaneLines(selectedProviderStatus, width)) {
			rows.push(line);
		}
		rows.push("");
		rows.push(this.theme.fg("dim", "Account Details"));
		for (const line of this.buildDetailsPaneLines(selectedProviderStatus, Math.max(1, width - 2))) {
			rows.push(line);
		}

		return clampRenderedRows(rows, bodyRowCount);
	}

	private buildProvidersPaneLines(columnWidth: number): string[] {
		const displayedStatuses = this.getDisplayedStatuses();
		const selectedEntry = this.getSelectedProviderPaneEntry(displayedStatuses);
		const contentWidth = Math.max(1, getPaneContentWidth(columnWidth));
		const lines = displayedStatuses.map((status, entryIndex) => {
			const isSelected =
				selectedEntry.kind === "provider" && selectedEntry.entryIndex === entryIndex;
			const cursor = isSelected ? "▶" : " ";
			const providerLabel = formatProviderLabel(status.provider);
			const shownCount = this.showDisabledAccounts
				? status.credentials.length
				: this.getVisibleCredentials(status).length;
			const badge = formatProviderBadge({
				isHidden: this.hiddenProviders.has(status.provider),
				isManual: Boolean(status.manualActiveCredentialId),
				visibleCount: shownCount,
				totalCount: status.credentials.length,
				maxWidth: Math.max(0, contentWidth - 6),
			});
			if (!badge) {
				return padRight(`${cursor} ${providerLabel}`, contentWidth);
			}

			const leftWidth = Math.max(1, contentWidth - visibleWidth(badge) - 1);
			if (leftWidth < 4) {
				return padRight(`${cursor} ${providerLabel}`, contentWidth);
			}
			const left = padRight(`${cursor} ${providerLabel}`, leftWidth);
			return padRight(`${left} ${badge}`, contentWidth);
		});
		const addCursor = selectedEntry.kind === "add" ? "▶" : " ";
		lines.push(
			padRight(contentWidth < 24 ? `${addCursor} + Add` : `${addCursor} + Add Provider`, contentWidth),
		);
		return lines;
	}

	private buildAccountEntryLines(
		credential: CredentialStatus,
		contentWidth: number,
		isSelected: boolean,
		isMarked: boolean,
		duplicateIndicator?: DuplicateAccountIndicator,
	): string[] {
		const lines = renderAccountEntryLines({
			credential,
			contentWidth,
			isSelected,
			isMarked,
			statusCell: this.getAccountStatusCell(credential, duplicateIndicator),
			formatPlanText: (text, planType) => this.colorizePlanText(text, planType),
			singleLine: true,
		});

		if (!credential.disabledError) {
			return lines;
		}

		return lines.map((line) => this.theme.fg("error", line));
	}

	private buildAccountsPaneLines(status: ProviderStatus | null, columnWidth: number): string[] {
		if (!status) {
			return this.resolveNoProviderSelectedLines();
		}

		const visibleCredentials = this.getVisibleCredentials(status);
		const selectedCredentialIds = new Set(this.getBatchSelectedCredentialIds(status));
		const contentWidth = Math.max(1, getPaneContentWidth(columnWidth));
		const selectedEntryIndex = this.getSelectedEntryIndex(status);
		const duplicateIndicators = this.getDuplicateAccountIndicators(status);
		const lines: string[] = [];
		for (const [index, credential] of visibleCredentials.entries()) {
			lines.push(
				...this.buildAccountEntryLines(
					credential,
					contentWidth,
					index === selectedEntryIndex,
					selectedCredentialIds.has(credential.credentialId),
					duplicateIndicators.get(credential.credentialId),
				),
			);
		}

		const addSelected = selectedEntryIndex === visibleCredentials.length;
		const addCursor = addSelected ? "▶" : " ";
		lines.push(
			padRight(
				contentWidth < 24 ? `${addCursor} + Add` : `${addCursor} + Add Backup Credential`,
				contentWidth,
			),
		);
		return lines;
	}

	private getSelectedAccountLineIndex(status: ProviderStatus, columnWidth: number): number {
		const visibleCredentials = this.getVisibleCredentials(status);
		const selectedEntryIndex = this.getSelectedEntryIndex(status);
		const contentWidth = Math.max(1, getPaneContentWidth(columnWidth));
		let lineIndex = 0;
		for (const [index, credential] of visibleCredentials.entries()) {
			if (index === selectedEntryIndex) {
				return lineIndex;
			}
			lineIndex += this.buildAccountEntryLines(
				credential,
				contentWidth,
				false,
				this.isCredentialBatchSelected(status.provider, credential.credentialId),
			).length;
		}
		return lineIndex;
	}

	private buildDetailsPaneLines(status: ProviderStatus | null, detailWidth: number): string[] {
		if (!status) {
			const lines = this.resolveNoProviderSelectedLines();
			return [lines[0] ?? "Select a provider to see details.", ...(lines[1] ? [lines[1]] : [])];
		}

		const safeDetailWidth = Math.max(1, detailWidth);
		if (safeDetailWidth < 12) {
			return [
				`Provider: ${formatProviderLabel(status.provider)}`,
				"Increase width for account details.",
			];
		}

		const selectedEntry = this.getSelectedEntry(status);
		if (selectedEntry.kind === "add") {
			const visibleCredentials = this.getVisibleCredentials(status);
			const disabledCount = status.credentials.length - visibleCredentials.length;
			const selectedForDeletion = this.getBatchSelectedCredentialIds(status);
			const hasVisibleAccounts = visibleCredentials.length > 0;
			const capabilities = this.accountManager.getProviderCapabilities(status.provider);
			const supportsImport = providerSupportsCredentialImport(status.provider);
			const addHint = capabilities.supportsOAuth
				? supportsImport
					? "Add backup via API key, OAuth login, or OmniOnboard/CPA/Sub2API JSON/CSV/ZIP import."
					: "Add backup via API key or OAuth login."
				: "Add backup via API key (batch mode opens a multiline editor; one key per line).";
			const lines = [
				`Provider: ${formatProviderLabel(status.provider)}`,
				`Rotation: ${formatRotationModeLabel(status.rotationMode)}`,
				hasVisibleAccounts ? addHint : `No visible credentials. ${addHint}`,
			];
			if (selectedForDeletion.length > 0) {
				lines.push(
					`Batch delete queue: ${selectedForDeletion.length} account${selectedForDeletion.length === 1 ? "" : "s"} selected. Press [d] to delete them.`,
				);
			}
			if (!this.showDisabledAccounts && disabledCount > 0) {
				lines.push(`Hidden disabled accounts: ${disabledCount}. Press [x] to show them.`);
			}
			lines.push("", "Press [Enter] or [a] to add a backup credential.", "Press [←]/[→] to switch pane focus.");
			return lines;
		}

		const selectedCredential = selectedEntry.credential;
		const duplicateIndicator = this.getDuplicateAccountIndicators(status).get(selectedCredential.credentialId);
		const batchSelectionCount = this.getBatchSelectedCredentialIds(status).length;
		const state = this.getCredentialState(selectedCredential);
		const planType = selectedCredential.usageSnapshot?.planType;
		const planLabel = this.colorizePlanText(
			formatPlanDetailLabel(planType, Boolean(selectedCredential.usageSnapshotDisplayOnly)),
			planType,
		);
		const hasUsageApi = this.accountManager.hasUsageProvider(status.provider);
		const selectionMode = selectedCredential.isManualActive
			? "Manual active (persists across sessions/restarts)"
			: "Automatic";
		const duplicatePeerCount = duplicateIndicator
			? duplicateIndicator.credentialIds.length - 1
			: 0;
		const duplicateDetailLine = duplicateIndicator
			? `Duplicate: ${this.theme.fg(
				"warning",
				[
					`Same email+plan as ${duplicatePeerCount} other account${duplicatePeerCount === 1 ? "" : "s"}`,
					`(${duplicateIndicator.email}, ${duplicateIndicator.planLabel})`,
				].join(" "),
			)}`
			: null;
		const detailLines: string[] = [
			`Name:      ${formatCredentialDisplayName(selectedCredential.credentialId, selectedCredential.friendlyName)}`,
			`ID:        ${selectedCredential.credentialId}`,
			`Type:      ${selectedCredential.credentialType}`,
			`Auth:      ${selectedCredential.redactedSecret}`,
			...(hasUsageApi ? [`Plan:      ${planLabel}`] : []),
			`State:     ${state.label}`,
			`Selection: ${selectionMode}`,
			`Marked:    ${this.isCredentialBatchSelected(status.provider, selectedCredential.credentialId) ? "Batch delete queue" : "No"}`,
			`Rotation:  ${formatRotationModeLabel(status.rotationMode)}`,
			`Usage:     ${selectedCredential.usageCount} usage units`,
			...(duplicateDetailLine ? [duplicateDetailLine] : []),
			...(selectedCredential.opencodeGoWorkspaceId
				? [`Quota:     workspace ${selectedCredential.opencodeGoWorkspaceId} (cookie set, [c] to edit)`]
				: status.provider === "opencode-go"
					? [`Quota:     ${this.theme.fg("warning", "no cookie configured (press [c])")}`]
					: []),
		];
		if (hasUsageApi) {
			detailLines.push(
				"",
				`${BORDER_GLYPHS.horizontal.repeat(2)} Usage & Quota ${BORDER_GLYPHS.horizontal.repeat(2)}`,
				...this.buildUsageDetailLines(selectedCredential, safeDetailWidth),
			);
		}
		if (batchSelectionCount > 0) {
			detailLines.push("");
			detailLines.push(
				`Batch delete queue: ${batchSelectionCount} account${batchSelectionCount === 1 ? "" : "s"} selected. Press [Space] to toggle this account and [d] to delete the queue.`,
			);
		}
		if (selectedCredential.disabledError) {
			detailLines.push("");
			detailLines.push(`${BORDER_GLYPHS.horizontal.repeat(2)} Disabled Reason ${BORDER_GLYPHS.horizontal.repeat(2)}`);
			detailLines.push(selectedCredential.disabledError);
			detailLines.push("Press [e] to re-enable this account.");
		}

		// Show cooldown/error details when a credential is exhausted
		const now = Date.now();
		const isExhausted =
			typeof selectedCredential.quotaExhaustedUntil === "number" &&
			selectedCredential.quotaExhaustedUntil > now;
		if (isExhausted && selectedCredential.lastTransientError) {
			detailLines.push("");
			detailLines.push(`${BORDER_GLYPHS.horizontal.repeat(2)} Transient Error ${BORDER_GLYPHS.horizontal.repeat(2)}`);
			detailLines.push(selectedCredential.lastTransientError);
			if (selectedCredential.transientErrorCount && selectedCredential.transientErrorCount > 0) {
				const cooldownSeconds = Math.max(
					1,
					Math.round((selectedCredential.quotaExhaustedUntil! - now) / 1000),
				);
				detailLines.push(`(Transient attempt ${selectedCredential.transientErrorCount}, cooldown: ~${cooldownSeconds}s)`);
			}
		} else if (isExhausted && selectedCredential.lastQuotaError) {
			detailLines.push("");
			detailLines.push(`${BORDER_GLYPHS.horizontal.repeat(2)} Quota Error ${BORDER_GLYPHS.horizontal.repeat(2)}`);
			detailLines.push(selectedCredential.lastQuotaError);
			if (selectedCredential.weeklyQuotaAttempts && selectedCredential.weeklyQuotaAttempts > 0) {
				const cooldownHours = Math.round((selectedCredential.quotaExhaustedUntil! - now) / (60 * 60 * 1000));
				detailLines.push(`(Weekly quota attempt ${selectedCredential.weeklyQuotaAttempts}, cooldown: ~${cooldownHours}h)`);
			}
		}

		if (
			this.renameEditor &&
			this.renameEditor.provider === status.provider &&
			this.renameEditor.credentialId === selectedCredential.credentialId
		) {
			const inputWidth = Math.max(8, safeDetailWidth - 2);
			const inputLine = this.renameEditor.input.render(inputWidth)[0] ?? "";
			return [
				"Rename account (Enter: save, Esc: cancel):",
				`> ${inputLine}`,
				"",
				...detailLines,
			];
		}

		return detailLines;
	}

	private buildUsageAdvisoryLines(credential: CredentialStatus, detailWidth: number): string[] {
		const lines = credential.usageSnapshotDisplayOnly ? ["Last known usage data."] : [];
		if (credential.usageFetchError) {
			lines.push(...wrapDetailMessageLines(credential.usageFetchError, detailWidth));
		}
		return lines;
	}

	private buildUsageDetailLines(credential: CredentialStatus, detailWidth: number): string[] {
		const snapshot = credential.usageSnapshot;
		if (!snapshot) {
			if (credential.usageFetchError) {
				return buildUsageUnavailableLines(credential.usageFetchError, detailWidth);
			}
			return buildMissingUsageDetailLines(detailWidth);
		}

		const barWidth = clamp(Math.floor(detailWidth * 0.45), 10, 26);
		const usageAdvisoryLines = this.buildUsageAdvisoryLines(credential, detailWidth);
		if (snapshot.copilotQuota) {
			const lines: string[] = [...usageAdvisoryLines];
			const chat = snapshot.copilotQuota.chat;
			lines.push("Chat Completions");
			lines.push(renderProgressBar(chat.percentUsed, barWidth));
			if (chat.unlimited) {
				lines.push("Unlimited (∞)");
			} else if (typeof chat.used === "number" && typeof chat.total === "number") {
				const reset = formatResetCountdown(snapshot.copilotQuota.resetAt);
				const resetText = reset === "n/a" ? "" : ` • Resets in ${reset}`;
				lines.push(`${chat.used}/${chat.total} used${resetText}`);
			}

			const completions = snapshot.copilotQuota.completions;
			if (completions) {
				lines.push("");
				lines.push("Code Completions");
				lines.push(renderProgressBar(completions.percentUsed, barWidth));
				if (completions.unlimited) {
					lines.push("Unlimited (∞)");
				} else if (
					typeof completions.used === "number" &&
					typeof completions.total === "number"
				) {
					lines.push(`${completions.used}/${completions.total} used`);
				}
			}
			return lines;
		}

		const lines: string[] = [...usageAdvisoryLines];
		if (snapshot.primary) {
			lines.push(resolveUsageWindowLabel(snapshot, "primary"));
			lines.push(renderProgressBar(snapshot.primary.usedPercent, barWidth));
			const reset = formatResetCountdown(snapshot.primary.resetsAt);
			if (reset !== "n/a") {
				lines.push(`Resets in ${reset}`);
			}
		}
		if (snapshot.secondary) {
			if (lines.length > 0) {
				lines.push("");
			}
			lines.push(resolveUsageWindowLabel(snapshot, "secondary"));
			lines.push(renderProgressBar(snapshot.secondary.usedPercent, barWidth));
			if (snapshot.provider === "blazeapi" && snapshot.credits?.balance) {
				lines.push(snapshot.credits.balance);
			}
			const reset = formatResetCountdown(snapshot.secondary.resetsAt);
			if (reset !== "n/a") {
				lines.push(`Resets in ${reset}`);
			}
		}
		if (lines.length === usageAdvisoryLines.length) {
			lines.push("Usage unavailable");
		}
		return lines;
	}

	private colorizePlanText(text: string, planType: string | null | undefined): string {
		return this.theme.fg(getPlanHighlightColor(planType), text);
	}

	private getAccountStatusCell(
		credential: CredentialStatus,
		duplicateIndicator?: DuplicateAccountIndicator,
	): string {
		const state = this.getCredentialState(credential);
		const statusCell = state.label === "Ready" || state.label === "Active" || state.label === "Manual"
			? "[●]"
			: "[○]";
		if (!duplicateIndicator) {
			return statusCell;
		}
		return `${statusCell} ${this.theme.fg("warning", "[DUP]")}`;
	}

	private static readonly EXHAUSTED_QUOTA_ERROR_THRESHOLD = 5;

	private getCredentialState(credential: CredentialStatus): { symbol: string; label: string } {
		const now = Date.now();
		if (credential.disabledError) {
			return { symbol: "◌", label: "Disabled" };
		}
		if (credential.isManualActive) {
			return { symbol: "◆", label: "Manual" };
		}
		if (credential.isActive) {
			return { symbol: "●", label: "Active" };
		}
		if (credential.isExpired) {
			return { symbol: "◌", label: "Expired" };
		}
		if (
			typeof credential.quotaExhaustedUntil === "number" &&
			credential.quotaExhaustedUntil > now
		) {
			return { symbol: "◌", label: "Exhaust" };
		}
		// Detect dead credentials that accumulated repeated quota errors
		// and never recovered (e.g. prepaid credits permanently depleted).
		// lastQuotaError is cleared on success, so if it's still set the
		// last operation failed with a quota/rate-limit error.
		if (
			typeof credential.quotaErrorCount === "number" &&
			credential.quotaErrorCount >= MultiAuthManagerModal.EXHAUSTED_QUOTA_ERROR_THRESHOLD &&
			typeof credential.lastQuotaError === "string" &&
			credential.lastQuotaError.length > 0
		) {
			return { symbol: "◌", label: "Exhaust" };
		}
		return { symbol: "○", label: "Ready" };
	}

	private switchPane(direction: -1 | 1): void {
		if (direction > 0) {
			this.focusedPane = this.focusedPane === "providers" ? "accounts" : "providers";
			return;
		}
		this.focusedPane = this.focusedPane === "accounts" ? "providers" : "accounts";
	}

	private moveSelectionInFocusedPane(direction: -1 | 1): void {
		if (this.focusedPane === "providers") {
			this.moveProviderSelection(direction);
			return;
		}
		this.moveAccountSelection(direction);
	}

	private moveProviderSelection(direction: -1 | 1): void {
		const displayedStatuses = this.getDisplayedStatuses();
		const entryCount = this.getProviderPaneEntryCount(displayedStatuses);
		const currentIndex = this.getSelectedProviderPaneEntryIndex(displayedStatuses);
		const nextIndex = (currentIndex + direction + entryCount) % entryCount;
		this.selectedProviderPaneIndex = nextIndex;
		const nextStatus = displayedStatuses[nextIndex];
		if (nextStatus) {
			this.selectedProviderId = nextStatus.provider;
		}
	}

	private moveAccountSelection(direction: -1 | 1): void {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}

		const entryCount = this.getEntryCount(status);
		if (entryCount <= 0) {
			return;
		}

		const currentIndex = this.getSelectedEntryIndex(status);
		const nextIndex = (currentIndex + direction + entryCount) % entryCount;
		this.selectedEntryByProvider.set(status.provider, nextIndex);
	}

	private activateSelectedEntry(): void {
		if (this.focusedPane === "providers") {
			const selectedProviderEntry = this.getSelectedProviderPaneEntry();
			if (selectedProviderEntry.kind === "add") {
				this.addProviderFromProvidersPane(this.resolveProviderPaneAddSelection());
				return;
			}
			this.selectedProviderId = selectedProviderEntry.provider;
			this.focusedPane = "accounts";
			this.infoMessage = "Focused Accounts pane.";
			this.requestRender();
			return;
		}

		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}

		const selectedEntry = this.getSelectedEntry(status);
		if (selectedEntry.kind === "add") {
			this.addAccount(status.provider);
			return;
		}

		const selectedCredentialLabel = formatCredentialDisplayName(
			selectedEntry.credential.credentialId,
			selectedEntry.credential.friendlyName,
		);
		const preserveSelection: SelectionAnchor = {
			provider: status.provider,
			kind: "account",
			credentialId: selectedEntry.credential.credentialId,
		};

		if (selectedEntry.credential.disabledError) {
			this.ctx.ui.notify(
				`${selectedCredentialLabel} is disabled and cannot be activated. Press [e] to re-enable it first.`,
				"warning",
			);
			return;
		}

		if (selectedEntry.credential.isManualActive) {
			this.runAction(`Clearing manual active account for ${status.provider}...`, async () => {
				await this.accountManager.clearManualActiveCredential(status.provider);
				await this.reloadStatuses(preserveSelection);
				return `Manual active account lock cleared for ${selectedCredentialLabel}. Extension-managed rotation is now enabled.`;
			});
			return;
		}

		this.runAction(`Setting manual active account for ${status.provider}...`, async () => {
			await this.accountManager.switchActiveCredential(status.provider, selectedEntry.credential.index);
			await this.reloadStatuses(preserveSelection);
			return `Manual active account set to ${selectedCredentialLabel}. This selection now persists across sessions and restarts.`;
		});
	}

	private toggleSelectedProviderHidden(): void {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			this.ctx.ui.notify("No provider selected.", "warning");
			return;
		}

		const shouldHide = !this.hiddenProviders.has(status.provider);
		this.runAction(
			shouldHide ? `Hiding provider ${status.provider}...` : `Showing provider ${status.provider}...`,
			async () => {
				const isHidden = await this.accountManager.setProviderHidden(status.provider, shouldHide);
				if (isHidden) {
					this.hiddenProviders.add(status.provider);
				} else {
					this.hiddenProviders.delete(status.provider);
				}

				this.syncSelectionState(status.provider);
				return isHidden
					? `Provider ${status.provider} is hidden from the modal. Press [v] to temporarily reveal hidden or empty providers.`
					: `Provider ${status.provider} is visible in the modal again.`;
			},
		);
	}

	private changeSelectedProviderRotationMode(): void {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			this.ctx.ui.notify("No provider selected.", "warning");
			return;
		}

		const preserveSelection = this.getCurrentSelectionAnchor() ?? {
			provider: status.provider,
			kind: "add" as const,
		};

		this.runAction(`Updating rotation mode for ${status.provider}...`, async () => {
			return this.modalVisibility.withHidden(async () => {
				const balancerAvailable = await this.accountManager.shouldUseBalancerMode(status.provider);
				const modes = resolveSelectableRotationModes(status.rotationMode, balancerAvailable);
				const options = modes.map((mode) => ({
					mode,
					label:
						mode === status.rotationMode
							? `${formatRotationModeLabel(mode)} (current)`
							: formatRotationModeLabel(mode),
				}));
				const pickedLabel = await this.ctx.ui.select(
					`Rotation mode for ${status.provider}`,
					options.map((option) => option.label),
				);
				if (!pickedLabel) {
					return "Rotation mode change cancelled.";
				}

				const picked = options.find((option) => option.label === pickedLabel);
				if (!picked || picked.mode === status.rotationMode) {
					return "Rotation mode unchanged.";
				}

				await this.accountManager.setRotationMode(status.provider, picked.mode);
				await this.reloadStatuses(preserveSelection);
				return `Rotation mode for ${status.provider} set to ${formatRotationModeLabel(picked.mode)}.`;
			});
		});
	}

	private toggleShowHiddenProviders(): void {
		this.showHiddenProviders = !this.showHiddenProviders;
		this.syncSelectionState(this.selectedProviderId ?? undefined);
		this.infoMessage = this.showHiddenProviders
			? "Showing hidden and empty providers. Press [h] on a provider to unhide it permanently."
			: "Showing only configured providers with credentials.";
		this.requestRender();
	}

	private toggleShowDisabledAccounts(): void {
		this.showDisabledAccounts = !this.showDisabledAccounts;
		this.syncSelectionState(this.selectedProviderId ?? undefined);
		this.infoMessage = this.showDisabledAccounts
			? "Showing disabled accounts."
			: "Hiding disabled accounts.";
		this.requestRender();
	}

	private reenableSelectedAccount(): void {
		if (this.focusedPane === "providers") {
			return;
		}

		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}

		const selectedEntry = this.getSelectedEntry(status);
		if (selectedEntry.kind === "add") {
			return;
		}

		const credential = selectedEntry.credential;
		if (!credential.disabledError) {
			this.ctx.ui.notify("Selected account is not disabled.", "warning");
			return;
		}

		const credentialLabel = formatCredentialDisplayName(credential.credentialId, credential.friendlyName);
		const preserveSelection: SelectionAnchor = {
			provider: status.provider,
			kind: "account",
			credentialId: credential.credentialId,
		};

		this.runAction(`Re-enabling ${credentialLabel}...`, async () => {
			await this.accountManager.reenableCredential(status.provider, credential.credentialId);
			await this.reloadStatuses(preserveSelection);
			return `Re-enabled ${credentialLabel} for ${status.provider}. The account will now participate in rotation.`;
		});
	}

	private addForSelectedProvider(): void {
		if (this.focusedPane === "providers") {
			this.addProviderFromProvidersPane(this.resolveProviderPaneAddSelection());
			return;
		}
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}
		this.addAccount(status.provider);
	}

	private addProviderFromProvidersPane(selectedProvider: SupportedProviderId): void {
		this.runAction("Adding provider...", async () => {
			return this.modalVisibility.withHidden(async () => {
				const target = await this.promptForProviderPaneAddTarget(selectedProvider);
				if (!target) {
					return "Add provider cancelled.";
				}
				return this.addCredentialForProvider(target.provider, target.method);
			});
		});
	}

	private addAccount(provider: SupportedProviderId): void {
		this.runAction(`Adding credential for ${provider}...`, async () => {
			return this.modalVisibility.withHidden(async () => {
				const selectedMethod = await this.promptForAddMethod(provider);
				if (!selectedMethod) {
					return "Add credential cancelled.";
				}
				return this.addCredentialForProvider(provider, selectedMethod);
			});
		});
	}

	private async promptForAddMethod(provider: SupportedProviderId): Promise<AddProviderMethod | null> {
		const capabilities = this.accountManager.getProviderCapabilities(provider);
		const methods: Array<{ label: string; value: AddProviderMethod }> = [
			{ label: "API key", value: "api_key" },
		];
		if (capabilities.supportsOAuth) {
			methods.push({ label: "OAuth login", value: "oauth" });
		}
		if (providerSupportsCredentialImport(provider)) {
			methods.push({ label: "Import OmniOnboard/CPA/Sub2API JSON/CSV/ZIP", value: "import" });
		}
		if (methods.length === 1) {
			return methods[0]?.value ?? null;
		}
		return this.selectAddMethod(`Add backup credential for ${provider}`, methods);
	}

	private async promptForProviderPaneAddTarget(
		selectedProvider: SupportedProviderId,
	): Promise<{ provider: SupportedProviderId; method: AddProviderMethod } | null> {
		const selectedMethod = await this.selectAddMethod("Add provider", [
			{ label: "Use API key", value: "api_key" },
			{ label: "Use OAuth login", value: "oauth" },
			{ label: "Import OmniOnboard/CPA/Sub2API JSON/CSV/ZIP", value: "import" },
		]);
		if (!selectedMethod) {
			return null;
		}
		if (selectedMethod === "import") {
			return { provider: OPENAI_CODEX_IMPORT_PROVIDER_ID, method: selectedMethod };
		}
		if (selectedMethod === "oauth") {
			const provider = await this.promptForOAuthProviderSelection(selectedProvider);
			return provider ? { provider, method: selectedMethod } : null;
		}
		const provider = await this.promptForApiKeyProviderSelection(selectedProvider);
		return provider ? { provider, method: selectedMethod } : null;
	}

	private async selectAddMethod(
		title: string,
		methods: readonly { label: string; value: AddProviderMethod }[],
	): Promise<AddProviderMethod | null> {
		const pickedLabel = await this.ctx.ui.select(
			title,
			methods.map((method) => method.label),
		);
		if (!pickedLabel) {
			return null;
		}
		return methods.find((method) => method.label === pickedLabel)?.value ?? null;
	}

	private async promptForOAuthProviderSelection(
		selectedProvider: SupportedProviderId,
	): Promise<SupportedProviderId | null> {
		const options = buildSmartOAuthProviderOptions(
			this.accountManager.getAvailableOAuthProviders(),
			this.statuses,
			selectedProvider,
		);
		if (options.length === 0) {
			throw new Error("No OAuth providers are currently available.");
		}
		const pickedProvider = await runProviderConfigurationDialog(this.ctx, {
			mode: "oauth",
			selectedProvider,
			options: options.map((option) => ({
				provider: option.provider,
				name: option.name,
				isConfigured: option.isConfigured,
				isSelected: option.isSelected,
				credentialCount: option.credentialCount,
			})),
		});
		if (!pickedProvider) {
			return null;
		}
		const selectedOption = options.find((option) => option.provider === pickedProvider);
		if (!selectedOption) {
			throw new Error("Selected OAuth provider is no longer available.");
		}
		return selectedOption.provider;
	}

	private async promptForApiKeyProviderSelection(
		selectedProvider: SupportedProviderId,
	): Promise<SupportedProviderId | null> {
		const supportedProviders = await this.accountManager.getAvailableApiKeyProviders();
		const options = buildSmartApiKeyProviderOptions(
			this.statuses,
			selectedProvider,
			supportedProviders,
		);
		const pickedProvider = await runProviderConfigurationDialog(this.ctx, {
			mode: "api_key",
			selectedProvider,
			options: options.map((option) => ({
				provider: option.provider,
				name: option.name,
				isConfigured: option.isConfigured,
				isSelected: option.isSelected,
				credentialCount: option.credentialCount,
			})),
		});
		if (!pickedProvider) {
			return null;
		}
		const selectedOption = options.find((option) => option.provider === pickedProvider);
		if (!selectedOption) {
			throw new Error("Selected provider is no longer available.");
		}
		if (selectedOption.provider !== CUSTOM_PROVIDER_NAME_OPTION) {
			return selectedOption.provider;
		}
		const knownProviderIds = options
			.map((option) => option.provider)
			.filter((provider): provider is SupportedProviderId => provider !== CUSTOM_PROVIDER_NAME_OPTION);
		return this.promptForCustomApiKeyProvider(selectedProvider, knownProviderIds);
	}

	private async promptForCustomApiKeyProvider(
		selectedProvider: SupportedProviderId,
		knownProviderIds: readonly SupportedProviderId[] = this.getKnownProviderIds(),
	): Promise<SupportedProviderId | null> {
		const providerInput = await this.ctx.ui.input(
			"Enter custom provider name:",
			selectedProvider,
		);
		if (!providerInput) {
			return null;
		}
		const normalizedProvider = normalizeProviderSelectionInput(
			providerInput,
			this.getKnownProviderIds(knownProviderIds),
		);
		if (!normalizedProvider.ok) {
			throw new Error(normalizedProvider.message);
		}
		return normalizedProvider.value;
	}

	private getKnownProviderIds(extraProviderIds: readonly SupportedProviderId[] = []): SupportedProviderId[] {
		const orderedProviders: SupportedProviderId[] = [];
		const pushUnique = (provider: SupportedProviderId): void => {
			if (!provider || orderedProviders.includes(provider)) {
				return;
			}
			orderedProviders.push(provider);
		};
		for (const status of this.statuses) {
			pushUnique(status.provider);
		}
		for (const provider of this.accountManager.getAvailableOAuthProviders()) {
			pushUnique(provider.provider);
		}
		for (const provider of extraProviderIds) {
			pushUnique(provider);
		}
		return orderedProviders;
	}

	private async addCredentialForProvider(
		provider: SupportedProviderId,
		method: AddProviderMethod,
	): Promise<string> {
		const result = method === "oauth"
			? await loginProviderFromModal(this.ctx, this.accountManager, provider)
			: method === "import"
				? await this.addOpenAICodexImportCredentialsForProvider(provider)
				: await this.addApiKeyCredentialForProvider(provider);
		if (!result) {
			if (method === "import") {
				return "Import cancelled.";
			}
			return method === "oauth" ? "OAuth login cancelled." : "API key add cancelled.";
		}
		await this.reloadStatuses({
			provider,
			kind: "account",
			credentialId: result.credentialId,
		});
		return result.message;
	}

	private async addApiKeyCredentialForProvider(
		provider: SupportedProviderId,
	): Promise<{ message: string; credentialId: string } | null> {
		const capabilities = this.accountManager.getProviderCapabilities(provider);
		const supportsBatchAdd = !capabilities.supportsOAuth;
		const cloudflareHint = isCloudflareWorkersAiProvider(provider)
			? " Include an account ID, dashboard token URL, or Workers AI base URL to skip account discovery."
			: "";
		const apiKeyInput = supportsBatchAdd
			? await this.ctx.ui.editor(`Paste API key(s) for ${provider} (one per line).${cloudflareHint}`)
			: await this.ctx.ui.input(`Paste API key for ${provider}.${cloudflareHint}`);
		if (!apiKeyInput) {
			return null;
		}
		return addApiKeysFromModal(this.accountManager, provider, apiKeyInput, supportsBatchAdd);
	}

	private async addOpenAICodexImportCredentialsForProvider(
		provider: SupportedProviderId,
	): Promise<{ message: string; credentialId: string } | null> {
		if (!providerSupportsCredentialImport(provider)) {
			throw new Error("Credential import is only supported for openai-codex.");
		}
		const importInput = await this.ctx.ui.editor(
			"Paste OpenAI Codex OmniOnboard/CPA/Sub2API JSON/CSV, or a path to a .zip export.",
		);
		if (!importInput) {
			return null;
		}
		return addOpenAICodexImportsFromModal(this.accountManager, importInput);
	}

	private renameSelectedAccount(): void {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}
		const selectedEntry = this.getSelectedEntry(status);
		if (selectedEntry.kind !== "account") {
			this.ctx.ui.notify("Select an account to rename.", "warning");
			return;
		}
		this.startRenameEditor(status.provider, selectedEntry.credential);
	}

	private async configureSelectedOpenCodeGoQuota(): Promise<void> {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}
		if (status.provider !== "opencode-go") {
			this.ctx.ui.notify(
				"Cookie-based quota lookup only applies to OpenCode Go accounts.",
				"warning",
			);
			return;
		}
		const selectedEntry = this.getSelectedEntry(status);
		if (selectedEntry.kind !== "account") {
			this.ctx.ui.notify("Select an OpenCode Go account to configure its quota lookup.", "warning");
			return;
		}
		const credential = selectedEntry.credential;
		const credentialLabel = formatCredentialDisplayName(credential.credentialId, credential.friendlyName);

		let current: { workspaceId: string; cookie: string };
		try {
			const stored = await this.accountManager.getOpenCodeGoQuotaConfig(status.provider, credential.credentialId);
			current = stored ?? { workspaceId: "", cookie: "" };
		} catch (error) {
			this.ctx.ui.notify(`Failed to read OpenCode Go quota config: ${getErrorMessage(error)}`, "error");
			return;
		}

		const configuredHint = current.workspaceId
			? `Current workspace: ${current.workspaceId} (cookie set).`
			: "No workspace id or cookie configured yet.";
		this.ctx.ui.notify(`OpenCode Go quota for ${credentialLabel}. ${configuredHint}`, "info");

		const workspaceIdInput = await this.ctx.ui.input(
			"OpenCode Go workspace id (e.g. wrk_01EXAMPLE0EXAMPLE0EXAMPLE0EXAMPL):",
			current.workspaceId,
		);
		if (workspaceIdInput === undefined) {
			this.ctx.ui.notify("OpenCode Go quota config cancelled.", "warning");
			return;
		}
		const workspaceId = workspaceIdInput.trim();

		const cookiePrompt = workspaceId
			? `Paste the OpenCode Go dashboard \`auth\` cookie for ${workspaceId}.
It looks like \`Fe26.2**…\` (browser devtools → Cookies → opencode.ai → \`auth\`).
Leave blank and save to clear the stored cookie.`
			: "Leave blank and save to clear the stored workspace id and cookie.";
		const cookieInput = await this.ctx.ui.editor(cookiePrompt, current.cookie);
		if (cookieInput === undefined) {
			this.ctx.ui.notify("OpenCode Go quota config cancelled.", "warning");
			return;
		}
		// The editor may wrap the pasted cookie; collapse stray whitespace/newlines.
		const cookie = cookieInput.replace(/\s+/g, "").trim();

		const preserveSelection: SelectionAnchor = {
			provider: status.provider,
			kind: "account",
			credentialId: credential.credentialId,
		};
		this.runAction(`Saving OpenCode Go quota config for ${credentialLabel}...`, async () => {
			const persisted = await this.accountManager.setOpenCodeGoQuotaConfig(
				status.provider,
				credential.credentialId,
				workspaceId,
				cookie,
			);
			await this.reloadStatuses(preserveSelection);
			if (!persisted) {
				return `Cleared OpenCode Go quota lookup for ${credentialLabel}.`;
			}
			return `Saved OpenCode Go quota config for ${credentialLabel} (workspace ${persisted.workspaceId}).`;
		});
	}

	private startRenameEditor(provider: SupportedProviderId, credential: CredentialStatus): void {
		if (this.isBusy) {
			this.ctx.ui.notify("Wait for the current action to finish.", "warning");
			return;
		}

		const input = new Input();
		input.focused = true;
		input.setValue(credential.friendlyName ?? credential.credentialId);

		input.onSubmit = (value: string) => {
			const preserveSelection: SelectionAnchor = {
				provider,
				kind: "account",
				credentialId: credential.credentialId,
			};
			this.renameEditor = null;
			this.runAction(`Renaming ${credential.credentialId}...`, async () => {
				const storedValue = await this.accountManager.setFriendlyName(
					provider,
					credential.credentialId,
					value,
				);
				await this.reloadStatuses(preserveSelection);
				return storedValue === credential.credentialId
					? `Account name reset to credential ID (${credential.credentialId}).`
					: `Account renamed to '${storedValue}'.`;
			});
		};

		input.onEscape = () => {
			this.renameEditor = null;
			this.infoMessage = "Rename cancelled.";
			this.requestRender();
		};

		this.renameEditor = {
			provider,
			credentialId: credential.credentialId,
			input,
		};
		this.requestRender();
	}

	private toggleSelectedAccountBatchSelection(): void {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}

		const selectedEntry = this.getSelectedEntry(status);
		if (selectedEntry.kind !== "account") {
			this.ctx.ui.notify("Select an account to add or remove it from the batch delete queue.", "warning");
			return;
		}

		const nextSelection = toggleBatchSelection(
			this.getBatchSelectedCredentialIdSet(status),
			selectedEntry.credential.credentialId,
		);
		this.batchSelectedCredentialIdsByProvider.set(status.provider, nextSelection);
		const displayName = formatCredentialDisplayName(
			selectedEntry.credential.credentialId,
			selectedEntry.credential.friendlyName,
		);
		const marked = nextSelection.has(selectedEntry.credential.credentialId);
		this.infoMessage = marked
			? `Marked ${displayName} for batch delete (${nextSelection.size} selected).`
			: nextSelection.size > 0
				? `Removed ${displayName} from the batch delete queue (${nextSelection.size} remaining).`
				: `Removed ${displayName} from the batch delete queue.`;
		this.requestRender();
	}

	private deleteSelectedAccount(): void {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}
		const selectedEntry = this.getSelectedEntry(status);
		const deletionTarget =
			selectedEntry.kind === "account"
				? { kind: "account" as const, credentialId: selectedEntry.credential.credentialId }
				: { kind: "add" as const };
		const deletion = resolveBatchDeleteSelection(
			this.getBatchSelectedCredentialIdSet(status),
			deletionTarget,
		);
		if (deletion.credentialIds.length === 0) {
			this.ctx.ui.notify("Select an account to delete or mark accounts with [Space].", "warning");
			return;
		}

		const credentialLabelById = new Map(
			status.credentials.map((credential) => [
				credential.credentialId,
				formatCredentialDisplayName(credential.credentialId, credential.friendlyName),
			]),
		);
		const deletionLabels = deletion.credentialIds.map(
			(credentialId) => credentialLabelById.get(credentialId) ?? credentialId,
		);
		const previewLines = deletionLabels.map((label) => `- ${label}`);
		const busyMessage =
			deletion.credentialIds.length === 1
				? `Deleting ${deletion.credentialIds[0]}...`
				: `Deleting ${deletion.credentialIds.length} accounts from ${status.provider}...`;

		this.runAction(busyMessage, async () => {
			const confirmed = await this.modalVisibility.withHidden(async () => {
				return this.ctx.ui.confirm(
					deletion.credentialIds.length === 1 && !deletion.usesBatchSelection
						? "Delete account"
						: "Delete accounts",
					deletion.credentialIds.length === 1 && !deletion.usesBatchSelection
						? `Remove ${deletionLabels[0]} from ${status.provider}? This deletes the credential from auth.json.`
						: [
							`Remove ${deletion.credentialIds.length} accounts from ${status.provider}? This deletes each credential from auth.json.`,
							...previewLines,
						].join("\n"),
				);
			});
			if (!confirmed) {
				return "Delete cancelled.";
			}

			await this.accountManager.deleteCredentials(status.provider, deletion.credentialIds);
			this.batchSelectedCredentialIdsByProvider.delete(status.provider);
			await this.reloadStatuses({ provider: status.provider, kind: "add" });
			return deletion.credentialIds.length === 1 && !deletion.usesBatchSelection
				? `Deleted account ${deletionLabels[0]}.`
				: `Deleted ${deletion.credentialIds.length} account${deletion.credentialIds.length === 1 ? "" : "s"} from ${status.provider}.`;
		});
	}

	private refreshSelectedAccount(): void {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}

		const selectedEntry = this.getSelectedEntry(status);
		if (selectedEntry.kind !== "account") {
			this.ctx.ui.notify("Select an account to refresh with [Shift+T].", "warning");
			return;
		}

		const preserveSelection: SelectionAnchor = {
			provider: status.provider,
			kind: "account",
			credentialId: selectedEntry.credential.credentialId,
		};
		const displayName = formatCredentialDisplayName(
			selectedEntry.credential.credentialId,
			selectedEntry.credential.friendlyName,
		);

		const isApiKeyCredential = selectedEntry.credential.credentialType === "api_key";
		const isCloudflareApiKeyCredential = isApiKeyCredential && isCloudflareWorkersAiProvider(status.provider);
		const hasUsageApi = this.accountManager.hasUsageProvider(status.provider);
		this.runAction(
			isApiKeyCredential
				? isCloudflareApiKeyCredential
					? hasUsageApi
						? `Refreshing identity and usage state for ${selectedEntry.credential.credentialId}...`
						: `Refreshing Cloudflare identity for ${selectedEntry.credential.credentialId}...`
					: hasUsageApi
						? `Refreshing usage state for ${selectedEntry.credential.credentialId}...`
						: `Checking ${selectedEntry.credential.credentialId}...`
				: `Refreshing token for ${selectedEntry.credential.credentialId}...`,
			async () => {
				const refreshResult = !isApiKeyCredential
					? await this.accountManager.refreshCredential(
							status.provider,
							selectedEntry.credential.credentialId,
						)
					: null;
				const cloudflareIdentityRefresh = isCloudflareApiKeyCredential
					? await this.accountManager.refreshCloudflareCredentialIdentity(
						status.provider,
						selectedEntry.credential.credentialId,
					)
					: null;
				const usage = hasUsageApi
					? await this.accountManager.getCredentialUsageSnapshot(
						status.provider,
						selectedEntry.credential.credentialId,
						{
							forceRefresh: true,
							coordinationOperation: "manual-account-refresh",
						},
					)
					: null;
				await this.reloadStatuses(preserveSelection);
				if (usage?.error) {
					if (isApiKeyCredential) {
						const checkedMessage = cloudflareIdentityRefresh
							? formatCloudflareIdentityRefreshMessage(cloudflareIdentityRefresh, displayName)
							: `Credential checked for ${displayName}.`;
						return `${checkedMessage} Usage warning: ${usage.error}.`;
					}
					if (refreshResult?.disposition === "preserved_active_token") {
						return `Refresh endpoint failed for ${displayName}, but the current token is still active. Usage warning: ${usage.error}.`;
					}
					if (refreshResult?.disposition === "skipped_missing_refresh_token") {
						return `Token refresh skipped for ${displayName} because it was imported without a refresh token. Usage warning: ${usage.error}.`;
					}
					return `Token refreshed for ${displayName}. Usage warning: ${usage.error}.`;
				}
				if (isApiKeyCredential) {
					return cloudflareIdentityRefresh
						? formatCloudflareIdentityRefreshMessage(cloudflareIdentityRefresh, displayName)
						: `Credential checked for ${displayName}.`;
				}
				if (refreshResult?.disposition === "preserved_active_token") {
					return `Refresh endpoint failed for ${displayName}, but the current token is still active and will continue to be used.`;
				}
				return refreshResult?.disposition === "skipped_missing_refresh_token"
					? `Token refresh skipped for ${displayName} because it was imported without a refresh token; current access token will continue to be used.`
					: `Token refreshed for ${displayName}.`;
			},
		);
	}

	private refreshSelectedProviderAccounts(): void {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return;
		}

		if (status.credentials.length === 0) {
			this.ctx.ui.notify(`No accounts available to refresh for ${status.provider}.`, "warning");
			return;
		}

		const preserveSelection = this.getCurrentSelectionAnchor() ?? {
			provider: status.provider,
			kind: "add" as const,
		};

		this.runAction(`Refreshing tokens for ${status.provider} accounts...`, async () => {
			const result = await this.accountManager.refreshProviderCredentials(status.provider);
			await this.reloadStatuses(preserveSelection);

			const refreshedCount = result.refreshedCredentialIds.length;
			const preservedCount = result.preservedCredentialIds.length;
			const failedCount = result.failedCredentials.length;
			const warningCount = result.usageWarnings.length;
			const processedCount = refreshedCount + preservedCount;
			const summary = `Processed ${processedCount}/${result.totalCredentials} account${result.totalCredentials === 1 ? "" : "s"} for ${status.provider}.`;

			const detailParts: string[] = [];
			if (refreshedCount > 0) {
				detailParts.push(`Refreshed: ${result.refreshedCredentialIds.join(", ")}`);
			}
			if (preservedCount > 0) {
				detailParts.push(`Still using current token: ${result.preservedCredentialIds.join(", ")}`);
			}
			if (failedCount > 0) {
				const failedIds = result.failedCredentials.map((item) => item.credentialId).join(", ");
				detailParts.push(`Failed: ${failedIds}`);
			}
			if (warningCount > 0) {
				const warningIds = result.usageWarnings.map((item) => item.credentialId).join(", ");
				detailParts.push(`Usage warnings: ${warningIds}`);
			}

			if (detailParts.length === 0) {
				return summary;
			}

			return `${summary} ${detailParts.join(" • ")}.`;
		});
	}

	private runAction(
		busyMessage: string,
		action: () => Promise<string>,
	): void {
		if (this.isBusy) {
			this.ctx.ui.notify("Another action is already running.", "warning");
			return;
		}

		this.isBusy = true;
		this.busyMessage = busyMessage;
		this.infoMessage = null;
		this.requestRender();

		void action()
			.then((message) => {
				this.infoMessage = message;
				if (message && message !== "Delete cancelled.") {
					this.ctx.ui.notify(message, "info");
				}
			})
			.catch((error: unknown) => {
				const message = getErrorMessage(error);
				this.infoMessage = `Action failed: ${message}`;
				this.ctx.ui.notify(`Multi-auth action failed: ${message}`, "error");
			})
			.finally(() => {
				this.isBusy = false;
				this.busyMessage = null;
				this.requestRender();
			});
	}

	private async reloadStatuses(preserveSelection?: SelectionAnchor): Promise<void> {
		const preferredProvider = preserveSelection?.provider ?? this.getSelectedProviderStatus()?.provider;
		this.statuses = await loadAllProviderStatuses(this.accountManager);
		this.syncSelectionState(preferredProvider);
		this.restoreSelection(preserveSelection ?? null);
		if (this.renameEditor) {
			const renameStatus = this.statuses.find(
				(status) => status.provider === this.renameEditor?.provider,
			);
			const stillExists = renameStatus?.credentials.some(
				(credential) => credential.credentialId === this.renameEditor?.credentialId,
			);
			if (!stillExists) {
				this.renameEditor = null;
			}
		}
		this.requestRender();
	}

	private getDisplayedStatuses(): readonly ProviderStatus[] {
		return this.getProviderVisibilitySummary().displayedStatuses;
	}

	private getVisibleCredentials(status: ProviderStatus): CredentialStatus[] {
		if (this.showDisabledAccounts) {
			return status.credentials;
		}
		return status.credentials.filter((credential) => !credential.disabledError);
	}

	private getBatchSelectedCredentialIdSet(status: ProviderStatus): Set<string> {
		const visibleCredentialIds = this.getVisibleCredentials(status).map(
			(credential) => credential.credentialId,
		);
		const nextSelection = pruneBatchSelection(
			this.batchSelectedCredentialIdsByProvider.get(status.provider),
			visibleCredentialIds,
		);
		this.batchSelectedCredentialIdsByProvider.set(status.provider, nextSelection);
		return nextSelection;
	}

	private getBatchSelectedCredentialIds(status: ProviderStatus): string[] {
		return [...this.getBatchSelectedCredentialIdSet(status)];
	}

	private isCredentialBatchSelected(
		provider: SupportedProviderId,
		credentialId: string,
	): boolean {
		return this.batchSelectedCredentialIdsByProvider.get(provider)?.has(credentialId) ?? false;
	}

	private isSelectedAccountMarked(status: ProviderStatus): boolean {
		const selectedEntry = this.getSelectedEntry(status);
		return selectedEntry.kind === "account"
			&& this.isCredentialBatchSelected(status.provider, selectedEntry.credential.credentialId);
	}

	private isProviderDisplayed(provider: SupportedProviderId): boolean {
		return this.getDisplayedStatuses().some((status) => status.provider === provider);
	}

	private syncSelectionState(preferredProvider?: SupportedProviderId): void {
		const nextSelection = new Map<SupportedProviderId, number>();
		const nextBatchSelection = new Map<SupportedProviderId, Set<string>>();
		for (const status of this.statuses) {
			const existing = this.selectedEntryByProvider.get(status.provider);
			const fallback = this.defaultEntryIndex(status);
			nextSelection.set(status.provider, this.clampEntryIndex(status, existing ?? fallback));
			nextBatchSelection.set(
				status.provider,
				pruneBatchSelection(
					this.batchSelectedCredentialIdsByProvider.get(status.provider),
					this.getVisibleCredentials(status).map((credential) => credential.credentialId),
				),
			);
		}
		this.selectedEntryByProvider = nextSelection;
		this.batchSelectedCredentialIdsByProvider = nextBatchSelection;

		const displayedStatuses = this.getDisplayedStatuses();
		this.selectedProviderPaneIndex = this.clampProviderPaneEntryIndex(
			this.selectedProviderPaneIndex,
			displayedStatuses,
		);
		if (displayedStatuses.length === 0) {
			this.selectedProviderId = null;
			this.selectedProviderPaneIndex = 0;
			return;
		}

		const displayedProviders = new Set(displayedStatuses.map((status) => status.provider));
		const shouldSyncProviderCursor = this.selectedProviderPaneIndex < displayedStatuses.length;
		if (preferredProvider && displayedProviders.has(preferredProvider)) {
			this.selectedProviderId = preferredProvider;
		} else if (this.selectedProviderId && displayedProviders.has(this.selectedProviderId)) {
			// Keep the current provider anchor when filters or reloads still display it.
		} else if (shouldSyncProviderCursor) {
			this.selectedProviderId = displayedStatuses[this.selectedProviderPaneIndex]?.provider ?? null;
		} else {
			this.selectedProviderId = displayedStatuses[displayedStatuses.length - 1]?.provider ?? null;
		}

		if (shouldSyncProviderCursor) {
			const selectedProviderIndex = displayedStatuses.findIndex(
				(status) => status.provider === this.selectedProviderId,
			);
			this.selectedProviderPaneIndex = selectedProviderIndex >= 0
				? selectedProviderIndex
				: this.selectedProviderPaneIndex;
		}
	}

	private restoreSelection(anchor: SelectionAnchor | null): void {
		if (!anchor) {
			return;
		}

		const status = this.statuses.find((item) => item.provider === anchor.provider);
		if (!status) {
			return;
		}

		if (this.isProviderDisplayed(anchor.provider)) {
			this.selectedProviderId = anchor.provider;
		}

		const visibleCredentials = this.getVisibleCredentials(status);
		if (anchor.kind === "add") {
			this.selectedEntryByProvider.set(status.provider, visibleCredentials.length);
			return;
		}

		const accountIndex = visibleCredentials.findIndex(
			(credential) => credential.credentialId === anchor.credentialId,
		);
		if (accountIndex >= 0) {
			this.selectedEntryByProvider.set(status.provider, accountIndex);
		}
	}

	private getCurrentSelectionAnchor(): SelectionAnchor | null {
		const status = this.getSelectedProviderStatus();
		if (!status) {
			return null;
		}

		const entry = this.getSelectedEntry(status);
		if (entry.kind === "add") {
			return { provider: status.provider, kind: "add" };
		}

		return {
			provider: status.provider,
			kind: "account",
			credentialId: entry.credential.credentialId,
		};
	}

	private getSelectedProviderStatus(): ProviderStatus | null {
		const displayedStatuses = this.getDisplayedStatuses();
		if (displayedStatuses.length === 0) {
			return null;
		}

		const selected = this.selectedProviderId
			? displayedStatuses.find((status) => status.provider === this.selectedProviderId)
			: undefined;
		if (selected) {
			return selected;
		}

		this.selectedProviderId = displayedStatuses[0]?.provider ?? null;
		return displayedStatuses[0] ?? null;
	}

	private resolveProviderPaneAddSelection(): SupportedProviderId {
		return this.getSelectedProviderStatus()?.provider
			?? this.getKnownProviderIds()[0]
			?? LEGACY_SUPPORTED_PROVIDERS[0];
	}

	private getProviderPaneEntryCount(
		displayedStatuses: readonly ProviderStatus[] = this.getDisplayedStatuses(),
	): number {
		return buildProviderPaneEntries(displayedStatuses).length;
	}

	private clampProviderPaneEntryIndex(
		index: number,
		displayedStatuses: readonly ProviderStatus[] = this.getDisplayedStatuses(),
	): number {
		const maxIndex = this.getProviderPaneEntryCount(displayedStatuses) - 1;
		if (maxIndex <= 0 || !Number.isInteger(index)) {
			return 0;
		}
		return clamp(index, 0, maxIndex);
	}

	private getSelectedProviderPaneEntryIndex(
		displayedStatuses: readonly ProviderStatus[] = this.getDisplayedStatuses(),
	): number {
		const entryIndex = this.clampProviderPaneEntryIndex(
			this.selectedProviderPaneIndex,
			displayedStatuses,
		);
		this.selectedProviderPaneIndex = entryIndex;
		return entryIndex;
	}

	private getSelectedProviderPaneEntry(
		displayedStatuses: readonly ProviderStatus[] = this.getDisplayedStatuses(),
	): ProviderPaneEntry {
		const selectedEntryIndex = this.getSelectedProviderPaneEntryIndex(displayedStatuses);
		return (
			buildProviderPaneEntries(displayedStatuses)[selectedEntryIndex] ?? {
				kind: "add",
				entryIndex: displayedStatuses.length,
			}
		);
	}

	private getSelectedProviderPaneEntryKind(): ProviderPaneEntry["kind"] {
		return this.getSelectedProviderPaneEntry().kind;
	}

	private getSelectedEntry(status: ProviderStatus): SelectedProviderEntry {
		const visibleCredentials = this.getVisibleCredentials(status);
		const selectedEntryIndex = this.getSelectedEntryIndex(status);
		if (selectedEntryIndex < visibleCredentials.length) {
			const credential = visibleCredentials[selectedEntryIndex];
			if (credential) {
				return {
					kind: "account",
					credential,
					entryIndex: selectedEntryIndex,
				};
			}
		}

		return {
			kind: "add",
			entryIndex: visibleCredentials.length,
		};
	}

	private getSelectedEntryIndex(status: ProviderStatus): number {
		const existing = this.selectedEntryByProvider.get(status.provider);
		const index = this.clampEntryIndex(status, existing ?? this.defaultEntryIndex(status));
		this.selectedEntryByProvider.set(status.provider, index);
		return index;
	}

	private defaultEntryIndex(status: ProviderStatus): number {
		const visibleCredentials = this.getVisibleCredentials(status);
		if (visibleCredentials.length === 0) {
			return 0;
		}

		const activeCredentialId = status.credentials[status.activeIndex]?.credentialId;
		if (activeCredentialId) {
			const visibleActiveIndex = visibleCredentials.findIndex(
				(credential) => credential.credentialId === activeCredentialId,
			);
			if (visibleActiveIndex >= 0) {
				return visibleActiveIndex;
			}
		}

		return 0;
	}

	private clampEntryIndex(status: ProviderStatus, index: number): number {
		const entryCount = this.getEntryCount(status);
		if (entryCount <= 1) {
			return 0;
		}
		if (!Number.isInteger(index)) {
			return 0;
		}
		return Math.max(0, Math.min(entryCount - 1, index));
	}

	private getEntryCount(status: ProviderStatus): number {
		return this.getVisibleCredentials(status).length + 1;
	}

}

export async function openMultiAuthModal(
	ctx: ExtensionCommandContext,
	accountManager: AccountManager,
): Promise<void> {
	const overlayOptions = resolveMultiAuthRuntimeOverlayOptions();
	const resolveMaxContentRows = (): number => resolveMultiAuthContentRows(resolveMultiAuthOverlayOptions());
	const modalVisibility = new ModalVisibilityController();

	await ctx.ui.custom<void>(
		(tui, theme, _keybindings, done) => {
			const content = new MultiAuthManagerModal(
				ctx,
				accountManager,
				theme,
				() => {
					modalVisibility.detach();
					done();
				},
				() => tui.requestRender(),
				modalVisibility,
				resolveMaxContentRows,
				[],
				[],
			);

			return {
				render(width: number): string[] {
					const framed = renderZellijFrameWithRenderer(width, theme, {
						titleLeft: "",
						focused: true,
					}, (contentWidth) => content.render(contentWidth));
					return framed.lines;
				},
				invalidate(): void {
					content.invalidate();
				},
				handleInput(data: string): void {
					content.handleInput(data);
					tui.requestRender();
				},
			};
		},
		{
			overlay: true,
			overlayOptions,
			onHandle: (handle) => {
				modalVisibility.attach(handle);
			},
		},
	);
}

/**
 * Registers /multi-auth command for unified account management.
 */
export function registerMultiAuthCommands(
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
				await openMultiAuthModal(ctx, accountManager);
			} catch (error) {
				ctx.ui.notify(`/multi-auth failed: ${getErrorMessage(error)}`, "error");
			}
		},
	});
}
