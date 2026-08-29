import assert from "node:assert/strict";
import test from "node:test";
import {
	formatProviderStatuslineAlias,
	formatAllAccountsQuotaStatusLine,
	formatStatusReport,
} from "../src/status-summary.js";
import type { CredentialStatus, ProviderStatus } from "../src/types.js";

function credential(overrides: Partial<CredentialStatus>): CredentialStatus {
	return {
		credentialId: "cred",
		credentialType: "oauth",
		redactedSecret: "***",
		index: 0,
		isActive: false,
		expiresAt: null,
		isExpired: false,
		usageCount: 0,
		quotaErrorCount: 0,
		...overrides,
	};
}

function providerStatus(overrides: Partial<ProviderStatus>): ProviderStatus {
	return {
		provider: "kimi-coding",
		rotationMode: "usage-based",
		activeIndex: 0,
		credentials: [],
		...overrides,
	};
}

/** Minimal UsageSnapshot-shaped object used across tests. */
interface TestWindow {
	usedPercent: number;
	windowMinutes: number | null;
	resetsAt?: number | null;
}
function usageSnapshot(
	primary: TestWindow,
	secondary: TestWindow | null,
	monthly?: TestWindow | null,
) {
	return {
		timestamp: 1,
		provider: "kimi-coding",
		planType: null,
		primary: { ...primary, resetsAt: primary.resetsAt ?? null },
		secondary: secondary ? { ...secondary, resetsAt: secondary.resetsAt ?? null } : null,
		monthly: monthly ? { ...monthly, resetsAt: monthly.resetsAt ?? null } : null,
		credits: null,
		copilotQuota: null,
		updatedAt: 1,
	};
}

test("formatAllAccountsQuotaStatusLine lists every account per quota window in index order", () => {
	const statuses = [
		providerStatus({
			credentials: [
				credential({
					credentialId: "kimi-coding",
					index: 0,
					usageSnapshot: usageSnapshot(
						{ usedPercent: 54, windowMinutes: 300 },
						{ usedPercent: 85, windowMinutes: 7 * 24 * 60 },
					),
				}),
				credential({
					credentialId: "kimi-coding-account-2",
					index: 1,
					usageSnapshot: usageSnapshot(
						{ usedPercent: 12, windowMinutes: 300 },
						{ usedPercent: 27, windowMinutes: 7 * 24 * 60 },
					),
				}),
			],
		}),
	];
	const line = formatAllAccountsQuotaStatusLine(statuses);
	// Primary window is bare, weekly carries `w`; both accounts appear in index order.
	assert.equal(line, "kimi|54|12|85w|27w");
});

test("formatAllAccountsQuotaStatusLine orders by index, not by active flag", () => {
	const statuses = [
		providerStatus({
			credentials: [
				credential({
					credentialId: "account-2",
					index: 1,
					isActive: true,
					usageSnapshot: usageSnapshot(
						{ usedPercent: 12, windowMinutes: 300 },
						{ usedPercent: 27, windowMinutes: 7 * 24 * 60 },
					),
				}),
				credential({
					credentialId: "account-1",
					index: 0,
					usageSnapshot: usageSnapshot(
						{ usedPercent: 54, windowMinutes: 300 },
						{ usedPercent: 85, windowMinutes: 7 * 24 * 60 },
					),
				}),
			],
		}),
	];
	const line = formatAllAccountsQuotaStatusLine(statuses);
	// Index 0 (account-1, 54/85) must come first even though account-2 is active.
	assert.equal(line, "kimi|54|12|85w|27w");
});

test("formatAllAccountsQuotaStatusLine renders short provider aliases", () => {
	const snapshot = usageSnapshot({ usedPercent: 14, windowMinutes: 300 }, null);
	const statuses = [
		providerStatus({
			provider: "openai-codex",
			credentials: [credential({ credentialId: "openai-codex", index: 0, usageSnapshot: snapshot })],
		}),
		providerStatus({
			provider: "zai-coding-cn",
			credentials: [
				credential({ credentialId: "zai-coding-cn", index: 0, usageSnapshot: { ...snapshot, provider: "zai-coding-cn" } }),
			],
		}),
		providerStatus({
			provider: "custom-provider",
			credentials: [
				credential({ credentialId: "custom-provider", index: 0, usageSnapshot: { ...snapshot, provider: "custom-provider" } }),
			],
		}),
	];
	const line = formatAllAccountsQuotaStatusLine(statuses);
	assert.equal(line, "gpt|14  glm|14  custom-provider|14");
});

test("formatProviderStatuslineAlias maps known providers and falls back to the id", () => {
	assert.equal(formatProviderStatuslineAlias("openai-codex"), "gpt");
	assert.equal(formatProviderStatuslineAlias("anthropic"), "claude");
	assert.equal(formatProviderStatuslineAlias("kimi-coding"), "kimi");
	assert.equal(formatProviderStatuslineAlias("zai-coding-cn"), "glm");
	assert.equal(formatProviderStatuslineAlias("opencode-go"), "go");
	assert.equal(formatProviderStatuslineAlias("unknown-provider"), "unknown-provider");
});

test("formatAllAccountsQuotaStatusLine returns undefined without usage data", () => {
	const statuses = [
		providerStatus({
			credentials: [credential({ credentialId: "ollama", index: 0 })],
		}),
	];
	assert.equal(formatAllAccountsQuotaStatusLine(statuses), undefined);
});

test("formatStatusReport lists providers, credentials, and usage windows", () => {
	const statuses = [
		providerStatus({
			credentials: [
				credential({
					credentialId: "kimi-coding",
					friendlyName: "work",
					isActive: true,
					usageSnapshot: {
						timestamp: 1,
						provider: "kimi-coding",
						planType: "Kimi Pro",
						primary: { usedPercent: 35, windowMinutes: 300, resetsAt: null },
						secondary: { usedPercent: 27, windowMinutes: 10080, resetsAt: null },
						credits: null,
						copilotQuota: null,
						updatedAt: 1,
					},
				}),
			],
		}),
	];
	const report = formatStatusReport(statuses);
	assert.match(report, /kimi-coding \(usage-based, 1 account\)/);
	assert.match(report, /work — 35% 5h, 27% weekly — Kimi Pro — \[active\]/);
});

test("formatStatusReport handles empty state", () => {
	assert.equal(formatStatusReport([]), "multi-auth: no credentials configured.");
});

test("formatAllAccountsQuotaStatusLine renders primary/weekly/monthly for OpenCode Go", () => {
	const statuses = [
		providerStatus({
			provider: "opencode-go",
			credentials: [
				credential({
					credentialId: "opencode-go",
					index: 0,
					usageSnapshot: {
						timestamp: 1,
						provider: "opencode-go",
						planType: "Go",
						primary: { usedPercent: 12, windowMinutes: 5 * 60, resetsAt: null },
						secondary: { usedPercent: 24, windowMinutes: 7 * 24 * 60, resetsAt: null },
						monthly: { usedPercent: 36, windowMinutes: 30 * 24 * 60, resetsAt: null },
						credits: null,
						copilotQuota: null,
						updatedAt: 1,
					},
				}),
			],
		}),
		providerStatus({
			provider: "kimi-coding",
			credentials: [
				credential({
					credentialId: "kimi-coding",
					index: 0,
					usageSnapshot: {
						timestamp: 1,
						provider: "kimi-coding",
						planType: null,
						primary: { usedPercent: 54, windowMinutes: 5 * 60, resetsAt: null },
						secondary: { usedPercent: 85, windowMinutes: 7 * 24 * 60, resetsAt: null },
						credits: null,
						copilotQuota: null,
						updatedAt: 1,
					},
				}),
			],
		}),
	];
	const line = formatAllAccountsQuotaStatusLine(statuses);
	// Primary window is bare; weekly carries `w`, monthly `m`.
	assert.equal(line, "go|12|24w|36m  kimi|54|85w");
});

test("formatAllAccountsQuotaStatusLine shows weekly suffix even when windowMinutes is unknown", () => {
	// kimi-coding's snapshot can carry windowMinutes: null for the secondary
	// window; the statusline must still render the `w` slot suffix.
	const statuses = [
		providerStatus({
			provider: "kimi-coding",
			credentials: [
				credential({
					credentialId: "kimi-coding",
					index: 0,
					usageSnapshot: usageSnapshot(
						{ usedPercent: 54, windowMinutes: 300 },
						{ usedPercent: 85, windowMinutes: null },
					),
				}),
			],
		}),
	];
	const line = formatAllAccountsQuotaStatusLine(statuses);
	assert.equal(line, "kimi|54|85w");
});

test("formatAllAccountsQuotaStatusLine drops empty runs and keeps – for within-run gaps", () => {
	const statuses = [
		providerStatus({
			provider: "opencode-go",
			credentials: [
				credential({
					credentialId: "go-1",
					index: 0,
					usageSnapshot: usageSnapshot(
						{ usedPercent: 12, windowMinutes: 60 },
						{ usedPercent: 24, windowMinutes: 7 * 24 * 60 },
						{ usedPercent: 36, windowMinutes: 30 * 24 * 60 },
					),
				}),
				credential({
					credentialId: "go-2",
					index: 1,
					usageSnapshot: usageSnapshot(
						{ usedPercent: 48, windowMinutes: 60 },
						{ usedPercent: 70, windowMinutes: 7 * 24 * 60 },
					),
				}),
				credential({ credentialId: "go-3", index: 2, usageSnapshot: null }),
			],
		}),
	];
	const line = formatAllAccountsQuotaStatusLine(statuses);
	// go-3 has no data at all; each run keeps a `–` placeholder for it.
	assert.equal(line, "go|12|48|–|24w|70w|–|36m|–|–");
});
