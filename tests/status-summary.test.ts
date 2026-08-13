import assert from "node:assert/strict";
import test from "node:test";
import {
	formatProviderStatuslineAlias,
	formatQuotaStatusLine,
	formatStatusReport,
	summarizeProviderStatuses,
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

test("summarizeProviderStatuses picks the active credential and its usage", () => {
	const statuses = [
		providerStatus({
			credentials: [
				credential({
					credentialId: "kimi-coding",
					isActive: true,
					usageSnapshot: {
						timestamp: 1,
						provider: "kimi-coding",
						planType: null,
						primary: { usedPercent: 35, windowMinutes: 300, resetsAt: null },
						secondary: { usedPercent: 27, windowMinutes: null, resetsAt: null },
						credits: null,
						copilotQuota: null,
						updatedAt: 1,
					},
				}),
				credential({ credentialId: "kimi-coding-account-2", index: 1 }),
			],
		}),
	];
	const summaries = summarizeProviderStatuses(statuses);
	assert.equal(summaries.length, 1);
	assert.equal(summaries[0]?.accountCount, 2);
	assert.equal(summaries[0]?.primaryPercent, 35);
	assert.equal(summaries[0]?.secondaryPercent, 27);
});

test("formatQuotaStatusLine compacts providers and marks quota exhaustion", () => {
	const now = Date.now();
	const statuses = [
		providerStatus({
			provider: "kimi-coding",
			credentials: [
				credential({
					credentialId: "kimi-coding",
					isActive: true,
					quotaExhaustedUntil: now + 60_000,
					usageSnapshot: {
						timestamp: 1,
						provider: "kimi-coding",
						planType: null,
						primary: { usedPercent: 100, windowMinutes: 300, resetsAt: null },
						secondary: null,
						credits: null,
						copilotQuota: null,
						updatedAt: 1,
					},
				}),
				credential({ credentialId: "kimi-coding-account-2", index: 1 }),
			],
		}),
		providerStatus({
			provider: "openai-codex",
			credentials: [credential({ credentialId: "openai-codex", isActive: true })],
		}),
	];
	const line = formatQuotaStatusLine(summarizeProviderStatuses(statuses, now));
	assert.equal(line, "kimi×2|100%!");
});

test("formatQuotaStatusLine renders short provider aliases", () => {
	const now = Date.now();
	const snapshot = {
		timestamp: 1,
		provider: "openai-codex",
		planType: null,
		primary: { usedPercent: 14, windowMinutes: 300, resetsAt: null },
		secondary: null,
		credits: null,
		copilotQuota: null,
		updatedAt: 1,
	};
	const statuses = [
		providerStatus({
			provider: "openai-codex",
			credentials: [credential({ credentialId: "openai-codex", isActive: true, usageSnapshot: snapshot })],
		}),
		providerStatus({
			provider: "zai-coding-cn",
			credentials: [
				credential({
					credentialId: "zai-coding-cn",
					isActive: true,
					usageSnapshot: { ...snapshot, provider: "zai-coding-cn" },
				}),
			],
		}),
		providerStatus({
			provider: "custom-provider",
			credentials: [
				credential({
					credentialId: "custom-provider",
					isActive: true,
					usageSnapshot: { ...snapshot, provider: "custom-provider" },
				}),
			],
		}),
	];
	const line = formatQuotaStatusLine(summarizeProviderStatuses(statuses, now));
	assert.equal(line, "gpt|14%  glm|14%  custom-provider|14%");
});

test("formatProviderStatuslineAlias maps known providers and falls back to the id", () => {
	assert.equal(formatProviderStatuslineAlias("openai-codex"), "gpt");
	assert.equal(formatProviderStatuslineAlias("anthropic"), "claude");
	assert.equal(formatProviderStatuslineAlias("kimi-coding"), "kimi");
	assert.equal(formatProviderStatuslineAlias("zai-coding-cn"), "glm");
	assert.equal(formatProviderStatuslineAlias("opencode-go"), "go");
	assert.equal(formatProviderStatuslineAlias("unknown-provider"), "unknown-provider");
});

test("formatQuotaStatusLine returns undefined without usage data", () => {
	const statuses = [
		providerStatus({
			credentials: [credential({ credentialId: "ollama", isActive: true })],
		}),
	];
	assert.equal(formatQuotaStatusLine(summarizeProviderStatuses(statuses)), undefined);
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
