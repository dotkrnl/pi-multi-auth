import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuthWriter } from "../src/auth-writer.js";
import { resetOAuthProviders } from "../src/oauth-compat.js";
import { ProviderRegistry } from "../src/provider-registry.js";

test.afterEach(() => {
	resetOAuthProviders();
});

test("provider registry restores approved OAuth providers after OAuth registry resets", async () => {
	resetOAuthProviders();
	const registry = new ProviderRegistry();

	for (const providerId of [
		"qwen",
		"kimi-coding",
		"anthropic",
		"github-copilot",
		"openai-codex",
	] as const) {
		assert.equal(
			registry.getProviderCapabilities(providerId).supportsOAuth,
			true,
			`expected ${providerId} to support OAuth`,
		);
	}

	const availableProviders = new Set(
		registry.listAvailableOAuthProviders().map((provider) => provider.provider),
	);
	assert.equal(availableProviders.has("qwen"), true);
	assert.equal(availableProviders.has("kimi-coding"), true);
	assert.equal(availableProviders.has("anthropic"), true);
	assert.equal(availableProviders.has("github-copilot"), true);
	assert.equal(availableProviders.has("openai-codex"), true);

	const apiKeyProviders = await registry.listAvailableApiKeyProviders();
	assert.equal(apiKeyProviders.some((provider) => provider.provider === "kimi-coding"), true);
});

test("provider registry merges Pi's refreshed models into the built-in catalog", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-model-store-"));
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true });
	});

	await writeFile(
		join(tempRoot, "models-store.json"),
		JSON.stringify({
			"kimi-coding": {
				lastModified: Number.MAX_SAFE_INTEGER,
				models: [
					{
						id: "k3",
						name: "Kimi K3",
						api: "openai-completions",
						provider: "kimi-coding",
						baseUrl: "https://api.kimi.com/coding/v1",
						reasoning: true,
						input: ["text", "image"],
						cost: { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 0 },
						contextWindow: 1048576,
						maxTokens: 131072,
					},
					{
						id: "k3.1-pro",
						name: "Kimi K3.1 Pro",
						api: "openai-completions",
						provider: "kimi-coding",
						baseUrl: "https://api.kimi.com/coding/v1",
						reasoning: true,
						input: ["text", "image"],
						cost: { input: 2, output: 10, cacheRead: 0.2, cacheWrite: 0 },
						contextWindow: 1048576,
						maxTokens: 131072,
						thinkingLevelMap: { low: "low", high: "high", max: "max" },
					},
					{
						id: "image-model",
						api: "openai-completions",
						provider: "kimi-coding",
						type: "image",
					},
				],
			},
		}),
		"utf-8",
	);

	const registry = new ProviderRegistry(
		new AuthWriter(join(tempRoot, "auth.json")),
		join(tempRoot, "models.json"),
		["kimi-coding"],
	);
	const metadata = await registry.resolveProviderRegistrationMetadata("kimi-coding");
	const model = metadata?.models.find((entry) => entry.id === "k3.1-pro");

	assert.ok(model);
	assert.equal(model.name, "Kimi K3.1 Pro");
	assert.equal(model.contextWindow, 1048576);
	assert.equal(model.maxTokens, 131072);
	assert.equal(model.thinkingLevelMap?.max, "max");
	assert.equal(metadata?.models.some((entry) => entry.id === "k3"), true);
	assert.equal(metadata?.models.some((entry) => entry.id === "kimi-for-coding"), true);
	assert.equal(metadata?.models.some((entry) => entry.id === "image-model"), false);
});
