import assert from "node:assert/strict";
import test from "node:test";

import { resetOAuthProviders } from "../src/oauth-compat.js";
import { ProviderRegistry } from "../src/provider-registry.js";
import { usageProviders } from "../src/usage/providers.js";

test.afterEach(() => {
	resetOAuthProviders();
});

test("usage provider registry adds zai-coding-cn with external account state", () => {
	const registry = new ProviderRegistry();
	const providerIds = new Set(usageProviders.map((provider) => provider.id));

	assert.equal(providerIds.has("zai-coding-cn"), true);
	assert.equal(registry.getProviderCapabilities("zai-coding-cn").hasExternalAccountState, true);
});

test("zai-coding-cn usage provider normalizes the quota/limit monitor response", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "zai-coding-cn");
	assert.ok(provider?.fetchUsage, "expected zai-coding-cn usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	let requestedUrl = "";
	let authorizationHeader = "";
	globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
		requestedUrl = String(input);
		authorizationHeader = new Headers(init?.headers).get("Authorization") ?? "";
		return new Response(
			JSON.stringify({
				code: 200,
				msg: "Operation successful",
				success: true,
				data: {
					limits: [
						// MCP tool pool (web-search / web-reader / zread) — excluded from
						// the model quota windows.
						{
							type: "TIME_LIMIT",
							unit: 5,
							number: 1,
							usage: 1000,
							currentValue: 0,
							remaining: 1000,
							percentage: 0,
							nextResetTime: 1_800_100_000_000,
							usageDetails: [
								{ modelCode: "search-prime", usage: 0 },
								{ modelCode: "web-reader", usage: 0 },
								{ modelCode: "zread", usage: 0 },
							],
						},
						// Weekly model token budget.
						{
							type: "TOKENS_LIMIT",
							unit: 6,
							number: 1,
							percentage: 30,
							nextResetTime: 1_800_000_000_000,
						},
						// Rolling 5-hour model token budget.
						{
							type: "TOKENS_LIMIT",
							unit: 3,
							number: 5,
							percentage: 15,
						},
					],
					level: "pro",
				},
			}),
			{
				status: 200,
				headers: { "Content-Type": "application/json" },
			},
		);
	}) as typeof fetch;

	const snapshot = await provider.fetchUsage({ accessToken: "glm-cn-key" });
	assert.ok(snapshot);
	assert.equal(requestedUrl, "https://open.bigmodel.cn/api/monitor/usage/quota/limit");
	assert.equal(authorizationHeader, "Bearer glm-cn-key");
	assert.equal(snapshot.provider, "zai-coding-cn");
	assert.equal(snapshot.planType, "pro");
	// The rolling 5-hour model token budget is the primary window, regardless of
	// row order in the response.
	assert.equal(snapshot.primary?.usedPercent, 15);
	assert.equal(snapshot.primary?.windowMinutes, 300);
	assert.equal(snapshot.primary?.resetsAt, null);
	// The weekly model token budget is the secondary window.
	assert.equal(snapshot.secondary?.usedPercent, 30);
	assert.equal(snapshot.secondary?.windowMinutes, 7 * 24 * 60);
	assert.equal(snapshot.secondary?.resetsAt, 1_800_000_000_000);
	assert.equal(snapshot.estimatedResetAt, 1_800_000_000_000);
});

test("zai-coding-cn usage provider classifies unknown token buckets by reset horizon", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "zai-coding-cn");
	assert.ok(provider?.fetchUsage, "expected zai-coding-cn usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	const now = Date.now();
	globalThis.fetch = (async (): Promise<Response> => {
		return new Response(
			JSON.stringify({
				success: true,
				data: {
					limits: [
						{
							type: "TOKENS_LIMIT",
							unit: 9,
							number: 2,
							percentage: 55,
							nextResetTime: now + 6 * 24 * 60 * 60 * 1000,
						},
						{
							type: "TOKENS_LIMIT",
							unit: 8,
							number: 4,
							percentage: 20,
							nextResetTime: now + 3 * 60 * 60 * 1000,
						},
					],
				},
			}),
			{ status: 200, headers: { "Content-Type": "application/json" } },
		);
	}) as typeof fetch;

	const snapshot = await provider.fetchUsage({ accessToken: "glm-cn-key" });
	assert.ok(snapshot);
	assert.equal(snapshot.primary?.usedPercent, 20);
	assert.equal(snapshot.primary?.windowMinutes, 300);
	assert.equal(snapshot.secondary?.usedPercent, 55);
	assert.equal(snapshot.secondary?.windowMinutes, 7 * 24 * 60);
});

test("zai-coding-cn usage provider rejects responses without model token limits", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "zai-coding-cn");
	assert.ok(provider?.fetchUsage, "expected zai-coding-cn usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	globalThis.fetch = (async (): Promise<Response> => {
		return new Response(
			JSON.stringify({
				success: true,
				data: {
					limits: [
						{ type: "TIME_LIMIT", unit: 5, number: 1, usage: 1000, currentValue: 40, remaining: 960, percentage: 4 },
					],
				},
			}),
			{ status: 200, headers: { "Content-Type": "application/json" } },
		);
	}) as typeof fetch;

	// A TIME_LIMIT-only response carries just the MCP tool pool, so there is no
	// model quota to report.
	await assert.rejects(provider.fetchUsage({ accessToken: "glm-cn-key" }), /format was invalid/);
});

test("zai-coding-cn usage provider derives the quota origin from credential base URL overrides", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "zai-coding-cn");
	assert.ok(provider?.fetchUsage, "expected zai-coding-cn usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	let requestedUrl = "";
	globalThis.fetch = (async (input: string | URL | Request): Promise<Response> => {
		requestedUrl = String(input);
		return new Response(
			JSON.stringify({
				success: true,
				data: {
					limits: [
						{ type: "TOKENS_LIMIT", unit: 3, number: 5, percentage: 40 },
					],
				},
			}),
			{ status: 200, headers: { "Content-Type": "application/json" } },
		);
	}) as typeof fetch;

	const snapshot = await provider.fetchUsage({
		accessToken: "glm-cn-key",
		credential: { type: "api_key", key: "glm-cn-key", request: { baseUrl: "https://open.bigmodel.cn/api/coding/paas/v4" } },
	});
	assert.ok(snapshot);
	assert.equal(requestedUrl, "https://open.bigmodel.cn/api/monitor/usage/quota/limit");
	assert.equal(snapshot.primary?.usedPercent, 40);
	assert.equal(snapshot.primary?.windowMinutes, 300);
	assert.equal(snapshot.secondary, null);
});

test("zai-coding-cn usage provider rejects invalid tokens", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "zai-coding-cn");
	assert.ok(provider?.fetchUsage, "expected zai-coding-cn usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	globalThis.fetch = (async (): Promise<Response> => {
		return new Response("Unauthorized", { status: 401 });
	}) as typeof fetch;

	await assert.rejects(
		provider.fetchUsage({ accessToken: "bad-key" }),
		/token expired or invalid/,
	);
});
