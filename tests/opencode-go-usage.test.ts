import assert from "node:assert/strict";
import test from "node:test";

import { resetOAuthProviders } from "../src/oauth-compat.js";
import { ProviderRegistry } from "../src/provider-registry.js";
import { usageProviders } from "../src/usage/providers.js";
import { __opencodeGoParser } from "../src/usage/opencode-go.js";
import type { UsageAuth } from "../src/usage/types.js";

const OPENCODE_GO_WORKSPACE = "wrk_01EXAMPLE0EXAMPLE0EXAMPLE0EXAMPL";
const OPENCODE_GO_COOKIE = "Fe26.2**session-cookie";

function authWith(overrides: Partial<UsageAuth["credential"]> = {}): UsageAuth {
	return {
		accessToken: "opencode-key",
		credential: {
			type: "api_key",
			key: "opencode-key",
			opencodeGo: { workspaceId: OPENCODE_GO_WORKSPACE, cookie: OPENCODE_GO_COOKIE },
			...overrides,
		},
	};
}

function authWithoutQuota(): UsageAuth {
	return {
		accessToken: "opencode-key",
		credential: { type: "api_key", key: "opencode-key" },
	};
}

function dashboardHtml(
	options: {
		rolling?: { resetInSec?: number; usagePercent?: number; status?: string };
		weekly?: { resetInSec?: number; usagePercent?: number; status?: string };
		monthly?: { resetInSec?: number; usagePercent?: number; status?: string };
		balance?: number;
	},
): string {
	const rolling = `$R[34]={status:"${options.rolling?.status ?? "ok"}",resetInSec:${options.rolling?.resetInSec ?? 18000},usagePercent:${options.rolling?.usagePercent ?? 0}}`;
	const weekly = `$R[35]={status:"${options.weekly?.status ?? "ok"}",resetInSec:${options.weekly?.resetInSec ?? 604800},usagePercent:${options.weekly?.usagePercent ?? 0}}`;
	const monthly = `$R[36]={status:"${options.monthly?.status ?? "ok"}",resetInSec:${options.monthly?.resetInSec ?? 2592000},usagePercent:${options.monthly?.usagePercent ?? 0}}`;
	const balance = options.balance ?? 0;
	return `<html><script>self.$R=self.$R||[];$R[28]($R[18],$R[32]={mine:!0,useBalance:!1,rollingUsage:${rolling},weeklyUsage:${weekly},monthlyUsage:${monthly}});$R[28]($R[22],$R[37]={balance:${balance},reload:null});</script></html>`;
}

test.afterEach(() => {
	resetOAuthProviders();
});

test("usage provider registry adds opencode-go with external account state", () => {
	const registry = new ProviderRegistry();
	const providerIds = new Set(usageProviders.map((provider) => provider.id));

	assert.equal(providerIds.has("opencode-go"), true);
	assert.equal(registry.getProviderCapabilities("opencode-go").hasExternalAccountState, true);
});

test("opencode-go usage provider reports no quota when credential has no opencodeGo config", async () => {
	const provider = usageProviders.find((entry) => entry.id === "opencode-go");
	assert.ok(provider?.fetchUsage, "expected opencode-go usage provider to be registered");

	const snapshot = await provider.fetchUsage(authWithoutQuota());
	assert.equal(snapshot, null);
});

test("opencode-go usage provider parses the dashboard hydration state", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "opencode-go");
	assert.ok(provider?.fetchUsage, "expected opencode-go usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	let requestedUrl = "";
	let cookieHeader = "";
	let acceptHeader = "";
	globalThis.fetch = (async (
		input: string | URL | Request,
		init?: RequestInit,
	): Promise<Response> => {
		requestedUrl = String(input);
		const headers = new Headers(init?.headers);
		cookieHeader = headers.get("Cookie") ?? "";
		acceptHeader = headers.get("Accept") ?? "";
		return new Response(
			dashboardHtml({
				rolling: { resetInSec: 18000, usagePercent: 42 },
				weekly: { resetInSec: 604_800, usagePercent: 17 },
				monthly: { usagePercent: 25 },
				balance: 0,
			}),
			{ status: 200, headers: { "Content-Type": "text/html" } },
		);
	}) as typeof fetch;

	const before = Date.now();
	const snapshot = await provider.fetchUsage(authWith());
	const after = Date.now();

	assert.ok(snapshot);
	assert.equal(requestedUrl, "https://opencode.ai/workspace/wrk_01EXAMPLE0EXAMPLE0EXAMPLE0EXAMPL/go");
	assert.equal(cookieHeader, `auth=${OPENCODE_GO_COOKIE}`);
	assert.equal(acceptHeader.includes("text/html"), true);
	assert.equal(snapshot.provider, "opencode-go");
	assert.equal(snapshot.planType, "Go");

	assert.equal(snapshot.primary?.usedPercent, 42);
	assert.equal(snapshot.primary?.windowMinutes, 5 * 60);
	assert.ok(snapshot.primary?.resetsAt !== null);
	if (snapshot.primary?.resetsAt !== null) {
		assert.ok(snapshot.primary.resetsAt >= before + 18000 * 1000 - 1000);
		assert.ok(snapshot.primary.resetsAt <= after + 18000 * 1000 + 1000);
	}

	assert.equal(snapshot.secondary?.usedPercent, 17);
	assert.equal(snapshot.secondary?.windowMinutes, 7 * 24 * 60);

	// Balance of 0 means no credits are reported.
	assert.equal(snapshot.credits, null);
});

test("opencode-go usage provider surfaces a positive balance as credits", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "opencode-go");
	assert.ok(provider?.fetchUsage, "expected opencode-go usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	globalThis.fetch = (async (): Promise<Response> => {
		return new Response(dashboardHtml({ rolling: { usagePercent: 5 }, balance: 1234 }), {
			status: 200,
			headers: { "Content-Type": "text/html" },
		});
	}) as typeof fetch;

	const snapshot = await provider.fetchUsage(authWith());
	assert.ok(snapshot);
	assert.equal(snapshot.credits?.hasCredits, true);
	assert.equal(snapshot.credits?.balance, "$12.34 credit");
});

test("opencode-go usage provider detects an expired cookie redirect", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "opencode-go");
	assert.ok(provider?.fetchUsage, "expected opencode-go usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	globalThis.fetch = (async (): Promise<Response> => {
		// Node fetch follows the redirect to the auth host; the resulting body
		// has no usage payload and looks like a sign-in page.
		return new Response("<html><body>Please sign in to opencode</body></html>", {
			status: 200,
			headers: { "Content-Type": "text/html" },
		});
	}) as typeof fetch;

	await assert.rejects(provider.fetchUsage(authWith()), /session cookie expired or invalid/);
});

test("opencode-go usage provider rejects a non-usage 200 response", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "opencode-go");
	assert.ok(provider?.fetchUsage, "expected opencode-go usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	globalThis.fetch = (async (): Promise<Response> => {
		return new Response("<html><body>Some unrelated page</body></html>", { status: 200 });
	}) as typeof fetch;

	await assert.rejects(provider.fetchUsage(authWith()), /format was invalid/);
});

test("opencode-go usage provider maps HTTP 401 to an auth failure", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "opencode-go");
	assert.ok(provider?.fetchUsage, "expected opencode-go usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	globalThis.fetch = (async (): Promise<Response> => {
		return new Response("Unauthorized", { status: 401 });
	}) as typeof fetch;

	await assert.rejects(provider.fetchUsage(authWith()), /session cookie expired or invalid/);
});

test("opencode-go usage provider sanitizes a pasted cookie with trailing cruft", async (t) => {
	const provider = usageProviders.find((entry) => entry.id === "opencode-go");
	assert.ok(provider?.fetchUsage, "expected opencode-go usage provider to be registered");

	const originalFetch = globalThis.fetch;
	t.after(() => {
		globalThis.fetch = originalFetch;
	});

	let cookieHeader = "";
	globalThis.fetch = (async (_input, init?: RequestInit): Promise<Response> => {
		cookieHeader = new Headers(init?.headers).get("Cookie") ?? "";
		return new Response(dashboardHtml({ rolling: { usagePercent: 1 } }), {
			status: 200,
			headers: { "Content-Type": "text/html" },
		});
	}) as typeof fetch;

	const snapshot = await provider.fetchUsage(
		authWith({ opencodeGo: { workspaceId: "wrk_x", cookie: "Fe26.2**session; Path=/; HttpOnly" } }),
	);
	assert.ok(snapshot);
	assert.equal(cookieHeader, "auth=Fe26.2**session");
});

test("opencode-go resolver ignores partial opencodeGo config", () => {
	assert.equal(
		__opencodeGoParser.resolveOpenCodeGoConfig({
			accessToken: "x",
			credential: { type: "api_key", key: "x", opencodeGo: { workspaceId: "wrk_x", cookie: "" } },
		}),
		null,
	);
	assert.equal(
		__opencodeGoParser.resolveOpenCodeGoConfig({
			accessToken: "x",
			credential: { type: "api_key", key: "x" },
		}),
		null,
	);
});

test("opencode-go parser tolerates intermediate SolidStart reference prefixes", () => {
	const html = `rollingUsage:$R[99]={status:"ok",resetInSec:18000,usagePercent:73}`;
	const parsed = __opencodeGoParser.extractUsageObject(html, "rollingUsage");
	assert.deepEqual(parsed, { status: "ok", resetInSec: 18000, usagePercent: 73 });
});

test("opencode-go parser returns null for missing keys", () => {
	assert.equal(__opencodeGoParser.extractUsageObject("<html></html>", "rollingUsage"), null);
	assert.equal(__opencodeGoParser.extractBalanceCents("<html></html>"), null);
});

test("opencode-go parser flags authorize-redirect urls", () => {
	assert.equal(
		__opencodeGoParser.looksLikeAuthRedirect("", "https://auth.opencode.ai/authorize?client_id=app"),
		true,
	);
	assert.equal(
		__opencodeGoParser.looksLikeAuthRedirect("", "https://opencode.ai/auth/callback?code=x"),
		true,
	);
	assert.equal(__opencodeGoParser.looksLikeAuthRedirect("<html>Sign in</html>", ""), true);
	assert.equal(
		__opencodeGoParser.looksLikeAuthRedirect("<html>dashboard</html>", "https://opencode.ai/workspace/wrk/go"),
		false,
	);
});

test("opencode-go parser clamps usage percentages", () => {
	const now = 100_000;
	const window = __opencodeGoParser.toRateLimitWindow(
		{ status: "ok", resetInSec: 100, usagePercent: 250 },
		300,
		now,
	);
	assert.deepEqual(window, { usedPercent: 100, windowMinutes: 300, resetsAt: now + 100 * 1000 });
});
