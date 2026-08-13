import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuthWriter } from "../src/auth-writer.js";

test("AuthWriter recovers corrupted auth.json from backup", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-auth-recovery-"));
	const authPath = join(tempRoot, "auth.json");
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	const backup = {
		provider: {
			type: "api_key",
			key: "secret-value",
		},
	};
	await writeFile(authPath, "{", "utf-8");
	await writeFile(`${authPath}.bak`, JSON.stringify(backup, null, 2), "utf-8");

	const writer = new AuthWriter(authPath);
	const credential = await writer.getCredential("provider");

	assert.equal(credential?.type, "api_key");
	assert.equal(credential?.key, "secret-value");
	assert.deepEqual(JSON.parse(await readFile(authPath, "utf-8")), backup);
});

test("AuthWriter backs up auth.json before overwrite", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-auth-backup-"));
	const authPath = join(tempRoot, "auth.json");
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	await writeFile(authPath, JSON.stringify({ provider: { type: "api_key", key: "old" } }), "utf-8");
	const writer = new AuthWriter(authPath);
	await writer.setApiKeyCredential("provider", "new");

	const backup = JSON.parse(await readFile(`${authPath}.bak`, "utf-8")) as Record<string, { key?: string }>;
	assert.equal(backup.provider?.key, "old");
	const current = await writer.getCredential("provider");
	assert.equal(current?.type, "api_key");
	assert.equal(current?.key, "new");
});

test("AuthWriter persists and clears per-credential OpenCode Go quota config", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-opencode-go-"));
	const authPath = join(tempRoot, "auth.json");
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	await writeFile(
		authPath,
		JSON.stringify({
			"opencode-go": { type: "api_key", key: "oc-key", request: { baseUrl: "https://opencode.ai/zen/go/v1" } },
		}),
		"utf-8",
	);
	const writer = new AuthWriter(authPath);

	// Setting preserves the existing key and sibling request overrides.
	const updated = await writer.setOpenCodeGoQuotaConfig("opencode-go", {
		workspaceId: "  wrk_demo  ",
		cookie: "  Fe26.2**demo  ",
	});
	assert.equal(updated.type, "api_key");
	assert.equal(updated.key, "oc-key");
	assert.equal(updated.request?.baseUrl, "https://opencode.ai/zen/go/v1");
	assert.deepEqual(updated.opencodeGo, { workspaceId: "wrk_demo", cookie: "Fe26.2**demo" });

	const reread = await writer.getCredential("opencode-go");
	assert.equal(reread?.opencodeGo?.workspaceId, "wrk_demo");
	assert.equal(reread?.opencodeGo?.cookie, "Fe26.2**demo");

	// Clearing removes the field but keeps the key.
	const cleared = await writer.setOpenCodeGoQuotaConfig("opencode-go", null);
	assert.equal(cleared.opencodeGo, undefined);
	assert.equal(cleared.key, "oc-key");

	// Empty/partial config is rejected.
	await assert.rejects(
		writer.setOpenCodeGoQuotaConfig("opencode-go", { workspaceId: "wrk_x", cookie: "" }),
		/both required/,
	);
	await assert.rejects(
		writer.setOpenCodeGoQuotaConfig("missing", { workspaceId: "wrk_x", cookie: "c" }),
		/missing from auth.json/,
	);
});

test("AuthWriter rejects empty credential id for OpenCode Go quota config", async (t) => {
	const tempRoot = await mkdtemp(join(tmpdir(), "pi-multi-auth-opencode-go-id-"));
	const authPath = join(tempRoot, "auth.json");
	t.after(async () => {
		await rm(tempRoot, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
	});

	await writeFile(authPath, JSON.stringify({ "opencode-go": { type: "api_key", key: "k" } }), "utf-8");
	const writer = new AuthWriter(authPath);
	await assert.rejects(
		writer.setOpenCodeGoQuotaConfig("   ", { workspaceId: "wrk_x", cookie: "c" }),
		/Credential ID cannot be empty/,
	);
});
