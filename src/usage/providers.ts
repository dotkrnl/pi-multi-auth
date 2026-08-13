import { anthropicUsageProvider } from "./anthropic.js";
import { blazeapiUsageProvider } from "./blazeapi.js";
import { codexUsageProvider } from "./codex.js";
import { commandCodeUsageProvider } from "./command-code.js";
import { copilotUsageProvider } from "./copilot.js";
import { kimiCodingUsageProvider } from "./kimi-coding.js";
import { kiroUsageProvider } from "./kiro.js";
import { opencodeGoUsageProvider } from "./opencode-go.js";
import { zaiCodingCnUsageProvider } from "./zai-coding-cn.js";
import type { UsageAuth, UsageProvider } from "./types.js";

// qwen remains intentionally excluded until it exposes a reliable
// credential-scoped usage endpoint that fits the current usage/quota architecture.
export const usageProviders: ReadonlyArray<UsageProvider<UsageAuth>> = [
	codexUsageProvider,
	copilotUsageProvider,
	anthropicUsageProvider,
	kimiCodingUsageProvider,
	commandCodeUsageProvider,
	kiroUsageProvider,
	blazeapiUsageProvider,
	zaiCodingCnUsageProvider,
	opencodeGoUsageProvider,
];
