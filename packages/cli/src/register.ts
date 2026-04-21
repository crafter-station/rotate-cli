/**
 * Register every adapter and consumer with the core registry.
 * Called once at CLI boot (before command.parse).
 *
 * Keep this file flat — one line per package. New adapters added to the
 * monorepo must also be added here to be usable from the CLI.
 */

import { registerAdapter, registerConsumer } from "@rotate/core";

import aiGatewayAdapter from "@rotate/adapter-ai-gateway";
import anthropicAdapter from "@rotate/adapter-anthropic";
import clerkAdapter from "@rotate/adapter-clerk";
import elevenLabsAdapter from "@rotate/adapter-elevenlabs";
import falAdapter from "@rotate/adapter-fal";
import githubTokenAdapter from "@rotate/adapter-github-token";
import neonAdapter from "@rotate/adapter-neon";
import neonConnectionAdapter from "@rotate/adapter-neon-connection";
import openaiAdapter from "@rotate/adapter-openai";
import polarAdapter from "@rotate/adapter-polar";
import resendAdapter from "@rotate/adapter-resend";
import supabaseAdapter from "@rotate/adapter-supabase";
import tursoAdapter from "@rotate/adapter-turso";
import upstashAdapter from "@rotate/adapter-upstash";
import vercelKvAdapter from "@rotate/adapter-vercel-kv";
import vercelTokenAdapter from "@rotate/adapter-vercel-token";

import githubActionsConsumer from "@rotate/consumer-github-actions";
import localEnvConsumer from "@rotate/consumer-local-env";
import vercelEnvConsumer from "@rotate/consumer-vercel-env";

let registered = false;

export function registerAll(): void {
  if (registered) return;
  registered = true;

  registerAdapter(clerkAdapter);
  registerAdapter(openaiAdapter);
  registerAdapter(anthropicAdapter);
  registerAdapter(githubTokenAdapter);
  registerAdapter(resendAdapter);
  registerAdapter(supabaseAdapter);
  registerAdapter(neonAdapter);
  registerAdapter(neonConnectionAdapter);
  registerAdapter(vercelTokenAdapter);
  registerAdapter(aiGatewayAdapter);
  registerAdapter(upstashAdapter);
  registerAdapter(vercelKvAdapter);
  registerAdapter(polarAdapter);
  registerAdapter(falAdapter);
  registerAdapter(elevenLabsAdapter);
  registerAdapter(tursoAdapter);

  registerConsumer(vercelEnvConsumer);
  registerConsumer(githubActionsConsumer);
  registerConsumer(localEnvConsumer);
}
