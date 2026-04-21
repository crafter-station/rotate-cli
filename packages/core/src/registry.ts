import type { Adapter, Consumer } from "./types.ts";
import { getAuthDefinition, registerAuthDefinition, resetAuthDefinitions } from "./auth.ts";

/** Simple registry. Packages register via register() at import time. */
const adapters = new Map<string, Adapter>();
const consumers = new Map<string, Consumer>();

export function registerAdapter(adapter: Adapter): void {
  if (adapters.has(adapter.name)) {
    throw new Error(`adapter already registered: ${adapter.name}`);
  }
  if (adapter.authDefinition) {
    const expectedName = adapter.authRef ?? adapter.name;
    if (adapter.authDefinition.name !== expectedName) {
      throw new Error(
        `adapter auth definition mismatch: ${adapter.name} expected ${expectedName}, got ${adapter.authDefinition.name}`,
      );
    }
    const registered = getAuthDefinition(adapter.authDefinition.name);
    if (registered) {
      throw new Error(`auth definition already registered: ${adapter.authDefinition.name}`);
    }
    registerAuthDefinition(adapter.authDefinition);
  }
  adapters.set(adapter.name, adapter);
}

export function registerConsumer(consumer: Consumer): void {
  if (consumers.has(consumer.name)) {
    throw new Error(`consumer already registered: ${consumer.name}`);
  }
  consumers.set(consumer.name, consumer);
}

export function getAdapter(name: string): Adapter | undefined {
  return adapters.get(name);
}

export function getConsumer(name: string): Consumer | undefined {
  return consumers.get(name);
}

export function listAdapters(): Adapter[] {
  return [...adapters.values()];
}

export function listConsumers(): Consumer[] {
  return [...consumers.values()];
}

export function resetRegistry(): void {
  adapters.clear();
  consumers.clear();
  resetAuthDefinitions();
}
