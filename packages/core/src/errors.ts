import type { AdapterError, AdapterErrorCode } from "./types.ts";

export function makeError(
  code: AdapterErrorCode,
  message: string,
  provider: string,
  opts: { retryable?: boolean; cause?: unknown } = {},
): AdapterError {
  return {
    code,
    message,
    provider,
    retryable: opts.retryable ?? defaultRetryable(code),
    cause: opts.cause,
  };
}

function defaultRetryable(code: AdapterErrorCode): boolean {
  switch (code) {
    case "rate_limited":
    case "network_error":
    case "provider_error":
      return true;
    default:
      return false;
  }
}

export class RotateError extends Error {
  constructor(
    public readonly adapterError: AdapterError,
    public readonly exitCode: number = 2,
  ) {
    super(adapterError.message);
    this.name = "RotateError";
  }
}

export const EXIT = {
  OK: 0,
  USER_ERROR: 1,
  PROVIDER_ERROR: 2,
  VERIFY_FAILED: 3,
  IN_GRACE_WARNING: 4,
  AGENT_GUARDRAIL: 5,
  INTERRUPTED: 130,
} as const;
