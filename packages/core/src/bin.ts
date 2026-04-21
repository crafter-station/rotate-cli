#!/usr/bin/env bun
import { runCli } from "./cli.ts";

runCli(process.argv).catch((err) => {
  process.stderr.write(`${String(err)}\n`);
  process.exit(1);
});
