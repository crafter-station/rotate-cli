#!/usr/bin/env bun
import { runCli } from "@rotate/core";
import { registerAll } from "./register.ts";

registerAll();

runCli(process.argv).catch((err) => {
  process.stderr.write(`${String(err)}\n`);
  process.exit(1);
});
