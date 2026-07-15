#!/usr/bin/env node

import { readFile } from "node:fs/promises";

import * as basic from "@secvisogram/csaf-validator-lib/basic.js";
import validateStrict from "@secvisogram/csaf-validator-lib/validateStrict.js";

const documentPaths = process.argv.slice(2);
if (documentPaths.length === 0) {
  console.error("usage: validate.mjs DOCUMENT [DOCUMENT ...]");
  process.exit(2);
}

const tests = Object.values(basic).filter((candidate) => typeof candidate === "function");
const mandatoryTests = tests.filter((test) => test.name.startsWith("mandatoryTest_"));
const strictSchemaTests = tests.filter((test) => test.name === "csaf_2_0_strict");

if (tests.length !== 43 || mandatoryTests.length !== 42 || strictSchemaTests.length !== 1) {
  console.error(
    `unexpected basic suite: ${tests.length} total, ` +
      `${mandatoryTests.length} mandatory, ${strictSchemaTests.length} strict schema`,
  );
  process.exit(1);
}

let failed = false;
for (const documentPath of documentPaths) {
  try {
    const document = JSON.parse(await readFile(documentPath, "utf8"));
    const result = await validateStrict(tests, document);
    if (!result.isValid) {
      failed = true;
      console.error(`${documentPath}: CSAF 2.0 basic suite failed`);
      for (const test of result.tests.filter((testResult) => !testResult.isValid)) {
        console.error(`  ${test.name}: failed`);
        for (const error of test.errors) {
          console.error(`    ${error.instancePath || "/"}: ${error.message}`);
        }
      }
      continue;
    }
    console.log(
      `${documentPath}: valid (${mandatoryTests.length} mandatory tests + strict schema)`,
    );
  } catch (error) {
    failed = true;
    const message = error instanceof Error ? error.message : String(error);
    console.error(`${documentPath}: validation could not run: ${message}`);
  }
}

if (failed) {
  process.exit(1);
}
