import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

const sourcePackagePath = require.resolve("picomatch/package.json");
const nextPackagePath = require.resolve("next/package.json");
const sourceDir = path.dirname(sourcePackagePath);
const nextDir = path.dirname(nextPackagePath);
const targetDir = path.join(nextDir, "dist", "compiled", "picomatch");

const sourcePackage = JSON.parse(fs.readFileSync(sourcePackagePath, "utf8"));
if (sourcePackage.version !== "4.0.4") {
  throw new Error(`Expected picomatch 4.0.4, found ${sourcePackage.version}`);
}

if (!fs.existsSync(targetDir)) {
  throw new Error(`Next.js bundled picomatch path not found: ${targetDir}`);
}

fs.rmSync(targetDir, { recursive: true, force: true });
fs.cpSync(sourceDir, targetDir, { recursive: true });

const patchedPackage = JSON.parse(fs.readFileSync(path.join(targetDir, "package.json"), "utf8"));
if (patchedPackage.version !== "4.0.4") {
  throw new Error(`Failed to patch Next.js bundled picomatch, found ${patchedPackage.version}`);
}

console.log(`Patched Next.js bundled picomatch to ${patchedPackage.version}`);
