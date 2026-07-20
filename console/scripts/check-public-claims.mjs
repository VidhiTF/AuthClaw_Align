import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const roots = [
  path.resolve("src/marketing"),
  path.resolve("src/app/(marketing)"),
  path.resolve("public"),
];

const supportedExtensions = new Set([".html", ".js", ".jsx", ".md", ".ts", ".tsx"]);
const prohibitedClaims = [
  ["SOC 2 Type II certification", /soc\s*2\s*type\s*ii\s*certif/gi],
  ["SOC 3 certification", /soc\s*3\s*certif/gi],
  ["unqualified GDPR compliance", /\bgdpr\s+compliant\b/gi],
  ["GDPR compliance guarantee", /guarantee(?:s|d)?\s+gdpr\s+compliance/gi],
  ["unsupported independent audit", /\bindependently\s+audited\b/gi],
  ["unissued SOC 2 report offer", /\blatest\s+soc\s*2\s+report\b/gi],
  ["tamper-proof guarantee", /\btamper-proof\b/gi],
  ["immutable audit guarantee", /\bimmutable\b/gi],
  ["unsupported 99.99% SLA", /99\.99%\s+(?:uptime\s+)?sla\b/gi],
  ["absolute 100% request claim", /\b100%[^\r\n]{0,80}\b(?:prompts|responses|requests)\b/gi],
];

async function filesUnder(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await filesUnder(candidate)));
    } else if (entry.isFile() && supportedExtensions.has(path.extname(entry.name))) {
      files.push(candidate);
    }
  }
  return files;
}

const violations = [];
for (const root of roots) {
  if (!(await stat(root)).isDirectory()) {
    continue;
  }
  for (const file of await filesUnder(root)) {
    const source = await readFile(file, "utf8");
    for (const [label, pattern] of prohibitedClaims) {
      pattern.lastIndex = 0;
      for (const match of source.matchAll(pattern)) {
        const index = match.index ?? 0;
        const line = source.slice(0, index).split(/\r?\n/).length;
        violations.push(
          `${path.relative(process.cwd(), file)}:${line}: ${label}: ${JSON.stringify(match[0])}`,
        );
      }
    }
  }
}

if (violations.length > 0) {
  console.error("Unsupported public compliance claims found:");
  console.error(violations.join("\n"));
  process.exit(1);
}

console.log("Public claim scan passed.");
