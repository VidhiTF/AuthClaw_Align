import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const roots = [
  path.resolve("src/marketing"),
  path.resolve("src/app/(marketing)"),
  path.resolve("src/app/trust-center"),
  path.resolve("src/components"),
  path.resolve("public"),
];

const claimRegister = await readFile(
  path.resolve("../docs/compliance/PUBLIC_CLAIM_REGISTER.md"),
  "utf8",
);
const approvalRecord = await readFile(
  path.resolve("../docs/compliance/ACL-35_PUBLIC_CLAIMS_APPROVAL.md"),
  "utf8",
);

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
  ["hardcoded public readiness score", /<b>\s*\d{1,3}(?:\.\d+)?%\s*<\/b>/gi],
];

const requiredClaims = [
  {
    id: "CLM-001",
    evidence: "docs/COMPLIANCE_BOUNDARY.md",
    surface: /technical controls that support GDPR obligations and SOC 2 readiness/i,
  },
  {
    id: "CLM-002",
    evidence: "gateway and agent redaction tests",
    surface: /configured sensitive-data patterns can be (?:detected and )?redacted before model-provider egress/i,
  },
  {
    id: "CLM-003",
    evidence: "audit-store tests",
    surface: /signed evidence export/i,
  },
  {
    id: "CLM-004",
    evidence: "evidence-supported readiness indicators",
    surface: /automated framework scoring/i,
  },
  {
    id: "CLM-006",
    evidence: "independent CPA firm",
    surface: /not an independent SOC 2 Type II report or a SOC 3 report/i,
  },
  {
    id: "CLM-014",
    evidence: "automated framework-scoring criteria",
    surface: /no certification is implied/i,
  },
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
let publicSource = "";
for (const root of roots) {
  let rootStat;
  try {
    rootStat = await stat(root);
  } catch (error) {
    if (error?.code === "ENOENT") continue;
    throw error;
  }
  if (!rootStat.isDirectory()) {
    continue;
  }
  for (const file of await filesUnder(root)) {
    const source = await readFile(file, "utf8");
    publicSource += `\n${source}`;
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

for (const claim of requiredClaims) {
  if (!claimRegister.includes(`| ${claim.id} |`)) {
    violations.push(`claim register: missing ${claim.id}`);
  }
  if (!claimRegister.includes(claim.evidence) && !approvalRecord.includes(claim.evidence)) {
    violations.push(`claim evidence: ${claim.id} is not mapped to ${JSON.stringify(claim.evidence)}`);
  }
  if (!claim.surface.test(publicSource)) {
    violations.push(`public surface: approved wording for ${claim.id} is missing`);
  }
}

const trustCenterContracts = [
  ["email-bound access", /X-Trust-Center-Access/i],
  ["control evidence", /control\.evidence/],
  ["signed export", /\/signed-export/],
  ["export verification", /Upload and Verify/],
];
const trustCenterSource = await readFile(path.resolve("src/app/trust-center/[token]/page.tsx"), "utf8");
for (const [label, pattern] of trustCenterContracts) {
  if (!pattern.test(trustCenterSource)) violations.push(`Trust Center: missing ${label} claim evidence`);
}

const demoSource = await readFile(path.resolve("src/app/(marketing)/demo/page.tsx"), "utf8");
if (!demoSource.includes('requestedAccess="DEMO"') || !demoSource.includes('sourcePage="/demo"')) {
  violations.push("Demo: canonical intake contract is missing");
}
if (/certif|compliant|guarantee|independently audited/i.test(demoSource)) {
  violations.push("Demo: unapproved material claim found on the intake route");
}

if (violations.length > 0) {
  console.error("Unsupported public compliance claims found:");
  console.error(violations.join("\n"));
  process.exit(1);
}

console.log("Public claim scan passed.");
