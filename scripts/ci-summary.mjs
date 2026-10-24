import fs from 'node:fs';

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

const lines = ['## Security CI summary', ''];
const audit = readJson('reports/npm-audit.json');
const eslint = readJson('reports/eslint.json');

if (audit && audit.metadata && audit.metadata.vulnerabilities) {
  const counts = audit.metadata.vulnerabilities;
  lines.push(
    `- SCA (npm audit): total=${counts.total ?? 0}, high=${counts.high ?? 0}, critical=${counts.critical ?? 0}`
  );
} else {
  lines.push('- SCA (npm audit): report unavailable');
}

if (Array.isArray(eslint)) {
  const errors = eslint.reduce((total, result) => total + result.errorCount, 0);
  const warnings = eslint.reduce((total, result) => total + result.warningCount, 0);
  lines.push(`- SAST (ESLint security): errors=${errors}, warnings=${warnings}`);
} else {
  lines.push('- SAST (ESLint security): report unavailable');
}

const summary = `${lines.join('\n')}\n`;
console.log(summary);

if (process.env.GITHUB_STEP_SUMMARY) {
  fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
}
