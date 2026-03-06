# File_Integrity_Check
for checking file version revert or deletion on portal.
install node.js
to install n8n use command: npm install n8n -g

run using>
on powershell:

''' 

$env:NODES_EXCLUDE='[]'


$env:N8N_RESTRICT_FILE_ACCESS_TO="C:\...\project\file_check;C:\...\reports"


n8n start

'''

view on: http://localhost:5678



Execute command cmd for windows: cmd /c python "C:\...\file_check\watch_s_drive.py" --root "C:\\" --max-workers 6 --no-hash-new-files --latest-json "C:\...\file_check\reports\latest.json"


the javascript:
"


const stdout = ($json.stdout || '').trim();
const stderr = ($json.stderr || '').trim();
const exitCode = $json.exitCode;

function makeErrorReport(title, details) {
  const lines = [];
  lines.push(title);
  lines.push(`Time (local): ${new Date().toISOString()}`);
  lines.push(`Exit code: ${exitCode}`);
  lines.push('');
  lines.push('Details:');
  lines.push(details);
  lines.push('');
  if (stderr) {
    lines.push('stderr:');
    lines.push(stderr.slice(0, 4000));
  }
  if (stdout) {
    lines.push('');
    lines.push('stdout (preview):');
    lines.push(stdout.slice(0, 2000));
  }
  return lines.join('\r\n');
}

if (!stdout) {
  const ops_report = makeErrorReport('ERROR: No stdout from Python run', 'The command produced no stdout output.');
  const payload = { ok: false, exitCode, stderr, ops_report };
  payload.full_json_text = JSON.stringify(payload, null, 2);
  return [{ json: payload }];
}

let data;
try {
  data = JSON.parse(stdout);
} catch (e) {
  const ops_report = makeErrorReport('ERROR: Failed to parse JSON from stdout', String(e));
  const payload = { ok: false, exitCode, stderr, parseError: String(e), ops_report };
  payload.full_json_text = JSON.stringify(payload, null, 2);
  return [{ json: payload }];
}

// success path: build report
const high = data.stats?.high ?? 0;
const events = Array.isArray(data.events) ? data.events : [];

const lines = [];
lines.push(`File Watch Run: ${data.run_id}`);
lines.push(`Started (UTC): ${data.started_at_utc}`);
lines.push(`Root: ${data.root}`);
lines.push(`Scanned files: ${data.stats?.scanned_files ?? '?'}`);
lines.push(`Hashed files: ${data.stats?.hashed_files ?? '?'}`);
lines.push(`Events: ${data.stats?.events ?? 0} (high=${high}, medium=${data.stats?.medium ?? 0}, low=${data.stats?.low ?? 0})`);
lines.push(`CSV: ${data.reports?.events_csv ?? ''}`);
lines.push('');

if (high > 0) {
  lines.push('HIGH SEVERITY EVENTS (up to 50):');
  events.filter(e => e.severity === 'high').slice(0, 50).forEach(e => {
    lines.push(`- ${e.type}: ${e.path || e.old_path || ''}`);
  });
} else {
  lines.push('No high severity events detected.');
}

data.ok = true;
data.ops_report = lines.join('\r\n');
data.full_json_text = JSON.stringify(data, null, 2);

return [{ json: data }];


"



