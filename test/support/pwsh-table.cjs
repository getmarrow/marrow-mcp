'use strict';

// The PowerShell table (R1 round): what each PowerShell command is, read as PowerShell reads it, never as Bash
// reads the same text. Every expectation below is about what the PowerShell command DOES:
//   protected: true  = it reads, writes, deletes or runs a secret or credential file (or a production /
//                      publish / push word the 3.9.103 classifier already held on);
//   protected: false = it does not (a source file, a directory listing, a plain message, a program).
// A PowerShell call is never read-only; its risk is never below medium (3.9.103 never put PowerShell below
// rw/medium), and high exactly when it is protected. `type`, `cat`, `gc`, `find` and `ls` are PowerShell
// aliases and programs of their own (Get-Content, Get-ChildItem, find.exe), so none of them is "non-content".
// Rows marked `eqBase` are the ones the fail-closed spec leaves at 3.9.103's answer (rw/medium, unprotected):
// nothing in them is a file name the splitter can see (an environment drive, an encoded command, a variable).
// Names only: no value of any credential appears here. Nothing here is executed.

const encoded = (text) => Buffer.from(text, 'utf16le').toString('base64');

// [command, protected, note]
const ROWS = [
  // type and its aliases, every case
  ['type ./production.env', true],
  ['type .env', true],
  ['TYPE ./production.env', true],
  ['Type ./production.env', true],
  ['tYpE .env', true],
  ['type ~/.ssh/id_rsa', true],
  ['type ./README.md', false],
  ['type ./prod*.env', true],
  ['type ./*.env', true],
  ['gc ./production.env', true],
  ['cat ./production.env', true],
  ['cat .env', true],
  ['Get-Content ./production.env', true],
  ['GET-CONTENT ./production.env', true],
  ['get-content .env', true],
  ['Get-Content -Path ./production.env', true],
  ['Get-Content -Path:.env', true],
  ['Get-Content -LiteralPath .env', true],
  ['Get-Content -Raw ./production.env', true],
  ['Get-Content -Raw README.md', false],
  ['more ./production.env', true],
  ['select-string KEY ./production.env', true],
  ['sls KEY ./production.env', true],
  ['Select-String -Path ./production.env -Pattern KEY', true],
  ['find "KEY" ./production.env', true],
  ['find "KEY" .env', true],
  ['findstr KEY ./production.env', true],
  ['ii ./production.env', true],
  ['Invoke-Item ./x.ps1', false],
  // Windows paths (a backslash is a path separator in PowerShell)
  ['type .\\.env', true],
  ['type .\\secrets\\a.txt', true],
  ['type C:\\Users\\u\\.ssh\\id_rsa', true],
  ['type ~\\.ssh\\id_rsa', true],
  ['type $HOME\\.ssh\\id_rsa', true],
  ['type .\\README.md', false],
  ['Get-Content C:\\work\\src\\index.ts', false],
  // writes and deletes
  ['ac ./production.env x', true],
  ['sc ./production.env x', true],
  ['Set-Content ./production.env x', true],
  ['Add-Content ./x.txt y', false],
  ['Out-File ./production.env', true],
  ['Get-Date | Out-File ./production.env', true],
  ['Get-Process | Out-File ./out.txt', false],
  ['rm ./production.env', true],
  ['ri ./production.env', true],
  ['del ./production.env', true],
  ['erase ./production.env', true],
  ['Remove-Item -Recurse -Force ./src', false],
  ['rd ./src', false],
  ['rmdir ./src', false],
  // redirection
  ['Get-Content README.md > ./production.env', true],
  ['Get-Content README.md >> .env', true],
  ['type .env 2>&1', true],
  ['echo hi >> ./x.txt', false],
  ['echo hi 2>&1', false],
  ['type .env *> ./out.txt', true],
  // listings and environment (eqBase: no file name is visible)
  ['dir ./.ssh', true],
  ['ls ~/.aws', true],
  ['ls env:', false, 'eqBase'],
  ['dir env:', false, 'eqBase'],
  ['gci env:', false, 'eqBase'],
  ['Get-ChildItem Env:', false, 'eqBase'],
  ['cat env:X', false, 'eqBase'],
  ['cat env:MARROW_API_KEY', false, 'eqBase'],
  ['type env:MARROW_API_KEY', false, 'eqBase'],
  ['echo $env:X', false, 'eqBase'],
  ['echo ${env:X}', false, 'eqBase'],
  ['echo $env:MARROW_API_KEY', false, 'eqBase'],
  ['Write-Output $env:MARROW_API_KEY', false, 'eqBase'],
  ['echo ${env:MARROW_API_KEY}', false, 'eqBase'],
  ['$env:MARROW_API_KEY', false, 'eqBase'],
  // bare env / printenv print every variable the process holds (pwsh on Linux and macOS runs them)
  ['env', true],
  ['printenv', true],
  ['env | Out-File ./o.txt || echo x’y', true],
  ['env 2>&1 && npm test x’y', true],
  // text PowerShell and Bash split differently: a secret either split finds is one
  ['powershell -Command "a\\" # ; TYPE \'.env\' *.env', true],
  ['ls', false],
  ['Get-ChildItem', false],
  ['dir', false],
  ['pwd', false],
  ['echo hello', false],
  ['Write-Output hello', false],
  ['git status', false],
  ['git log --oneline -5', false],
  ['Get-Process | Select-Object -First 5', false],
  ['Get-Date', false],
  // chaining
  ['echo hi; type ./production.env', true],
  ['echo hi; type .env', true],
  ['echo hi | type ./production.env', true],
  ['echo hi | type .env', true],
  ['echo hi && type ./production.env', true],
  ['echo hi && type .env', true],
  ['false || type .env', true],
  ['echo $(type .env)', true],
  ['(type .env)', true],
  ['echo hi; ls; pwd', false],
  ['ls | Select-Object -First 3', false],
  ['ls && pwd', false],
  // nested shells and code carriers
  ['pwsh -Command "type ./production.env"', true],
  ['pwsh -Command "type .env"', true],
  ['powershell -c "type .env"', true],
  ['powershell -c type .env', true],
  ['cmd /c type .env', true],
  ['cmd /c "type .env"', true],
  ['cmd --% /c type .env', true],
  ['iex "type ./production.env"', true],
  ['iex "type .env"', true],
  ['Invoke-Expression "type .env"', true],
  ['iex $payload', false, 'eqBase'],
  ['Invoke-Expression $payload', false, 'eqBase'],
  ['. ./x.ps1', false],
  ['Start-Process notepad ./production.env', true],
  ['Start-Process notepad .env', true],
  ['Start-Process ./build.exe', false],
  [`powershell -EncodedCommand ${encoded('type ./production.env')}`, false, 'eqBase'],
  [`powershell -enc ${encoded('type .env')}`, false, 'eqBase'],
  [`powershell -e ${encoded('type .env')}`, false, 'eqBase'],
  [`pwsh -ec ${encoded('type .env')}`, false, 'eqBase'],
  // call operator, quoting, escapes, comments, here-strings
  ['& type ./production.env', true],
  ['& type .env', true],
  ['& "type" ./production.env', true],
  ["& 'type' .env", true],
  ['& "type" .env', true],
  ['ty`pe ./production.env', true],
  ['ty`pe .env', true],
  ['type `\n.env', true],
  ['type <# a comment #> .env', true],
  ['type .env # a comment', true],
  ["Get-Content @'\n.env\n'@", true],
  ['Get-Content @"\n.env\n"@', true],
  ["Write-Output @'\nhello\n'@", false],
  ['echo "a\\" ; type ./production.env ; echo \\"b"', true],
  ['echo "a\\" ; type .env ; echo \\"b"', true],
  ['echo "a” ; type .env ; echo “b"', true],
  ["echo 'a’ ; type .env ; echo ‘b'", true],
  // unknown verbs and aliases fail closed
  ['Foo-Bar .env', true],
  ['Foo-Bar README.md', false],
  ['gcm', false],
  ['xyz ./production.env', true],
  ['xyz', false],
  // misleading words and publish/push words (3.9.103 already held these)
  ['git push origin main', true],
  ['git commit -m "production fix"', true],
  ['Write-Output "production deploy"', true],
  ['npm publish', true],
  ['npm test', false],
];

// The labels a PowerShell call arrives under; all but the last are the same tool.
const POWERSHELL_LABELS = ['PowerShell', 'powershell', 'POWERSHELL', ' PowerShell ', 'PowerShell\n', 'PoWeRsHeLl'];
// A PowerShell call of another MCP server (stays a named, protected MCP tool).
const MCP_LABELS = ['mcp__x__PowerShell', 'mcp__plugin_x_y__powershell'];

// The input forms a PowerShell call takes: the shell text in `command`, in `script`, or in both.
const FORMS = [
  ['command', (c) => ({ command: c })],
  ['command+description', (c) => ({ command: c, description: 'd' })],
  ['script', (c) => ({ script: c })],
  ['script+timeout', (c) => ({ script: c, timeout: 5000, run_in_background: false })],
  ['command+script(same)', (c) => ({ command: c, script: c })],
  ['command(ls)+script', (c) => ({ command: 'ls', script: c })],
  ['command+script(ls)', (c) => ({ command: c, script: 'ls' })],
];

/** Every event of the table (canonical label, every form), as {key, event, row}. */
function tableEvents() {
  const events = [];
  for (const row of ROWS) {
    for (const [form, make] of FORMS) {
      events.push({ form, row, event: { tool_name: 'PowerShell', tool_input: make(row[0]) } });
    }
  }
  // Label variants and the MCP look-alike over a fixed set of anchor commands.
  const anchors = ['type .env', 'type ./README.md', 'ls', 'type ./production.env', 'echo hi; type .env'];
  for (const command of anchors) {
    const row = ROWS.find((r) => r[0] === command);
    for (const label of [...POWERSHELL_LABELS, ...MCP_LABELS]) {
      for (const [form, make] of FORMS.slice(0, 3)) events.push({ form: `${label}|${form}`, row, event: { tool_name: label, tool_input: make(command) }, label });
    }
  }
  return events;
}

const eventKey = (event) => JSON.stringify({ tool_name: event.tool_name, tool_input: event.tool_input });

module.exports = { ROWS, POWERSHELL_LABELS, MCP_LABELS, FORMS, tableEvents, eventKey };
