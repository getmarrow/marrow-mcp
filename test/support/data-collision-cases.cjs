'use strict';
// Approval-key collision cases for data a command reads (echo/printf into a
// pipe or file, here-strings, heredocs) and the other places a secret can sit.
// build(secret, tail): the tail differs outside the secret. `bash` events go
// through the shell normalizer, `mcp` events through the tool-input path.
// feedsSecrets: everything the data carries is stored in a secrets store, so
// the whole data is the secret and the pair is equal by design (truncated,
// never binds an approval).
// keyShapedOnly: the command escapes quotes inside double quotes (`"{\"k\":…}"`),
// which the shell-word approximation does not unescape (pre-existing, as in
// 3.9.102): a secret there is found only by its key shape, so these cases use
// the key-shaped dummy only.

const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } });
const mcp = (input) => ({ tool_name: 'mcp__api__post', tool_input: input });

const DATA_CASES = [
  { path: 'echo json pipe', build: (s, t) => bash(`echo '{"api_key":"${s}","env":"${t}"}' | post`) },
  { path: 'echo json pipe, spaced password', build: (s, t) => bash(`echo '{"password": "${s}", "env": "${t}"}' | post`) },
  { path: 'echo json pipe, token', build: (s, t) => bash(`echo '{"token":"${s}","env":"${t}"}' | post`) },
  { path: 'echo double-quoted json pipe', keyShapedOnly: true, build: (s, t) => bash(`echo "{\\"client_secret\\":\\"${s}\\",\\"env\\":\\"${t}\\"}" | post`) },
  { path: 'echo json into a file', build: (s, t) => bash(`echo '{"api_key":"${s}","env":"${t}"}' > payload.json`) },
  { path: 'echo NAME=value pipe', build: (s, t) => bash(`echo "DB_PASSWORD=${s} env=${t}" | post`) },
  { path: 'echo Authorization header pipe', build: (s, t) => bash(`echo "Authorization: Basic ${s} env=${t}" | post`) },
  { path: 'echo URL userinfo pipe', build: (s, t) => bash(`echo "postgres://admin:${s}@db.example/${t}" | migrate`) },
  { path: 'echo -n json pipe', build: (s, t) => bash(`echo -n '{"access_token":"${s}","env":"${t}"}' | post`) },
  { path: 'printf json pipe', build: (s, t) => bash(`printf '{"api_key":"${s}","env":"${t}"}' | post`) },
  { path: 'printf %s json pipe', build: (s, t) => bash(`printf '%s' '{"password":"${s}","env":"${t}"}' | post`) },
  { path: 'printf URL userinfo pipe', build: (s, t) => bash(`printf 'postgres://admin:${s}@db.example/${t}' | migrate`) },
  { path: 'here-string json', build: (s, t) => bash(`post <<< '{"api_key":"${s}","env":"${t}"}'`) },
  { path: 'here-string NAME=value', build: (s, t) => bash(`post <<< "API_KEY=${s} env=${t}"`) },
  { path: 'heredoc json', build: (s, t) => bash(`cat <<EOF | post\n{"api_key":"${s}","env":"${t}"}\nEOF`) },
  { path: 'heredoc env lines', build: (s, t) => bash(`cat <<'EOF' > settings.ini\nTOKEN=${s}\nENV=${t}\nEOF`) },
  { path: 'curl -d json', build: (s, t) => bash(`curl -d '{"api_key":"${s}","env":"${t}"}' https://api.example/x`) },
  { path: 'curl -d form body', build: (s, t) => bash(`curl -d "password=${s}&env=${t}" https://api.example/x`) },
  { path: 'curl --data-urlencode', build: (s, t) => bash(`curl --data-urlencode "token=${s}" --data-urlencode "env=${t}" https://api.example/x`) },
  { path: 'URL query, field after', build: (s, t) => bash(`curl "https://api.example/x?token=${s}&env=${t}"`) },
  { path: 'URL query, path differs', build: (s, t) => bash(`curl "https://api.example/${t}?api_key=${s}"`) },
  { path: 'URL userinfo', build: (s, t) => bash(`psql "postgres://admin:${s}@db.example/${t}" -c "select 1"`) },
  { path: 'header Bearer', build: (s, t) => bash(`curl -H "Authorization: Bearer ${s}" https://api.example/${t}`) },
  { path: 'header X-Api-Key', build: (s, t) => bash(`curl -H "X-Api-Key: ${s}" https://api.example/${t}`) },
  { path: 'env assignment', build: (s, t) => bash(`API_KEY=${s} ./deploy.sh ${t}`) },
  { path: 'export then command', build: (s, t) => bash(`export TOKEN=${s}; ./deploy.sh ${t}`) },
  { path: 'plain env assignment holding json', build: (s, t) => bash(`PAYLOAD='{"api_key":"${s}","env":"${t}"}' ./post.sh`) },
  { path: 'flag value', build: (s, t) => bash(`tool --token ${s} --env ${t}`) },
  { path: 'flag=value', build: (s, t) => bash(`tool --api-key=${s} --stage ${t}`) },
  { path: 'bash -c echo json pipe', keyShapedOnly: true, build: (s, t) => bash(`bash -c "echo '{\\"api_key\\":\\"${s}\\",\\"env\\":\\"${t}\\"}' | post"`) },
  { path: 'ssh echo json pipe', keyShapedOnly: true, build: (s, t) => bash(`ssh host "echo '{\\"api_key\\":\\"${s}\\",\\"env\\":\\"${t}\\"}' | post"`) },
  { path: 'env store json value', build: (s, t) => bash(`netlify env:set PAYLOAD '{"api_key":"${s}","env":"${t}"}'`) },
  { path: 'chained: echo json pipe && deploy', build: (s, t) => bash(`echo '{"api_key":"${s}"}' | post && deploy --env ${t}`) },
  { path: 'JSON tool input', build: (s, t) => mcp({ api_key: s, env: t }) },
  { path: 'JSON tool input, json string field', build: (s, t) => mcp({ body: `{"api_key":"${s}","env":"${t}"}` }) },
  { path: 'JSON tool input, URL field', build: (s, t) => mcp({ url: `https://api.example/x?token=${s}&env=${t}` }) },
  { path: 'echo json into a secrets command (by design equal)', feedsSecrets: true, build: (s, t) => bash(`echo '{"api_key":"${s}","env":"${t}"}' | wrangler secret put PAYLOAD`) },
];

module.exports = { DATA_CASES };
