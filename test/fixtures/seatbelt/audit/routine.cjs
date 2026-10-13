// Copied verbatim from the independent audit of 613473cf (Barvis, 2026-10-12): out/evidence/ of the audit.
// Each row is the auditor's own reproducing case; test/seatbelt-audit-regression.test.js runs them.
'use strict';
const lines = String.raw`ls
ls -la
ls -la src
pwd
cd src && ls
git status
git status -sb
git diff
git diff --stat
git diff HEAD~1 -- src/index.ts
git log --oneline -20
git log --graph --decorate --all -n 30
git show HEAD
git show HEAD:package.json
git branch
git branch -a
git branch -D old-feature
git checkout -b feat/new
git checkout main
git switch -c fix/bug
git switch main
git add .
git add -A
git add src/index.ts
git commit -m "fix: handle null"
git commit -am "deploy to prod docs"
git commit --amend --no-edit
git commit -m "chore(release): publish 1.2.3"
git stash
git stash pop
git stash list
git fetch
git fetch --all --prune
git pull
git pull --rebase
git pull origin main
git rebase main
git rebase -i HEAD~3
git rebase --continue
git merge main
git merge --no-ff feat/x
git cherry-pick abc123
git reset --hard HEAD~1
git reset HEAD src/index.ts
git restore src/index.ts
git restore --staged .
git tag v1.2.3
git push
git push origin feat/new
git push -u origin feat/new
git push --set-upstream origin fix/bug
git push -f origin feat/work
git push --force-with-lease
git push --force-with-lease origin feat/work
git push origin main
git push --tags
git push origin v1.2.3
git remote -v
git remote add upstream https://github.com/acme/proj.git
git clone https://github.com/acme/other.git /tmp/other
git worktree add ../wt feat/x
git blame src/index.ts
git grep -n TODO
git clean -fd
git clean -fdx
git config user.name
git config --get remote.origin.url
git rev-parse HEAD
git rev-parse --abbrev-ref HEAD
git describe --tags
git bisect start
git submodule update --init --recursive
git ls-files
git shortlog -sn
gh pr create --fill
gh pr view
gh pr list
gh pr checkout 12
gh pr merge 12 --squash
gh issue list
gh run list
gh run view --log
gh repo view
gh api repos/acme/proj/pulls
npm install
npm i
npm ci
npm install --save-dev typescript
npm i -D vitest
npm uninstall lodash
npm update
npm outdated
npm audit
npm audit fix
npm test
npm t
npm run test
npm run build
npm run lint
npm run dev
npm run typecheck
npm run format
npm run clean
npm run deploy:preview
npm run deploy:staging
npm start
npm pack
npm publish --dry-run
npm version patch
npm ls
npm ls react
npm view react version
npm run test -- --watch
npm exec tsc -- --noEmit
npx tsc --noEmit
npx eslint .
npx prettier --check .
npx prettier --write src
npx vitest run
npx jest --coverage
npx playwright test
npx prisma generate
npx prisma migrate dev
npx create-next-app@latest app
npx vercel
npx wrangler dev
npx wrangler deploy --env staging
npx tsx scripts/tool.ts
pnpm install
pnpm i
pnpm add zod
pnpm test
pnpm build
pnpm run lint
pnpm -r build
pnpm --filter web dev
pnpm dlx create-vite
yarn
yarn install
yarn add react
yarn test
yarn build
yarn dev
bun install
bun test
bun run build
bun run dev
bunx tsc
node server.js
node scripts/tool.js
node -e "console.log(process.version)"
node --test
tsc -p .
tsc --noEmit
eslint . --fix
prettier --write .
jest
vitest
mocha
python -m pytest
pytest -q
pytest tests/test_api.py -k login
python3 -m venv .venv
source .venv/bin/activate
. .venv/bin/activate
pip install -r requirements.txt
pip install -e .
python manage.py migrate
python manage.py runserver
python -c "import sys; print(sys.version)"
python3 scripts/gen.py
uv sync
uv run pytest
poetry install
poetry run pytest
ruff check .
black .
mypy src
cargo build
cargo build --release
cargo test
cargo run
cargo clippy
cargo fmt
cargo publish --dry-run
go build ./...
go test ./...
go run .
go mod tidy
go vet ./...
make
make build
make test
make clean
make -j8
docker build -t app .
docker compose up -d
docker compose down
docker ps
docker logs app
docker run --rm -it app sh
docker push ghcr.io/acme/app:latest
docker system prune -f
kubectl get pods
kubectl get pods -n staging
kubectl describe pod x
kubectl logs -f deploy/web
kubectl apply -f k8s/
kubectl port-forward svc/web 8080:80
helm list
helm template ./chart
terraform init
terraform plan
terraform fmt
terraform validate
vercel
vercel dev
vercel env pull .env.local
netlify deploy
netlify dev
wrangler dev
wrangler tail
wrangler deploy --env staging
firebase emulators:start
cat package.json
cat README.md
cat .env.example
cp .env.example .env
head -50 src/index.ts
tail -f logs/app.log
less README.md
grep -rn "TODO" src
grep -r "useState" src --include=*.tsx
rg "fetchUser" src
rg -n deploy
find . -name "*.ts" -not -path "./node_modules/*"
find . -name '*.log' -delete
find src -type f | wc -l
wc -l src/*.ts
sed -n '1,40p' src/index.ts
sed -i 's/foo/bar/g' src/index.ts
awk '{print $1}' data.txt
sort data.txt | uniq -c
jq '.scripts' package.json
jq . package.json > /tmp/pkg.json
echo hello
echo $PATH
printf '%s\n' a b
mkdir -p src/components
touch src/new.ts
cp src/a.ts src/b.ts
cp -r templates/ out/
mv src/old.ts src/new.ts
rm src/old.ts
rm -f dist/bundle.js
rm -rf node_modules
rm -rf dist build coverage
rm -rf node_modules package-lock.json && npm install
rm -rf .next
rm -rf /tmp/build-123
rm -rf ./tmp
rm -rf .git
chmod +x scripts/build.sh
./scripts/build.sh
bash scripts/build.sh
sh ./safe.sh
curl -s https://api.example.com/health
curl -fsSL https://bun.sh/install | bash
curl -X POST http://localhost:3000/api -d '{"a":1}'
wget https://example.com/file.tar.gz
tar -xzf file.tar.gz
unzip archive.zip -d /tmp/x
du -sh node_modules
df -h
ps aux | grep node
lsof -i :3000
kill 12345
top -b -n 1
which node
node --version
npm --version
env | grep NODE
printenv PATH
export NODE_ENV=development
export PATH="$PATH:./node_modules/.bin"
NODE_ENV=test npm test
DEBUG=* npm run dev
history | tail
code .
open http://localhost:3000
ssh -i ~/.ssh/id_x host uptime
ls ~/.ssh
cat ~/.ssh/id_ed25519.pub
aws s3 ls
gcloud config list
date
whoami
uname -a
tree -L 2 src
diff a.txt b.txt
patch -p1 < fix.patch
xargs -n1 echo < list.txt
time npm test
timeout 60 npm test
nohup npm run dev > /tmp/dev.log 2>&1 &
for f in src/*.ts; do echo $f; done
if [ -f package.json ]; then npm ci; fi
npm test && npm run build
npm run lint || true
npm test 2>&1 | tail -n 40
git add -A && git commit -m "wip" && git push
cd /tmp && ls
mkdir -p /tmp/x && cd /tmp/x && git init
psql -c "select 1"
sqlite3 db.sqlite ".tables"
redis-cli ping
docker exec app ls
ssh host 'ls /srv'
rsync -av dist/ host:/srv/app/
rsync -a --delete dist/ /tmp/out/
scp file.txt host:/tmp/
openssl rand -hex 16
base64 README.md
echo aGVsbG8= | base64 -d
xxd README.md | head
make release-notes
npm run release:notes
npx changeset
npx changeset version
gh release list
gh release view v1.0.0
git log --grep=publish
grep -rn "publish" src
cat scripts/deploy.md
ls deploy/
cd deploy && ls
vim src/index.ts
nano README.md
true`.split('\n');
module.exports = lines.map((cmd, i) => ({ id: `r${i + 1}`, cmd, expect: 'pass' }));
