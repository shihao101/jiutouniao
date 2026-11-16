JTN_EVALPACK_PATH ?=

.PHONY: build web run test clean pack

build:
	cd server && go build -o ../jiutouniao .

# 前端构建：web-app(Vue3+Vite) → web/（本地非 Docker 运行必需；docker compose 构建自动完成，无需本步）
web:
	cd web-app && npm install --no-audit --no-fund && npm run build
	rm -rf web && mkdir -p web && cp -r web-app/dist/. web/

run: build
	./jiutouniao -config config.json

test:
	cd server && go test ./...

clean:
	rm -f jiutouniao
	rm -rf projects jiutouniao.db

# 部署包：symlink-safe zip；自动排除 config.json/projects/override/.env 等敏感与环境专属文件，
# 打包后执行敏感信息扫描（内网地址/令牌/口令模式），命中即失败
pack:
	python3 scripts/pack.py

# 评测环：本地靶场完整跑一个项目并按预期清单判分（需真实 LLM；详见 eval/）
eval:
	python3 scripts/eval_run.py

# P3 前端工程化：打包体积预算守卫 + 真实浏览器 E2E（需先起 E2E 实例，见 scripts/ui-e2e/README.md）
ui-check:
	cd web-app && node node_modules/vite/bin/vite.js build && node ../scripts/check-bundle.mjs
ui-e2e:
	node scripts/ui-e2e/run.mjs /tmp/ui-e2e/e2e-run "" both
