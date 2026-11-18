# 九头鸟（鬼車）— 实战型 AI 渗透测试智能体
# 多阶段构建：Vue3 前端(Vite) + Go 静态编译 + Kali Linux 工具链运行时
# 注意：安全工具安装刻意放在源码 COPY 之前——源码变更不会重装工具（层缓存）
#
# v2.5 变更：运行时基础系统 alpine → Kali GNU/Linux Rolling；
# v2.6 变更：构建/工具安装代理改为按需注入（默认直连，国内源已内置）——
#            代理仅限构建期与工具下载，运行时 LLM/靶机流量一律直连

# ---------- 全局构建参数 ----------
# 构建期代理（npm/go/apt）按需注入：默认直连（国内源已内置，实测直连更快）。
# 本地/测试环境经 docker-compose.override.yml 或 --build-arg 提供代理；
# 代理仅作用于构建期，最终镜像运行时环境已清空，不进运行时。
ARG HTTP_PROXY=
ARG HTTPS_PROXY=
ARG NO_PROXY=localhost,127.0.0.1,jiutouniao
# 运行时底座：默认 vxcontrol/kali-linux（正宗 Kali Rolling 2026.3 全量工具链，
# docker hub 公开可拉、本机已缓存——离线也能构建）。
# 求最小体积可换官方底座：--build-arg RUNTIME_BASE=kalilinux/kali-rolling:latest（需联网装工具）
# v5.2.0 P1-3：供应链 digest 锁定（升级时人工更新 PIN——构建会校验内容一致性）
ARG RUNTIME_BASE=vxcontrol/kali-linux@sha256:7f803e5be80ec33dcf4228d9702ea1264658b43301e9d6bf3bce6cf8b1077399

# ---------- 前端构建阶段 ----------
FROM node:24.17.0-slim@sha256:862263c612aa437e3037674b85419622a9d93bff80aa1eee5398dfe686375532 AS febuilder
ARG HTTP_PROXY HTTPS_PROXY NO_PROXY
ENV http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY} \
    HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY} NO_PROXY=${NO_PROXY}
WORKDIR /fe
RUN npm config set registry https://registry.npmmirror.com
# v2.4.1：node_modules 随源码包分发（离线自洽，不依赖 npm registry——实测构建容器对镜像源 TLS 断流）。
# v2.5：构建入口不再依赖 node_modules/.bin 符号链接（部署包经 zip/python 解压会丢符号链接与执行位，
# 实测 .bin/vite 被展开成 644 普通文件致 npm run 127）——直接以 node 调 vite 入口，任何解压方式都健壮；
# 干净 checkout（无 node_modules）时回退联网安装（重试 3 次）。
COPY web-app/ ./
# v2.5：修复部署包经部分解压工具（python zipfile 等）丢可执行位（实测 esbuild 755→644 致 spawn EACCES）
# 与丢符号链接（.bin/* 展开成普通文件致 npm run 127）两类问题——统一 chmod + 直接以 node 调 vite 入口
RUN chmod -R u+x node_modules/.bin node_modules/*/bin node_modules/@*/*/bin 2>/dev/null; true; \
    if [ -f node_modules/vite/bin/vite.js ]; then \
      node node_modules/vite/bin/vite.js build; \
    elif [ -d node_modules ] && [ -x node_modules/.bin/vite ]; then \
      npm run build; \
    else \
      ok=0; for i in 1 2 3; do npm install --no-audit --no-fund && ok=1 && break || sleep 8; done; [ $ok -eq 1 ] && npm run build; \
    fi

# ---------- 引擎构建阶段 ----------
FROM golang:1.26-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS builder
ARG GOPROXY=https://goproxy.cn,direct
ARG HTTP_PROXY HTTPS_PROXY NO_PROXY
ENV GOPROXY=${GOPROXY} CGO_ENABLED=0 \
    http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY} \
    HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY} NO_PROXY=${NO_PROXY}

# 安全工具（与引擎解耦）：优先 go install 最新版；编译失败时回退底座自带版本——
# 两者皆无则构建失败（不再静默跳过产出残缺镜像）
RUN mkdir -p /out/tools; \
    (go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0 || echo "go install subfinder failed——回退底座版本") && \
    (go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0 || echo "go install httpx failed——回退底座版本") && \
    (go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1 || echo "go install nuclei failed——回退底座版本") && \
    (go install github.com/ffuf/ffuf/v2@v2.3.0 || echo "go install ffuf failed——回退底座版本") && \
    for t in subfinder httpx nuclei ffuf; do \
      if [ -f /go/bin/$t ]; then cp /go/bin/$t /out/tools/; \
      elif p=$(command -v $t 2>/dev/null) && [ -n "$p" ]; then cp "$p" /out/tools/; \
      else echo "FATAL: $t 编译失败且底座未提供，拒绝产出镜像"; exit 1; fi; \
    done && ls -la /out/tools/

# 引擎本体（v2.4.1：依赖已 vendor 进源码包，构建离线自洽，不再依赖 go 模块代理）
WORKDIR /src
COPY server/ .
RUN go build -mod=vendor -trimpath -ldflags="-s -w" -o /out/jiutouniao .

# ---------- 运行阶段：Kali Linux（v2.5 基础系统切换）----------
# 合规护栏不变：审批矩阵 + 熔断 + 证据链照旧作用于一切命令（含 apt 安装类）
FROM ${RUNTIME_BASE}
ARG HTTP_PROXY HTTPS_PROXY NO_PROXY
# 构建期 apt 走宿主机代理（仅本阶段构建生效，最终镜像内已清空，不进运行时环境）
ENV http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY} \
    HTTP_PROXY=${HTTP_PROXY} HTTPS_PROXY=${HTTPS_PROXY} NO_PROXY=${NO_PROXY}

# Kali apt 三镜像重试（kali.org → USTC → aliyun）+ 工具链补装：
# 全量底座（vxcontrol）绝大多数已装、离线构建可直接通过；
# 官方最小底座必须联网装齐（全部来自 kali-rolling 官方源，即 Kali 全部工具均可 apt 获得）
RUN rm -f /etc/apt/sources.list.d/docker.list && \
    ok=0; for i in 1 2 3; do \
      for m in http://http.kali.org/kali http://mirrors.ustc.edu.cn/kali http://mirrors.aliyun.com/kali; do \
        printf 'Types: deb\nURIs: %s/\nSuites: kali-rolling\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n' "$m" > /etc/apt/sources.list.d/kali.sources && \
        apt-get update -o Acquire::Retries=3 && ok=1 && break; \
      done; [ $ok -eq 1 ] && break; sleep 5; done; \
    if [ $ok -eq 1 ]; then \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bash ca-certificates tzdata \
        nmap sqlmap whatweb nikto hydra gobuster john hashcat masscan dirb \
        ffuf seclists \
        jadx apktool arjun \
        curl wget git jq openssl graphviz \
        python3 python3-pip python3-requests python3-yaml \
        dnsutils whois openssh-client libpcap-dev \
        netcat-openbsd iputils-ping traceroute tcpdump \
        procps file unzip zip xxd \
        || { echo "FATAL: apt 工具链安装失败（源可达但安装出错）——拒绝产出残缺镜像，请重建重试"; exit 1; }; \
    else \
      echo "warn: apt sources unreachable (offline build)——全量 Kali 底座可离线通过；最小底座请在联网环境重建"; \
    fi; \
    rm -rf /var/lib/apt/lists/*; \
    for t in nmap python3 curl sqlmap git; do \
      command -v $t >/dev/null 2>&1 || { echo "FATAL: 运行时缺 $t（底座与 apt 均未提供），请联网重建或换全量 Kali 底座"; exit 1; }; \
    done; true

# v2.5.2：剥离越界文件能力位（实测 vxcontrol 底座 nmap 带 fcap=cap_net_admin，
# 不在 Docker 默认 bounding set → exec EPERM，智能体报「nmap 二进制存在但容器权限受限」）；
# 剥离后 root 自带 cap_net_raw，nmap -sS/-sV 全功能不受影响。脚本保留在镜像内可随时重跑。
COPY tools-extra/strip-fcaps.py /usr/local/bin/strip-fcaps
RUN chmod +x /usr/local/bin/strip-fcaps && python3 /usr/local/bin/strip-fcaps

# v2.5：Kali 正版 sqlmap 优先；仅当底座缺失 sqlmap 时回退 vendored 源码（tools-extra/sqlmap 随包分发）
COPY tools-extra/sqlmap /opt/tools/sqlmap
COPY tools-extra/authz-diff.py /opt/tools/authz-diff.py
COPY tools-extra/subdomain-takeover.py /opt/tools/subdomain-takeover.py
COPY tools-extra/captcha-ocr.py /opt/tools/captcha-ocr.py
COPY tools-extra/primitive-graph.py /opt/tools/primitive-graph.py
COPY tools-extra/chain-proxy.py /opt/tools/chain-proxy.py
COPY tools-extra/blind-inject-adjudicator.py /opt/tools/blind-inject-adjudicator.py
COPY tools-extra/idor-baseline.py /opt/tools/idor-baseline.py
COPY tools-extra/field-exposure.py /opt/tools/field-exposure.py
COPY tools-extra/authz-matrix-roles.py /opt/tools/authz-matrix-roles.py
COPY tools-extra/logic-invariant.py /opt/tools/logic-invariant.py
COPY tools-extra/exit-pool.py /opt/tools/exit-pool.py
COPY tools-extra/browser-farm.py /opt/tools/browser-farm.py
COPY tools-extra/jsvm-challenge-solver.py /opt/tools/jsvm-challenge-solver.py
COPY browser-kit/channel-heartbeat.py /opt/tools/browser-kit/channel-heartbeat.py
RUN chmod +x /opt/tools/sqlmap/sqlmap.py 2>/dev/null; \
    if ! command -v sqlmap >/dev/null 2>&1; then \
      printf '#!/bin/sh\nexec python3 /opt/tools/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap && chmod +x /usr/local/bin/sqlmap; \
    fi

# v2.7.1：Node 运行时 + wxappUnpacker（B2 专项解包 wxapkg）——
# unveilr 已从 npm/GitHub 双双下架（r3x5ur/unveilr 404、xdmjun/wxappUnpacker 被清空），
# 固化幸存增强 fork rtcatc/wxappUnpacker（含分包/主包合并解析），入口命令 wxappUnpacker
# v5.6.0：S2 伪造凭证工具链固化（审计修复）——jwt_tool 钉克隆（S2 轨核心武器：
# alg:none/混淆/kid/jku 全自动）+ hashcat 补进 apt 清单（JWT HMAC 爆破 mode 16500）
COPY --from=febuilder /usr/local/bin/node /usr/local/bin/node
COPY --from=febuilder /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
# v5.6.0：PyJWT 与 jwt_tool 依赖 wheels 随仓库固化（离线自洽——构建容器 pip 镜像源断流，
# 与 playwright wheelhouse 同因同解；宿主经代理从 pypi.org 下载后随包分发）
COPY wheelhouse/pyjwt/ /tmp/jtwheel/
COPY wheelhouse/jwttool/ /tmp/jtwheel/
RUN chmod +x /usr/local/bin/node && \
    ln -sf ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    ln -sf ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx && \
    git clone --depth 1 https://github.com/rtcatc/wxappUnpacker /opt/wxappUnpacker && \
    if [ "$(git -C /opt/wxappUnpacker rev-parse HEAD)" != "46207ff7c9b1a84ab5f7d02338163f00ea6ddd56" ]; then echo "FATAL: wxappUnpacker pin 不匹配（v5.2.0 供应链锁定）——人工复核后更新 PIN"; exit 1; fi; \
    cd /opt/wxappUnpacker && npm install --registry=https://registry.npmmirror.com && \
    printf '#!/bin/sh\nexec node /opt/wxappUnpacker/wuWxapkg.js "$@"\n' > /usr/local/bin/wxappUnpacker && \
    chmod +x /usr/local/bin/wxappUnpacker && \
    wxappUnpacker 2>&1 | grep -q "Unpack a wxapkg" || { echo "FATAL: wxappUnpacker 冒烟失败"; exit 1; }; \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool && \
    if [ "$(git -C /opt/jwt_tool rev-parse HEAD)" != "3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b" ]; then echo "FATAL: jwt_tool pin 不匹配（v5.6.0 供应链锁定）——人工复核后更新 PIN"; exit 1; fi; \
    python3 -c "import re; p='/opt/jwt_tool/jwt_tool.py'; s=open(p,encoding='utf-8').read(); s2,n=re.subn(r\"'#[^']*': None,?\\s*\", '', s); open(p,'w',encoding='utf-8').write(s2); print('jwt_tool py3.14 compat patch: removed', n, 'None-comment keys')" && \
    pip3 install --no-cache-dir --break-system-packages --no-index --find-links=/tmp/jtwheel \
      setuptools wheel termcolor pycryptodomex ratelimit pyjwt && \
    printf '#!/bin/sh\ncd /opt/jwt_tool && exec python3 jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool && \
    out=$(jwt_tool 2>&1); \
    echo "$out" | grep -qi "Traceback" && { echo "FATAL: jwt_tool 冒烟出现 Traceback（依赖缺失）"; exit 1; }; \
    echo "$out" | grep -qi "jwt" || { echo "FATAL: jwt_tool 冒烟失败（无横幅输出）"; exit 1; }; \
    python3 -c "import jwt; assert jwt.encode({'a':1},'k',algorithm='HS256')" || { echo "FATAL: PyJWT 冒烟失败（伪造令牌构造依赖）"; exit 1; }

# v2.7.1：nuclei 模板固化（fail-hard）——git 浅克隆主分支（与 nuclei -update-templates 同机制，
# release zip 自 v10.x 起已停止附带）。校验模板数量，失败即构建失败。替换 v2.6 的 best-effort
# `-update-templates` 方案（实测代理慢时 420s 超时静默跳过，产出无模板镜像，导致每个项目
# 开工重复下载且永远失败）。运行时开工预热 project-warmup 仍可增量更新（写入容器可写层）。
# v5.5.0 重钉复核记录（2026-11-18）：1cb2d50b(v5.2.0) → 9588ad5b，diff --stat 3764 文件，
# 全部为模板数据（3759 yaml + templates-checksum.txt/cves.json 索引 + .new-additions +
# .github/dependabot.yml CI 元数据），无 scripts/workflows/hooks 等可执行代码变更 → 通过复核。
# v5.6.0 模板分发方式升级：钉版本 tarball 随仓库分发（tools-extra/）——构建容器内 github
# 大仓库克隆经代理不稳定（实测 3 连败），改为宿主一次性下载 + SHA256 供应链锁定 + 构建期
# 校验解压（确定性、离线可构建）。PIN: 9588ad5b（v5.5.0 复核记录见上）。
# tarball sha256: e1c87a283fc05faeebdc5253986c1a8a72cb70941836d84004d8ead229669e98
COPY tools-extra/nuclei-templates-9588ad5b.tar.gz /tmp/nuclei-templates.tar.gz
RUN set -e; \
    rm -rf /root/nuclei-templates /tmp/tpl; \
    echo "e1c87a283fc05faeebdc5253986c1a8a72cb70941836d84004d8ead229669e98  /tmp/nuclei-templates.tar.gz" | sha256sum -c - || { echo "FATAL: nuclei-templates tarball SHA256 不匹配（供应链锁定）——人工复核后更新"; exit 1; }; \
    mkdir -p /tmp/tpl && tar xzf /tmp/nuclei-templates.tar.gz -C /tmp/tpl --strip-components=1; \
    [ -d /tmp/tpl/http ] || { echo "FATAL: nuclei-templates 解包异常"; exit 1; }; \
    n=$(find /tmp/tpl -name '*.yaml' -o -name '*.yml' | wc -l); \
    echo "nuclei templates baked: $n yaml files"; \
    [ "$n" -ge 3000 ] || { echo "FATAL: 模板数量异常（$n < 3000），拒绝产出镜像"; exit 1; }; \
    mv /tmp/tpl /root/nuclei-templates

# v4.4：payload 语料资产（批次2）——PayloadsAllTheThings 本地语料层（对标 BreachWeave，与 nuclei-templates
# 同一 fail-hard 纪律）+ curated 绕过字典（payload-mutation-algebra §7/ssti-engine-map 配套，403 头族/路径族/SSTI 矩阵）
COPY tools-extra/wordlists/ /opt/tools/wordlists/
RUN set -e; \
    for i in 1 2 3; do \
      git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings /tmp/pat && break || \
      { echo "PAT clone attempt $i failed"; rm -rf /tmp/pat; sleep 10; }; \
    done; \
    [ -d /tmp/pat ] || { echo "FATAL: PayloadsAllTheThings 克隆失败（网络/代理）"; exit 1; }; \
    if [ "$(git -C /tmp/pat rev-parse HEAD)" != "08ea40e77db3f42ef8f20c65196f3936a19b6c86" ]; then echo "FATAL: PayloadsAllTheThings pin 不匹配（v5.2.0 供应链锁定）——人工复核后更新 PIN"; exit 1; fi; \
    rm -rf /tmp/pat/.git && mv /tmp/pat /opt/tools/PayloadsAllTheThings; \
    n=$(find /opt/tools/PayloadsAllTheThings -name '*.md' | wc -l); \
    d=$(find /opt/tools/PayloadsAllTheThings -maxdepth 1 -type d | wc -l); \
    echo "PayloadsAllTheThings baked: $n md files, $((d-1)) categories"; \
    [ "$n" -ge 120 ] && [ "$d" -ge 30 ] || { echo "FATAL: PAT 语料异常（$n md / $d 目录，实测基线 142/66），拒绝产出镜像"; exit 1; }

COPY --from=builder /out/jiutouniao /app/jiutouniao
COPY --from=builder /out/tools/ /usr/local/bin/

# v2.8.0：浏览器认证套件（browser-kit）——真实浏览器登录/加密协议预言机。
# playwright 预装进底座 /opt/venv：wheel 随仓库固化（/wheelhouse，47MB，
# 同 v2.4.1 node_modules 的离线自洽哲学）——构建期 --no-index 离线安装，不依赖网络
# （实测构建容器直连 pip 镜像源 TLS 断流，与 febuilder npm 断流同因，故 wheel 固化）。
# 驱动底座自带系统 Chromium（executable_path 直连 /usr/bin/chromium，无需下载浏览器）。
# 构建期冒烟：sync API 启动 headless Chromium 求值 7*6，失败即构建失败（fail-hard）。
COPY wheelhouse/ /tmp/wheelhouse/
RUN /opt/venv/bin/pip install --no-cache-dir --no-index --find-links=/tmp/wheelhouse playwright && \
    rm -rf /tmp/wheelhouse && \
    /opt/venv/bin/python -c "from playwright.sync_api import sync_playwright; pw=sync_playwright().start(); b=pw.chromium.launch(executable_path='/usr/bin/chromium', args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']); assert b.new_page().evaluate('7*6')==42; b.close(); pw.stop(); print('browser smoke OK: playwright + system chromium')" && \
    /opt/venv/bin/pip install --no-cache-dir ddddocr >/dev/null 2>&1 && echo "captcha OCR: ddddocr installed" || echo "captcha OCR: ddddocr unavailable (install_tool 兜底)"
COPY browser-kit/ /opt/tools/browser-kit/
RUN chmod +x /opt/tools/browser-kit/*.py /opt/tools/browser-kit/selftest/*.py /opt/tools/browser-kit/selftest/*.sh

# 构建终检（fail-hard）：核心工具与 nuclei 模板必须齐全——杜绝再产出"静默残缺"镜像。
# 注意：本镜像是"固化基线"，需要联网（apt/npm/git 经构建代理）构建；离线构建将在此明确失败。
RUN missing=""; \
    for t in nmap sqlmap gobuster ffuf httpx nuclei subfinder whatweb nikto hydra john hashcat \
             dig jq curl python3 git whois jadx apktool arjun wxappUnpacker interactsh-client \
             jwt_tool chromium; do \
      command -v $t >/dev/null 2>&1 || missing="$missing $t"; \
    done; \
    /opt/venv/bin/python -c "import playwright" 2>/dev/null || missing="$missing playwright"; \
    python3 -c "import jwt" 2>/dev/null || missing="$missing pyjwt"; \
    python3 -c "import impacket" 2>/dev/null || missing="$missing impacket"; \
    hashcat --version >/dev/null 2>&1 || missing="$missing hashcat-smoke"; \
    jwt_tool 2>&1 | grep -qi "Traceback" && missing="$missing jwt-tool-smoke"; \
    [ -d /usr/share/seclists/Discovery/Web-Content ] || missing="$missing seclists"; \
    [ -x /opt/tools/browser-kit/browser_login.py ] || missing="$missing browser-kit"; \
    tpl=$(find /root/nuclei-templates -name '*.yaml' -o -name '*.yml' 2>/dev/null | wc -l); \
    [ "$tpl" -ge 3000 ] || missing="$missing nuclei-templates(${tpl}个)"; \
    [ -f /opt/tools/wordlists/403-bypass-paths.txt ] || missing="$missing wordlists-403-paths"; \
    [ -f /opt/tools/wordlists/403-bypass-headers.txt ] || missing="$missing wordlists-403-headers"; \
    [ -f /opt/tools/wordlists/ssti-matrix.txt ] || missing="$missing wordlists-ssti"; \
    pat=$(find /opt/tools/PayloadsAllTheThings -name '*.md' 2>/dev/null | wc -l); \
    [ "$pat" -ge 120 ] || missing="$missing PayloadsAllTheThings(${pat}个)"; \
    if [ -n "$missing" ]; then echo "FATAL: 镜像终检缺失:$missing"; exit 1; fi; \
    echo "image check OK: 工具齐全, nuclei 模板 ${tpl} 个, PAT 语料 ${pat} 篇"

# 方法论资产（heads/prompts/skills 建议以卷挂载覆盖，便于热更新）
COPY --from=febuilder /fe/dist /app/web/
COPY heads/   /app/heads/
COPY prompts/ /app/prompts/
# v5.3.0：策略单一事实源（coverage-contract/execution-profiles）
COPY policies/ /app/policies/
COPY skills/  /app/skills/
# v3.5.1：评测靶场进镜像（智能体在容器内访问 127.0.0.1 靶场）
# v4.7.1 评测体系分离：镜像零靶场信息（靶标/埋点/mocks 在外部评测包）
COPY scripts/eval_run.py /app/eval/
COPY eval/README.md /app/eval/README.md
COPY eval/roe/ /app/eval/roe/

WORKDIR /app
RUN mkdir -p /app/projects
# TOOL_PROXY：运行时 install_tool（apt/pip/git）与智能体外网下载类命令的专用代理；
# 与 LLM 直连旁路无关（HTTP_PROXY 保持清空），对目标靶机的测试流量同样不注入代理——
# 渗透流程逻辑与流量真实性均不受影响。
# 构建期注入的代理变量在此清空，最终镜像运行时环境干净。
ENV TZ=Asia/Shanghai LANG=C.UTF-8 TOOL_PROXY= \
    http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= NO_PROXY= no_proxy=
EXPOSE 8787

# 环境变量覆盖配置：AUTH_TOKEN / ADMIN_USER / ADMIN_PASSWORD / HEXSTRIKE_URL /
# LLM_BASE_URL / LLM_API_KEY / LLM_MODEL / LLM_MOCK / MAX_PROJECT_TOKENS / PRICE_IN / PRICE_OUT /
# TOOL_PROXY（工具安装代理）/ RUNTIME_BASE（仅构建期）
ENTRYPOINT ["/app/jiutouniao", "-config", "/app/config.json"]
