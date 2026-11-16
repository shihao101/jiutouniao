---
id: upload-bypass
title: 文件上传绕过手册（校验链/解析形态/条件竞争）
tags: upload,上传,解析漏洞,竞争,s4,s5
---
# 文件上传绕过手册

> 判据=上传成功且**可控位置可达**；执行级验证（webshell 落地）一律转 S5 审批。本手册只做「传得上去+落点可控」的存在性证明。
>
> **渐进式上传验证协议（v4.8.1 合规口径，强制顺序）**：①**先常规文件类型**——用无害内容（.txt/.jpg/.png/.pdf，内容为探测标记串）测试上传面本身：能否上传、是否回显存储路径、落点是否公开可达、有无同名覆盖；②常规类型拿到结论后，**才尝试可执行脚本**（按目标栈选后缀变体，经审批矩阵，见 S5-3）。**每一步上传的每个文件（无论成功/被拦）都必须登记《上传文件记录清单》**（路径/指纹/内容标记/上传通道），处置口径见 webshell-memshell 第四节：只记录、不删除、不重启。

## 一、校验链逐层探针

```bash
# ① 前端校验：直接 curl 跳过前端（请求层绕过）
# ② Content-Type 白名单：multipart type 改 image/png，内容仍为探测文本
# ③ 后缀黑名单：php → php3/4/5/7, phtml, phar, pht; asp → asa, cer, aspx→ashx/asmx; jsp→jspx, jspf, jsa
# ④ 后缀白名单：双写 shell.php.jpg / shell.jpg.php / shell.jpg/  / shell.php%00.jpg（截断按栈年代）
# ⑤ 内容检测（magic bytes/关键词）：合法图片头 + 文本探针；禁 <? 时用 <script language="php">（旧版）/ 短标签 <?=
# ⑥ 图片二次渲染：理论不可传码 → 转判据「文件名注入/路径参数」路线
# ⑦ .htaccess / .user.ini / web.config / %00 截断（按中间件指纹，见 middleware-web）
```

## 二、落点与可达性证明

- 响应/资源页提取**存储路径**（JSON url 字段/Location/列表页遍历）；路径不可见 → 时间戳/uid 规律假设（hypothesis-0day）。
- **上传路径穿越**：filename=`../../1.txt` 探针（改写落点）；目录参数污染（uploadDir=../）。
- 覆盖/删除原文件判定：同名重传前后文件变化（只读对比，禁止覆盖业务文件）。

## 三、解析形态清单（按指纹联动 middleware-web）

| 组件 | 形态 |
|---|---|
| Nginx | 解析缺陷路径（/x.jpg/.php 按旧版本）、alias 目录穿越（/alias../） |
| IIS | `x.asp;.jpg`、目录 `/x.asp/`、短文件名枚举（dotnet-family 联动） |
| Apache | 多后缀（AddHandler 段）、`.htaccess` 可写 |
| Tomcat | PUT 只读探测（readonly 开关，见 middleware-web） |
| OSS/S3 | 上传桶权限：直传策略签名缺陷（cloud-security 联动） |

## 四、条件竞争（上传+校验分离类）

- 大文件多线程上传 + 并发 GET 访问，命中「未校验瞬间」窗口 → 判据为响应 200 的探测文本文件；**竞争脚本并发数受 scan-tiering 限速约束，目标侧禁高并发**。
- 命中即 record_finding（cwe-367/434）；落地执行转 S5。

## 五、纪律

- 上传的自建探测文件逐项登记四元组并入《需人工清理清单》移交（v5.3.0 铁律：不执行删除——Lab 模式以快照恢复回收）；禁止覆盖目标已有文件（红线 5）。

## 四阶段模型与编辑器矩阵

- **四阶段分开验证**：Accept（客户端白名单）/Store（落盘路径）/Process（解析/改图）/Serve（回显与执行）——成功率 = P(bypass)×P(拿到路径)×P(服务器解析)，三因子各自检验
- **解析差异**：IIS `shell.asp;.jpg` 分号、`shell.asp::$DATA`；Apache `x.php\x0a`（CVE-2017-15715）；Nginx `x.jpg/.php`（cgi.fix_pathinfo=1）
- **响应操控**：拦截返回的 allowedTypes 改含 .php（客户端校验信任服务端响应）；filename 后缀为空时补 .html + 大小写混淆 `<sCript>`（存储 XSS）
- **传不了马上传 html 嵌 XSS**：不解析马子的上传点常收带 `<script>` 的 html 文件（企业 SRC 常见中危）
- **富文本编辑器路径+指纹表**：FCKeditor `/fckeditor/editor/filemanager/connectors/`、eWebEditor `admin_login.asp`、KindEditor `/kind/editor/attached/`、UEditor `/ueditor/net/`（controller 型）

### 缺陷分类与处理器×风险

校验缺陷五维分类表：Location（仅前端/前后不一致）｜Method（黑名单不全/仅 MIME/仅 magic）｜Logic order（检查后才改名）｜Scope（查文件名不查内容/只查头几字节）｜Execution context（上传成功但被其他 vhost/handler 处理）。处理器×风险表：图片缩略→ImageMagick 差异；音视频转码→FFmpeg 协议滥用；解压→zip slip 越目录写+解压炸弹；**AV/DLP 扫描→深层嵌套/隐藏内容/竞态**；HTML→PDF 预览→SSRF（AV/DLP 与 zip slip 为本表独有）。上传授权五检查（统一 A/B 双账号测试；账号来自客户提供/索取闭环，禁止自动注册，无身份时逐条 record_vt 移交）：配额仅 UI 限制 API 不限；套餐限制只在页面上传口不在 import 接口；属主校验只在列表不在直链/替换接口；审批流可直调最终存储端点绕过；删除/替换缺对象级授权。文件名反射面清单：gallery HTML、管理员审核面板、PDF/CSV 导出任务、日志/审计/邮件通知——**文件名按存储型输入对待**。编辑器版本指纹：`/fckeditor/_whatsnew.html`、`/ckeditor/CHANGES.md`、`/kindeditor/kindeditor.js`、`/ueditor/ueditor.config.js`。
## Execution Profile 标注（v5.3.2）

- **Lab Only 动作**：上传可执行脚本/样本验证上传面可达性（生产档只允许常规无害文件类型验证）——仅 isolated_lab（可快照回滚的隔离靶场，项目显式声明）可执行；production_safe 下引擎逐动作强制禁止（v5.3.1 governanceGates 全通道确定性拦截并留证），不要尝试绕行。
- **production_safe 口径**：只做存在性证明（无害回显/随机标记/受控 OOB/量级与哈希证明），可达性证明即止。
- **工件处置两档分流**：生产=四元组（路径/指纹/建议清理命令/验证命令）登记移交《需人工清理清单》；实验室=快照恢复/环境重置回收（恢复成功须只读验证）。两档均不执行目标侧删除/还原。
