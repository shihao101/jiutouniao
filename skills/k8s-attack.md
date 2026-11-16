---
id: k8s-attack
title: Kubernetes/容器编排攻击（kubelet/SA token/RBAC/逃逸）
tags: k8s,容器,云原生,逃逸,s4,s6
---
# Kubernetes/容器编排攻击

**定位**：目标暴露 K8s 组件（6443 API / 10250 kubelet / 2379 etcd / Dashboard / kubectl 配置文件）或已获容器内立足点时的攻击路径（与 cloud-security 的云元数据、privesc-checklist 的容器段互补）。

## 一、暴露面枚举（L0/L1）

- **API Server 6443**：`curl -sk https://<ip>:6443/version`（匿名可达性）；`/api` 无凭据返回 401/403=正常，返回 JSON=匿名权限过大。
- **kubelet 10250**：`curl -sk https://<ip>:10250/pods`（匿名读 Pod 清单=高危）；`/runningpods/` 只在认证后。
- **etcd 2379**：`curl http://<ip>:2379/version`（HTTP 明文=未加密）。
- **Dashboard**：`/api/v1/csrftoken` 登录面；历史跳过登录绕过判据按版本检索。
- **配置文件搜集**（已有容器/主机立足点时）：`/root/.kube/config`、`/var/run/secrets/kubernetes.io/serviceaccount/`（**SA token 三件套**：token/ca.crt/namespace）。

## 二、SA Token 滥用（拿到 token 后，L1 只读先行）

```bash
kubectl --server=https://<api>:6443 --certificate-authority=ca.crt --token=<tok> auth can-i --list
kubectl ... get pods -A / get secrets -A / get nodes
```

- **权限判定→利用**：`auth can-i create pods` = 可创建特权 Pod 挂宿主根 → 直取节点（利用级转 S5）；`list secrets` → 集群凭据面存在性证明（含 docker-registry 型 secret = 镜像仓库凭据）。
- **etcd 直读**（未加密时）：`etcdctl --endpoints=... get /registry/secrets/ --prefix --keys-only`（需证书时如实标注待验证）。

## 三、RBAC 提权候选（枚举判据）

- Role/RoleBinding 含 `verbs: ["*"]`、`pods/exec`、`secrets` 且 subjects 指向可达 SA/组；
- `create pods`（特权 Pod 逃逸）、`patch daemonsets`（植入）、`impersonate users/groups`（冒充 cluster-admin）；
- 判据 → upsert_fact(confirmed)，利用转 S5 审批。

## 四、容器逃逸候选（评估留证、执行转 S5）

| 候选 | 判据 |
|---|---|
| privileged | `/proc/self/status` CapEff 含 CAP_SYS_ADMIN |
| docker.sock 挂载 | `/var/run/docker.sock` 存在 |
| hostPath 根挂载 | `/proc/mounts` 见宿主 / 挂载 |
| 敏感 capability | CAP_DAC_READ_SEARCH / CAP_SYS_PTRACE |
| 内核 CVE | 版本比对（cve-weaponization 衔接） |
| SA 可创建特权 Pod | `auth can-i create pods` + 无 admission 限制 |

## 五、纪律

- **只读优先**：枚举/`auth can-i`/secret 存在性 = L1；创建 Pod/exec/改 RBAC = S5 全程审批。
- 集群组件是生产核心：限速、禁全量 watch、Dashboard 类组件禁重启类 PoC。
- 发现 upsert_fact（`k8s.<集群>.<组件>`），SA token/registry 凭据 record_loot 掩码登记。
