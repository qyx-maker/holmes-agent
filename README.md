# 告警分析程序

这个程序接收 Alertmanager 的 webhook，将告警任务先写入 MySQL，再由后台 worker 调用集群内的 Holmes 做只读分析。飞书通知可选；未配置时会跳过发送，但分析结果仍会保存在 MySQL。

## 当前集群接入信息

以下信息来自 2026-10-01 对集群的只读检查；集群调整后需要重新核对：

- 三台 Kubernetes 节点均为 Ready。
- Holmes 部署在 `default` 命名空间，Service 名为 `holmesgpt-holmes`，端口 80，Pod 容器端口 5050，镜像版本为 `0.42.0`。
- 当前 Holmes 没有 `/api/investigate` 路由，实际接口是 `POST /api/chat`。HolmesGPT 0.42.0 的 `analysis` 字段返回自然语言 Markdown；程序保留原文，不再要求 JSON Schema。
- 当次 HolmesGPT 请求日志显示推理模型为 `glm-5.3-flash`（Z.AI provider）。
- MySQL Service `mysql` 是 headless Service，同时选择两个数据库 Pod。检查时 `mysql-0` 为可写节点，`mysql-1` 为只读节点，因此程序默认连接 `mysql-0.mysql.mysql.svc.cluster.local:3306`。
- 当前 Python Service 的端口是 80，转发到容器端口 5000；本程序保留 5000。

## 处理流程

1. Alertmanager 将选中的告警 POST 到 `/alert`。一个请求可以包含多条告警。
2. 程序先将 firing/resolved 状态和 payload 写入 MySQL。事务提交后返回 HTTP 202；数据库不可用时返回 503，让 Alertmanager 有机会重试。
3. 后台 worker 从 MySQL 取 firing 告警并调用 Holmes。Webhook 不会等待 Holmes 完成，因此收到 202 不代表分析已完成。
4. Holmes 返回自然语言分析。程序只校验 `analysis` 是非空文本，然后将原文保存到 MySQL 并用于飞书卡片。
5. 如果没有配置 `FEISHU_WEBHOOK_URL`，程序记录分析完成日志并将任务标记完成；配置后才会发飞书卡片。

Holmes 被提示以“已确认故障 / 可能误报 / 证据不足”开头，并在自然语言中说明证据和建议；程序不解析或替模型验证这些结论。Holmes 调用失败、响应体无效或 `analysis` 为空时，任务会按独立重试流程处理，最终标记为调查失败，不会被当成误报。

## 配置

必需环境变量：

| 变量 | 用途 |
| --- | --- |
| `MYSQL_DATABASE` | 已创建的应用数据库，建议命名为 `alert_analyzer` |
| `MYSQL_USER` | 专用应用数据库账号 |
| `MYSQL_PASSWORD` | 数据库密码，通过 Kubernetes Secret 注入 |

可选环境变量：

| 变量 | 默认值/说明 |
| --- | --- |
| `MYSQL_HOST` | `mysql-0.mysql.mysql.svc.cluster.local` |
| `MYSQL_PORT` | `3306` |
| `HOLMES_API_URL` | `http://holmesgpt-holmes.default.svc.cluster.local` |
| `HOLMES_API_KEY` | 默认不设置；仅当 Holmes 开启 API 认证时配置 |
| `HOLMES_TIMEOUT_SECONDS` | `900` 秒 |
| `FEISHU_WEBHOOK_URL` | 不设置即跳过飞书通知；准备启用时由 Secret 注入 |
| `FEISHU_SIGNING_SECRET` | 飞书机器人启用签名校验时配置 |
| `ALERT_RULES_FILE` | `config/alert_rules.yaml` |
| `RETRY_DELAYS_SECONDS` | `60,180,600` 秒；初次尝试失败后重试三次 |
| `WORKER_POLL_SECONDS` | `2` 秒 |
| `TASK_LEASE_SECONDS` | `1200` 秒；必须大于 Holmes 的 900 秒超时，避免慢请求时租约提前过期并被重复认领 |
| `ANALYSIS_MAX_AGE_SECONDS` | `1800` 秒；必须大于 Holmes 超时，超龄或已 resolved 的告警不再启动/重试调查 |

MySQL 数据库需要先由管理员创建。首版程序启动时自动建表，所以应用账号需要对目标库有建表和索引权限；运行时还需要读写这些表的权限。不要在程序中使用 MySQL root 账号。

示例部署清单引用 `holmes` 命名空间中的 Secret `alert-analyzer-secrets`。至少提供 `mysql-database`、`mysql-user`、`mysql-password`；飞书和 Holmes API Key 的 Secret 键是可选的。清单不包含真实凭据。

## 规则扩展

Alertmanager 负责筛选哪些告警会路由到本程序。程序不在 Python 代码里写死告警名称；未配置专属规则的告警会使用通用 Holmes 调查提示。

`config/alert_rules.yaml` 已包含 `PodCPUUsageHigh` 的专项提示，要求 Holmes 只调查告警 Pod，最多进行 6 次只读工具调用。后续可以增加其他告警类型：

```yaml
rules:
  - match:
      alertname: KubernetesPodPending
      severity: warning
    guidance: >-
      优先只读检查目标 Pod、调度事件、节点资源和污点容忍、PVC 绑定及镜像拉取状态。
```

未匹配规则仍走通用调查提示。规则只补充调查重点，不提供写操作命令。集群只读权限由 Holmes 自身的数据源和部署配置控制；本程序不直接执行 `kubectl` 或修改集群。

resolved 告警会关闭当前 firing 事件；尚未开始的分析会直接标记为 `skipped`。正在执行的 Holmes 请求无法中断，返回时会检查状态并抑制通知。超过 `ANALYSIS_MAX_AGE_SECONDS` 的待分析任务也会标记为 `skipped`，通知阶段的重试不受此时效限制。

## 首阶段：构建镜像并验证分析

GitLab CI 只在推送 Git tag 时构建并推送镜像，不会自动部署到集群。先在 GitLab 项目 CI/CD Variables 中配置 masked/protected 变量 `HARBOR_USER` 和 `HARBOR_PASSWORD`，再推送 tag。镜像路径为：

```text
hb.reg.com/project/<项目名>:<tag>
```

部署前准备 MySQL 数据库/专用账号及对应 Secret，然后使用 `deploy/kubernetes.example.yaml` 作为参考，替换镜像 tag 并检查变量。当前示例保持单副本和单 worker。该示例清单是参考模板，不要在没有替换镜像 tag、核对 ConfigMap 和 Secret 的情况下直接 apply。

把 Alertmanager webhook 指向：

```text
http://<Python Service DNS>/alert
```

触发一条会被 Alertmanager 路由过来的告警后，可通过以下方式确认结果：

1. 查看分析程序日志，应看到 `Starting Holmes investigation`，之后是 `Holmes analysis completed` 或明确的重试/失败阶段。
2. 查询 MySQL 的 `alert_events` 表，查看 `phase` 和 JSON `result` 字段：

```sql
SELECT id, alert_name, fingerprint, phase,
       JSON_UNQUOTE(JSON_EXTRACT(result, '$.analysis')) AS analysis,
       failure_stage, failure_message
FROM alert_events
ORDER BY id DESC
LIMIT 10;
```

任务的 `phase` 为 `complete` 且 `result.analysis` 有文本，表示分析和通知阶段已结束。若启用了飞书，`notification_pending` 表示只在重试发送通知，不会再次调查。

## 状态、去重和重试

- 同一个 fingerprint 仍处于 firing 时，Alertmanager 的重复推送只更新现有事件，不重复调查。
- `resolved` 结束当前事件；之后再次 firing 会新建事件并重新调查。
- 告警身份以 Alertmanager fingerprint 和 firing 周期为准；自然语言不用于比较根因。当前版本不跨告警合并原因通知，避免从自由文本猜测 `cause_key` 导致误合并。
- Holmes 分析和飞书发送分阶段持久化。通知失败只重试发送，不重复调用 Holmes。
- 两个阶段均为初次尝试加最多三次重试，间隔为 1、3、10 分钟。Holmes 重试用尽会生成一次调查失败通知；飞书重试用尽会保留失败记录和失败阶段。
- 飞书 webhook 没有通用的幂等键保证。网络在“飞书已接收、程序未收到响应”时失败，重试仍可能造成重复消息。
- 首版示例使用单副本。MySQL 队列保存任务，过期租约可在进程重启后重新认领。
- `ANALYSIS_MAX_AGE_SECONDS` 默认 1800 秒；超龄的待分析/重试任务会标记为 `skipped`。收到 resolved 后，尚未开始的分析也会跳过；正在进行的 Holmes 请求无法中断，完成后会抑制通知。

## 部署示例和本地运行

`deploy/kubernetes.example.yaml` 提供单副本 Deployment 和端口 80 到 5000 的 Service 参考。本仓库不会自动对集群应用该清单。

本地运行时，通过环境变量提供 MySQL 连接信息；不要把密码或飞书机器人 URL 写进代码或提交到 Git：

```powershell
$env:MYSQL_HOST = "<mysql-writer-host>"
$env:MYSQL_DATABASE = "alert_analyzer"
$env:MYSQL_USER = "<app-user>"
$env:MYSQL_PASSWORD = "<app-password>"
python -m uvicorn app:app --host 0.0.0.0 --port 5000
```

服务提供 `/alert`、`/healthz` 和 `/readyz`；`/readyz` 会检查 MySQL 连通性。
