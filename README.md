# 告警分析程序

这个程序接收 Alertmanager 的 webhook，将告警任务先写入 MySQL，再由后台 worker 调用集群内的 Holmes 做只读分析。第一阶段重点是验证“告警进入程序后能触发 Holmes，并保存结构化分析结果”；飞书通知是可选功能，暂时不配置时会跳过发送，不影响分析。

## 当前集群接入信息

以下信息来自 2026-09-29 对集群的只读检查；集群调整后需要重新核对：

- 三台 Kubernetes 节点均为 Ready。
- Holmes 部署在 `default` 命名空间，Service 名为 `holmesgpt-holmes`，端口 80，Pod 容器端口 5050，镜像版本为 `0.42.0`。
- 当前 Holmes 没有 `/api/investigate` 路由，实际接口是 `POST /api/chat`。程序通过该接口提交告警和 JSON Schema，要求 Holmes 返回结构化分析。Holmes API 的 `analysis` 字段承载结构化 JSON 结果。
- MySQL Service `mysql` 是 headless Service，同时选择两个数据库 Pod。检查时 `mysql-0` 为可写节点，`mysql-1` 为只读节点，因此程序默认连接 `mysql-0.mysql.mysql.svc.cluster.local:3306`。
- 当前 Python Service 的端口是 80，转发到容器端口 5000；本程序保留 5000。

## 处理流程

1. Alertmanager 将选中的告警 POST 到 `/alert`。一个请求可以包含多条告警。
2. 程序先将 firing/resolved 状态和 payload 写入 MySQL。事务提交后返回 HTTP 202；数据库不可用时返回 503，让 Alertmanager 有机会重试。
3. 后台 worker 从 MySQL 取 firing 告警并调用 Holmes。Webhook 不会等待 Holmes 完成，因此收到 202 不代表分析已完成。
4. Holmes 返回结构化结论、证据来源、证据是否缺失、建议和后续取证项。程序校验契约后保存到 MySQL。
5. 如果没有配置 `FEISHU_WEBHOOK_URL`，程序记录分析完成日志并将任务标记完成；配置后才会发飞书卡片。

分析结论有三种：

- `confirmed_incident`：已确认故障。
- `possible_false_positive`：可能误报。
- `insufficient_evidence`：证据不足，只保留后续取证建议，不输出确定性修复建议。

Holmes 调用失败或响应不符合结构化契约时，任务状态会标记为调查失败并按独立重试流程处理，不会被当成“可能误报”。

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
| `HOLMES_TIMEOUT_SECONDS` | `300` |
| `FEISHU_WEBHOOK_URL` | 不设置即跳过飞书通知；准备启用时由 Secret 注入 |
| `FEISHU_SIGNING_SECRET` | 飞书机器人启用签名校验时配置 |
| `ALERT_RULES_FILE` | `config/alert_rules.yaml` |
| `DEDUP_WINDOW_SECONDS` | `1800` 秒，即 30 分钟 |
| `RETRY_DELAYS_SECONDS` | `60,180,600` 秒；初次尝试失败后重试三次 |
| `WORKER_POLL_SECONDS` | `2` 秒 |
| `TASK_LEASE_SECONDS` | `420` 秒；用于进程异常退出后回收运行中任务 |

MySQL 数据库需要先由管理员创建。首版程序启动时自动建表，所以应用账号需要对目标库有建表和索引权限；运行时还需要读写这些表的权限。不要在程序中使用 MySQL root 账号。

示例部署清单引用 `python` 命名空间中的 Secret `alert-analyzer-secrets`。首测阶段只需提供 `mysql-database`、`mysql-user`、`mysql-password`；飞书和 Holmes API Key 的 Secret 键是可选的。清单不包含真实凭据。

## 规则扩展

Alertmanager 负责筛选哪些告警会路由到本程序。程序不在 Python 代码里写死告警名称；未配置专属规则的告警会使用通用 Holmes 调查提示。

后续可以在 `config/alert_rules.yaml` 增加按标签精确匹配的调查提示：

```yaml
rules:
  - match:
      alertname: KubernetesPodPending
      severity: warning
    guidance: >-
      优先只读检查目标 Pod、调度事件、节点资源和污点容忍、PVC 绑定及镜像拉取状态。
```

规则只补充调查重点，不提供写操作命令。集群只读权限由 Holmes 自身的数据源和部署配置控制；本程序不直接执行 `kubectl` 或修改集群。

## 首阶段：构建镜像并验证分析

GitLab CI 只在推送 Git tag 时构建并推送镜像，不会自动部署到集群。先在 GitLab 项目 CI/CD Variables 中配置 masked/protected 变量 `HARBOR_USER` 和 `HARBOR_PASSWORD`，再推送 tag。镜像路径为：

```text
hb.reg.com/project/<项目名>:<tag>
```

部署前准备 MySQL 数据库/专用账号及对应 Secret，然后使用 `deploy/kubernetes.example.yaml` 作为参考，替换镜像 tag 并检查变量。当前示例保持单副本和单 worker。

首测时先不要配置 `FEISHU_WEBHOOK_URL`。把 Alertmanager webhook 指向：

```text
http://<Python Service DNS>/alert
```

触发一条会被 Alertmanager 路由过来的告警后，可通过以下方式确认结果：

1. 查看 Python Pod 日志，应出现 `Holmes analysis completed and saved`，其中带有 verdict；若出现 `Holmes analysis completed`，说明已得到有效分析结果。
2. 查询 MySQL 的 `alert_events` 表，查看 `phase` 和 JSON `result` 字段：

```sql
SELECT id, alert_name, fingerprint, phase,
       JSON_UNQUOTE(JSON_EXTRACT(result, '$.verdict')) AS verdict,
       failure_stage, failure_message
FROM alert_events
ORDER BY id DESC
LIMIT 10;
```

任务的 `phase` 为 `complete` 且 `result.verdict` 有值，表示分析已完成。暂未配置飞书时，程序也会将分析结果持久化，不会因为通知配置缺失进入重试。

## 状态、去重和重试

- 同一个 fingerprint 仍处于 firing 时，Alertmanager 的重复推送只更新现有事件，不重复调查。
- `resolved` 结束当前事件；之后再次 firing 会新建事件并重新调查。
- Holmes 返回完整原因类别、范围和根因资源时，程序规范化后生成 `cause_key`。相同 key 在 30 分钟内只通知一次；窗口内的新对象会被记录，窗口后的下一条同原因告警会触发汇总。
- Holmes 分析和飞书发送分阶段持久化。通知失败只重试发送，不重复调用 Holmes。
- 两个阶段均为初次尝试加最多三次重试，间隔为 1、3、10 分钟。Holmes 重试用尽会生成一次调查失败通知；飞书重试用尽会保留失败记录和失败阶段。
- 飞书 webhook 没有通用的幂等键保证。网络在“飞书已接收、程序未收到响应”时失败，重试仍可能造成重复消息。
- 首版示例使用单副本。MySQL 队列保存任务，过期租约可在进程重启后重新认领。

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
