# 科学计算任务运营服务

这是一个面向科研平台、实验室和计算中心的 Python 后端，使用 FastAPI 与 SQLite 管理参数模板、计算任务提交、优先级排队、工作者领取、取消、失败重试、租约恢复、用户配额、结果版本和管理员人工干预记录。服务同时保留用户、角色、会话和审计等基础能力，所有运行数据都在单个本地数据库文件中，不需要另行部署数据库、缓存、消息队列或浏览器界面。

## 已有能力

- 参数模板：保存参数类型、必填项、数值范围、默认值、最大运行时间和最大尝试次数。
- 任务提交：根据模板校验参数，使用用户与幂等键避免重复创建，并保存项目、提交人和输入摘要。
- 排队领取：按优先级和进入队列的顺序分配任务，工作者可声明算法能力并获得有期限的租约。
- 执行回执：工作者可以续租、提交结果或报告失败；可重试错误使用确定的退避时间重新排队。
- 失败恢复：租约过期后可由恢复入口将任务重新排队，达到最大尝试次数的任务转为失败。
- 配额控制：可保存用户、角色或项目的排队数、运行数和每日提交上限；当前提交路径执行用户配额。
- 结果版本：每次成功回执保存不可变结果、指标摘要和内容摘要，任务指向当前结果版本。
- 人工干预：取消、人工重试、优先级调整和批量操作均保留操作者、原因、前后状态和批次标识。
- 登录与角色：基础管理模块提供管理员初始化、用户、角色、会话和细粒度权限。
- 辐射事件隔离：接收地面站高能粒子告警，按任务风险等级（关键诊断 / 普通批处理 / 维护类）执行隔离策略，支持批量冻结与解冻、带原因的人工豁免、结果可信度标注和按事件回放受影响任务；策略变更保留版本与操作者记录，重复告警幂等，进程重启后隔离状态完整还原。

## 运行环境

- Python 3.11
- SQLite 3，由 Python 标准库提供
- Linux、macOS 或 Windows

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `./data/compute-operations.db`。可以复制 `.env.example` 并通过 `TOWNSHIP_DATABASE_PATH` 指定其他本地路径。

## 数据库初始化与检查

```bash
python -m app.cli init-db
python -m app.cli check-db
```

## 启动 API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查：

```bash
curl -sS http://127.0.0.1:8432/api/system/health
```

计算任务摘要位于 `/api/compute/summary`，模板、配额、提交、领取、回执和人工操作接口统一使用 `/api/compute` 前缀。

## 辐射事件任务隔离

收到地面站高能粒子告警后，系统不再让所有卫星任务无差别运行：关键诊断任务（`critical`）保留，普通批处理（`normal`）与维护类任务（`maintenance`）按当前策略自动冻结，事件作用窗口内已产出的结果自动标记为“可能受辐射影响”。接口统一使用 `/api/radiation` 前缀。

- 告警接入：`POST /api/radiation/events`。同一 `external_id` 的重复告警只累计 `deduplicated_count`，绝不会重复生成隔离记录（`radiation_quarantines` 上有 `UNIQUE(event_id, task_id)` 约束兜底）。
- 风险分级：`PUT /api/radiation/tasks/{task_id}/risk?actor=...` 维护任务风险等级；未分级任务按普通批处理处理。
- 批量冻结 / 解冻 / 豁免：`POST /api/radiation/events/{id}/freeze|unfreeze|exempt?actor=...`，请求体带任务列表与原因；豁免必须填写原因，豁免 / 解冻后若没有其它活跃事件仍冻结该任务，任务才恢复排队（多起事件重叠时取最后一个冻结持有者）。
- 结果可信度：`POST /api/radiation/events/{id}/tasks/{task_id}/results/{version}/annotation?actor=...`，等级为 `suspect`（可能受辐射影响）、`confirmed_clean`（人工核验可信）、`recomputed_clean`（辐射后重算可信）。
- 按事件回放：`GET /api/radiation/events/{id}/replay` 返回受影响任务、隔离记录、结果标注与完整操作时间线。
- 策略版本：`GET /api/radiation/policy`、`POST /api/radiation/policy?actor=...`（新版本，校验必须完整覆盖三个风险等级且冻结 / 保留不冲突）、`GET /api/radiation/policy/versions`；每版记录规则、变更原因与操作者，历史版本永久保留。
- 状态还原：隔离、豁免、标注与策略全部落 SQLite，服务无内存态；重启后 `GET /api/radiation/tasks/{task_id}/isolation`、`GET /api/radiation/snapshot` 与计算任务调度守卫（被活跃事件冻结的任务不可被领取）均能准确还原。

新事件按其入库时的当前策略版本执行，并在事件上记录 `policy_version`；冻结运行中任务会释放工作者租约，解冻后统一回到排队重新调度，避免出现无主 `running`。旧数据库会在启动时幂等迁移，为 `compute_tasks` 增加 `frozen` 状态。

## 测试

```bash
python -m pytest
```

测试覆盖参数规则、幂等提交、配额拒绝、优先级领取、能力匹配、租约续期、失败退避、结果版本、取消、人工重试、批量操作和租约恢复，并保留身份与既有科学计算模块的回归用例。

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
python -m app.cli compute-demo
```

`smoke` 在进程内检查根路径和健康接口，`compute-demo` 会创建示例参数模板、提交一个计算任务并让匹配能力的工作者领取，用于快速确认核心运营链路。

## 目录结构

```text
app/
  compute/         计算模板、配额、任务、结果版本和人工干预
  radiation/       辐射事件、任务风险等级、隔离策略、豁免与结果可信度
  api/             用户、角色、认证、审计和系统管理接口
  core/            时钟、安全、异常和分页能力
  repositories/    通用 SQLite 查询
  seismic/         既有地震计算示例领域
  services/        身份、审计和通用后台任务服务
  cli.py           初始化、检查和冒烟入口
  database.py      SQLite 连接、事务、表结构与基础权限
tests/             核心、计算运营和身份回归测试
tools/             本地维护脚本
```

## 数据一致性

SQLite 连接启用外键、WAL、busy timeout 和同步写入策略。提交、领取、回执和人工干预使用即时事务；任务领取通过条件更新避免同一条排队记录被重复领取。服务保存 UTC 时间字符串，测试可以注入固定时钟验证退避、租约到期和跨日配额。会话令牌只保存摘要，审计与人工干预记录不会写入明文密码或令牌。
