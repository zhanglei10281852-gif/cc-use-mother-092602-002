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
- 辐射事件隔离：地面站高能粒子告警接入后，按任务风险等级与版本化隔离策略批量冻结普通批处理、保留关键诊断任务，支持带原因的人工豁免、结果可信度标注、按事件回放受影响任务；重复告警幂等去重，服务重启后自动对账还原隔离状态。

## 辐射事件与任务隔离

`/api/radiation` 前缀提供完整链路：

- 事件接入：`POST /api/radiation/events` 按 `event_code` 幂等去重，重复告警只累计 `duplicate_count`，不会生成重复隔离；`POST /events/{id}/resolve` 结束事件并释放隔离。
- 风险分级：`PUT /api/radiation/profiles` 按 task/template/project 维度维护 `critical`（关键诊断，保留）、`sensitive`、`batch`（普通批处理，冻结）风险档案，解析优先级为 task > template > project > 策略默认等级。
- 隔离策略：`POST /api/radiation/policies` 生成新版本（记录操作者与变更原因），`GET /policies/current`、`GET /policies/versions/{v}` 查询；每个等级可配置 `freeze`/`keep` 与是否标注结果。
- 批量冻结/解冻：`POST /api/radiation/freeze`（可指定任务或按策略全量）、`POST /events/{id}/unfreeze`；冻结任务状态为 `frozen`，不可被工作者领取，解冻后回到排队。
- 人工豁免：`POST /events/{id}/tasks/{task_id}/exempt` 与 `POST /events/{id}/exemptions`，必须给出原因，可设有效期；豁免任务立即恢复可领取状态。
- 结果标注：事件窗口内产生的结果自动标注 `suspect`，`POST /annotations/{id}/clear` 带原因解除并转为 `verified`。
- 事件回放：`POST /events/{id}/replay` 将带可疑标注的终态任务重新排队、解除仍冻结的隔离；`GET /events/{id}` 返回隔离明细与操作时间线。
- 重启对账：服务启动时自动执行 `reconcile`，以隔离记录为准修复任务状态漂移；也可手动 `POST /api/radiation/reconcile`。

告警期间新提交或人工重试的任务会在同一事务内按活跃事件自动筛查隔离。

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

## 测试

```bash
python -m pytest
```

测试覆盖参数规则、幂等提交、配额拒绝、优先级领取、能力匹配、租约续期、失败退避、结果版本、取消、人工重试、批量操作和租约恢复，辐射隔离部分覆盖告警幂等、策略版本、风险档案、冻结与解冻、人工豁免、结果标注、事件回放、重启对账和告警期间新任务筛查，并保留身份与既有科学计算模块的回归用例。

## 编译检查

```bash
python -m compileall -q app tests
```

## API 冒烟

```bash
python -m app.cli smoke
python -m app.cli compute-demo
python -m app.cli radiation-demo
```

`smoke` 在进程内检查根路径和健康接口，`compute-demo` 会创建示例参数模板、提交一个计算任务并让匹配能力的工作者领取，用于快速确认核心运营链路；`radiation-demo` 演示告警接入、重复告警去重、关键任务保留、批处理冻结、人工豁免与事件结束的完整隔离链路。

## 目录结构

```text
app/
  compute/         计算模板、配额、任务、结果版本和人工干预
  radiation/       辐射事件、风险档案、策略版本、隔离、豁免、结果标注与回放
  api/             用户、角色、认证、审计和系统管理接口
  core/            时钟、安全、异常和分页能力
  repositories/    通用 SQLite 查询
  seismic/         既有地震计算示例领域
  services/        身份、审计和通用后台任务服务
  cli.py           初始化、检查和冒烟入口
  database.py      SQLite 连接、事务、表结构与基础权限
tests/             核心、计算运营、辐射隔离和身份回归测试
tools/             本地维护脚本
```

## 数据一致性

SQLite 连接启用外键、WAL、busy timeout 和同步写入策略。提交、领取、回执和人工干预使用即时事务；任务领取通过条件更新避免同一条排队记录被重复领取。服务保存 UTC 时间字符串，测试可以注入固定时钟验证退避、租约到期和跨日配额。会话令牌只保存摘要，审计与人工干预记录不会写入明文密码或令牌。
