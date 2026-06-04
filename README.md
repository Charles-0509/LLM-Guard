# LLM-Guard

面向大模型交互场景的敏感信息检测与文档脱敏系统。系统在用户把提示词或附件发送给大模型之前，先检测手机号、邮箱、身份证号、银行卡号、密码字段、API Key、数据库连接凭据、URL 敏感参数和提示注入风险，并输出脱敏结果与风险报告。

## 技术栈

- 前端：Vue 3 + Vite
- 后端：FastAPI
- 文件支持：txt、csv、docx、xlsx、pdf、pptx

## 本地运行

推荐使用一键启动脚本。前端会从 5050 端口开始寻找可用端口，如果 5050 被占用，就自动尝试 5051、5052，直到找到可用端口。后端默认从 8010 端口开始做同样的冲突避让。

PowerShell：

```powershell
.\start.ps1
```

Windows CMD：

```cmd
start.cmd
```

Git Bash / Linux / macOS：

```sh
sh ./start.sh
```

脚本会自动检查依赖，缺少后端虚拟环境时会创建 `.venv`，缺少前端依赖时会执行 `npm install`。启动后终端会输出实际访问地址。

也可以手动启动。

后端：

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8010
```

前端：

```powershell
cd frontend
npm install
npm run dev
```

访问 http://localhost:5173

## 账号登录

系统内置了一个简单的账号密码验证层。后端使用 SQLite 保存账号、随机盐和 PBKDF2-HMAC-SHA256 哈希后的密码，不保存明文密码。登录成功后，后端会生成随机会话令牌，前端通过 `Authorization: Bearer <token>` 访问检测和文件下载接口。

首次启动后端时，如果数据库中不存在初始账号，系统会自动创建：

- 账号：`charles`
- 密码：`Charles939433.`

账号数据库默认位于：

```text
backend/storage/llm_guard.sqlite3
```

可以通过环境变量覆盖初始账号和密码：

```bash
export LLM_GUARD_INITIAL_USERNAME=yourname
export LLM_GUARD_INITIAL_PASSWORD='your-strong-password'
export LLM_GUARD_SESSION_SECONDS=86400
```

初始账号只会在不存在时创建。数据库已经创建后，再修改环境变量不会自动改旧账号密码；如需重置演示环境，可以先停止服务，再删除 `backend/storage/llm_guard.sqlite3` 后重新启动。

## 脱敏原理

LLM-Guard 的脱敏流程可以概括为：文本提取、敏感信息识别、风险分级、内容替换和报告生成。

1. 文本提取：系统会先从用户输入的提示词或上传文件中提取可检测文本。对于 txt 文件直接读取全文；对于 csv 文件按行和列读取；对于 xlsx 文件按工作表和单元格读取；对于 docx 文件读取段落和表格；对于 pdf 文件逐页提取文字；对于 pptx 文件读取幻灯片中的文本框内容。

2. 敏感信息识别：系统使用一组预定义规则扫描文本。每条规则对应一种敏感信息类型，例如手机号、邮箱、身份证号、密码字段、API Key、数据库连接凭据等。规则主要基于正则表达式，适合识别格式相对固定的敏感数据。

3. 风险分级：每个命中项会被标记为 medium、high 或 critical 等风险等级。手机号、邮箱、学号、地址等通常属于中风险；身份证号、银行卡号、URL 敏感参数、提示注入语句属于高风险；密码、API Key、数据库连接凭据属于严重风险。

4. 内容替换：检测到敏感信息后，系统根据用户选择的处理策略生成脱敏结果。处理策略包括遮蔽、占位符和删除。

5. 报告生成：系统会汇总命中数量、风险类型、严重风险数量、风险分数、原始命中内容和替换结果，并在网页中展示风险报告。对于文件检测，系统还会生成一个脱敏后的新文件，文件名格式为“原文件名-fixed.扩展名”。

## 脱敏策略

- 遮蔽：保留少量必要上下文，其余部分用星号或占位文本替代。例如手机号 `13812345678` 会变成 `138****5678`，邮箱 `alice@example.com` 会变成 `al***@example.com`。
- 占位符：将敏感内容替换成类型化标签，例如 `[PHONE_1]`、`[EMAIL_2]`、`[API_KEY_3]`。这种方式适合保留上下文中的实体关系。
- 删除：直接移除命中的敏感内容，适合不希望保留任何敏感字段的场景。

## 匹配规则说明

当前系统包含以下敏感信息匹配规则。

- 身份证号：匹配 15 位或 18 位中国居民身份证号，其中 18 位身份证最后一位允许是数字或 X。

- 手机号：匹配中国大陆常见 11 位手机号，规则为以 1 开头，第二位为 3 到 9，后面跟 9 位数字。

- 数据库连接凭据：匹配包含用户名和密码的数据库连接串，例如 MySQL、PostgreSQL、MongoDB、Redis 等连接地址。系统不会整条删除连接串，而是只替换连接串中的密码部分，例如 `mysql://root:pass@localhost:3306/db` 会变成 `mysql://root:[PASSWORD]@localhost:3306/db`。

- 邮箱地址：匹配常见邮箱格式，例如 `alice@example.com`、`user.name@school.edu.cn`。系统支持中英文混排以及邮箱后面带句号的情况。

- 地址：匹配包含省、市、区、县、镇、乡、街道、路、街、巷、小区、大街等地址关键词的中文地址片段。例如“家庭住址是北京市海淀区中关村大街27号”会被识别为地址信息。

- 学号 / 工号：匹配以“学号”或“工号”开头，后面跟 6 到 14 位数字的编号。例如“学号：2023123456”。

- 银行卡号：匹配 16 到 19 位银行卡号，允许数字之间存在空格或短横线。

- 密码字段：匹配常见密码字段写法，包括 `password`、`passwd`、`pwd`、`口令`、`密码`、`数据库密码` 等字段名后面跟冒号、中文冒号或等号的形式。例如 `password=Admin@123456`、`数据库密码：dbRoot2026`。

- API Key / Token：匹配常见密钥和令牌字段，包括 `api_key`、`access_token`、`secret_key`、`bearer`，以及以 `sk-` 开头的密钥形态。例如 `API Key 为 sk-demo1234567890abcdef`。

- URL 敏感参数：匹配 URL 或查询字符串中的敏感参数，例如 `token=...`、`key=...`、`secret=...`、`password=...`、`pwd=...`。

- 提示注入风险：匹配常见提示注入或越权指令，例如“忽略之前的规则”“忽略之前的指令”“泄露系统提示词”“ignore previous instructions”“reveal the system prompt”“developer message”“jailbreak”等。

## OpenAI 兼容本地代理

LLM-Guard 也可以作为本机 OpenAI `/v1` 兼容安全代理使用。推荐把它放在 ccswitch 后面：Codex 仍然连接 ccswitch，ccswitch 把请求转发给 LLM-Guard，LLM-Guard 脱敏后再发往真实中转站或模型服务。

典型链路如下：

```text
Codex / OpenAI SDK
  -> ccswitch
  -> LLM-Guard 代理脱敏
  -> 中转站 / 模型服务
```

代理接口只覆盖 `/v1/{path}`，不会影响网页登录和原有 `/api/*` 接口。`/api/*` 仍然需要网页登录令牌，`/v1/*` 默认不额外要求网页登录，建议只监听 `127.0.0.1` 供本机使用。

后端代理环境变量：

```env
LLM_GUARD_PROXY_UPSTREAM=https://你的中转站地址/v1
LLM_GUARD_PROXY_MODE=mask
LLM_GUARD_PROXY_ENABLED=true
```

说明：

- `LLM_GUARD_PROXY_UPSTREAM` 为必填项，填写原本 ccswitch 指向的真实中转站或模型服务地址；未配置时访问 `/v1/*` 会返回 `503`。
- `LLM_GUARD_PROXY_UPSTREAM` 可以带 `/v1`，也可以不带 `/v1`，系统会自动拼接正确的 OpenAI 兼容路径。
- `LLM_GUARD_PROXY_MODE` 支持 `mask`、`placeholder`、`remove`、`report_only`、`off`，默认是 `mask`。
- `mask` 会实际遮蔽敏感信息；`placeholder` 会替换为类型占位符；`remove` 会删除命中内容；`report_only` 只统计不修改请求；`off` 完全透传。
- 代理只处理发往上游的 JSON 请求体，不脱敏模型响应。
- 非 JSON 请求体会直接透传，JSON 解析失败时也会按原始请求体透传。
- 代理不会主动记录原始提示词或上传内容，避免 LLM-Guard 自己成为敏感信息日志源。

PowerShell 启动示例：

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
$env:LLM_GUARD_PROXY_UPSTREAM="https://你的中转站地址/v1"
$env:LLM_GUARD_PROXY_MODE="mask"
uvicorn app.main:app --host 127.0.0.1 --port 8010
```

Linux / macOS 启动示例：

```sh
cd backend
source .venv/bin/activate
export LLM_GUARD_PROXY_UPSTREAM="https://你的中转站地址/v1"
export LLM_GUARD_PROXY_MODE="mask"
uvicorn app.main:app --host 127.0.0.1 --port 8010
```

ccswitch 中把原本的上游地址改为 LLM-Guard：

```text
http://127.0.0.1:8010/v1
```

Codex 或 OpenAI SDK 仍然保持原来的 ccswitch 配置即可。也就是说，这种接入方式下只需要修改 ccswitch 的模型服务地址，让 ccswitch 指向 `http://127.0.0.1:8010/v1`；LLM-Guard 的 `LLM_GUARD_PROXY_UPSTREAM` 再指向真实中转站。

代理会在上游响应头中附加调试信息：

```http
X-LLM-Guard-Proxy: active
X-LLM-Guard-Mode: mask
X-LLM-Guard-Redacted-Count: 2
```

其中 `X-LLM-Guard-Redacted-Count` 表示本次请求命中的敏感信息数量。正式使用时仍建议只在本机监听代理端口，不要把未认证的 `/v1/*` 代理直接暴露到公网。

## 局限性

- 当前规则以正则表达式为主，适合识别格式明确的敏感信息，但对模糊语义、隐晦表达和复杂上下文的识别能力有限。
- 地址、学号、工号等规则可能存在误报或漏报，需要根据实际使用场景继续优化。
- PDF 脱敏依赖文本提取结果，如果 PDF 是扫描图片或文字被拆分，可能无法完整识别。
- DOCX、PPTX 的文本替换可能改变局部样式，因为系统优先保证脱敏效果和文件可下载。
- 当前系统不调用真实大模型，只负责在发送给大模型前进行本地安全预处理。

## 公网部署安全防护

提示词输入和文件上传都属于不可信输入。系统已经加入基础防护，降低公网部署时被滥用或注入攻击影响的风险。

- 提示词输入限制：后端会限制单次提示词最大长度，避免超长文本造成正则扫描和响应生成的资源消耗。
- 脱敏模式白名单：后端只接受 `mask`、`placeholder`、`remove` 三种处理模式，拒绝未知参数。
- 上传类型限制：后端只接受 txt、csv、docx、xlsx、pdf、pptx，并在保存前检查扩展名和基础文件签名。
- 上传大小限制：后端限制单个文件最大 20MB，建议 Nginx 同步配置 `client_max_body_size 20M` 或更小。
- Office 压缩包防护：docx、xlsx、pptx 本质是 ZIP 包，系统会检查内部文件数量、路径和解压后总体积，拒绝异常路径和疑似压缩炸弹。
- PDF 页数限制：系统限制 PDF 最大页数，避免恶意大文件拖慢服务。
- 提取文本限制：系统限制单段提取文本长度，避免异常文件触发过高内存或 CPU 消耗。
- CSV / Excel 公式注入防护：生成脱敏 csv、xlsx 时，如果单元格以 `=`、`+`、`-`、`@` 开头，会在前面加 `'`，避免用户下载后用表格软件打开时执行公式。
- 下载路径校验：下载接口只允许访问脱敏目录中的文件名，拒绝带路径分隔符的非法文件名。
- 错误信息收敛：公网接口不会把后端异常堆栈或底层解析错误直接返回给用户。

这些防护不能替代完整的生产安全体系。正式公网部署时，仍建议在 Nginx 层增加 HTTPS、访问日志、限流、`client_max_body_size`、必要的身份认证和存储目录定期清理策略。
