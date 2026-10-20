/**
 * dsh-auto-approve —— 第四种权限模式「自动审批」。
 *
 * ── 它解决什么 ──────────────────────────────────────────────────────────
 * DSH 原生三种模式都不理想：
 *   · 工作区内修改 —— 每次碰到工作区外都要弹人工确认，打断心流；
 *   · 完全权限     —— 一次都不问，出了事不可逆。
 * 这个插件在两者之间加一档：**不弹人工确认，改由模型判定风险**。
 * 低风险直接执行，危险操作被拒绝，并把"为什么危险 + 该怎么改"回给主模型，
 * 让它自己换一条更安全的路继续干活 —— 这就是 Codex「帮我审批」的行为。
 *
 * ── 它怎么接进去 ────────────────────────────────────────────────────────
 * 1. 第四种模式本身是**权限预设**，不在这个文件里，在 cordis.patch.yml：
 *    覆盖内置 `permission` 行，加一项 `auto-approve`（沙箱 danger-full-access +
 *    审批策略 ask），并设为新会话默认。这样它出现在 GUI 的 Permissions 选择器里，
 *    也能作为"新会话默认权限"被选中。
 *
 * 2. 判定闸门是 `tools/pre-execute` waterfall（本文件）。每一条工具调用在进入
 *    工具体之前都会经过这里，**参数是完整的** —— 这是必须走这条路的原因：
 *    `approval/request` 那条缝的文档明确写着请求不带工具参数，只看得到工具名，
 *    而 `rm -rf /` 和 `ls` 的工具名都是 shell，没法判断。
 *
 * 3. 判定用一次独立的 LLM 调用（provider/model 可配，默认 DeepSeek flash + low），
 *    与主模型解耦：换主模型不影响审查成本，审查也不会污染主对话的 KV 缓存。
 *
 * ── 安全立场 ────────────────────────────────────────────────────────────
 * fail-closed：解析失败、超时、模型报错、服务不可用 —— 全部按**拒绝**处理。
 * 因为误拒的代价是模型换个方法重试，误放的代价不可逆。
 *
 * @module dsh-auto-approve
 */

import { existsSync, realpathSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

import { classifyPath, denialMessage, parseDecision, reviewUserText, REVIEW_POLICY } from './policy.js'
import {
  DEFAULT_ALLOW_MAX,
  DEFAULT_ALLOW_TTL_MS,
  DEFAULT_DENY_MAX,
  DEFAULT_DENY_TTL_MS,
  cacheFile,
  cacheKey,
  loadCache,
  lookupCache,
  rememberCache,
  resolveCacheDir,
  saveCache,
} from './cache.js'

/** Cordis 诊断名。 */
export const name = 'dsh-auto-approve'

/**
 * 依赖服务。三个都是硬依赖：
 *   permissionPresets —— 读当前会话的权限模式（决定要不要审查）；
 *   llm               —— 发审查请求；
 *   workingDirectory  —— 取会话当前工作目录（审查的重要输入）。
 */
export const inject = ['permissionPresets', 'llm', 'workingDirectory']

/**
 * 代码版本常量，写进 .status.json。
 * 排查「改了代码但现象没变」时第一件事就是看它 —— 时间戳分不清
 * 「新代码加载了但没生效」和「新代码压根没加载」（Node 的 ESM 缓存不因文件变化失效）。
 * 每次修完 bump 一下。
 */
export const REVISION = 30

const PLUGIN_DIR = dirname(fileURLToPath(import.meta.url))
const STATUS_FILE = join(PLUGIN_DIR, '.status.json')

/** PTC 的外层传输工具名。它的内层调用会各自单独过闸，外层不用审查。 */
const RUN_CODE = 'run_code'

/**
 * 拒绝用的错误标识 —— **必须和官方 Auto review 完全一致**，否则 UI 不给展开视图。
 *
 * `dsh-client-ui-tool` 里写死了这一段：
 *
 *     if (error?.name !== "AutoReviewDeniedError" || error.code !== "AUTO_REVIEW_DENIED") return null
 *     return { reason: typeof error.reason === "string" ? error.reason : null }
 *
 * 命中它，工具卡片才有"展开看完整原因"的视图（中文「工具未执行。原因：{reason}」）；
 * 用自定义标识时，拒绝只会显示成一行通用错误，`reason` 全部看不到 —— 实测踩到。
 * **这里的名字不是命名自由，是 UI 的识别键。**
 */
const DENIED_NAME = 'AutoReviewDeniedError'
const DENIED_CODE = 'AUTO_REVIEW_DENIED'

/** 风险等级的中文标签，用在给用户看的展开文本里。 */
const RISK_LABEL = Object.freeze({ low: '低风险', medium: '中风险', high: '高风险' })

/** 取不到工作目录时的拒绝理由。没有工作目录就没有路径判据，缺了就开不了闸。 */
const NO_CWD_REASON = '取不到会话工作目录，无法判断目标落在哪里'

/** 模型目录缓存多久（毫秒）。目录变化事件到达时会立即失效。 */
const MODEL_CACHE_MS = 10 * 60 * 1000

/** `.status.json` 里最多保留多少个会话的桶。 */
const PER_SESSION_KEEP = 20

/** 跳过路径最多每这么多毫秒落一次盘，避免每个工具调用都写文件。 */
const FLUSH_THROTTLE_MS = 2000

/**
 * 从工具参数里取“路径”的键名。
 * 只认这几个 —— 认错了会把命令文本当路径做包含判断，方向反而危险。
 */
const PATH_KEYS = Object.freeze(['file_path', 'path', 'cwd'])


// ---------------------------------------------------------------------------
// 第 1 层：确定性判定（不调模型）
//
// 为什么需要：low 风险的操作让模型判，是纯浪费 —— 一次 1.4 秒、约 1500 token。
// 上一轮 70 次调用里 46 次进了模型，其中绝大多数是"改本会话刚建的文件"，
// 这种判断根本不需要模型。
//
// 更重要的是**稳定性**：确定性规则不会"这次拒下次放"。
// ---------------------------------------------------------------------------

/**
 * 会话开始时间。首次见到某个会话时记一次。
 *
 * 为什么需要：判断"这个文件是不是本会话产出的"，光看目录不够 ——
 * 目录里可能有用户早就在的文件。加上 mtime（不早于会话开始）才安全。
 */
const SESSION_STARTED_AT = new Map()

function sessionStartedAt(session) {
  const id = session === undefined || session === null || session.id === undefined
    ? 'unknown'
    : String(session.id)
  let at = SESSION_STARTED_AT.get(id)
  if (at === undefined) {
    at = Date.now()
    SESSION_STARTED_AT.set(id, at)
  }
  return at
}

/** 只读类工具：不会改变磁盘状态。 */
const READ_ONLY_TOOLS = new Set(['read', 'glob', 'read_image'])

/** 写类工具：参数里有明确的 file_path，可以确定性判定。 */
const WRITE_TOOLS = new Set(['write', 'edit'])

/**
 * 路径归一化成集合键。Windows 大小写不敏感，统一小写。
 * @param {string} p - 路径。
 * @param {string} [base] - 相对路径的解析基准（会话 cwd）；省略时用进程 cwd。
 * @returns {string} 归一化后的键。
 */
function pathKey(p, base) {
  try {
    return (base === undefined ? resolve(p) : resolve(base, p)).toLowerCase()
  } catch {
    return String(p).toLowerCase()
  }
}

/**
 * 本会话创建过的文件路径集合。
 *
 * 判定"这文件是不是本会话自己建的"必须看**整个会话**，不能只看最近 8 条 ——
 * 一个文件可能是 30 步之前建的。缓存键和 recentToolCalls 用同一套（id + seq），
 * 会话没推进就直接复用。
 *
 * 注意：这里只回答"write/edit 碰过哪些路径"。**判断删除豁免时不再用它** ——
 * 程序自己 mkdir 新目录再写的产物不会留下 write/edit 记录，见 deterministicDecision
 * 里的 cwd 树 + mtime。返回值保持 `{ key, paths }` 一种形状，不再夹带半成品 dirs。
 *
 * @param {object} session - agent.session。
 * @param {object} [cache] - 上次的计算结果。
 * @param {string} [cwd] - 会话工作目录；用于解析相对 file_path。
 * @returns {{ key: string, paths: Set<string> }} 缓存与新结果。
 */
export function createdPaths(session, cache, cwd) {
  if (session === undefined || session === null) return { key: '', paths: new Set() }
  const key = `${String(session.id)}:${String(session.seq)}`
  if (cache !== undefined && cache.key === key) return cache
  const paths = new Set()
  let messages
  try {
    messages = session.deriveMessages()
  } catch {
    return { key, paths }
  }
  for (const message of messages) {
    if (message?.role !== 'assistant' || !Array.isArray(message.content)) continue
    for (const block of message.content) {
      if (block?.type !== 'tool-call') continue
      if (block.name !== 'write' && block.name !== 'edit') continue
      let args = block.arguments
      if (typeof args === 'string') {
        try { args = JSON.parse(args) } catch { continue }
      }
      const p = args?.file_path
      if (typeof p === 'string' && p.trim() !== '') {
        paths.add(pathKey(p.trim(), cwd))
      }
    }
  }
  return { key, paths }
}

/**
 * 路径（含 realpath 与父目录）落在哪个保护区。
 *
 * 为什么要 realpath：工作区里一个指向 `~/.ssh/id_rsa` 的符号链接，
 * 只看字面路径是看不出来的。
 *
 * @param {string} abs - 绝对路径。
 * @returns {'privacy'|'system'|undefined} 保护区。
 */
function zoneOf(abs) {
  const direct = classifyPath(abs)
  if (direct !== undefined) return direct
  try {
    const real = classifyPath(realpathSync(abs))
    if (real !== undefined) return real
  } catch { /* 目标不存在：下面查父目录 */ }
  try {
    const viaParent = classifyPath(realpathSync(dirname(abs)))
    if (viaParent !== undefined) return viaParent
  } catch { /* 父目录也取不到就不判 */ }
  return undefined
}

/** 删除类动作。只认删除 —— 写/改不在此列（写新路径本来就放行）。 */
const DESTRUCTIVE_PATTERN = /\b(remove-item|rmdir|rm|del|erase|unlink|rd)\b/iu

/**
 * 系统级不可逆动作：一律拒绝，不做意图追溯 —— 误判代价是整块环境没了。
 *
 * ⚠️ `format` 必须和 PowerShell 的 `Format-Table` / `Format-List` 区分开：
 * 后者是纯展示命令，误杀会让模型连列目录都被拒（全量回放实测踩到）。
 * 所以只认：
 *   · `format.com`、`Format-Volume`（明确的磁盘操作）；
 *   · 独立的 `format` 命令（后面跟空白或行尾，例如 `format D: /q`）。
 * `git log --format=…`、`format(x)`、`Format-Table` 都不匹配。
 */
const SYSTEM_DESTRUCTIVE_PATTERN = /(^|[|;&\r\n]\s*)(?:(format\.com|format-volume|diskpart|bcdedit|vssadmin|cipher|fdisk)\b|format(?=\s|$))/iu

/** 从命令行里抠绝对路径。中文路径也算（不排非 ASCII）。 */
const ABS_PATH_PATTERN = /(?<![a-z0-9])([a-z]:[\\/][^"'\u0060\r\n|;<>]+)/giu

/**
 * shell 命令里的“内容访问动词”。
 *
 * 为什么只认这些：shell 是编程语言，静态规则不可能判准所有效果。这里只做
 * **高置信度的内容访问**（读文件内容、写文件、复制/移动、跑脚本解释器）；
 * 元数据命令（Test-Path / Get-Item / Resolve-Path / Get-Acl）和“只是提到路径”
 * 的命令不在此列，继续交给模型判断 —— 避免把 `Test-Path .env` 这种安全退路也杀掉。
 *
 * 仍然有漏网写法（变量路径、相对路径、[IO.File]::ReadAllText、git show 等），
 * 所以这只是**静态兜底**，不是 shell 的完整语义判断。
 */
const SHELL_CONTENT_ACCESS_PATTERN = /(^|[|;&\r\n({]\s*)(get-content|gc|cat|type|select-string|sls|format-hex|fh|get-childitem|gci|dir|ls|findstr|rg|grep|head|tail|more|less|tar|expand-archive|compress-archive|copy-item|cp|copy|xcopy|robocopy|move-item|mv|move|set-content|add-content|ac|out-file|new-item|ni|rename-item|rni|set-item|si|set-itemproperty|sp|clear-content|clc|tee-object|export-csv|get-filehash|select-xml|import-csv|invoke-expression|iex|add-type|start-process|python|node|perl|ruby|php|powershell|pwsh|cmd|wsl|certutil)\b/iu

/**
 * 授权窗口：只看最近几条**人类**消息。
 *
 * 为什么不能扫全会话：拼接整个会话时，几小时前提过的文件名会**永久有效**。
 * 用户当时可能只是让你读它，几十步之后一次误删就拿到了"授权" ——
 * 授权是有时效的意图，窗口应当以"最近几轮"为准，而不是整段历史。
 */
const USER_SAID_WINDOW = 3

/** 送进审查输入的指令条数。比授权窗口宽一些：来源与约束需要更多上下文。 */
const INSTRUCTION_WINDOW = 6

/**
 * 一条用户侧消息的来源角色。
 *
 * 为什么需要它：`role: 'user'` 不等于"人类用户"。子代理的父会话指令、
 * 项目约束（AGENTS.md）、压缩摘要都以 user 消息的形式出现，但只有真实人类
 * 能授权删除既有对象。不区分来源，子代理的一句"清理一下"就会变成删除授权。
 *
 * 规则对齐官方 Auto review：
 *   · human-instruction —— 带 rpcId 的 Web 用户消息（唯一可授权的来源）；
 *   · direct-parent-instruction —— 子代理里父会话下发的指令；
 *   · constraint —— agent-instructions（项目约束，只能收窄）；
 *   · checkpoint —— compact-checkpoint（只是上下文）；
 *   · unattributed-user —— 没有 rpcId、也不是子代理的用户侧文字，来源不明；
 *   · fact —— 其余（工具结果、通知、插件注入等）。
 *
 * @param {object|undefined} source - 消息的 `source`。
 * @param {object} session - `agent.session`（用 header 判断是否子代理）。
 * @returns {string} 来源角色。
 */
export function instructionRole(source, session) {
  const kind = source !== null && typeof source === 'object' ? source.kind : undefined
  const header = session !== null && typeof session === 'object' ? session.header : undefined
  const isSubagent = header !== undefined && header !== null
    && (header.origin === 'subagent' || header.parentSession !== undefined)
  if (kind === 'user') {
    if (typeof source.rpcId === 'string' && source.rpcId !== '') return 'human-instruction'
    return isSubagent ? 'direct-parent-instruction' : 'unattributed-user'
  }
  if (kind === 'agent-message') {
    const parent = header?.parentSession
    return parent !== undefined && source.senderSessionId === parent
      ? 'direct-parent-instruction'
      : 'fact'
  }
  if (kind === 'agent-instructions') return 'constraint'
  if (kind === 'compact-checkpoint') return 'checkpoint'
  return 'fact'
}

/**
 * 会话里用户侧最近说过的话，**按来源分类**。
 *
 * 为什么要它：闸门看不到输入框，但**能看到会话里用户的发言**。
 * "用户说过要删这个文件"是一个可以被机器验证的事实，而"这个删除合不合理"
 * 是一个判断 —— 前者稳定，后者会抖（实测出现过模型第一次拒、第二次放）。
 *
 * 返回值里只有 `text` 参与删除授权，且只收 human-instruction；
 * `instructions` 带来源送进审查输入，让审查器自己区分可信度。
 *
 * @param {object} session - agent.session。
 * @param {object} [cache] - 上次结果，按 id:seq 复用。
 * @returns {{ key: string, text: string, last: string, instructions: Array<{role: string, text: string}> }} 用户侧发言。
 */
export function userSaid(session, cache) {
  if (session === undefined || session === null) return { key: '', text: '', last: '', instructions: [] }
  const key = `${String(session.id)}:${String(session.seq)}`
  if (cache !== undefined && cache.key === key) return cache
  let messages
  try {
    messages = session.deriveMessages()
  } catch {
    return { key, text: '', last: '', instructions: [] }
  }
  const entries = []
  for (const message of messages) {
    if (message?.role !== 'user' || !Array.isArray(message.content)) continue
    const blocks = []
    for (const block of message.content) {
      if (block?.type === 'text' && typeof block.text === 'string') blocks.push(block.text)
    }
    if (blocks.length === 0) continue
    entries.push({ role: instructionRole(message.source, session), text: blocks.join('\n') })
  }
  const human = entries.filter((entry) => entry.role === 'human-instruction')
  return {
    key,
    // 只有人类指令能授权删除；子代理/约束/检查点一律不算。
    text: human.slice(-USER_SAID_WINDOW).map((entry) => entry.text).join('\n').toLowerCase(),
    last: human.length === 0 ? '' : human[human.length - 1].text,
    // fact 不进指令段：工具结果/通知只是事实，已经由历史工具调用表达；
    // 混进来反而会把真正的人类指令挤出窗口。
    instructions: entries.filter((entry) => entry.role !== 'fact').slice(-INSTRUCTION_WINDOW),
  }
}

/**
 * 取待审工具在注册表里的 schema（描述 + 参数 schema）。
 *
 * 为什么要它：审查器只看参数原文时，对自定义/MCP 工具的参数语义只能猜。
 * 官方 Auto review 把工具 schema 作为审查输入的一段；这里对齐。
 *
 * 来源优先级：PTC 内层调用的 `exec.schema` → 最近一次请求头 → 工具历史（含动态新增）。
 * 同名但内容不一致的多个 schema 视为歧义，返回 undefined（不下结论）。
 *
 * @param {object} session - `agent.session`。
 * @param {object} exec - 待审调用。
 * @returns {{description: string, parameters: object}|undefined} 工具 schema。
 */
export function toolSchemaFor(session, exec) {
  if (exec === null || typeof exec !== 'object' || typeof exec.name !== 'string') return undefined
  const own = exec.schema
  if (own !== null && typeof own === 'object' && own.name === exec.name
    && own.parameters !== null && typeof own.parameters === 'object') {
    return {
      description: typeof own.description === 'string' ? own.description : '',
      parameters: own.parameters,
    }
  }
  const candidates = []
  const collect = (list) => {
    if (!Array.isArray(list)) return
    for (const item of list) {
      if (item !== null && typeof item === 'object') candidates.push(item)
    }
  }
  try { collect(session?.requestHeader?.()?.tools) } catch { /* 没有请求头就退到工具历史 */ }
  try {
    const history = session?.toolHistory?.()
    collect(history?.tools)
    if (Array.isArray(history?.updates)) {
      for (const update of history.updates) collect(update?.additions)
    }
  } catch { /* 取不到历史不代表没有 schema */ }
  const matches = candidates.filter((candidate) => candidate.name === exec.name)
  const unique = []
  for (const candidate of matches) {
    try {
      if (!unique.some((seen) => JSON.stringify(seen) === JSON.stringify(candidate))) unique.push(candidate)
    } catch {
      return undefined
    }
  }
  if (unique.length !== 1) return undefined
  const schema = unique[0]
  if (schema.parameters === null || typeof schema.parameters !== 'object') return undefined
  return {
    description: typeof schema.description === 'string' ? schema.description : '',
    parameters: schema.parameters,
  }
}

/**
 * 从命令字符串里提取候选绝对路径。
 * @param {string} command - 命令行。
 * @returns {string[]} 候选路径。
 */
function pathsInCommand(command) {
  const out = []
  const matches = String(command).match(ABS_PATH_PATTERN) ?? []
  for (const raw of matches) {
    // 去掉尾随的 -Force / -Recurse 这类开关
    const trimmed = raw.trim().split(/\s+-/u)[0].trim()
    if (trimmed !== '') out.push(trimmed)
  }
  return out
}

/**
 * 取 shell 类工具的命令文本。
 * @param {object} exec - 待审调用。
 * @returns {string} command 或 script 字段；没有则空串。
 */
export function commandTextOf(exec) {
  const args = exec?.arguments
  if (args === null || typeof args !== 'object') return ''
  return typeof args.command === 'string' ? args.command
    : (typeof args.script === 'string' ? args.script : '')
}

/**
 * 扫描 shell 命令里的**字面绝对路径**，返回落在保护区的那些。
 *
 * 只认绝对路径：变量、相对路径、`~`、UNC 都不在这里判 —— 那些继续交模型。
 * 这是静态兜底的**证据来源**，不是完整 shell 解析器。
 *
 * @param {string} command - 命令文本。
 * @param {string} cwd - 会话工作目录。
 * @returns {Array<{path: string, zone: string}>} 命中保护区的路径。
 */
export function shellZoneHits(command, cwd) {
  if (typeof command !== 'string' || command === '') return []
  const seen = new Set()
  const hits = []
  for (const raw of pathsInCommand(command)) {
    let abs
    try { abs = resolve(cwd, raw) } catch { continue }
    const key = pathKey(abs)
    if (seen.has(key)) continue
    seen.add(key)
    const zone = zoneOf(abs)
    if (zone !== undefined) hits.push({ path: abs, zone })
  }
  return hits
}


/** 删除类动词。只认明确的删除意图，"清理"这种含糊的词不算。 */
const DELETE_VERB = /(删除|删掉|删了|移除|清掉|去掉|remove-item|\brm\b|\bdel\b|\brmdir\b|\bdelete\b)/iu

/** 否定的删除指令（"不要删除…"）不能当作授权。 */
const NEGATED_DELETE = /(不要|别|勿|禁止|不准)\s*(?:再|继续)?\s*(删除|删掉|删了|删|移除|清掉|去掉)|(do\s+not|don't|never)\s+(delete|remove)/iu

/** 列表项：`-` / `*` / `•` / `1.` / `1)`。 */
const LIST_ITEM = /^\s*(?:[-*•]|\d+[.)])\s+/u

/**
 * 判断一行是不是“删除引导语”。
 *
 * 例：`删除以下文件：`、`5. 逐个文件用 Remove-Item 删除（不要合并）：`。
 * 引导语后面的连续列表项共享删除授权 —— 这是为了支持用户最常见的多行写法，
 * 同时仍然要求“引导语 + 列表项”这个明确结构，而不是看到路径就授权。
 *
 * @param {string} line - 已小写、斜杠归一的一行。
 * @returns {boolean} 是否删除引导语。
 */
function isDeleteBlockHeader(line) {
  if (NEGATED_DELETE.test(line)) return false
  return DELETE_VERB.test(line) && /[：:]\s*$/u.test(line.trim())
}

/**
 * 标出“删除引导语”后面连续列表项所在的行。
 * @param {string[]} lines - 已归一化的行。
 * @returns {boolean[]} 每行是否在删除列表中。
 */
function deletionBlockMarkers(lines) {
  const marked = new Array(lines.length).fill(false)
  for (let i = 0; i < lines.length; i += 1) {
    if (!isDeleteBlockHeader(lines[i])) continue
    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j]
      if (line.trim() === '') break
      if (!LIST_ITEM.test(line)) break
      if (!NEGATED_DELETE.test(line)) marked[j] = true
    }
  }
  return marked
}

/**
 * 用户是否**明确要求删除这个文件**。
 *
 * 为什么要这么严（实测教训一）：只做 basename 子串匹配时，
 * 用户提过 foo.txt（哪怕是为了读它），模型删 foo.txt 就会被放行 —— 那是误删。
 *
 * 授权成立的两种结构：
 *   1. 同一行里出现完整路径/完整词文件名 + 删除动词（最严格）；
 *   2. **删除引导语 + 连续列表项**：引导语以冒号结尾且含删除动词，
 *      后续 `-` / `*` / `1.` 列表项里的路径都算被点名。
 *
 * 否定句（"不要删除 a.txt"）永远不算授权；列表中间空行会结束授权块。
 *
 * @param {string} userText - 用户发言（已小写，斜杠归一）。
 * @param {string} absPath - 待删文件的绝对路径。
 * @returns {boolean} 是否已获授权。
 */
export function deletionAuthorized(userText, absPath) {
  if (typeof userText !== 'string' || userText === '') return false
  const norm = userText.replace(/\\/gu, '/').toLowerCase()
  const target = String(absPath).replace(/\\/gu, '/').toLowerCase()
  const base = target.slice(target.lastIndexOf('/') + 1)
  const lines = norm.split('\n')
  const inDeleteBlock = deletionBlockMarkers(lines)

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]
    // 按逗号/分号/句号拆成小句：同一行里既有"删除 a"又有"保留 b"时，
    // 不能让 b 沾上 a 的删除动词。
    for (const clause of line.split(/[，,;；。]/u)) {
      if (NEGATED_DELETE.test(clause)) continue
      const tokens = clause.split(/[^\p{L}\p{N}._\-]+/u)
      const mentionsTarget = clause.includes(target) || (base !== '' && base.length >= 2 && tokens.includes(base))
      if (!mentionsTarget) continue
      if (inDeleteBlock[i] || DELETE_VERB.test(clause)) return true
    }
  }
  return false
}

/**
 * 第 1 层判定。三种结局：allow / deny / undefined（下沉给模型）。
 *
 * 原则：**判不准就下沉**，确定性层只负责它百分之百确定的事。
 * 宁可多花一次审查，也不要在不确定的时候放行。
 *
 * @param {object} exec - 待执行调用。
 * @param {string} cwd - 会话工作目录。
 * @param {object} config - 归一化配置。
 * @param {{ paths: Set<string>, startedAt?: number }} created - 本会话创建过的路径与开始时间。
 * @param {string} [userText] - 人类指令文本（删除授权用）。
 * @returns {{ outcome: 'allow'|'deny', why: string, zone?: string }|undefined} 判定。
 */
export function deterministicDecision(exec, cwd, config, created, userText = '') {
  // ⚠️ `fastPath: false` 只关闭**确定性放行**，绝不关闭保护区/破坏性的硬拒绝。
  //
  // 这里以前是一行 `if (!config.fastPath) return undefined` —— 一个性能开关把整层
  // 安全边界一起关掉了：A 区隐私、B 区系统、format/diskpart、未授权删除既有文件
  // 全部下沉给模型。而模型会抖（实测一次拒绝后换个写法就被放行，永久删掉了用户文件），
  // 这个开关恰好关掉了"判错没有第二次机会"的那一层，配置里还完全看不出来。
  // 现在只有 allow 分支受开关控制，拒绝规则始终生效。
  const allowEnabled = config.fastPath !== false
  const allow = (why) => (allowEnabled ? { outcome: 'allow', why } : undefined)
  const args = exec.arguments
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return undefined

  const targets = []
  for (const key of PATH_KEYS) {
    const value = args[key]
    if (typeof value !== 'string' || value.trim() === '') continue
    try { targets.push(resolve(cwd, value.trim())) } catch { return undefined }
  }
  // ── 破坏性命令：不交给模型二次判断 ────────────────────────────────
  // 实测教训：一次 Remove-Item 被模型判 high 拒绝，模型换个写法重试，
  // 第二次被判成"可接受"并永久删掉了用户的既有文件（-Force 不进回收站）。
  // 删除不可逆，判错没有第二次机会 —— 所以这一类别只认确定性规则。
  const commandText = commandTextOf(exec)
  if (commandText !== '') {
    if (SYSTEM_DESTRUCTIVE_PATTERN.test(commandText)) {
      return { outcome: 'deny', zone: 'system', why: '磁盘/引导级操作（B 区），一律拒绝' }
    }
    if (DESTRUCTIVE_PATTERN.test(commandText)) {
      let authorizedDelete = false
      for (const raw of pathsInCommand(commandText)) {
        let abs
        try { abs = resolve(cwd, raw) } catch { continue }
        if (!existsSync(abs)) continue                       // 删不存在的，没风险
        // ⚠️ 保护区优先于一切豁免：A/B 区文件**即使被用户点名、即使是本会话产物**，
        // 也不允许删除。以前这里先查 created/dirs/授权，用户一句"删除 .env"就能绕过去。
        const zone = zoneOf(abs)
        if (zone !== undefined) {
          return {
            outcome: 'deny',
            zone,
            why: zone === 'privacy'
              ? '隐私/凭据路径（A 区），即使点名也不允许删除'
              : '操作系统路径（B 区），即使点名也不允许删除',
          }
        }
        if (created.paths.has(pathKey(abs))) { authorizedDelete = true; continue }
        // A+B：cwd 树 + mtime → 本会话产物。
        //
        // 依据从"write/edit 写过的目录"放宽到 **cwd 树**：程序自己 mkdir 新目录再写
        // （例如 node cli.mjs --out out/清单.json）不会留下 write/edit 记录，
        // 只看"写过的目录"就永远认不出这些产物 —— 用户想删自己刚生成的东西也删不掉。
        // cwd 树更宽，但 mtime 仍保护用户既有文件（它们的 mtime 早于会话开始）。
        if (typeof created.startedAt === 'number' && withinCwd(cwd, abs)) {
          try {
            if (statSync(abs).mtimeMs >= created.startedAt) { authorizedDelete = true; continue }
          } catch { /* 读不到 mtime 就不豁免 */ }
        }
        const base = abs.slice(abs.lastIndexOf('\\') + 1)
        // 授权要用严格匹配（完整路径，或"完整词 + 同一行有删除动词"），
        // 不能只做子串 —— 否则用户提过这个文件（哪怕只是要读）就会放行删除。
        if (!deletionAuthorized(userText, abs)) {
          return {
            outcome: 'deny',
            zone: 'destructive',
            why: `要删除既有文件 ${base}，但用户没有明确要求删除它`,
          }
        }
        authorizedDelete = true
      }
      // 所有目标都已获授权 → 确定性放行，**不交给模型**。
      // 实测：模型会把"删用户点名的文件"判成 high 拒绝，而 high 硬规则还会兜底，
      // 结果用户明明要求了却删不掉。授权是事实，不该再赌一次判断。
      if (authorizedDelete) {
        return allow('用户明确要求删除这个文件')
      }
    }

    // shell 里的 A 区内容访问：静态兜底，不依赖模型状态。
    // 只认“字面绝对路径 + 高置信度内容访问动词”；Test-Path / Get-Item / 仅提及路径
    // 不在此列，继续走模型 —— 否则会把本次实测里那条安全退路也堵死。
    if (SHELL_CONTENT_ACCESS_PATTERN.test(commandText)) {
      const privacy = shellZoneHits(commandText, cwd).find((hit) => hit.zone === 'privacy')
      if (privacy !== undefined) {
        return {
          outcome: 'deny',
          zone: 'privacy',
          why: 'shell 命令包含 A 区路径与内容访问动作（隐私/凭据）',
        }
      }
    }
  }

  // 参数里没有结构化路径（pwsh 这类命令）→ 确定性层判不了，交模型。
  if (targets.length === 0) return undefined

  for (const abs of targets) {
    const zone = zoneOf(abs)
    if (zone !== undefined) {
      return { outcome: 'deny', zone, why: zone === 'privacy' ? '隐私/凭据路径（A 区）' : '操作系统路径（B 区）' }
    }
  }

  // 读：不在保护区就能放行 —— 读不会破坏任何东西。
  if (READ_ONLY_TOOLS.has(exec.name)) return allow('只读，且不在保护区')

  if (!WRITE_TOOLS.has(exec.name)) return undefined

  const target = targets[0]
  if (!existsSync(target)) return allow('新建路径，不会覆盖任何既有内容')
  if (created.paths.has(pathKey(target))) return allow('目标是本会话自己创建的')
  // 既有文件被覆盖/修改：可能是用户的东西，交模型判断。
  return undefined
}

const DEFAULTS = Object.freeze({
  enabled: true,
  preset: 'auto-approve',
  provider: 'deepseek-official',
  model: '',
  fallbackModel: 'deepseek-flash',
  reasoningEffort: 'low',
  skipTools: ['todo_write', 'job_list', 'list_agents'],
  fastPath: true,
  cacheEnabled: true,
  // 默认值**只有一处定义**（cache.js 的常量），这里引用而不是抄一遍 ——
  // 抄两份迟早会漂移：改了 cache.js 忘记改这里，配置项就名不副实。
  cacheAllowTtlMs: DEFAULT_ALLOW_TTL_MS,
  cacheDenyTtlMs: DEFAULT_DENY_TTL_MS,
  cacheAllowMax: DEFAULT_ALLOW_MAX,
  cacheDenyMax: DEFAULT_DENY_MAX,
  // 纯展示字段，不参与缓存键。实测：模型每次会把 `description` 换个说法，
  // 它一旦进哈希，同一个命令就永远命中不了缓存。
  cacheIgnoreArgs: ['description'],
  cacheDir: '',
  historyCalls: 3,
  historyArgChars: 400,
  pendingArgChars: 1500,
  shellArgChars: 4000,
  // 审查输出的封顶。0 = 不限制。推理 token 是延迟的主要来源，封顶能压住长尾。
  maxTokens: 0,
  timeoutMs: 20000,
  onReviewFailure: 'deny',
  debug: false,
})

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

function asString(value, fallback) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : fallback
}

function asBoolean(value, fallback) {
  return typeof value === 'boolean' ? value : fallback
}

function asPositiveInt(value, fallback) {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback
}

function asStringArray(value) {
  if (!Array.isArray(value)) return []
  return value.map((item) => (typeof item === 'string' ? item.trim() : '')).filter((item) => item !== '')
}

/**
 * 归一化配置。**非法值不静默吞掉**：该报错就报错，让它在加载时响亮地失败，
 * 而不是让一个写错的 preset 名静默地把审查关掉。
 *
 * @param {unknown} raw - loader 行上的 config。
 * @returns {object} 归一化后的配置。
 */
export function normalizeConfig(raw) {
  const source = raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}
  const failure = asString(source.onReviewFailure, DEFAULTS.onReviewFailure)
  if (failure !== 'deny' && failure !== 'allow') {
    throw new TypeError(`dsh-auto-approve: onReviewFailure 只能是 'deny' 或 'allow'，收到 ${JSON.stringify(failure)}`)
  }
  return Object.freeze({
    enabled: asBoolean(source.enabled, DEFAULTS.enabled),
    preset: asString(source.preset, DEFAULTS.preset),
    provider: asString(source.provider, DEFAULTS.provider),
    model: asString(source.model, DEFAULTS.model),
    fallbackModel: asString(source.fallbackModel, DEFAULTS.fallbackModel),
    reasoningEffort: asString(source.reasoningEffort, DEFAULTS.reasoningEffort),
    // ⚠️ 必须回落到 DEFAULTS：写成 `asStringArray(source.skipTools)` 时，
    // 配置里不写这一项得到的是 `[]`，DEFAULTS 里的默认值等于**死代码**。
    skipTools: Array.isArray(source.skipTools) ? asStringArray(source.skipTools) : [...DEFAULTS.skipTools],
    fastPath: asBoolean(source.fastPath, DEFAULTS.fastPath),
    cacheEnabled: asBoolean(source.cacheEnabled, DEFAULTS.cacheEnabled),
    cacheAllowTtlMs: asPositiveInt(source.cacheAllowTtlMs, DEFAULTS.cacheAllowTtlMs),
    cacheDenyTtlMs: asPositiveInt(source.cacheDenyTtlMs, DEFAULTS.cacheDenyTtlMs),
    cacheAllowMax: asPositiveInt(source.cacheAllowMax, DEFAULTS.cacheAllowMax),
    cacheDenyMax: asPositiveInt(source.cacheDenyMax, DEFAULTS.cacheDenyMax),
    cacheIgnoreArgs: Array.isArray(source.cacheIgnoreArgs) ? asStringArray(source.cacheIgnoreArgs) : [...DEFAULTS.cacheIgnoreArgs],
    cacheDir: asString(source.cacheDir, DEFAULTS.cacheDir),
    historyCalls: asPositiveInt(source.historyCalls, DEFAULTS.historyCalls),
    historyArgChars: asPositiveInt(source.historyArgChars, DEFAULTS.historyArgChars),
    pendingArgChars: asPositiveInt(source.pendingArgChars, DEFAULTS.pendingArgChars),
    shellArgChars: asPositiveInt(source.shellArgChars, DEFAULTS.shellArgChars),
    maxTokens: typeof source.maxTokens === 'number' && Number.isFinite(source.maxTokens) && source.maxTokens >= 0 ? Math.floor(source.maxTokens) : DEFAULTS.maxTokens,
    timeoutMs: asPositiveInt(source.timeoutMs, DEFAULTS.timeoutMs),
    onReviewFailure: failure,
    debug: asBoolean(source.debug, DEFAULTS.debug),
  })
}

// ---------------------------------------------------------------------------
// 审查模型解析
// ---------------------------------------------------------------------------

/**
 * 把可能很长的参数序列化并截断。
 *
 * 为什么保留截断标记：审查器需要知道"我看到的不全"。信息不全时的正确反应是
 * 判得更保守，而这个判断只能靠标记告诉它。
 *
 * @param {unknown} value - 工具参数（任意 JSON 值）。
 * @param {number} limit - 字符上限。
 * @param {string} label - 出现在截断说明里的标签。
 * @param {string[]} notes - 收集截断说明。
 * @returns {string} 序列化后的文本。
 */
export function clipArguments(value, limit, label, notes) {
  let text
  try {
    text = typeof value === 'string' ? value : JSON.stringify(value)
  } catch {
    text = String(value)
  }
  if (typeof text !== 'string') text = String(text)
  if (text.length <= limit) return text
  notes.push(`${label} 被截断，少了 ${text.length - limit} 个字符`)
  return `${text.slice(0, limit)}…(已截断 ${text.length - limit} 字符)`
}

/**
 * `target` 是否在 `root` 之内（含 root 本身）。
 * @param {string} root - 已 realpath 的根。
 * @param {string} target - 待判断路径。
 * @returns {boolean} 在内为 true。
 */
function isInside(root, target) {
  const rel = relative(root, target)
  if (rel === '') return true
  if (rel.startsWith('..')) return false
  // Windows 上跨盘符时 relative 会返回绝对路径（带冒号）
  return !rel.includes(':') && !rel.startsWith(sep)
}

/**
 * `target` 是否落在 `root` 这棵树里（两者都先 realpath）。
 *
 * 用父目录判断而不是目标本身：待删的文件可能刚被删掉/还不存在，
 * `realpathSync` 会抛；父目录通常稳定，且"父目录在树内"已经足够回答
 * "这个路径是不是 cwd 树里的东西"。
 *
 * @param {string} root - 会话工作目录。
 * @param {string} target - 待判断的绝对路径。
 * @returns {boolean} 在树内为 true。
 */
function withinCwd(root, target) {
  if (typeof root !== 'string' || root.trim() === '') return false
  let realRoot
  try { realRoot = realpathSync(root) } catch { realRoot = resolve(root) }
  let realParent
  try { realParent = realpathSync(dirname(target)) } catch {
    try { realParent = resolve(dirname(target)) } catch { return false }
  }
  return isInside(realRoot, realParent)
}

/**
 * 从会话里取最近的工具调用，用来判断"待删的对象是不是本会话自己创建的"。
 *
 * 用 `deriveMessages()`（公开 API）而不是官方那份 `snapshotEvents()`（已标记废弃）：
 * 宁可慢一点，也不要绑在一个明确要改的接口上。
 * 结果按 `会话 id + seq` 缓存 —— 同一个状态下重复审查不重复推导。
 *
 * @param {object} session - Session 实例。
 * @param {number} limit - 最多取几条。
 * @param {number} argChars - 每条参数截断长度。
 * @param {{ key: string, calls: Array<object> }|undefined} cache - 上一次的缓存。
 * @returns {{ key: string, calls: Array<object> }} 新的缓存值。
 */
export function recentToolCalls(session, limit, argChars, cache) {
  if (session === undefined || session === null) return { key: '', calls: [] }
  const key = `${String(session.id)}:${String(session.seq)}`
  if (cache !== undefined && cache.key === key) return cache
  if (limit <= 0) return { key, calls: [] }

  let messages
  try {
    messages = session.deriveMessages()
  } catch {
    // 推导失败不该让审查失去全部上下文 —— 但要在截断说明里体现（调用方会加）。
    return { key, calls: [] }
  }
  const calls = []
  for (const message of messages) {
    if (message?.role !== 'assistant' || !Array.isArray(message.content)) continue
    for (const block of message.content) {
      if (block?.type !== 'tool-call') continue
      const text = typeof block.arguments === 'string' ? block.arguments : JSON.stringify(block.arguments ?? '')
      calls.push({
        name: typeof block.name === 'string' ? block.name : '(未知)',
        arguments: text.length <= argChars ? text : `${text.slice(0, argChars)}…`,
      })
    }
  }
  return { key, calls: calls.slice(-limit) }
}

/**
 * 选出审查用的模型。
 *
 * 配置写死 `model` 就用它；留空表示**自动**：去 provider 的模型目录里挑
 * id 或显示名带 `flash` 的那个 —— 这样官方发布新 flash 时不用改配置。
 * 目录取不到才退回 `fallbackModel`。
 *
 * @param {object} ctx - 插件上下文。
 * @param {object} config - 归一化配置。
 * @param {{ id: string, at: number, ok: boolean }|undefined} cache - 模型缓存。
 * @returns {Promise<{ model: string, source: string, cache: object }>} 选中的模型。
 */
export async function resolveModel(ctx, config, cache) {
  if (config.model !== '') return { model: config.model, source: 'config', cache: { id: config.model, at: Date.now(), ok: true } }
  if (cache !== undefined && Date.now() - cache.at < MODEL_CACHE_MS) {
    return { model: cache.id, source: cache.ok ? 'catalog-cached' : 'fallback-cached', cache }
  }
  try {
    const models = await ctx.llm.listModels(config.provider)
    const flash = Array.isArray(models)
      ? models.find((entry) => /flash/iu.test(String(entry?.id ?? '')) || /flash/iu.test(String(entry?.name ?? '')))
      : undefined
    if (flash !== undefined && typeof flash.id === 'string' && flash.id !== '') {
      return { model: flash.id, source: 'catalog', cache: { id: flash.id, at: Date.now(), ok: true } }
    }
  } catch {
    /* 目录不可用就退回兜底，不阻断审查 */
  }
  return {
    model: config.fallbackModel,
    source: 'fallback',
    cache: { id: config.fallbackModel, at: Date.now(), ok: false },
  }
}

// ---------------------------------------------------------------------------
// 审查
// ---------------------------------------------------------------------------

/**
 * 读完一次审查请求的流，返回合并后的文本。
 *
 * 只取 `text-delta`：思考块（reasoning）不参与解析，这样即使模型先想一段也不影响。
 *
 * @param {AsyncIterable<object>} stream - ctx.llm.stream 的返回值。
 * @param {AbortSignal} signal - 取消信号。
 * @returns {Promise<{ text: string, usage: { inputTokens: number, outputTokens: number, cacheReadTokens: number, cacheWriteTokens: number } }>} 文本与用量。
 */
export async function collectText(stream, signal) {
  let text = ''
  let finished = false
  const usage = { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, reasoningTokens: 0 }
  for await (const chunk of stream) {
    if (signal.aborted) throw new Error('审查被取消')
    if (chunk?.type === 'text-delta') text += String(chunk.text ?? '')
    else if (chunk?.type === 'usage') {
      // 用量在这里就能算出来 —— 这是把"审查花了多少钱"从估算变成实测的唯一途径。
      const counted = chunk.usage ?? {}
      usage.inputTokens += counted.inputTokens ?? 0
      usage.outputTokens += counted.outputTokens ?? 0
      usage.cacheReadTokens += counted.cacheReadTokens ?? 0
      usage.cacheWriteTokens += counted.cacheWriteTokens ?? 0
      // 推理 token 是输出的主要成本项（4 元/M），也是延迟的主要来源 —— 必须量出来。
      usage.reasoningTokens += counted.reasoningTokens ?? 0
    } else if (chunk?.type === 'finish') {
      finished = true
      if (chunk.reason?.kind === 'error' || chunk.reason?.kind === 'aborted') {
        const failure = chunk.reason.failure ?? {}
        throw new Error(`审查请求失败（${String(failure.code ?? 'unknown')}）：${String(failure.message ?? '')}`)
      }
      if (chunk.reason?.kind !== 'stop') throw new Error(`审查请求以 ${String(chunk.reason?.kind)} 结束`)
    }
  }
  if (!finished) throw new Error('审查请求没有收到 finish')
  if (text.trim() === '') throw new Error('审查请求返回空文本')
  return { text, usage }
}

/**
 * 给一次审查加超时。到点就 abort，让底层请求也停下来。
 *
 * 为什么不用 `Promise.race`：race 只是不再等，底层请求还在跑、还在烧 token。
 * abort 才是真的停。
 *
 * @param {number} ms - 超时毫秒。
 * @param {AbortSignal} outer - 外层信号（用户取消 / 插件卸载）。
 * @returns {{ signal: AbortSignal, timedOut: () => boolean, dispose: () => void }}
 */
function withTimeout(ms, outer) {
  const controller = new AbortController()
  let timedOut = false
  const onOuterAbort = () => controller.abort()
  outer.addEventListener('abort', onOuterAbort, { once: true })
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, ms)
  return {
    signal: controller.signal,
    timedOut: () => timedOut,
    dispose: () => {
      clearTimeout(timer)
      outer.removeEventListener('abort', onOuterAbort)
    },
  }
}

// ---------------------------------------------------------------------------
// 插件入口
// ---------------------------------------------------------------------------

/**
 * Cordis 插件入口。
 * @param {import('@deepseek-ai/cordis').Context} ctx - 已注入三个服务的上下文。
 * @param {unknown} rawConfig - loader 行上的 config。
 */
export function apply(ctx, rawConfig) {
  const config = normalizeConfig(rawConfig)

  const log = (message) => {
    if (!config.debug) return
    try {
      if (typeof ctx.logger?.info === 'function') {
        ctx.logger.info(`[dsh-auto-approve] ${message}`)
        return
      }
    } catch { /* 日志不可用就退到 console */ }
    console.log(`[dsh-auto-approve] ${message}`)
  }

  /** 告警：不受 debug 影响，永远出声，但同一条只报一次。 */
  const warned = new Set()
  const warn = (message) => {
    if (warned.has(message)) return
    warned.add(message)
    try {
      if (typeof ctx.logger?.warn === 'function') {
        ctx.logger.warn(`[dsh-auto-approve] ${message}`)
        return
      }
    } catch { /* 同上 */ }
    console.warn(`[dsh-auto-approve] ${message}`)
  }

  /** 诊断：宿主控制台看不到插件输出，落盘是唯一可靠的观测手段。 */
  const status = {
    plugin: name,
    revision: REVISION,
    pluginDir: PLUGIN_DIR,
    appliedAt: new Date().toISOString(),
    enabled: config.enabled,
    preset: config.preset,
    provider: config.provider,
    configuredModel: config.model,
    reasoningEffort: config.reasoningEffort,
    onReviewFailure: config.onReviewFailure,
    resolvedModel: null,
    resolvedModelSource: null,
    reviews: 0,
    allowed: 0,
    denied: 0,
    failed: 0,
    timedOut: 0,
    skippedOtherPreset: 0,
    skippedTool: 0,
    deterministicAllowed: 0,
    deterministicDenied: 0,
    cacheHits: 0,
    cacheEntries: 0,
    cacheAllowEntries: 0,
    cacheDenyEntries: 0,
    cachePath: null,
    // 审查耗时累计 —— 只有 lastReviewMs 时，平均值只能靠猜。
    reviewMsTotal: 0,
    reviewMsMax: 0,
    // 按会话分桶。全局计数在多个窗口同时跑的时候会互相污染
    // （实测出现过"单会话预设没变过，却有了 skippedOtherPreset: 1"）。
    perSession: {},
    // 审查自身的 token 消耗 —— 这是把"审查花多少钱"从估算变成实测的唯一途径。
    reviewInputTokens: 0,
    reviewOutputTokens: 0,
    reviewCacheReadTokens: 0,
    reviewReasoningTokens: 0,
    lastReviewReasoningTokens: null,
    lastReviewInputTokens: null,
    lastReviewOutputTokens: null,
    lastReviewCacheReadTokens: null,
    lastRisk: null,
    lastDecision: null,
    lastReason: null,
    lastTool: null,
    lastReviewMs: null,
    lastEventAt: null,
    warnings: [],
    updatedAt: null,
  }
  const flush = () => {
    try {
      status.warnings = [...warned].slice(-20)
      status.updatedAt = new Date().toISOString()
      writeFileSync(STATUS_FILE, `${JSON.stringify(status, null, 2)}\n`, 'utf8')
      flushedAt = Date.now()
    } catch { /* 诊断写不进去不能影响审查 */ }
  }

  /**
   * 节流刷新。
   *
   * 为什么跳过路径也要落盘：`skippedOtherPreset` 不写出去的话，.status.json 会一直显示 0，
   * 读的人会以为"闸门根本没跑过"从而查错方向（这是实测暴露出来的问题）。
   * 但每个工具调用都写一次文件又太吵，所以节流。
   */
  let flushedAt = 0
  const flushThrottled = () => {
    if (Date.now() - flushedAt < FLUSH_THROTTLE_MS) return
    flush()
  }

  /**
   * 按会话分桶。
   *
   * 为什么需要：`.status.json` 是**进程全局**的，多个窗口同时跑时会互相污染 ——
   * 实测出现过"单会话、预设一次没变过，却有了 skippedOtherPreset: 1"，
   * 因为另一个窗口的调用被算进了同一份计数。分桶之后每个会话的轨迹才可解释。
   *
   * @param {object} session - `agent.session`。
   * @returns {object} 该会话的计数桶。
   */
  const bucket = (session) => {
    const id = session === undefined || session === null || session.id === undefined
      ? 'unknown'
      : String(session.id)
    let entry = status.perSession[id]
    if (entry === undefined) {
      entry = {
        reviews: 0, allowed: 0, denied: 0, noCwd: 0, deterministicAllowed: 0, deterministicDenied: 0, cacheHits: 0,
        skippedTool: 0, skippedOtherPreset: 0, failed: 0, timedOut: 0,
        reviewMsTotal: 0, reviewMsMax: 0, lastTool: null, lastEventAt: null,
      }
      status.perSession[id] = entry
      pruneBuckets()
    }
    return entry
  }

  /** 只保留最近若干个会话的桶，避免 `.status.json` 无限膨胀。 */
  const pruneBuckets = () => {
    const ids = Object.keys(status.perSession)
    if (ids.length <= PER_SESSION_KEEP) return
    ids.sort((a, b) => String(status.perSession[a]?.lastEventAt ?? '').localeCompare(String(status.perSession[b]?.lastEventAt ?? '')))
    for (const id of ids.slice(0, ids.length - PER_SESSION_KEEP)) delete status.perSession[id]
  }

  /**
   * 同时累加全局计数和该会话的桶。
   * @param {object} session - `agent.session`。
   * @param {string} key - 计数字段名。
   * @param {number} [by] - 增量。
   */
  const count = (session, key, by = 1) => {
    if (typeof status[key] === 'number') status[key] += by
    const entry = bucket(session)
    if (typeof entry[key] === 'number') entry[key] += by
  }

  /**
   * 记一次工具事件（最近工具 + 时间戳），全局和桶同步。
   * @param {object} session - `agent.session`。
   * @param {string} toolName - 工具名。
   */
  const touch = (session, toolName) => {
    const at = new Date().toISOString()
    status.lastTool = toolName
    status.lastEventAt = at
    const entry = bucket(session)
    entry.lastTool = toolName
    entry.lastEventAt = at
  }

  /**
   * 记一次审查耗时：累计、峰值、以及该会话的桶。
   * 没有这三个数，"平均延迟"只能靠时间戳反推 —— 那是猜，不是测。
   * @param {object} session - `agent.session`。
   * @param {number} ms - 本次耗时。
   */
  const recordReviewMs = (session, ms) => {
    status.lastReviewMs = ms
    status.reviewMsTotal += ms
    if (ms > status.reviewMsMax) status.reviewMsMax = ms
    const entry = bucket(session)
    entry.reviewMsTotal += ms
    if (ms > entry.reviewMsMax) entry.reviewMsMax = ms
  }

  if (!config.enabled) {
    status.enabled = false
    flush()
    log('config.enabled=false，不注册审查闸门')
    return
  }

  if (config.onReviewFailure === 'allow') {
    warn('onReviewFailure=allow：审查失败时工具将**直接执行**，这等于关掉了 fail-closed 保护')
  }

  /** 模型解析缓存；provider 拓扑变化时失效。 */
  let modelCache
  let callCache
  let createdCache
  let saidCache
  const lifecycle = new AbortController()

  // ── 判定缓存（跨会话、落盘）──────────────────────────────────────────
  // 目录默认是 `<DSH_HOME>/auto-approve`，不存在时由 saveCache 自动创建。
  const cacheDirPath = config.cacheEnabled ? resolveCacheDir(config.cacheDir) : undefined
  const cacheFilePath = cacheDirPath === undefined ? undefined : cacheFile(cacheDirPath)
  const decisionCache = cacheFilePath === undefined
    ? { version: 1, entries: {} }
    : loadCache(cacheFilePath)
  status.cachePath = cacheFilePath ?? null
  // ⚠️ 缓存文件是**整份** JSON 重写的。20000 条约 9–12 MB —— 磁盘放得下，
  // 但每审一次就写 11 MB 会直接拖慢审查路径。所以落盘节流 2 秒，
  // 卸载时再补一次最终保存。
  /**
   * 缓存条数统计：allow / deny 分开数。
   * 合成一个总数就看不出两类的实际使用情况 —— 而它们的 TTL 和寿命差了一个数量级。
   */
  const cacheStats = () => {
    let allow = 0
    let deny = 0
    for (const entry of Object.values(decisionCache.entries)) {
      if (entry?.decision === 'deny') deny += 1
      else allow += 1
    }
    status.cacheEntries = allow + deny
    status.cacheAllowEntries = allow
    status.cacheDenyEntries = deny
  }

  let lastCacheSave = 0
  const saveCacheThrottled = () => {
    const now = Date.now()
    if (now - lastCacheSave < 2000) return
    lastCacheSave = now
    saveCache(cacheFilePath, decisionCache)
  }
  cacheStats()

  ctx.effect(
    () => ctx.on('llm/adapters-updated', () => {
      modelCache = undefined
      status.resolvedModel = null
      status.resolvedModelSource = null
    }),
    'dsh-auto-approve: model cache',
  )

  /**
   * 主闸门。**prepend** 让它在其它监听器之前跑：
   * 我们要在任何人有机会修改决定之前就拿到待审调用。
   */
  ctx.effect(
    () => ctx.on('tools/pre-execute', async (exec, next) => {
      const agent = exec?.agent
      if (agent === undefined || agent === null) return next()
      // 外层 run_code 只是 PTC 传输层，内层每次调用会各自过闸，这里跳过避免双重审查。
      if (exec.parent === undefined && exec.name === RUN_CODE) return next()

      let preset
      try {
        preset = ctx.permissionPresets.current(agent.session)
      } catch (error) {
        warn(`读当前权限模式失败，本次不审查：${error instanceof Error ? error.message : String(error)}`)
        return next()
      }
      if (preset !== config.preset) {
        count(agent.session, 'skippedOtherPreset')
        flushThrottled()
        return next()
      }
      if (config.skipTools.includes(exec.name)) {
        count(agent.session, 'skippedTool')
        flushThrottled()
        return next()
      }
      if (lifecycle.signal.aborted) return { kind: 'cancel' }

      const started = Date.now()
      const reviewSignal = AbortSignal.any([exec.signal, lifecycle.signal])

      // 工作目录既要喂确定性判定、也要喂审查、还要当缓存键的一部分 —— 先取一次。
      //
      // ⚠️ 用**独立的短超时**，两个理由都是踩过的坑：
      //   · 不能共用审查的守卫 —— 工作目录超时会连带 abort 审查信号，把整次审查作废；
      //   · 更不能**没有**超时 —— 工作区不可达时（断连的网盘、拔掉的移动硬盘）这里会
      //     一直悬着，工具调用跟着一起悬着，等于绕过 fail-closed。
      let cwd
      const cwdGuard = withTimeout(Math.min(5000, config.timeoutMs), reviewSignal)
      try {
        cwd = await ctx.workingDirectory.ensure(agent, cwdGuard.signal)
      } catch (error) {
        cwd = undefined
        warn(`取工作目录失败：${cwdGuard.timedOut() ? '超时' : error instanceof Error ? error.message : String(error)}`)
      } finally {
        cwdGuard.dispose()
      }

      // 没有工作目录就没有判据。**放行 = 在不知道边界在哪的情况下开闸**，做不到。
      // 宁可拒绝并让模型先确认工作目录，也不要在缺判据的情况下赌一把。
      if (cwd === undefined) {
        count(agent.session, 'denied')
        touch(agent.session, exec.name)
        status.lastDecision = 'no-cwd'
        status.lastReason = NO_CWD_REASON
        flush()
        return {
          kind: 'deny',
          reason: `工具调用 "${exec.name}" 未通过自动审批：${NO_CWD_REASON}。` +
            '该操作没有被执行。请先确认会话工作目录，或请用户切换到「完全权限」。',
          info: { name: DENIED_NAME, code: DENIED_CODE, reason: NO_CWD_REASON },
        }
      }

      // ── 第 1 层：确定性判定（不调模型）────────────────────────────────
      // 保护区一律拒；只读、新建、改本会话自己的文件一律放行。
      // 判不准（无结构化路径、改既有文件）才下沉给第 2 层。
      {
        createdCache = createdPaths(agent.session, createdCache, cwd)
        createdCache = { ...createdCache, startedAt: sessionStartedAt(agent.session) }
        saidCache = userSaid(agent.session, saidCache)
        const fixed = deterministicDecision(exec, cwd, config, createdCache, saidCache.text)
        if (fixed !== undefined) {
          if (fixed.outcome === 'allow') {
            count(agent.session, 'deterministicAllowed')
            touch(agent.session, exec.name)
            flushThrottled()
            log(`确定性放行 ${exec.name}（${fixed.why}），未调用模型`)
            return next()
          }
          count(agent.session, 'deterministicDenied')
          count(agent.session, 'denied')
          touch(agent.session, exec.name)
          status.lastRisk = 'high'
          status.lastDecision = 'deny'
          status.lastReason = fixed.why
          flush()
          log(`确定性拒绝 ${exec.name}（${fixed.why}）`)
          return {
            kind: 'deny',
            reason: `工具调用 "${exec.name}" 已被自动审批拒绝：${fixed.why}。该操作没有被执行。` +
              '请改用不触碰该区域的方式完成目标；如果确实必须，请向用户说明用途并请其手动切换到「完全权限」。',
            info: { name: DENIED_NAME, code: DENIED_CODE, reason: `命中保护区 · ${fixed.why}` },
          }
        }
      }


      // ── 判定缓存：同一个调用重复出现时复用上次结论 ──────────────────────
      // 键里带工作目录和**完整参数**（不是截断后的），所以不会把"看起来一样、
      // 其实不同"的调用混在一起。模型被拒后原样重试是最常见的模式，这里直接挡掉。
      const cacheK = config.cacheEnabled ? cacheKey(exec.name, cwd, exec.arguments, config.cacheIgnoreArgs) : undefined
      if (cacheK !== undefined) {
        const cached = lookupCache(decisionCache, cacheK, Date.now(), config.cacheAllowTtlMs, config.cacheDenyTtlMs)
        if (cached !== undefined) {
          // 防御性复核：缓存文件是外部可改的，不信任它 —— high + allow 一律降级成拒绝。
          const effective = cached.decision === 'allow' && cached.risk === 'high'
            ? { ...cached, decision: 'deny', reason: `${cached.reason}（缓存中的 high+allow 被本地规则降级）` }
            : cached
          count(agent.session, 'cacheHits')
          touch(agent.session, exec.name)
          status.lastRisk = effective.risk
          status.lastDecision = effective.decision
          status.lastReason = effective.reason
          if (effective.decision === 'allow') count(agent.session, 'allowed')
          else count(agent.session, 'denied')
          flushThrottled()
          log(`缓存命中 ${exec.name}（${effective.decision}，${effective.risk}）`)
          if (effective.decision === 'allow') return next()
          return {
            kind: 'deny',
            reason: denialMessage(exec.name, effective),
            info: {
              name: DENIED_NAME,
              code: DENIED_CODE,
              reason: `${RISK_LABEL[effective.risk] ?? effective.risk} · ${effective.reason}（同一调用此前已被拒绝，缓存结论）`,
            },
          }
        }
      }

      count(agent.session, 'reviews')
      touch(agent.session, exec.name)

      const guard = withTimeout(config.timeoutMs, reviewSignal)

      try {
        const resolved = await resolveModel(ctx, config, modelCache)
        modelCache = resolved.cache
        status.resolvedModel = resolved.model
        status.resolvedModelSource = resolved.source

        const notes = []
        // shell 命令的每个字符都可能是判据，保持长截断；文件名类工具只看路径，收紧。
        const shellTool = exec.name === 'pwsh' || exec.name === 'bash' || exec.name === 'shell'
        const argLimit = shellTool ? config.shellArgChars : config.pendingArgChars
        const pendingArguments = clipArguments(exec.arguments, argLimit, '待审调用的参数', notes)
        callCache = recentToolCalls(agent.session, config.historyCalls, config.historyArgChars, callCache)
        if (callCache.calls.length === 0 && config.historyCalls > 0) {
          notes.push('没有可用的历史工具调用（推导失败或本会话还没有调用过），无法判断对象是否本会话创建')
        }

        // 静态兜底只拦“内容访问动词 + 字面 A 区路径”；元数据/仅提及会走到这里，
        // 把扫描结果作为证据交给模型，别让模型在不知情的情况下放行。
        const shellCommand = commandTextOf(exec)
        if (shellCommand !== '') {
          const hits = shellZoneHits(shellCommand, cwd)
          const privacyHits = hits.filter((hit) => hit.zone === 'privacy')
          const systemHits = hits.filter((hit) => hit.zone === 'system')
          if (privacyHits.length > 0) {
            notes.push(`命令文本中出现 A 区路径：${privacyHits.slice(0, 3).map((hit) => hit.path).join('；')}。确定性层未拦（可能是元数据或仅提及），请重点判断是否读取其内容。`)
          }
          if (systemHits.length > 0) {
            notes.push(`命令文本中出现 B 区路径：${systemHits.slice(0, 3).map((hit) => hit.path).join('；')}。若该命令会写入或删除，请从严判断。`)
          }
        }

        // 用户侧指令带来源送审；工具 schema 让审查器看懂自定义工具的参数语义。
        // 两者都可能很长，截断处会留下"信息不全"的标记 —— 审查器据此判得更保守。
        const instructions = (saidCache.instructions ?? []).map((entry) => ({
          role: entry.role,
          text: clipArguments(entry.text, 500, `指令（${entry.role}）`, notes),
        }))
        const rawSchema = toolSchemaFor(agent.session, exec)
        let schema
        if (rawSchema === undefined) {
          notes.push('取不到工具 schema（请求头与工具历史里没有唯一匹配），本次只能按工具名与参数判断')
        } else {
          schema = {
            description: clipArguments(rawSchema.description, 600, '工具描述', notes),
            parameters: clipArguments(rawSchema.parameters, 2000, '工具参数 schema', notes),
          }
        }

        const userText = reviewUserText({
          instructions,
          schema,
          cwd,
          history: callCache.calls,
          pending: { name: exec.name, arguments: pendingArguments },
          truncations: notes,
        })

        const stream = ctx.llm.stream({
          provider: config.provider,
          model: resolved.model,
          reasoningEffort: config.reasoningEffort,
          temperature: 0,
          ...(config.maxTokens > 0 ? { maxTokens: config.maxTokens } : {}),
          system: REVIEW_POLICY,
          messages: [{ role: 'user', content: [{ type: 'text', text: userText }] }],
          signal: guard.signal,
        })

        const { text, usage } = await collectText(stream, guard.signal)
        // 计量：审查自己花了多少 token（费用分析的唯一实测来源）
        status.reviewInputTokens += usage.inputTokens
        status.reviewOutputTokens += usage.outputTokens
        status.reviewCacheReadTokens += usage.cacheReadTokens
        status.lastReviewInputTokens = usage.inputTokens
        status.lastReviewOutputTokens = usage.outputTokens
        status.lastReviewCacheReadTokens = usage.cacheReadTokens
        status.reviewReasoningTokens += usage.reasoningTokens
        status.lastReviewReasoningTokens = usage.reasoningTokens

        const decision = parseDecision(text)
        status.lastRisk = decision.risk
        status.lastDecision = decision.decision
        status.lastReason = decision.reason
        recordReviewMs(agent.session, Date.now() - started)

        // 只缓存**审查完成**的结论。审查失败/超时不缓存 —— 那是瞬时故障，不该被记住。
        if (cacheK !== undefined) {
          rememberCache(decisionCache, cacheK, decision, Date.now(), config.cacheAllowTtlMs, config.cacheDenyTtlMs, config.cacheAllowMax, config.cacheDenyMax)
          cacheStats()
          saveCacheThrottled()
        }

        if (decision.decision === 'allow') {
          count(agent.session, 'allowed')
          flush()
          log(`放行 ${exec.name}（${decision.risk}）`)
          return next()
        }

        count(agent.session, 'denied')
        flush()
        log(`拒绝 ${exec.name}（${decision.risk}）：${decision.reason}`)
        return {
          kind: 'deny',
          reason: denialMessage(exec.name, decision),
          info: {
            name: DENIED_NAME,
            code: DENIED_CODE,
            // 这一行是用户在卡片里"展开"后能看到的全部内容，所以写人话：风险等级 + 具体原因。
            reason: `${RISK_LABEL[decision.risk] ?? decision.risk} · ${decision.reason}`,
          },
        }
      } catch (error) {
        const timedOut = guard.timedOut()
        count(agent.session, timedOut ? 'timedOut' : 'failed')
        const message = error instanceof Error ? error.message : String(error)
        recordReviewMs(agent.session, Date.now() - started)
        status.lastDecision = timedOut ? 'timeout' : 'failure'
        status.lastReason = message
        flush()
        warn(`审查 ${exec.name} 失败：${message}`)

        if (lifecycle.signal.aborted || exec.signal.aborted) return { kind: 'cancel' }
        if (config.onReviewFailure === 'allow') return next()
        return {
          kind: 'deny',
          reason: `工具调用 "${exec.name}" 未通过自动审批：审查器${timedOut ? '超时' : '出错'}（${message}）。` +
            '该操作没有被执行。请改用更简单、更容易被验证的方式完成目标，或请用户切换到「完全权限」。',
          // 审查失败也用同一个 UI 识别标识：用户同样需要"展开看到底怎么了"，
          // 而 UI 只认这一个。区别写在 reason 里（审查器超时 / 出错），
          // 而且 .status.json 的 lastDecision 仍然区分 timeout 与 failure。
          info: { name: DENIED_NAME, code: DENIED_CODE, reason: `审查器${timedOut ? '超时' : '出错'} · ${message}` },
        }
      } finally {
        guard.dispose()
      }
    }, { prepend: true }),
    'dsh-auto-approve: tools/pre-execute',
  )

  // 卸载时中断所有在途审查：不留下还在烧 token 的请求。
  ctx.effect(() => () => {
    lifecycle.abort()
    // 卸载前把没来得及落盘的结论补上，别丢最后一次判断。
    if (cacheFilePath !== undefined) saveCache(cacheFilePath, decisionCache)
  }, 'dsh-auto-approve: lifecycle')

  flush()
  log(`已注册审查闸门：预设=${config.preset} provider=${config.provider} 模型=${config.model || '(自动选 flash)'}`)
}
