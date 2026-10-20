/**
 * dsh-auto-approve — 判定缓存（跨会话、落盘）。
 *
 * ── 为什么值得缓存 ──────────────────────────────────────────────────────
 * 模型被拒之后**经常原样重试**同一个调用。每次都完整跑一遍审查，等于为同一条
 * 结论反复付费。缓存命中后：省一次请求，而且"重试被拒"变成近乎零成本 ——
 * 反而让模型更快放弃。
 *
 * ── 为什么键里必须有 cwd ────────────────────────────────────────────────
 * 同一个相对路径在不同工作区里是完全不同的目标。`rm build/` 在 A 项目里可能是
 * 正常清理，在 B 项目里可能是删掉源码。所以键 = 工具名 + 工作目录 + **完整参数**。
 *
 * ── 为什么用完整参数而不是截断后的 ──────────────────────────────────────
 * 送审时会截断参数（`pendingArgChars`），两条超长的不同调用截断后可能一模一样。
 * 对 deny 结论无害（多拒一次），但对 **allow** 结论是实打实的放行错误。
 * 所以键用完整参数的哈希 —— 哈希是廉价的，放错是不廉价的。
 *
 * ── 边界 ────────────────────────────────────────────────────────────────
 * · 只缓存**审查完成**的结论。审查失败/超时不缓存 —— 那是瞬时故障，不该被记住。
 * · 有 TTL（默认 60 分钟）：结论只对"刚刚成立的事实"负责。
 * · 有容量上限（默认 20000 条），超了淘汰最早记录的。
 * · 文件写坏/读不出来时**静默降级为空缓存** —— 缓存是优化，不是依赖。
 *
 * @module dsh-auto-approve/cache
 */

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/** 缓存文件格式版本。格式不兼容时直接丢弃，不做迁移。 */
export const CACHE_VERSION = 1

/**
 * allow 结论的 TTL：60 分钟。
 * 放行要信任"当时的事实" —— 同样的命令，环境变了风险就变了。
 */
export const DEFAULT_ALLOW_TTL_MS = 60 * 60 * 1000

/**
 * deny 结论的 TTL：14 天。
 * 拒绝的陈旧风险几乎为零 —— 重新拒绝是安全的，最坏情况是模型多绕一次。
 * 而"这条命令被拒过"是缓存最值钱的部分：模型原样重试时应该几乎零成本。
 */
export const DEFAULT_DENY_TTL_MS = 14 * 24 * 60 * 60 * 1000

/** allow 条目的上限。 */
export const DEFAULT_ALLOW_MAX = 5000

/** deny 条目的上限。 */
export const DEFAULT_DENY_MAX = 5000

/**
 * 解析缓存目录。默认 `<DSH_HOME>/auto-approve`，`DSH_HOME` 缺失时退回 `~/.dsh`。
 * @param {string} [configured] - 配置里显式给的目录。
 * @returns {string} 绝对或用户目录相对的路径。
 */
export function resolveCacheDir(configured) {
  if (typeof configured === 'string' && configured.trim() !== '') return configured.trim()
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh')
  return join(home, 'auto-approve')
}

/**
 * 算一个调用的缓存键。
 *
 * 参数序列化不出来（循环引用、BigInt 等）时返回 `undefined` —— 调用方据此**不缓存**，
 * 宁可多审一次也不要猜。
 *
 * @param {string} name - 工具名。
 * @param {string} cwd - 会话工作目录。
 * @param {unknown} args - 调用的完整参数。
 * @param {string[]} [ignoreKeys] - 不参与哈希的参数名（纯展示字段）。
 * @returns {string|undefined} 64 位十六进制键。
 */
export function cacheKey(name, cwd, args, ignoreKeys = []) {
  let serialized
  try {
    serialized = JSON.stringify(withoutKeys(args, ignoreKeys))
  } catch {
    return undefined
  }
  if (typeof serialized !== 'string') return undefined
  const hash = createHash('sha256')
  hash.update(String(name))
  hash.update('\u0000')
  hash.update(String(cwd))
  hash.update('\u0000')
  hash.update(serialized)
  return hash.digest('hex')
}

/**
 * 去掉纯展示字段后再参与哈希。
 *
 * 为什么需要它（实测踩到）：`pwsh` 调用长这样 ——
 *   {"command":"node --version","description":"Run node version first time","workdir":"..."}
 *   {"command":"node --version","description":"Run node version second time","workdir":"..."}
 * `command` 和 `workdir` 一模一样，只有 `description` 这个**纯展示**字段换了说法。
 * 哈希完整参数时这就是两个不同的键 —— 缓存永远命中不了，等于白装。
 *
 * 所以按名字剔除展示字段。这**不降低安全性**：工具本来就不读 `description`，
 * 剔除它不可能让两个行为不同的调用撞成同一个键。
 *
 * @param {unknown} args - 原始参数。
 * @param {string[]} ignoreKeys - 要剔除的字段名。
 * @returns {unknown} 剔除后的参数（原始值不被修改）。
 */
function withoutKeys(args, ignoreKeys) {
  if (ignoreKeys.length === 0) return args
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return args
  const copy = { ...args }
  for (const key of ignoreKeys) delete copy[key]
  return copy
}

/**
 * 读缓存文件。文件不存在、内容坏掉、版本不符 —— 一律返回空缓存，不抛。
 * @param {string} file - 缓存文件路径。
 * @returns {{ version: number, entries: Record<string, object> }} 缓存对象。
 */
export function loadCache(file) {
  const empty = { version: CACHE_VERSION, entries: {} }
  try {
    if (!existsSync(file)) return empty
    const parsed = JSON.parse(readFileSync(file, 'utf8'))
    if (parsed?.version !== CACHE_VERSION) return empty
    if (parsed?.entries === null || typeof parsed.entries !== 'object') return empty
    return { version: CACHE_VERSION, entries: { ...parsed.entries } }
  } catch {
    return empty
  }
}

/**
 * 原子写缓存文件：先写 `.tmp` 再 rename。
 *
 * 为什么要原子：审查是并发跑的（多个工具调用可能同时在审）。直接覆写时进程被杀会
 * 留下半个 JSON；rename 在同一个卷上是原子的，最坏情况是丢掉最后一次更新，而不是
 * 把整个缓存读坏。
 *
 * @param {string} file - 目标路径。
 * @param {{ version: number, entries: Record<string, object> }} cache - 缓存对象。
 * @returns {boolean} 写成功为 true；失败静默返回 false（缓存不是依赖）。
 */
export function saveCache(file, cache) {
  try {
    mkdirSync(dirname(file), { recursive: true })
    const temporary = `${file}.tmp`
    writeFileSync(temporary, `${JSON.stringify(cache, null, 2)}\n`, 'utf8')
    renameSync(temporary, file)
    return true
  } catch {
    try { unlinkSync(`${file}.tmp`) } catch { /* 忽略 */ }
    return false
  }
}

/**
 * 查一条结论。命中且未过期才返回。
 * @param {object} cache - `loadCache` 的返回值。
 * @param {string} key - `cacheKey` 的结果。
 * @param {number} now - 当前毫秒时间戳。
 * @param {number} ttlMs - 有效期。
 * @returns {{ risk: string, decision: string, reason: string }|undefined} 结论或 undefined。
 */
export function lookupCache(cache, key, now, allowTtlMs, denyTtlMs) {
  const entry = cache?.entries?.[key]
  if (entry === undefined || entry === null) return undefined
  if (typeof entry.at !== 'number') return undefined
  // TTL 按条目自己的结论类型取 —— deny 记得久，allow 记得短。
  const ttlMs = entry.decision === 'deny' ? denyTtlMs : allowTtlMs
  if (now - entry.at > ttlMs) return undefined
  if (entry.decision !== 'allow' && entry.decision !== 'deny') return undefined
  return { risk: String(entry.risk ?? ''), decision: entry.decision, reason: String(entry.reason ?? '') }
}

/**
 * 记一条结论，并按 TTL / 容量修剪。
 * @param {object} cache - 缓存对象（原地修改）。
 * @param {string} key - 缓存键。
 * @param {{ risk: string, decision: string, reason: string }} decision - 已校验的结论。
 * @param {number} now - 当前毫秒时间戳。
 * @param {number} ttlMs - 有效期。
 * @param {number} maxEntries - 容量上限。
 * @returns {object} 同一个缓存对象。
 */
export function rememberCache(cache, key, decision, now, allowTtlMs, denyTtlMs, allowMax, denyMax) {
  cache.entries[key] = {
    risk: decision.risk,
    decision: decision.decision,
    reason: decision.reason,
    at: now,
  }
  return pruneCache(cache, now, allowTtlMs, denyTtlMs, allowMax, denyMax)
}

/**
 * 修剪：先丢过期项；还超限就丢掉最早记录的（FIFO，不是 LRU —— `at` 是判定时间，命中不回写）。
 * @param {object} cache - 缓存对象（原地修改）。
 * @param {number} now - 当前毫秒时间戳。
 * @param {number} ttlMs - 有效期。
 * @param {number} maxEntries - 容量上限。
 * @returns {object} 同一个缓存对象。
 */
export function pruneCache(cache, now, allowTtlMs, denyTtlMs, allowMax, denyMax) {
  const entries = cache.entries ?? {}
  const allows = []
  const denies = []
  for (const [key, entry] of Object.entries(entries)) {
    if (typeof entry?.at !== 'number') {
      delete entries[key]
      continue
    }
    const isDeny = entry.decision === 'deny'
    if (now - entry.at > (isDeny ? denyTtlMs : allowTtlMs)) {
      delete entries[key]
      continue
    }
    ;(isDeny ? denies : allows).push(key)
  }
  // 两类各自淘汰，互不挤占 —— 拒绝的记忆不该被大量的放行挤掉。
  const evict = (keys, max) => {
    if (keys.length <= max) return
    keys.sort((a, b) => (entries[a]?.at ?? 0) - (entries[b]?.at ?? 0))
    for (const key of keys.slice(0, keys.length - max)) delete entries[key]
  }
  evict(allows, allowMax)
  evict(denies, denyMax)
  cache.entries = entries
  return cache
}

/**
 * 缓存文件路径。
 * @param {string} dir - 缓存目录。
 * @returns {string} 缓存文件路径。
 */
export function cacheFile(dir) {
  return join(dir, 'decision-cache.json')
}
