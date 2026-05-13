<script setup>
import { computed, nextTick, ref } from 'vue'
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  Download,
  FileSearch,
  KeyRound,
  Loader2,
  LogOut,
  ShieldCheck,
  Upload,
} from 'lucide-vue-next'
import ResultBlock from './components/ResultBlock.vue'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8010'
const TOKEN_KEY = 'llm_guard_token'
const USERNAME_KEY = 'llm_guard_username'

const promptText = ref('')
const mode = ref('mask')
const promptResult = ref(null)
const fileResult = ref(null)
const resultsRef = ref(null)
const selectedFile = ref(null)
const promptLoading = ref(false)
const fileLoading = ref(false)
const errorMessage = ref('')
const loginUsername = ref('')
const loginPassword = ref('')
const loginLoading = ref(false)
const loginError = ref('')
const authToken = ref(localStorage.getItem(TOKEN_KEY) || '')
const currentUser = ref(localStorage.getItem(USERNAME_KEY) || '')

const modeLabel = computed(() => {
  if (mode.value === 'placeholder') return '占位符'
  if (mode.value === 'remove') return '删除'
  return '默认遮蔽'
})

const isAuthenticated = computed(() => Boolean(authToken.value))

async function login() {
  loginError.value = ''
  loginLoading.value = true
  try {
    const response = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: loginUsername.value,
        password: loginPassword.value,
      }),
    })
    if (!response.ok) throw new Error(await readError(response))
    const data = await response.json()
    authToken.value = data.access_token
    currentUser.value = data.username
    localStorage.setItem(TOKEN_KEY, data.access_token)
    localStorage.setItem(USERNAME_KEY, data.username)
    loginPassword.value = ''
  } catch (error) {
    loginError.value = error.message
  } finally {
    loginLoading.value = false
  }
}

function logout() {
  clearSession()
}

function clearSession() {
  authToken.value = ''
  currentUser.value = ''
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USERNAME_KEY)
  promptResult.value = null
  fileResult.value = null
}

function authHeaders(headers = {}) {
  return {
    ...headers,
    Authorization: `Bearer ${authToken.value}`,
  }
}

async function requireOk(response) {
  if (response.status === 401) {
    const message = await readError(response)
    clearSession()
    throw new Error(message)
  }
  if (!response.ok) throw new Error(await readError(response))
}

async function scanPrompt() {
  errorMessage.value = ''
  promptLoading.value = true
  try {
    const response = await fetch(`${API_BASE}/api/scan/prompt`, {
      method: 'POST',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ text: promptText.value, mode: mode.value }),
    })
    await requireOk(response)
    promptResult.value = await response.json()
    await revealResults()
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    promptLoading.value = false
  }
}

async function scanFile() {
  if (!selectedFile.value) {
    errorMessage.value = '请先选择要检测的文件'
    return
  }
  errorMessage.value = ''
  fileLoading.value = true
  const formData = new FormData()
  formData.append('file', selectedFile.value)
  formData.append('mode', mode.value)

  try {
    const response = await fetch(`${API_BASE}/api/scan/file`, {
      method: 'POST',
      headers: authHeaders(),
      body: formData,
    })
    await requireOk(response)
    fileResult.value = await response.json()
    await revealResults()
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    fileLoading.value = false
  }
}

async function readError(response) {
  try {
    const data = await response.json()
    return data.detail || '请求失败'
  } catch {
    return '请求失败'
  }
}

function chooseFile(event) {
  selectedFile.value = event.target.files?.[0] || null
  fileResult.value = null
}

function downloadUrl(fileId) {
  return `${API_BASE}/api/files/${encodeURIComponent(fileId)}`
}

async function downloadFile() {
  if (!fileResult.value) return
  errorMessage.value = ''
  try {
    const response = await fetch(downloadUrl(fileResult.value.file_id), {
      headers: authHeaders(),
    })
    await requireOk(response)
    const blob = await response.blob()
    const objectUrl = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = objectUrl
    link.download = fileResult.value.redacted_filename || 'redacted-file'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(objectUrl)
  } catch (error) {
    errorMessage.value = error.message
  }
}

function copyRedacted() {
  if (promptResult.value?.redacted_text) {
    navigator.clipboard.writeText(promptResult.value.redacted_text)
  }
}

async function revealResults() {
  await nextTick()
  resultsRef.value?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
</script>

<template>
  <main v-if="!isAuthenticated" class="shell auth-shell">
    <section class="auth-card">
      <p class="eyebrow">LLM-Guard</p>
      <h1>登录隐私脱敏工作台</h1>
      <p class="subtitle">请输入账号密码后继续使用提示词与文档检测服务。</p>
      <form class="login-form" @submit.prevent="login">
        <label>
          账号
          <input v-model="loginUsername" autocomplete="username" placeholder="请输入账号" />
        </label>
        <label>
          密码
          <input v-model="loginPassword" autocomplete="current-password" placeholder="请输入密码" type="password" />
        </label>
        <p v-if="loginError" class="error">{{ loginError }}</p>
        <button class="primary wide" :disabled="loginLoading">
          <Loader2 v-if="loginLoading" class="spin" :size="18" />
          <KeyRound v-else :size="18" />
          登录
        </button>
      </form>
    </section>
  </main>

  <main v-else class="shell">
    <section class="masthead">
      <div>
        <p class="eyebrow">LLM-Guard</p>
        <h1>提示词与文档隐私脱敏工作台</h1>
        <p class="subtitle">在发送给大模型之前，检测文本和附件中的敏感信息、密钥泄露与提示注入风险。</p>
      </div>
      <div class="masthead-side">
        <div class="user-chip">
          <span>{{ currentUser }}</span>
          <button class="icon-button" title="退出登录" @click="logout">
            <LogOut :size="17" />
          </button>
        </div>
        <div class="status-strip">
          <span>txt</span>
          <span>csv</span>
          <span>docx</span>
          <span>xlsx</span>
          <span>pdf</span>
          <span>pptx</span>
        </div>
      </div>
    </section>

    <section class="toolbar">
      <div class="mode-picker">
        <p>请选择如何处理敏感信息</p>
        <div class="segmented" aria-label="脱敏模式">
          <button :class="{ active: mode === 'mask' }" @click="mode = 'mask'">遮蔽</button>
          <button :class="{ active: mode === 'placeholder' }" @click="mode = 'placeholder'">占位符</button>
          <button :class="{ active: mode === 'remove' }" @click="mode = 'remove'">删除</button>
        </div>
      </div>
      <div class="mode-note">当前策略：{{ modeLabel }}</div>
    </section>

    <p v-if="errorMessage" class="error">{{ errorMessage }}</p>

    <section class="workspace">
      <div class="panel prompt-panel">
        <div class="panel-title">
          <ShieldCheck :size="20" />
          <h2>提示词检测</h2>
        </div>
        <textarea v-model="promptText" spellcheck="false" placeholder="请输入待检测文本" />
        <div class="actions">
          <button class="primary" :disabled="promptLoading" @click="scanPrompt">
            <Loader2 v-if="promptLoading" class="spin" :size="18" />
            <ClipboardCheck v-else :size="18" />
            检测提示词
          </button>
          <button class="ghost" :disabled="!promptResult" @click="copyRedacted">
            <ClipboardCheck :size="18" />
            复制脱敏结果
          </button>
          <span v-if="promptResult" class="inline-status" :class="promptResult.summary.risk_level">
            已检测：{{ promptResult.summary.total_findings }} 项，风险分 {{ promptResult.summary.score }}
          </span>
        </div>
      </div>

      <div class="panel file-panel">
        <div class="panel-title">
          <FileSearch :size="20" />
          <h2>文件检测</h2>
        </div>
        <label class="dropzone">
          <Upload :size="34" />
          <span>{{ selectedFile ? selectedFile.name : '选择 txt、csv、docx、xlsx、pdf 或 pptx 文件' }}</span>
          <input type="file" accept=".txt,.csv,.docx,.xlsx,.pdf,.pptx" @change="chooseFile" />
        </label>
        <button class="primary wide" :disabled="fileLoading || !selectedFile" @click="scanFile">
          <Loader2 v-if="fileLoading" class="spin" :size="18" />
          <FileSearch v-else :size="18" />
          检测并生成脱敏文件
        </button>
        <p v-if="fileResult" class="file-status">
          已生成脱敏文件，发现 {{ fileResult.summary.total_findings }} 项风险。
        </p>
      </div>
    </section>

    <section ref="resultsRef" class="results">
      <ResultBlock v-if="promptResult" title="提示词风险报告" :result="promptResult">
        <template #content>
          <h3>脱敏结果</h3>
          <pre>{{ promptResult.redacted_text }}</pre>
        </template>
      </ResultBlock>

      <ResultBlock v-if="fileResult" title="文件风险报告" :result="fileResult">
        <template #content>
          <div class="file-download">
            <span>{{ fileResult.redacted_filename }}</span>
            <button class="download-button" @click="downloadFile">
              <Download :size="18" />
              下载脱敏文件
            </button>
          </div>
          <h3>文本预览</h3>
          <pre class="file-preview">{{ fileResult.preview || '该文件未提取到可预览文本，或未发现需要替换的内容。' }}</pre>
        </template>
      </ResultBlock>
    </section>
  </main>
</template>
