<script setup>
import { computed, nextTick, ref } from 'vue'
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  Download,
  FileSearch,
  Loader2,
  ShieldCheck,
  Upload,
} from 'lucide-vue-next'
import ResultBlock from './components/ResultBlock.vue'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8010'

const promptText = ref('')
const mode = ref('mask')
const promptResult = ref(null)
const fileResult = ref(null)
const resultsRef = ref(null)
const selectedFile = ref(null)
const promptLoading = ref(false)
const fileLoading = ref(false)
const errorMessage = ref('')

const modeLabel = computed(() => {
  if (mode.value === 'placeholder') return '占位符'
  if (mode.value === 'remove') return '删除'
  return '默认遮蔽'
})

async function scanPrompt() {
  errorMessage.value = ''
  promptLoading.value = true
  try {
    const response = await fetch(`${API_BASE}/api/scan/prompt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: promptText.value, mode: mode.value }),
    })
    if (!response.ok) throw new Error(await readError(response))
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
      body: formData,
    })
    if (!response.ok) throw new Error(await readError(response))
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
  <main class="shell">
    <section class="masthead">
      <div>
        <p class="eyebrow">LLM-Guard</p>
        <h1>提示词与文档隐私脱敏工作台</h1>
        <p class="subtitle">在发送给大模型之前，检测文本和附件中的敏感信息、密钥泄露与提示注入风险。</p>
      </div>
      <div class="status-strip">
        <span>txt</span>
        <span>csv</span>
        <span>docx</span>
        <span>xlsx</span>
        <span>pdf</span>
        <span>pptx</span>
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
            <a :href="downloadUrl(fileResult.file_id)">
              <Download :size="18" />
              下载脱敏文件
            </a>
          </div>
          <h3>文本预览</h3>
          <pre class="file-preview">{{ fileResult.preview || '该文件未提取到可预览文本，或未发现需要替换的内容。' }}</pre>
        </template>
      </ResultBlock>
    </section>
  </main>
</template>
