<script setup>
import { computed } from 'vue'

const props = defineProps({
  title: {
    type: String,
    required: true,
  },
  result: {
    type: Object,
    required: true,
  },
})

const risk = computed(() => {
  const meta = {
    safe: { label: '安全', className: 'safe' },
    low: { label: '低风险', className: 'low' },
    medium: { label: '中风险', className: 'medium' },
    high: { label: '高风险', className: 'high' },
  }
  return meta[props.result.summary.risk_level] || meta.safe
})

const topFindings = computed(() => props.result.findings.slice(0, 12))
</script>

<template>
  <div class="report">
    <div class="report-head">
      <h2>{{ title }}</h2>
      <div class="risk-pill" :class="risk.className">{{ risk.label }} · {{ result.summary.score }}</div>
    </div>
    <div class="metrics">
      <div><strong>{{ result.summary.total_findings }}</strong><span>命中项</span></div>
      <div><strong>{{ Object.keys(result.summary.counts_by_type).length }}</strong><span>风险类型</span></div>
      <div><strong>{{ result.summary.counts_by_severity.critical || 0 }}</strong><span>严重项</span></div>
    </div>
    <slot name="content"></slot>
    <h3>命中明细</h3>
    <div v-if="topFindings.length" class="finding-list">
      <div v-for="(item, index) in topFindings" :key="index" class="finding">
        <div class="finding-meta">
          <span class="tag">{{ item.label }}</span>
          <span class="severity">{{ item.severity }}</span>
        </div>
        <div class="finding-change">
          <code>{{ item.evidence }}</code>
          <span class="arrow">=> {{ item.replacement || '已删除' }}</span>
        </div>
      </div>
    </div>
    <p v-else class="empty">未发现敏感信息。</p>
  </div>
</template>
