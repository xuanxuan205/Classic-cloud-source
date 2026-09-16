// IronWall v1.3: 公告等富文本安全渲染
// 先转义全部 HTML，再把换行转为 <br>，保证任何存储内容都无法注入脚本
export function escapeHtml(input: string | null | undefined): string {
  if (input == null) return ''
  return String(input)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export function textToHtml(input: string | null | undefined): string {
  return escapeHtml(input).replace(/\n/g, '<br>')
}

// IronWall v1.45.2: 公告安全 Markdown 子集——先转义全部 HTML，再解析加粗/标题/列表。
// 任何原始 HTML 都无法注入，服务端 stripHtmlTags 仍保留（双保险）。
export function announcementToHtml(input: string | null | undefined): string {
  const escaped = escapeHtml(input).replace(/\\\*/g, '*')
  if (!escaped) return ''
  const lines = escaped.split(/\r?\n/)
  const out: string[] = []
  for (const line of lines) {
    let l = line.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    const heading = l.match(/^#{1,4}\s+(.*)$/)
    if (heading) {
      out.push('<span style="font-weight:700;font-size:1.06em;">' + heading[1] + '</span>')
      continue
    }
    const bullet = l.match(/^\s*[-*]\s+(.*)$/)
    if (bullet) {
      out.push('<span style="display:inline-block;margin-left:0.75em;">• ' + bullet[1] + '</span>')
      continue
    }
    const ordered = l.match(/^\s*\d+[.、]\s+(.*)$/)
    if (ordered) {
      out.push('<span style="display:inline-block;margin-left:0.75em;">' + ordered[1] + '</span>')
      continue
    }
    out.push(l || '&nbsp;')
  }
  return out.join('<br>')
}

// IronWall v1.47.9: 纯文本摘要——去掉 Markdown 标记与多余空白，用于列表/折叠行展示
export function stripMarkdown(input: string | null | undefined): string {
  if (!input) return ''
  return String(input)
    .replace(/\\\*/g, '*')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/^#{1,4}\s+/gm, '')
    .replace(/^\s*[-*]\s+/gm, '')
    .replace(/^\s*\d+[.、]\s+/gm, '')
    .replace(/\s+/g, ' ')
    .trim()
}
