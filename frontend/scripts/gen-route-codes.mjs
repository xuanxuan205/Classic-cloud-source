// IronWall v1.41.0: 路由码生成器。node scripts/gen-route-codes.mjs
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const here = path.dirname(fileURLToPath(import.meta.url))
const table = JSON.parse(readFileSync(path.join(here, 'route-table.json'), 'utf-8'))

function codeOf(logical) {
  return createHash('sha256').update(logical, 'utf8').digest('hex')
}
function constName(logical) {
  return 'R_' + logical
    .replace(/\{(\d+)\}/g, (_, n) => (n === '0' ? 'ID' : 'ID' + n))
    .replace(/[^0-9a-zA-Z]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .toUpperCase()
}

const out = []
out.push('// 本文件由 scripts/gen-route-codes.mjs 自动生成，请勿手改。')
out.push('// IronWall v1.41.0: 路由码常量——bundle 内不含任何真实接口路径名。')
out.push('// 生成命令：node scripts/gen-route-codes.mjs')
out.push('')
for (const r of table.routes) {
  out.push(`export const ${constName(r.logical)} = '/${codeOf(r.logical)}'`)
}
writeFileSync(path.join(here, '..', 'src', 'utils', 'routeCodes.ts'), out.join('\n') + '\n', 'utf8')
console.log('routeCodes.ts generated:', table.routes.length, 'entries')
