// Strict XML allowlist Content Disarm & Reconstruction (CDR) sanitizer for SVG outputs.
// Enforces XML security rules:
// - Rejects DTDs, <!ENTITY>, XInclude, <?xml-stylesheet?>, and CDATA blocks outright (prevents XXE / billion laughs).
// - Parses into a bounded AST in pure TypeScript (works identically in Cloudflare Workers, Node, and browser).
// - Drops disallowed elements AND their entire subtrees (<script>, <foreignObject>, <iframe>, <style>, <image>, <feImage>, <a>, SMIL <animate*>/<set>).
// - Decodes XML character/named entities BEFORE validating attributes so hex/decimal entity-encoded javascript:/data:/external URLs cannot bypass checks.
// - Re-serializes canonical XML with escaped attributes/text, xmlns="http://www.w3.org/2000/svg", and a numeric viewBox.
// TODO(security): Optional external AV scanner integration if enterprise compliance requires scanning beyond strict AST CDR reconstruction.


export class SvgSanitizeError extends Error {
  constructor(
    readonly code:
      | 'svg_empty'
      | 'svg_too_large'
      | 'svg_unsafe_xml'
      | 'svg_malformed_xml'
      | 'svg_too_deep'
      | 'svg_too_complex'
      | 'svg_invalid_root'
      | 'svg_no_vector_shapes',
    message: string,
  ) {
    super(message)
    this.name = 'SvgSanitizeError'
  }
}

const MAX_DEPTH = 32
const MAX_NODES = 10_000
const MAX_TEXT_LENGTH = 1_000

const GEOMETRY_TAGS = new Set([
  'path',
  'rect',
  'circle',
  'ellipse',
  'line',
  'polyline',
  'polygon',
  'text',
])

const TEXT_CONTENT_TAGS = new Set(['title', 'desc', 'text', 'tspan'])

const ALLOWED_TAGS = new Set([
  'svg',
  'g',
  'defs',
  'symbol',
  'title',
  'desc',
  'clipPath',
  'mask',
  'linearGradient',
  'radialGradient',
  'stop',
  'pattern',
  'filter',
  'feGaussianBlur',
  'feOffset',
  'feBlend',
  'feColorMatrix',
  'feComposite',
  'feFlood',
  'feMerge',
  'feMergeNode',
  'feDropShadow',
  'path',
  'rect',
  'circle',
  'ellipse',
  'line',
  'polyline',
  'polygon',
  'text',
  'tspan',
  'use',
])

const ALLOWED_ATTRS = new Set([
  'id',
  'viewBox',
  'width',
  'height',
  'preserveAspectRatio',
  'x',
  'y',
  'x1',
  'y1',
  'x2',
  'y2',
  'cx',
  'cy',
  'r',
  'rx',
  'ry',
  'fx',
  'fy',
  'fr',
  'dx',
  'dy',
  'd',
  'points',
  'pathLength',
  'fill',
  'fill-opacity',
  'fill-rule',
  'stroke',
  'stroke-width',
  'stroke-linecap',
  'stroke-linejoin',
  'stroke-dasharray',
  'stroke-dashoffset',
  'stroke-miterlimit',
  'stroke-opacity',
  'vector-effect',
  'paint-order',
  'opacity',
  'color',
  'display',
  'visibility',
  'overflow',
  'transform',
  'transform-origin',
  'gradientUnits',
  'gradientTransform',
  'spreadMethod',
  'offset',
  'stop-color',
  'stop-opacity',
  'clip-path',
  'clip-rule',
  'clipPathUnits',
  'mask',
  'maskUnits',
  'maskContentUnits',
  'patternUnits',
  'patternContentUnits',
  'patternTransform',
  'filter',
  'filterUnits',
  'primitiveUnits',
  'stdDeviation',
  'in',
  'in2',
  'result',
  'mode',
  'type',
  'values',
  'operator',
  'k1',
  'k2',
  'k3',
  'k4',
  'flood-color',
  'flood-opacity',
  'font-family',
  'font-size',
  'font-weight',
  'font-style',
  'text-anchor',
  'dominant-baseline',
  'alignment-baseline',
  'letter-spacing',
  'word-spacing',
  'xml:space',
  'href',
  'style',
])

const ALLOWED_STYLE_PROPS = new Set([
  'fill',
  'fill-opacity',
  'fill-rule',
  'stroke',
  'stroke-width',
  'stroke-linecap',
  'stroke-linejoin',
  'stroke-dasharray',
  'stroke-dashoffset',
  'stroke-miterlimit',
  'stroke-opacity',
  'vector-effect',
  'paint-order',
  'opacity',
  'color',
  'stop-color',
  'stop-opacity',
  'flood-color',
  'flood-opacity',
  'display',
  'visibility',
  'clip-path',
  'clip-rule',
  'mask',
  'filter',
  'transform',
  'font-family',
  'font-size',
  'font-weight',
  'font-style',
  'text-anchor',
  'dominant-baseline',
  'letter-spacing',
])

const URL_BEARING_ATTRS = new Set(['fill', 'stroke', 'clip-path', 'mask', 'filter'])
const LOCAL_FRAGMENT_RE = /^#[A-Za-z0-9_.:-]+$/
const LOCAL_URL_FUNC_RE = /^url\(\s*#[A-Za-z0-9_.:-]+\s*\)$/i
const SAFE_ID_RE = /^[A-Za-z0-9_.:-]+$/

interface SvgNode {
  tag: string
  attrs: Array<[string, string]>
  children: Array<SvgNode | string>
}

export interface SanitizeSvgResult {
  svg: string
  viewBox: string
  shapeCount: number
}

export function sanitizeSvg(raw: string, options: { maxBytes?: number } = {}): SanitizeSvgResult {
  if (typeof raw !== 'string') {
    throw new SvgSanitizeError('svg_empty', 'SVG input must be a string')
  }
  const maxBytes = options.maxBytes ?? 512 * 1024
  const trimmed = raw.replace(/^\uFEFF/, '').trim()
  if (!trimmed) {
    throw new SvgSanitizeError('svg_empty', 'SVG input is empty')
  }
  const byteLength = new TextEncoder().encode(trimmed).byteLength
  if (byteLength > maxBytes) {
    throw new SvgSanitizeError('svg_too_large', `SVG exceeds maximum size of ${maxBytes} bytes`)
  }

  // Hard reject DTD, ENTITY, CDATA, xml-stylesheet, and XInclude directives before parsing.
  if (/<!(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST|\[CDATA\[)/i.test(trimmed) || /<\?xml-stylesheet/i.test(trimmed) || /\bxi:include\b/i.test(trimmed)) {
    throw new SvgSanitizeError('svg_unsafe_xml', 'XML DTD, ENTITY, CDATA, XInclude, and stylesheet directives are forbidden')
  }

  const parsed = parseXmlRoot(trimmed)
  if (parsed.tag !== 'svg') {
    throw new SvgSanitizeError('svg_invalid_root', `Expected <svg> root, got <${parsed.tag}>`)
  }

  let shapeCount = 0
  const cleanRoot = cleanElement(parsed, true, () => {
    shapeCount += 1
  })
  if (!cleanRoot) {
    throw new SvgSanitizeError('svg_invalid_root', 'Root <svg> could not be sanitized')
  }
  if (shapeCount < 1) {
    throw new SvgSanitizeError('svg_no_vector_shapes', 'SVG contains no valid vector geometry')
  }

  const viewBox = ensureRootAttributes(cleanRoot)
  const svg = serializeNode(cleanRoot)
  if (new TextEncoder().encode(svg).byteLength > maxBytes) {
    throw new SvgSanitizeError('svg_too_large', `Sanitized SVG exceeds maximum size of ${maxBytes} bytes`)
  }
  return { svg, viewBox, shapeCount }
}

function cleanElement(node: SvgNode, isRoot: boolean, onGeometry: () => void): SvgNode | null {
  if (!ALLOWED_TAGS.has(node.tag)) return null
  if (!isRoot && node.tag === 'svg') return null

  const cleanAttrs: Array<[string, string]> = []
  const seen = new Set<string>()

  for (const [rawName, rawVal] of node.attrs) {
    const lower = rawName.toLowerCase()
    if (lower.startsWith('on') || lower === 'xmlns' || lower.startsWith('xmlns:')) continue

    const name = lower === 'xlink:href' ? 'href' : rawName
    if (!ALLOWED_ATTRS.has(name)) continue
    if (seen.has(name)) continue

    const decoded = decodeXmlEntities(rawVal).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim()
    const sanitized = sanitizeAttrValue(name, decoded)
    if (sanitized === null) continue

    seen.add(name)
    cleanAttrs.push([name, sanitized])
  }

  // <use> without a valid local #id href is useless and potentially dangerous; drop it.
  if (node.tag === 'use' && !cleanAttrs.some(([k]) => k === 'href')) {
    return null
  }

  if (GEOMETRY_TAGS.has(node.tag)) {
    onGeometry()
  }

  const cleanChildren: Array<SvgNode | string> = []
  const allowText = TEXT_CONTENT_TAGS.has(node.tag)

  for (const child of node.children) {
    if (typeof child === 'string') {
      if (!allowText) continue
      const text = decodeXmlEntities(child).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').slice(0, MAX_TEXT_LENGTH)
      if (text) cleanChildren.push(text)
    } else {
      const cleaned = cleanElement(child, false, onGeometry)
      if (cleaned) cleanChildren.push(cleaned)
    }
  }

  return { tag: node.tag, attrs: cleanAttrs, children: cleanChildren }
}

function sanitizeAttrValue(name: string, value: string): string | null {
  if (!value && name !== 'd') return null
  if (value.length > 65_536) return null

  if (name === 'id') {
    return SAFE_ID_RE.test(value) ? value : null
  }

  if (name === 'href') {
    return LOCAL_FRAGMENT_RE.test(value) ? value : null
  }

  if (name === 'style') {
    return sanitizeStyleValue(value)
  }

  // Block embedded schemes, CSS imports, legacy IE expressions, and external url(...) references.
  const compact = value.replace(/\s+/g, '').toLowerCase()
  if (
    compact.includes('javascript:') ||
    compact.includes('vbscript:') ||
    compact.includes('data:') ||
    compact.includes('@import') ||
    compact.includes('expression(') ||
    compact.includes('-moz-binding') ||
    compact.includes('behavior:')
  ) {
    return null
  }

  if (compact.includes('url(')) {
    if (!URL_BEARING_ATTRS.has(name)) return null
    return LOCAL_URL_FUNC_RE.test(value) ? value : null
  }

  // No attribute value outside href/style should contain http/https/protocol-relative URLs.
  if (/https?:|\/\//i.test(value)) return null

  return value
}

function sanitizeStyleValue(rawStyle: string): string | null {
  const safeDecls: string[] = []
  for (const part of rawStyle.split(';')) {
    const colon = part.indexOf(':')
    if (colon <= 0) continue
    const prop = part.slice(0, colon).trim().toLowerCase()
    const val = part.slice(colon + 1).trim()
    if (!ALLOWED_STYLE_PROPS.has(prop) || !val) continue
    // Strip !important before validating value
    const cleanVal = val.replace(/\s*!important\s*$/i, '').trim()
    const validated = sanitizeAttrValue(prop, cleanVal)
    if (validated !== null && !/[;{}<>\\]/.test(validated)) {
      safeDecls.push(`${prop}:${validated}`)
    }
  }
  return safeDecls.length > 0 ? safeDecls.join(';') : null
}

function ensureRootAttributes(root: SvgNode): string {
  const map = new Map(root.attrs)
  let viewBox = parseValidViewBox(map.get('viewBox'))
  if (!viewBox) {
    const w = parsePositiveDimension(map.get('width'))
    const h = parsePositiveDimension(map.get('height'))
    viewBox = w && h ? `0 0 ${w} ${h}` : '0 0 1024 1024'
  }
  map.set('viewBox', viewBox)

  const ordered: Array<[string, string]> = [
    ['xmlns', 'http://www.w3.org/2000/svg'],
    ['viewBox', viewBox],
  ]
  for (const [k, v] of map) {
    if (k === 'xmlns' || k === 'viewBox') continue
    ordered.push([k, v])
  }
  root.attrs = ordered
  return viewBox
}

function parseValidViewBox(value: string | undefined): string | null {
  if (!value) return null
  const parts = value
    .trim()
    .split(/[\s,]+/)
    .map(Number)
  if (parts.length !== 4 || parts.some((n) => !Number.isFinite(n))) return null
  if (parts[2]! <= 0 || parts[3]! <= 0) return null
  return parts.join(' ')
}

function parsePositiveDimension(value: string | undefined): number | null {
  if (!value) return null
  const match = /^(\d+(?:\.\d+)?)(?:px)?$/i.exec(value.trim())
  if (!match) return null
  const num = Number(match[1])
  return Number.isFinite(num) && num > 0 ? num : null
}

function serializeNode(node: SvgNode): string {
  const attrs = node.attrs.map(([k, v]) => ` ${k}="${escapeXmlAttr(v)}"`).join('')
  if (node.children.length === 0) {
    return `<${node.tag}${attrs}/>`
  }
  const inner = node.children.map((child) => (typeof child === 'string' ? escapeXmlText(child) : serializeNode(child))).join('')
  return `<${node.tag}${attrs}>${inner}</${node.tag}>`
}

function escapeXmlAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function escapeXmlText(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
}

function decodeXmlEntities(input: string): string {
  return input.replace(/&(?:#(\d+)|#x([0-9a-fA-F]+)|([a-zA-Z]+));/g, (full, dec: string | undefined, hex: string | undefined, named: string | undefined) => {
    if (dec !== undefined) {
      const code = Number.parseInt(dec, 10)
      return isValidCodePoint(code) ? String.fromCodePoint(code) : full
    }
    if (hex !== undefined) {
      const code = Number.parseInt(hex, 16)
      return isValidCodePoint(code) ? String.fromCodePoint(code) : full
    }
    if (named !== undefined && named in NAMED_ENTITIES) {
      return NAMED_ENTITIES[named]!
    }
    return full
  })
}

function isValidCodePoint(code: number): boolean {
  return Number.isInteger(code) && code >= 0x09 && code <= 0x10ffff && (code < 0xd800 || code > 0xdfff)
}

// ---------- Deterministic Recursive-Descent XML Parser ----------

function parseXmlRoot(source: string): SvgNode {
  let pos = 0
  let nodeCount = 0
  const len = source.length

  const isSpace = (ch: string) => ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r'
  const isNameStart = (ch: string) => /[A-Za-z_:]/.test(ch)
  const isNameChar = (ch: string) => /[A-Za-z0-9_.:-]/.test(ch)

  function skipSpaceAndComments(allowXmlDecl: boolean) {
    while (pos < len) {
      while (pos < len && isSpace(source[pos]!)) pos += 1
      if (source.startsWith('<!--', pos)) {
        const end = source.indexOf('-->', pos + 4)
        if (end < 0) throw new SvgSanitizeError('svg_malformed_xml', 'Unclosed XML comment')
        pos = end + 3
        continue
      }
      if (allowXmlDecl && source.startsWith('<?xml', pos) && (pos + 5 < len && isSpace(source[pos + 5]!))) {
        const end = source.indexOf('?>', pos + 5)
        if (end < 0) throw new SvgSanitizeError('svg_malformed_xml', 'Unclosed XML declaration')
        pos = end + 2
        allowXmlDecl = false
        continue
      }
      if (source.startsWith('<?', pos)) {
        throw new SvgSanitizeError('svg_unsafe_xml', 'XML processing instructions are not allowed')
      }
      if (source.startsWith('<!', pos)) {
        throw new SvgSanitizeError('svg_unsafe_xml', 'XML declarations/DTDs are not allowed')
      }
      break
    }
  }

  function readName(): string {
    if (pos >= len || !isNameStart(source[pos]!)) {
      throw new SvgSanitizeError('svg_malformed_xml', `Invalid XML name at offset ${pos}`)
    }
    const start = pos
    pos += 1
    while (pos < len && isNameChar(source[pos]!)) pos += 1
    return source.slice(start, pos)
  }

  function parseElement(depth: number): SvgNode {
    if (depth > MAX_DEPTH) throw new SvgSanitizeError('svg_too_deep', 'SVG nesting exceeds maximum depth')
    nodeCount += 1
    if (nodeCount > MAX_NODES) throw new SvgSanitizeError('svg_too_complex', 'SVG element count exceeds maximum limit')

    if (source[pos] !== '<') throw new SvgSanitizeError('svg_malformed_xml', `Expected '<' at offset ${pos}`)
    pos += 1
    const tag = readName()
    const attrs: Array<[string, string]> = []

    for (;;) {
      while (pos < len && isSpace(source[pos]!)) pos += 1
      if (pos >= len) throw new SvgSanitizeError('svg_malformed_xml', `Unexpected EOF inside <${tag}>`)
      if (source.startsWith('/>', pos)) {
        pos += 2
        return { tag, attrs, children: [] }
      }
      if (source[pos] === '>') {
        pos += 1
        break
      }
      const attrName = readName()
      while (pos < len && isSpace(source[pos]!)) pos += 1
      if (source[pos] !== '=') {
        throw new SvgSanitizeError('svg_malformed_xml', `Missing '=' for attribute ${attrName} on <${tag}>`)
      }
      pos += 1
      while (pos < len && isSpace(source[pos]!)) pos += 1
      const quote = source[pos]
      if (quote !== '"' && quote !== "'") {
        throw new SvgSanitizeError('svg_malformed_xml', `Unquoted attribute ${attrName} on <${tag}>`)
      }
      pos += 1
      const valStart = pos
      const valEnd = source.indexOf(quote, valStart)
      if (valEnd < 0) throw new SvgSanitizeError('svg_malformed_xml', `Unclosed attribute ${attrName} on <${tag}>`)
      const attrVal = source.slice(valStart, valEnd)
      if (attrVal.includes('<')) {
        throw new SvgSanitizeError('svg_malformed_xml', `Unescaped '<' in attribute ${attrName}`)
      }
      attrs.push([attrName, attrVal])
      pos = valEnd + 1
    }

    const children: Array<SvgNode | string> = []
    for (;;) {
      if (pos >= len) throw new SvgSanitizeError('svg_malformed_xml', `Unclosed <${tag}> element`)
      if (source.startsWith('<!--', pos)) {
        const end = source.indexOf('-->', pos + 4)
        if (end < 0) throw new SvgSanitizeError('svg_malformed_xml', 'Unclosed XML comment')
        pos = end + 3
        continue
      }
      if (source.startsWith('<?', pos) || source.startsWith('<!', pos)) {
        throw new SvgSanitizeError('svg_unsafe_xml', 'Embedded XML declarations or processing instructions are forbidden')
      }
      if (source.startsWith('</', pos)) {
        pos += 2
        const closingTag = readName()
        while (pos < len && isSpace(source[pos]!)) pos += 1
        if (closingTag !== tag || source[pos] !== '>') {
          throw new SvgSanitizeError('svg_malformed_xml', `Mismatched closing tag </${closingTag}> for <${tag}>`)
        }
        pos += 1
        return { tag, attrs, children }
      }
      if (source[pos] === '<') {
        children.push(parseElement(depth + 1))
        continue
      }
      const nextLt = source.indexOf('<', pos)
      if (nextLt < 0) throw new SvgSanitizeError('svg_malformed_xml', `Unclosed <${tag}> before EOF`)
      const text = source.slice(pos, nextLt)
      if (text) children.push(text)
      pos = nextLt
    }
  }

  skipSpaceAndComments(true)
  if (pos >= len || source[pos] !== '<') {
    throw new SvgSanitizeError('svg_invalid_root', 'Document does not start with an XML element')
  }
  const root = parseElement(1)
  skipSpaceAndComments(false)
  if (pos !== len) {
    throw new SvgSanitizeError('svg_malformed_xml', 'Unexpected trailing content after root </svg>')
  }
  return root
}
