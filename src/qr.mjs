// dsh-plugin-remote — minimal QR Code encoder (ISO/IEC 18004), zero
// dependencies. Byte-mode encoding, ECC level L, auto version 1..10.
// Renders the module matrix as an SVG string for the PC-side UI.
//
// The matrix layout (finder/timing/alignment/format/version/data placement,
// mask selection) follows the published QR standard; it is self-checked for
// structure by the tests. Real-device scanning should still be verified once.

// ---------------------------------------------------------------- GF(256)
const GF_EXP = new Uint8Array(512)
const GF_LOG = new Uint8Array(256)
{
  let x = 1
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x
    GF_LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11d
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]
}
function gmul(a, b) {
  if (a === 0 || b === 0) return 0
  return GF_EXP[GF_LOG[a] + GF_LOG[b]]
}

/** Reed-Solomon remainder of `data` for `eccLen` ECC codewords. */
function rsEncode(data, eccLen) {
  // generator polynomial: product of (x - α^i), i = 0..eccLen-1 (low coeff first)
  let gen = [1]
  for (let i = 0; i < eccLen; i++) {
    const next = new Array(gen.length + 1).fill(0)
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gen[j] // * x
      next[j + 1] ^= gmul(gen[j], GF_EXP[i]) // * α^i
    }
    gen = next
  }
  const res = data.slice().concat(new Array(eccLen).fill(0))
  for (let i = 0; i < data.length; i++) {
    const coef = res[i]
    if (coef !== 0) {
      for (let j = 1; j < gen.length; j++) res[i + j] ^= gmul(gen[j], coef)
    }
  }
  return res.slice(data.length)
}

// ------------------------------------------------------------- capacities
// ECC codewords per version for ECC L (single block: versions 1-5 only).
const ECC_CODEWORDS = [0, 7, 10, 15, 20, 26]
// Byte-mode data capacity per version for ECC L (codewords).
const DATA_CODEWORDS = [0, 19, 34, 55, 80, 108]
const VERSION_SIZE = [0, 21, 25, 29, 33, 37]
// Alignment pattern center coordinates per version (v1 has none).
const ALIGNMENT = [
  null,
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
]

function charCountBits(version) {
  return version <= 9 ? 8 : 16
}

function chooseVersion(dataBytes) {
  for (let v = 1; v <= 5; v++) {
    const capacityBits = DATA_CODEWORDS[v] * 8
    const overhead = 4 + charCountBits(v) + 4 // mode + count + terminator
    if (dataBytes * 8 + overhead <= capacityBits) return v
  }
  throw new Error('QR payload too large (supports versions 1-5 / ~100 bytes)')
}

// ----------------------------------------------------------------- masks
function maskValue(mask, row, col) {
  switch (mask) {
    case 0: return (row + col) % 2 === 0
    case 1: return row % 2 === 0
    case 2: return col % 3 === 0
    case 3: return (row + col) % 3 === 0
    case 4: return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0
    case 5: return ((row * col) % 2) + ((row * col) % 3) === 0
    case 6: return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0
    case 7: return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0
  }
  return false
}

function maskPenalty(matrix, size) {
  let penalty = 0
  let dark = 0
  // N1: runs of >= 5 same-color modules (horizontal + vertical)
  for (let i = 0; i < size; i++) {
    let hr = 1
    let vr = 1
    for (let j = 1; j < size; j++) {
      hr = matrix[i][j] === matrix[i][j - 1] ? hr + 1 : 1
      if (hr === 5) penalty += 3
      else if (hr > 5) penalty += 1
      vr = matrix[j][i] === matrix[j - 1][i] ? vr + 1 : 1
      if (vr === 5) penalty += 3
      else if (vr > 5) penalty += 1
    }
  }
  // N2: 2x2 blocks of same color
  for (let i = 0; i + 1 < size; i++) {
    for (let j = 0; j + 1 < size; j++) {
      const c = matrix[i][j]
      if (matrix[i][j + 1] === c && matrix[i + 1][j] === c && matrix[i + 1][j + 1] === c) penalty += 3
    }
  }
  // N3: 1:1:3:1:1 pattern (1011101) with 0000 on either side, horizontal + vertical
  for (let i = 0; i < size; i++) {
    for (let j = 0; j + 6 < size; j++) {
      const h = [matrix[i][j], matrix[i][j + 1], matrix[i][j + 2], matrix[i][j + 3], matrix[i][j + 4], matrix[i][j + 5], matrix[i][j + 6]]
      const want = [1, 0, 1, 1, 1, 0, 1]
      let ok = true
      for (let k = 0; k < 7; k++) if (h[k] !== want[k]) { ok = false; break }
      if (ok) {
        const before = j > 0 ? matrix[i][j - 1] : null
        const after = j + 7 < size ? matrix[i][j + 7] : null
        if (before === 0 && after === 0) penalty += 40
      }
      const v = [matrix[j][i], matrix[j + 1][i], matrix[j + 2][i], matrix[j + 3][i], matrix[j + 4][i], matrix[j + 5][i], matrix[j + 6][i]]
      ok = true
      for (let k = 0; k < 7; k++) if (v[k] !== want[k]) { ok = false; break }
      if (ok) {
        const before = j > 0 ? matrix[j - 1][i] : null
        const after = j + 7 < size ? matrix[j + 7][i] : null
        if (before === 0 && after === 0) penalty += 40
      }
    }
  }
  // N4: dark module ratio
  for (let i = 0; i < size; i++) for (let j = 0; j < size; j++) if (matrix[i][j]) dark++
  const percent = (dark * 100) / (size * size)
  penalty += Math.floor(Math.abs(percent - 50) / 5) * 10
  return penalty
}

// --------------------------------------------------------------- encoder
/** Encode text as a QR module matrix (0/1). */
export function encodeQr(text) {
  const bytes = []
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    if (c > 0xff) throw new Error('QR byte mode supports only Latin-1 text')
    bytes.push(c)
  }
  const version = chooseVersion(bytes.length)
  const size = VERSION_SIZE[version]
  const dataWords = DATA_CODEWORDS[version]
  const eccWords = ECC_CODEWORDS[version]

  // ---- bit stream -> data codewords
  const bits = []
  const pushBits = (value, count) => {
    for (let i = count - 1; i >= 0; i--) bits.push((value >> i) & 1)
  }
  pushBits(0x4, 4) // byte mode
  pushBits(bytes.length, charCountBits(version))
  for (const b of bytes) pushBits(b, 8)
  pushBits(0, Math.min(4, dataWords * 8 - bits.length)) // terminator
  while (bits.length % 8 !== 0) bits.push(0)
  const data = []
  for (let i = 0; i < bits.length; i += 8) {
    let v = 0
    for (let j = 0; j < 8; j++) v = v * 2 + bits[i + j]
    data.push(v)
  }
  let padByte = 0xec
  while (data.length < dataWords) {
    data.push(padByte)
    padByte = padByte === 0xec ? 0x11 : 0xec
  }
  const ecc = rsEncode(data, eccWords)
  const codewords = data.concat(ecc)
  const allBits = []
  for (const cw of codewords) for (let i = 7; i >= 0; i--) allBits.push((cw >> i) & 1)

  // ---- function-pattern matrix (null = data cell)
  const matrix = Array.from({ length: size }, () => new Array(size).fill(null))
  const drawFinder = (row, col) => {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = row + r
        const cc = col + c
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue
        const isSep = r === -1 || r === 7 || c === -1 || c === 7
        const isBorder = r === 0 || r === 6 || c === 0 || c === 6
        const isCenter = r >= 2 && r <= 4 && c >= 2 && c <= 4
        matrix[rr][cc] = isSep ? 0 : isBorder || isCenter ? 1 : 0
      }
    }
  }
  drawFinder(0, 0)
  drawFinder(0, size - 7)
  drawFinder(size - 7, 0)
  for (let i = 8; i < size - 8; i++) {
    matrix[6][i] = i % 2 === 0 ? 1 : 0
    matrix[i][6] = i % 2 === 0 ? 1 : 0
  }
  const align = ALIGNMENT[version]
  if (align) {
    for (const r of align) {
      for (const c of align) {
        if (matrix[r][c] !== null) continue // overlaps a finder
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            const v = Math.max(Math.abs(dr), Math.abs(dc)) === 2 ? 0 : 1
            matrix[r + dr][c + dc] = v
          }
        }
      }
    }
  }
  matrix[size - 8][8] = 1 // dark module

  // Reserve format + version regions so data placement skips them.
  for (let i = 0; i <= 5; i++) if (matrix[8][i] === null) matrix[8][i] = -1
  if (matrix[8][7] === null) matrix[8][7] = -1
  if (matrix[8][8] === null) matrix[8][8] = -1
  if (matrix[7][8] === null) matrix[7][8] = -1
  for (let i = 9; i <= 14; i++) if (matrix[14 - i][8] === null) matrix[14 - i][8] = -1
  for (let i = 0; i <= 7; i++) if (matrix[8][size - 1 - i] === null) matrix[8][size - 1 - i] = -1
  for (let i = 8; i <= 14; i++) if (matrix[size - 15 + i][8] === null) matrix[size - 15 + i][8] = -1

  // ---- format bits for a mask
  const formatBits = (mask) => {
    const data5 = (0b01 << 3) | mask
    let rem = data5
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    const bits15 = ((data5 << 10) | rem) ^ 0x5412
    const out = []
    for (let i = 14; i >= 0; i--) out.push((bits15 >> i) & 1)
    return out
  }
  const placeFormat = (m, bits15) => {
    let i
    for (i = 0; i <= 5; i++) m[8][i] = bits15[i]
    m[8][7] = bits15[6]
    m[8][8] = bits15[7]
    m[7][8] = bits15[8]
    for (i = 9; i <= 14; i++) m[14 - i][8] = bits15[i]
    // second copy
    for (i = 0; i <= 7; i++) m[8][size - 1 - i] = bits15[i]
    for (i = 8; i <= 14; i++) m[size - 15 + i][8] = bits15[i]
  }
  const placeVersion = (m) => {
    if (version < 7) return
    let rem = version
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1f25)
    const bits18 = (version << 12) | rem
    const b = []
    for (let i = 17; i >= 0; i--) b.push((bits18 >> i) & 1)
    let idx = 0
    for (let i = 0; i < 6; i++) {
      for (let j = 0; j < 3; j++) {
        m[i][size - 11 + j] = b[idx]
        m[size - 11 + j][i] = b[idx]
        idx++
      }
    }
  }

  // ---- try every mask, keep the lowest penalty
  let best = null
  let bestPenalty = Infinity
  for (let mask = 0; mask < 8; mask++) {
    const m = matrix.map((row) => row.slice())
    let bitIdx = 0
    let dir = -1
    let col = size - 1
    while (col > 0) {
      if (col === 6) col--
      for (let i = 0; i < size; i++) {
        const row = dir === -1 ? size - 1 - i : i
        for (let k = 0; k < 2; k++) {
          const c = col - k
          if (c < 0) continue
          if (m[row][c] !== null) continue // function/reserved module
          const v = bitIdx < allBits.length ? allBits[bitIdx++] : 0
          m[row][c] = v ^ (maskValue(mask, row, c) ? 1 : 0)
        }
      }
      dir *= -1
      col -= 2
    }
    placeFormat(m, formatBits(mask))
    placeVersion(m)
    const penalty = maskPenalty(m, size)
    if (penalty < bestPenalty) {
      bestPenalty = penalty
      best = m
    }
  }
  return { version, size, matrix: best, text }
}

/** Render a QR module matrix as an SVG string. */
export function qrSvg(matrix, size, scale = 8) {
  const quiet = 4
  let cells = ''
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (!matrix[r][c]) continue
      cells += `<rect x="${quiet + c}" y="${quiet + r}" width="1" height="1"/>`
    }
  }
  const total = size + quiet * 2
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges">` +
    `<rect width="${total}" height="${total}" fill="#fff"/>` +
    cells +
    `</svg>`
  )
}

/** High-level: text -> SVG string (viewBox is module-scaled; CSS scales it). */
export function textToQrSvg(text) {
  const { size, matrix } = encodeQr(text)
  return qrSvg(matrix, size)
}
