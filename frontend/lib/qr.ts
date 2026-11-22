/**
 * Minimal QR encoder (byte mode) used to draw the hotspot's join code.
 *
 * The app installs with `bun install --frozen-lockfile`, so a runtime QR
 * dependency is not an option; this is a self-contained implementation.
 * Tables and control flow follow ISO/IEC 18004. The generated matrices were
 * verified module-for-module against an independent reference encoder for
 * every version (1-40), every error-correction level and all eight masks.
 */

// Error-correction codewords per block, indexed [ecl][version]; index 0 unused.
const ECC_CODEWORDS_PER_BLOCK: number[][] = [
  [
    -1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30,
    28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    30, 30, 30,
  ], // L
  [
    -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26,
    26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    28, 28, 28,
  ], // M
  [
    -1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28,
    26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    30, 30, 30,
  ], // Q
  [
    -1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28,
    26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30,
    30, 30, 30,
  ], // H
];

const NUM_ERROR_CORRECTION_BLOCKS: number[][] = [
  [
    -1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10,
    12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25,
  ], // L
  [
    -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17,
    17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
  ], // M
  [
    -1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23,
    23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68,
  ], // Q
  [
    -1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25,
    25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77,
    81,
  ], // H
];

/** Format-info bit pattern per error-correction level (L, M, Q, H). */
const ECC_FORMAT_BITS = [1, 0, 3, 2];

const PENALTY_N1 = 3;
const PENALTY_N2 = 3;
const PENALTY_N3 = 40;
const PENALTY_N4 = 10;

export type EccLevel = 0 | 1 | 2 | 3;

function numRawDataModules(ver: number): number {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) {
      result -= 36;
    }
  }
  return result;
}

function numDataCodewords(ver: number, ecl: EccLevel): number {
  return (
    Math.floor(numRawDataModules(ver) / 8) -
    ECC_CODEWORDS_PER_BLOCK[ecl][ver] * NUM_ERROR_CORRECTION_BLOCKS[ecl][ver]
  );
}

function alignmentPatternPositions(ver: number): number[] {
  if (ver === 1) {
    return [];
  }
  const numAlign = Math.floor(ver / 7) + 2;
  const step =
    ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
  const result = [6];
  let pos = ver * 4 + 17 - 7;
  while (result.length < numAlign) {
    result.splice(1, 0, pos);
    pos -= step;
  }
  return result;
}

// ------------------------------------------------------------- GF(256) ---

function gfMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i -= 1) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function reedSolomonDivisor(degree: number): number[] {
  const result = new Array<number>(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i += 1) {
    for (let j = 0; j < degree; j += 1) {
      result[j] = gfMultiply(result[j], root);
      if (j + 1 < degree) {
        result[j] ^= result[j + 1];
      }
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}

function reedSolomonRemainder(data: number[], divisor: number[]): number[] {
  const result = new Array<number>(divisor.length).fill(0);
  for (const b of data) {
    const factor = b ^ (result.shift() as number);
    result.push(0);
    for (let i = 0; i < divisor.length; i += 1) {
      result[i] ^= gfMultiply(divisor[i], factor);
    }
  }
  return result;
}

function getBit(x: number, i: number): boolean {
  return ((x >>> i) & 1) !== 0;
}

// -------------------------------------------------------------- symbol ---

export class QrCode {
  readonly version: number;
  readonly ecl: EccLevel;
  readonly size: number;
  readonly modules: boolean[][];
  readonly mask: number;

  private readonly isFunction: boolean[][];

  constructor(
    version: number,
    ecl: EccLevel,
    dataCodewords: number[],
    mask: number,
  ) {
    this.version = version;
    this.ecl = ecl;
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () =>
      new Array<boolean>(this.size).fill(false),
    );
    this.isFunction = Array.from({ length: this.size }, () =>
      new Array<boolean>(this.size).fill(false),
    );

    this.drawFunctionPatterns();
    this.drawCodewords(this.addEccAndInterleave(dataCodewords));

    if (mask === -1) {
      let minPenalty = Infinity;
      let best = 0;
      for (let i = 0; i < 8; i += 1) {
        this.applyMask(i);
        this.drawFormatBits(i);
        const penalty = this.getPenaltyScore();
        if (penalty < minPenalty) {
          minPenalty = penalty;
          best = i;
        }
        this.applyMask(i); // xor is its own inverse
      }
      mask = best;
    }
    this.mask = mask;
    this.applyMask(mask);
    this.drawFormatBits(mask);
  }

  private drawFunctionPatterns(): void {
    for (let i = 0; i < this.size; i += 1) {
      this.setFunctionModule(6, i, i % 2 === 0);
      this.setFunctionModule(i, 6, i % 2 === 0);
    }

    this.drawFinderPattern(3, 3);
    this.drawFinderPattern(this.size - 4, 3);
    this.drawFinderPattern(3, this.size - 4);

    const align = alignmentPatternPositions(this.version);
    const n = align.length;
    for (let i = 0; i < n; i += 1) {
      for (let j = 0; j < n; j += 1) {
        if (
          (i === 0 && j === 0) ||
          (i === 0 && j === n - 1) ||
          (i === n - 1 && j === 0)
        ) {
          continue;
        }
        this.drawAlignmentPattern(align[i], align[j]);
      }
    }

    this.drawFormatBits(0);
    this.drawVersion();
  }

  private drawFormatBits(mask: number): void {
    const data = (ECC_FORMAT_BITS[this.ecl] << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i += 1) {
      rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    }
    const bits = (((data << 10) | rem) ^ 0x5412) & 0x7fff;

    for (let i = 0; i <= 5; i += 1) {
      this.setFunctionModule(8, i, getBit(bits, i));
    }
    this.setFunctionModule(8, 7, getBit(bits, 6));
    this.setFunctionModule(8, 8, getBit(bits, 7));
    this.setFunctionModule(7, 8, getBit(bits, 8));
    for (let i = 9; i < 15; i += 1) {
      this.setFunctionModule(14 - i, 8, getBit(bits, i));
    }

    for (let i = 0; i < 8; i += 1) {
      this.setFunctionModule(this.size - 1 - i, 8, getBit(bits, i));
    }
    for (let i = 8; i < 15; i += 1) {
      this.setFunctionModule(8, this.size - 15 + i, getBit(bits, i));
    }
    this.setFunctionModule(8, this.size - 8, true);
  }

  private drawVersion(): void {
    if (this.version < 7) {
      return;
    }
    let rem = this.version;
    for (let i = 0; i < 12; i += 1) {
      rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    }
    const bits = (this.version << 12) | rem;

    for (let i = 0; i < 18; i += 1) {
      const color = getBit(bits, i);
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.setFunctionModule(a, b, color);
      this.setFunctionModule(b, a, color);
    }
  }

  private drawFinderPattern(x: number, y: number): void {
    for (let dy = -4; dy <= 4; dy += 1) {
      for (let dx = -4; dx <= 4; dx += 1) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const xx = x + dx;
        const yy = y + dy;
        if (xx >= 0 && xx < this.size && yy >= 0 && yy < this.size) {
          this.setFunctionModule(xx, yy, dist !== 2 && dist !== 4);
        }
      }
    }
  }

  private drawAlignmentPattern(x: number, y: number): void {
    for (let dy = -2; dy <= 2; dy += 1) {
      for (let dx = -2; dx <= 2; dx += 1) {
        this.setFunctionModule(
          x + dx,
          y + dy,
          Math.max(Math.abs(dx), Math.abs(dy)) !== 1,
        );
      }
    }
  }

  private setFunctionModule(x: number, y: number, isDark: boolean): void {
    this.modules[y][x] = isDark;
    this.isFunction[y][x] = true;
  }

  private addEccAndInterleave(data: number[]): number[] {
    const ver = this.version;
    const ecl = this.ecl;
    const numBlocks = NUM_ERROR_CORRECTION_BLOCKS[ecl][ver];
    const blockEccLen = ECC_CODEWORDS_PER_BLOCK[ecl][ver];
    const rawCodewords = Math.floor(numRawDataModules(ver) / 8);
    const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
    const shortBlockLen = Math.floor(rawCodewords / numBlocks);

    const blocks: number[][] = [];
    const rsDiv = reedSolomonDivisor(blockEccLen);
    let k = 0;
    for (let i = 0; i < numBlocks; i += 1) {
      const take = shortBlockLen - blockEccLen + (i < numShortBlocks ? 0 : 1);
      const dat = data.slice(k, k + take);
      k += take;
      const ecc = reedSolomonRemainder(dat, rsDiv);
      // Pad short blocks with a dummy byte so every block has the same length;
      // the interleave loop below skips exactly that position.
      if (i < numShortBlocks) {
        dat.push(0);
      }
      blocks.push(dat.concat(ecc));
    }

    const result: number[] = [];
    for (let i = 0; i < blocks[0].length; i += 1) {
      for (let j = 0; j < blocks.length; j += 1) {
        if (i !== shortBlockLen - blockEccLen || j >= numShortBlocks) {
          result.push(blocks[j][i]);
        }
      }
    }
    return result;
  }

  private drawCodewords(data: number[]): void {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) {
        right = 5;
      }
      for (let vert = 0; vert < this.size; vert += 1) {
        for (let j = 0; j < 2; j += 1) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < data.length * 8) {
            this.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
            i += 1;
          }
        }
      }
    }
  }

  private applyMask(mask: number): void {
    for (let y = 0; y < this.size; y += 1) {
      for (let x = 0; x < this.size; x += 1) {
        let invert: boolean;
        switch (mask) {
          case 0:
            invert = (x + y) % 2 === 0;
            break;
          case 1:
            invert = y % 2 === 0;
            break;
          case 2:
            invert = x % 3 === 0;
            break;
          case 3:
            invert = (x + y) % 3 === 0;
            break;
          case 4:
            invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
            break;
          case 5:
            invert = ((x * y) % 2) + ((x * y) % 3) === 0;
            break;
          case 6:
            invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
            break;
          case 7:
            invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
            break;
          default:
            throw new Error('bad mask');
        }
        if (!this.isFunction[y][x] && invert) {
          this.modules[y][x] = !this.modules[y][x];
        }
      }
    }
  }

  private getPenaltyScore(): number {
    let result = 0;
    const size = this.size;
    const mods = this.modules;

    for (let y = 0; y < size; y += 1) {
      let runColour = false;
      let runX = 0;
      const runHistory = new Array<number>(7).fill(0);
      for (let x = 0; x < size; x += 1) {
        if (mods[y][x] === runColour) {
          runX += 1;
          if (runX === 5) {
            result += PENALTY_N1;
          } else if (runX > 5) {
            result += 1;
          }
        } else {
          this.finderPenaltyAddHistory(runX, runHistory);
          if (!runColour) {
            result += this.finderPenaltyCountPatterns(runHistory) * PENALTY_N3;
          }
          runColour = mods[y][x];
          runX = 1;
        }
      }
      result +=
        this.finderPenaltyTerminateAndCount(runColour, runX, runHistory) *
        PENALTY_N3;
    }

    for (let x = 0; x < size; x += 1) {
      let runColour = false;
      let runY = 0;
      const runHistory = new Array<number>(7).fill(0);
      for (let y = 0; y < size; y += 1) {
        if (mods[y][x] === runColour) {
          runY += 1;
          if (runY === 5) {
            result += PENALTY_N1;
          } else if (runY > 5) {
            result += 1;
          }
        } else {
          this.finderPenaltyAddHistory(runY, runHistory);
          if (!runColour) {
            result += this.finderPenaltyCountPatterns(runHistory) * PENALTY_N3;
          }
          runColour = mods[y][x];
          runY = 1;
        }
      }
      result +=
        this.finderPenaltyTerminateAndCount(runColour, runY, runHistory) *
        PENALTY_N3;
    }

    for (let y = 0; y < size - 1; y += 1) {
      for (let x = 0; x < size - 1; x += 1) {
        const c = mods[y][x];
        if (
          c === mods[y][x + 1] &&
          c === mods[y + 1][x] &&
          c === mods[y + 1][x + 1]
        ) {
          result += PENALTY_N2;
        }
      }
    }

    let dark = 0;
    for (const row of mods) {
      for (const c of row) {
        if (c) {
          dark += 1;
        }
      }
    }
    const total = size * size;
    const k =
      Math.floor((Math.abs(dark * 20 - total * 10) + total - 1) / total) - 1;
    result += k * PENALTY_N4;
    return result;
  }

  private finderPenaltyCountPatterns(runHistory: number[]): number {
    const n = runHistory[1];
    const core =
      n > 0 &&
      runHistory[2] === n &&
      runHistory[3] === n * 3 &&
      runHistory[4] === n &&
      runHistory[5] === n;
    return (
      (core && runHistory[0] >= n * 4 && runHistory[6] >= n ? 1 : 0) +
      (core && runHistory[6] >= n * 4 && runHistory[0] >= n ? 1 : 0)
    );
  }

  private finderPenaltyTerminateAndCount(
    currentRunColour: boolean,
    currentRunLength: number,
    runHistory: number[],
  ): number {
    let runLength = currentRunLength;
    if (currentRunColour) {
      this.finderPenaltyAddHistory(runLength, runHistory);
      runLength = 0;
    }
    runLength += this.size;
    this.finderPenaltyAddHistory(runLength, runHistory);
    return this.finderPenaltyCountPatterns(runHistory);
  }

  private finderPenaltyAddHistory(
    currentRunLength: number,
    runHistory: number[],
  ): void {
    let runLength = currentRunLength;
    if (runHistory[0] === 0) {
      runLength += this.size;
    }
    runHistory.pop();
    runHistory.unshift(runLength);
  }
}

/** Encode `text` as UTF-8 in byte mode. `ecl` defaults to M. */
export function encodeText(text: string, ecl: EccLevel = 1): QrCode {
  const data = Array.from(new TextEncoder().encode(text));

  let version = 0;
  let ccBits = 0;
  for (let candidate = 1; candidate <= 40; candidate += 1) {
    const capacityBits = numDataCodewords(candidate, ecl) * 8;
    ccBits = candidate <= 9 ? 8 : 16;
    if (4 + ccBits + data.length * 8 <= capacityBits) {
      version = candidate;
      break;
    }
  }
  if (version === 0) {
    throw new Error('data too long for a QR symbol');
  }

  const bb: number[] = [];
  appendBits(bb, 0x4, 4);
  appendBits(bb, data.length, ccBits);
  for (const b of data) {
    appendBits(bb, b, 8);
  }

  const dataCapacityBits = numDataCodewords(version, ecl) * 8;
  appendBits(bb, 0, Math.min(4, dataCapacityBits - bb.length));
  appendBits(bb, 0, (8 - (bb.length % 8)) % 8);

  let pad = 0xec;
  while (bb.length < dataCapacityBits) {
    appendBits(bb, pad, 8);
    pad ^= 0xec ^ 0x11;
  }

  const codewords = new Array<number>(bb.length / 8).fill(0);
  bb.forEach((bit, i) => {
    codewords[i >>> 3] |= bit << (7 - (i & 7));
  });

  return new QrCode(version, ecl, codewords, -1);
}

function appendBits(bb: number[], val: number, length: number): void {
  for (let i = length - 1; i >= 0; i -= 1) {
    bb.push((val >>> i) & 1);
  }
}

/**
 * Build the `WIFI:` join string a phone camera understands.
 * `\`, `;`, `,`, `:` and `"` are escaped per the de-facto scheme.
 */
export function wifiPayload(ssid: string, passphrase: string): string {
  const escapeField = (value: string) => value.replace(/([\\;,:"])/g, '\\$1');
  // A value made entirely of hex digits is ambiguous here: a reader is entitled
  // to decode it as hex rather than as literal text, so an SSID like "ABCD1234"
  // could be joined under a different name. Quoting forces the literal reading.
  const literal = (value: string) => {
    const escaped = escapeField(value);
    return value.length > 0 && /^[0-9A-Fa-f]+$/.test(value)
      ? `"${escaped}"`
      : escaped;
  };
  const auth = passphrase.length > 0 ? 'WPA' : 'nopass';
  return `WIFI:T:${auth};S:${literal(ssid)};P:${literal(passphrase)};H:false;;`;
}
