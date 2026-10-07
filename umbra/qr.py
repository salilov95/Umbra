"""A small QR code generator (byte mode, error correction M or L, versions 1-40).

Written by hand because the project has no third-party dependencies. It
follows the QR standard (ISO/IEC 18004) step by step:

  1. pick the smallest version (size) the text fits into;
  2. pack the text into data codewords and pad them;
  3. split into blocks and add Reed-Solomon error correction;
  4. draw the fixed patterns (finders, timing, alignment, format/version);
  5. lay the bits out in the zigzag order;
  6. try all 8 masks and keep the one with the lowest penalty.

make_qr(text) returns a list of rows, each a string of "1" (dark) and "0".
"""
from __future__ import annotations

# Index 0 is unused: versions start at 1. Tables are from the standard.
_ECC_PER_BLOCK = {
    "L": [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28,
          28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
    "M": [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
          26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
}
_NUM_BLOCKS = {
    "L": [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8,
          8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
    "M": [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
          17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
}
_FORMAT_BITS = {"L": 1, "M": 0}


def _raw_modules(ver: int) -> int:
    """Number of modules available for data + error correction bits."""
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        num_align = ver // 7 + 2
        result -= (25 * num_align - 10) * num_align - 55
        if ver >= 7:
            result -= 36
    return result


def _data_codewords(ver: int, ecl: str) -> int:
    return _raw_modules(ver) // 8 - _ECC_PER_BLOCK[ecl][ver] * _NUM_BLOCKS[ecl][ver]


# ---- Reed-Solomon over GF(2^8), polynomial 0x11D -------------------------
def _gf_mul(x: int, y: int) -> int:
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree: int) -> list[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 2)
    return result


def _rs_remainder(data: list[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def _encode_data(payload: bytes, ver: int, ecl: str) -> list[int]:
    """Text -> data codewords -> blocks with error correction -> interleaved."""
    capacity = _data_codewords(ver, ecl) * 8
    bits: list[int] = []

    def put(value: int, length: int) -> None:
        bits.extend((value >> i) & 1 for i in reversed(range(length)))

    put(0b0100, 4)                                   # mode: bytes
    put(len(payload), 8 if ver <= 9 else 16)         # how many bytes follow
    for b in payload:
        put(b, 8)
    put(0, min(4, capacity - len(bits)))             # terminator
    put(0, -len(bits) % 8)                           # up to a whole byte
    pad = 0xEC
    while len(bits) < capacity:                      # standard filler bytes
        put(pad, 8)
        pad ^= 0xEC ^ 0x11
    data = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]

    num_blocks = _NUM_BLOCKS[ecl][ver]
    ecc_len = _ECC_PER_BLOCK[ecl][ver]
    raw = _raw_modules(ver) // 8
    num_short = num_blocks - raw % num_blocks
    short_len = raw // num_blocks
    divisor = _rs_divisor(ecc_len)

    blocks, k = [], 0
    for i in range(num_blocks):
        size = short_len - ecc_len + (0 if i < num_short else 1)
        chunk = data[k:k + size]
        k += size
        ecc = _rs_remainder(chunk, divisor)
        if i < num_short:
            chunk = chunk + [0]                      # placeholder to align the columns
        blocks.append(chunk + ecc)

    result = []
    for i in range(len(blocks[0])):
        for j, block in enumerate(blocks):
            if i != short_len - ecc_len or j >= num_short:   # skip the placeholders
                result.append(block[i])
    return result


class _Matrix:
    def __init__(self, ver: int, ecl: str):
        self.ver, self.ecl = ver, ecl
        self.size = ver * 4 + 17
        self.dark = [[False] * self.size for _ in range(self.size)]
        self.fixed = [[False] * self.size for _ in range(self.size)]   # not data: do not mask

    def _set(self, x: int, y: int, dark: bool) -> None:
        self.dark[y][x] = dark
        self.fixed[y][x] = True

    def _alignment_positions(self) -> list[int]:
        if self.ver == 1:
            return []
        num = self.ver // 7 + 2
        step = 26 if self.ver == 32 else (self.ver * 4 + num * 2 + 1) // (num * 2 - 2) * 2
        result = [6]
        pos = self.size - 7
        for _ in range(num - 1):
            result.insert(1, pos)
            pos -= step
        return result

    def draw_fixed(self) -> None:
        size = self.size
        for i in range(size):                         # timing patterns
            self._set(6, i, i % 2 == 0)
            self._set(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):   # finders with separators
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < size and 0 <= y < size:
                        self._set(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        positions = self._alignment_positions()
        last = len(positions) - 1
        for i, cx in enumerate(positions):            # alignment patterns
            for j, cy in enumerate(positions):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue                          # those corners hold finders
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self._set(cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format(0)                           # reserve the cells; real mask comes later
        if self.ver >= 7:                             # version information
            rem = self.ver
            for _ in range(12):
                rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
            bits = self.ver << 12 | rem
            for i in range(18):
                bit = (bits >> i) & 1 == 1
                a, b = size - 11 + i % 3, i // 3
                self._set(a, b, bit)
                self._set(b, a, bit)

    def draw_format(self, mask: int) -> None:
        data = _FORMAT_BITS[self.ecl] << 3 | mask
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ ((rem >> 9) * 0x537)
        bits = (data << 10 | rem) ^ 0x5412
        bit = lambda i: (bits >> i) & 1 == 1          # noqa: E731
        size = self.size
        for i in range(6):
            self._set(8, i, bit(i))
        self._set(8, 7, bit(6))
        self._set(8, 8, bit(7))
        self._set(7, 8, bit(8))
        for i in range(9, 15):
            self._set(14 - i, 8, bit(i))
        for i in range(8):
            self._set(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self._set(8, size - 15 + i, bit(i))
        self._set(8, size - 8, True)                  # always dark

    def place(self, codewords: list[int]) -> None:
        """Zigzag from the bottom-right corner, two columns at a time."""
        size, i, total = self.size, 0, len(codewords) * 8
        right = size - 1
        while right >= 1:
            if right == 6:                            # skip the vertical timing column
                right = 5
            for vert in range(size):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = size - 1 - vert if upward else vert
                    if not self.fixed[y][x] and i < total:
                        self.dark[y][x] = (codewords[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    def apply_mask(self, mask: int) -> None:
        """XOR the data cells with a pattern (calling it twice undoes it)."""
        tests = (
            lambda x, y: (x + y) % 2 == 0, lambda x, y: y % 2 == 0,
            lambda x, y: x % 3 == 0, lambda x, y: (x + y) % 3 == 0,
            lambda x, y: (x // 3 + y // 2) % 2 == 0, lambda x, y: x * y % 2 + x * y % 3 == 0,
            lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
            lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
        )
        test = tests[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.fixed[y][x] and test(x, y):
                    self.dark[y][x] = not self.dark[y][x]

    def penalty(self) -> int:
        """How hard this picture is for a scanner (lower is better)."""
        size, rows = self.size, self.dark
        cols = [[rows[y][x] for y in range(size)] for x in range(size)]
        score = 0
        finder = [True, False, True, True, True, False, True]
        for line in rows + cols:
            run, prev = 0, None
            for cell in line:                          # long runs of one colour
                if cell == prev:
                    run += 1
                    if run == 5:
                        score += 3
                    elif run > 5:
                        score += 1
                else:
                    run, prev = 1, cell
            for i in range(size - 6):                  # things that look like a finder
                if line[i:i + 7] == finder:
                    before = line[max(0, i - 4):i]
                    after = line[i + 7:i + 11]
                    if (len(before) == 4 and not any(before)) or (len(after) == 4 and not any(after)):
                        score += 40
        for y in range(size - 1):                      # 2x2 blocks of one colour
            for x in range(size - 1):
                c = rows[y][x]
                if c == rows[y][x + 1] == rows[y + 1][x] == rows[y + 1][x + 1]:
                    score += 3
        dark = sum(cell for row in rows for cell in row)
        total = size * size                            # balance of dark and light
        score += (abs(dark * 20 - total * 10) + total - 1) // total * 10 - 10 if dark * 2 != total else 0
        return max(score, 0)


def make_qr(text: str) -> list[str]:
    """Rows of '1'/'0' for the given text. Raises ValueError if it is too long."""
    payload = text.encode("utf-8")
    for ecl in ("M", "L"):                             # prefer the sturdier level
        for ver in range(1, 41):
            header = 4 + (8 if ver <= 9 else 16)
            if header + len(payload) * 8 <= _data_codewords(ver, ecl) * 8:
                break
        else:
            continue
        break
    else:
        raise ValueError("текст слишком длинный для QR-кода")

    matrix = _Matrix(ver, ecl)
    matrix.draw_fixed()
    matrix.place(_encode_data(payload, ver, ecl))

    best_mask, best_score = 0, None
    for mask in range(8):
        matrix.apply_mask(mask)
        matrix.draw_format(mask)
        score = matrix.penalty()
        if best_score is None or score < best_score:
            best_mask, best_score = mask, score
        matrix.apply_mask(mask)                        # undo
    matrix.apply_mask(best_mask)
    matrix.draw_format(best_mask)
    return ["".join("1" if cell else "0" for cell in row) for row in matrix.dark]
