/** Unicode controls which can reorder, hide, or forge security-relevant display text. */
export function isUnsafeDisplayCodePoint(code: number): boolean {
  return code <= 0x1f ||
    (code >= 0x7f && code <= 0x9f) ||
    code === 0x061c ||
    (code >= 0x200b && code <= 0x200f) ||
    (code >= 0x2028 && code <= 0x202e) ||
    (code >= 0x2060 && code <= 0x206f) ||
    (code >= 0xd800 && code <= 0xdfff) ||
    code === 0xfeff;
}

export function containsUnsafeDisplayCharacters(value: string): boolean {
  for (const character of value) {
    if (isUnsafeDisplayCodePoint(character.codePointAt(0)!)) return true;
  }
  return false;
}

export function sanitizeBoundedDisplayText(value: string, maximumBytes: number, fallback: string): string {
  let output = '';
  let bytes = 0;
  for (const character of value) {
    const safe = isUnsafeDisplayCodePoint(character.codePointAt(0)!) ? '?' : character;
    const size = Buffer.byteLength(safe);
    if (bytes + size > maximumBytes) break;
    output += safe;
    bytes += size;
  }
  return output || fallback;
}
