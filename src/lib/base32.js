const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function decodeBase32(input) {
  const normalized = input
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/=+$/g, "");

  if (!normalized || /[^A-Z2-7]/.test(normalized)) {
    throw new Error("Secret must be a valid Base32 string.");
  }

  let bits = "";
  for (const character of normalized) {
    const value = BASE32_ALPHABET.indexOf(character);
    if (value === -1) {
      throw new Error("Secret contains invalid Base32 characters.");
    }

    bits += value.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }

  return new Uint8Array(bytes);
}
