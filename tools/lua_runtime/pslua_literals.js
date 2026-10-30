// pslua parses every numeric literal as a double; Fengari keeps integers and truncates
// 64-bit hex literals to 32 bits, so 0x100000000 becomes 0 (a literal 0, making a
// modulo by it yield NaN) and 0x80000000 becomes a negative integer. Rewrite the hex
// literals the payload uses so both sides see the same doubles pslua would produce.
// Comments and string literals are matched first so their text stays untouched.
const LITERALS = /--\[(=*)\[[\s\S]*?\]\1\]|--[^\r\n]*|"(?:\\[\s\S]|[^"\\])*"|'(?:\\[\s\S]|[^'\\])*'|\[(=*)\[[\s\S]*?\]\2\]|([.\w])?0x([0-9a-fA-F]{8,16})(?![0-9a-fA-FpP.])/g;

function psluaLiterals(source) {
  return source.replace(LITERALS, (match, _c, _s, prefix, hex) => {
    if (prefix || !hex) return match;
    const value = parseInt(hex, 16);
    // 8 digits below 0x80000000 already fit a Fengari integer; 9 digits and up are
    // truncated, so every literal from 0x100000000 needs the double spelling.
    if (hex.length > 8 || value >= 0x80000000) return `${value}.0`;
    return match;
  });
}

module.exports = { psluaLiterals };
