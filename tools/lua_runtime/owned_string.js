// Fengari's public lua_pushlstring copies through Uint8Array.from. Memory reads
// already allocate a private array, so hand that array to the VM instead.
// This adapter deliberately depends on the pinned VM's internal string layout.
const {lua} = require('fengari');
const {luaS_bless} = require('fengari/src/lstring.js');
const {pushsvalue2s} = require('fengari/src/lobject.js');
if (require('fengari/package.json').version !== '0.1.4') {
  throw Error('owned string adapter requires review for this Fengari version');
}

// Caller relinquishes ownership: bytes must never be mutated or reused after
// this call. Never pass a native memory window, pooled buffer, or borrowed view.
function pushOwnedBytes(L, bytes) {
  if (!lua.lua_checkstack(L, 1)) throw Error('Lua string stack overflow');
  pushsvalue2s(L, luaS_bless(L, bytes));
}

module.exports = {pushOwnedBytes};
