#!/usr/bin/env node
/**
 * Mock test for modulus block header storage (height % 100).
 *
 * Uses the same on-disk layout as the contract: 84 bytes = uint32 LE height + 80-byte
 * dummy header. Legacy rows are 80 bytes only — that length difference is how
 * GetBlockHeaderBytes disambiguates when blockSlotKey(h) == legacyBlockKey(h) for h < 100.
 *
 * Seeds at realistic BTC-like heights (~4.88M) so slot keys are not confused with
 * toy heights 0-99 where modulus and legacy keys share the same string (b-0 .. b-99).
 */

const BlockHeaderModulus = 100;
const BlockPrefix = "b-";
const LastHeightKey = "h";
const SeedHeightKey = "sh";

/** Match contract: tip heights in the millions, not 0-99 (slot/legacy key collision). */
const BASE_HEIGHT = 4_888_800;

const SLOT_LEN = 84; // 4 + 80

class MockState {
  constructor() {
    this.store = new Map();
  }
  get(key) {
    return this.store.get(key) || "";
  }
  set(key, val) {
    this.store.set(key, val);
  }
  countBlockKeys() {
    let count = 0;
    for (const k of this.store.keys()) {
      if (k.startsWith(BlockPrefix)) count++;
    }
    return count;
  }
  slotKey(height) {
    return BlockPrefix + (height % BlockHeaderModulus);
  }
  /** Same encoding as contract encodeBlockSlot: LE uint32 + 80 bytes */
  encodeModulusSlot(height) {
    const buf = Buffer.alloc(SLOT_LEN);
    buf.writeUInt32LE(height >>> 0, 0);
    buf.fill(0x5a, 4, SLOT_LEN);
    return buf.toString("binary");
  }
  decodeModulusAtHeight(wantHeight, raw) {
    const b = Buffer.from(raw, "binary");
    if (b.length !== SLOT_LEN) return null;
    const got = b.readUInt32LE(0) >>> 0;
    if (got !== (wantHeight >>> 0)) return null;
    return b.subarray(4, SLOT_LEN);
  }
}

function simulateAddBlocks(state, newHeaderCount) {
  const lastHeight = parseInt(state.get(LastHeightKey), 10) || 0;
  if (lastHeight === 0) throw new Error("not seeded");

  let currentHeight = lastHeight;
  for (let i = 0; i < newHeaderCount; i++) {
    currentHeight++;
    const key = state.slotKey(currentHeight);
    state.set(key, state.encodeModulusSlot(currentHeight));
  }
  state.set(LastHeightKey, String(currentHeight));
  return currentHeight;
}

function seedBlocks(state, height) {
  state.set(state.slotKey(height), state.encodeModulusSlot(height));
  state.set(LastHeightKey, String(height));
  state.set(SeedHeightKey, String(height));
}

let passed = 0;
let failed = 0;
function assert(cond, msg) {
  if (cond) passed++;
  else {
    failed++;
    console.error(`  FAIL: ${msg}`);
  }
}

console.log("\nTest: at most 100 block keys after many addBlocks (realistic base height)");
{
  const state = new MockState();
  seedBlocks(state, BASE_HEIGHT);
  for (let i = 0; i < 20; i++) simulateAddBlocks(state, 50);
  const tip = parseInt(state.get(LastHeightKey), 10);
  assert(tip === BASE_HEIGHT + 1000, `tip ${BASE_HEIGHT + 1000}, got ${tip}`);
  assert(state.countBlockKeys() <= BlockHeaderModulus, `key count ${state.countBlockKeys()} <= ${BlockHeaderModulus}`);
  console.log(`  tip=${tip}, distinct block keys=${state.countBlockKeys()}`);
}

console.log("\nTest: slot lookup returns correct height (84-byte modulus format)");
{
  const state = new MockState();
  const seedH = BASE_HEIGHT + 105;
  seedBlocks(state, seedH);
  simulateAddBlocks(state, 10);
  const tip = parseInt(state.get(LastHeightKey), 10);
  const key = state.slotKey(tip);
  const raw = state.get(key);
  const dec = state.decodeModulusAtHeight(tip, raw);
  assert(dec !== null && dec.length === 80, `decoded 80-byte header for tip ${tip}`);
  console.log(`  tip ${tip} @ ${key} -> ok`);
}

console.log("\nTest: overwritten slot rejects stale height (embedded height mismatch)");
{
  const state = new MockState();
  const seedH = BASE_HEIGHT + 100;
  seedBlocks(state, seedH);
  simulateAddBlocks(state, 100);
  const oldH = seedH;
  const raw = state.get(state.slotKey(oldH));
  assert(state.decodeModulusAtHeight(oldH, raw) === null, `height ${oldH} should not decode after slot overwrite`);
  console.log(`  slot ${state.slotKey(seedH)} now holds a newer block only`);
}

console.log("\nTest: same key, 84-byte modulus vs 80-byte legacy (disambiguation)");
{
  const state = new MockState();
  const h = BASE_HEIGHT + 7; // arbitrary; key is b-7
  const k = state.slotKey(h);
  state.set(k, state.encodeModulusSlot(h));
  assert(state.decodeModulusAtHeight(h, state.get(k)) !== null, "modulus row decodes");
  // Simulate legacy: same key string would only happen for h<100 with legacy key b-<h>;
  // at realistic h, legacy key differs; still test length rule:
  const legacyOnly = Buffer.alloc(80, 0xbb).toString("binary");
  state.set(k, legacyOnly);
  assert(state.decodeModulusAtHeight(h, legacyOnly) === null, "80-byte value is not modulus format");
  console.log("  len 84 vs len 80 distinguishes formats");
}

console.log(`\n${"=".repeat(60)}`);
console.log(`Results: ${passed} checks passed, ${failed} failed`);
console.log(`${"=".repeat(60)}`);
process.exit(failed > 0 ? 1 : 0);
