#!/usr/bin/env node
/**
 * Mock test for modulus block header storage (height % 100).
 *
 * Matches contract behavior: at most 100 keys b-0 … b-99; each value is
 * "height:" + payload so the correct block can be retrieved for proofs.
 */

const BlockHeaderModulus = 100;
const BlockPrefix = "b-";
const LastHeightKey = "h";
const SeedHeightKey = "sh";

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
  encodeSlot(height, payload) {
    return `h${height}:` + payload;
  }
  decodeSlot(wantHeight, raw) {
    const m = /^h(\d+):(.+)$/.exec(raw);
    if (!m) return null;
    const h = parseInt(m[1], 10);
    if (h !== wantHeight) return null;
    return m[2];
  }
}

function simulateAddBlocks(state, newHeaderCount) {
  const lastHeight = parseInt(state.get(LastHeightKey), 10) || 0;
  if (lastHeight === 0) throw new Error("not seeded");

  let currentHeight = lastHeight;
  for (let i = 0; i < newHeaderCount; i++) {
    currentHeight++;
    const key = state.slotKey(currentHeight);
    state.set(key, state.encodeSlot(currentHeight, "hdr_" + currentHeight));
  }
  state.set(LastHeightKey, String(currentHeight));
  return currentHeight;
}

function seedBlocks(state, height) {
  state.set(state.slotKey(height), state.encodeSlot(height, "hdr_" + height));
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

console.log("\nTest: at most 100 block keys after many addBlocks");
{
  const state = new MockState();
  seedBlocks(state, 1000);
  for (let i = 0; i < 20; i++) simulateAddBlocks(state, 50);
  const tip = parseInt(state.get(LastHeightKey), 10);
  assert(tip === 2000, `tip 2000, got ${tip}`);
  assert(state.countBlockKeys() <= BlockHeaderModulus, `key count ${state.countBlockKeys()} <= ${BlockHeaderModulus}`);
  console.log(`  tip=${tip}, distinct block keys=${state.countBlockKeys()}`);
}

console.log("\nTest: slot lookup returns correct height");
{
  const state = new MockState();
  seedBlocks(state, 105);
  simulateAddBlocks(state, 10);
  const tip = parseInt(state.get(LastHeightKey), 10);
  const key = state.slotKey(tip);
  const raw = state.get(key);
  const dec = state.decodeSlot(tip, raw);
  assert(dec === "hdr_" + tip, `decoded header for tip ${tip}`);
  console.log(`  tip ${tip} @ ${key} -> ok`);
}

console.log("\nTest: overwritten slot loses old height (no legacy key)");
{
  const state = new MockState();
  seedBlocks(state, 100);
  simulateAddBlocks(state, 100);
  const oldRaw = state.get(state.slotKey(100));
  assert(state.decodeSlot(100, oldRaw) === null, "height 100 should not resolve after tip moved on");
  console.log("  slot 0 now holds a newer height only");
}

console.log(`\n${"=".repeat(60)}`);
console.log(`Results: ${passed} checks passed, ${failed} failed`);
console.log(`${"=".repeat(60)}`);
process.exit(failed > 0 ? 1 : 0);
