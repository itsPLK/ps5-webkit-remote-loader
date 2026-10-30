// WebKit host-only bulk-memory diagnostics. No Lua/native comparison implied.
// --arg quick runs a short correctness smoke test, not a performance measurement.
return async function(api) {
  const p = api.p;
  if (typeof p.probeMemoryWindow !== "function" || typeof p.readInto !== "function" ||
      typeof p.writeBytes !== "function" || !(p.memoryWindowSize > 0))
    throw Error("Reload the updated loader: bulk memory diagnostics are missing");
  if (typeof performance === "undefined" || typeof performance.now !== "function")
    throw Error("performance.now is required for host timing");
  const quick = (api.args || []).includes("quick");
  const samples = quick ? 2 : 5;
  const totalBytes = quick ? 16384 : 2097152;
  const now = () => performance.now();
  let last = now(), resolution = Infinity;
  for (let i = 0; i < 10000; i++) {
    const current = now();
    if (current < last) throw Error("Host clock moved backwards");
    if (current > last) resolution = Math.min(resolution, current - last);
    last = current;
  }
  if (!Number.isFinite(resolution)) throw Error("Host clock resolution could not be measured");
  api.setPayloadTimeout(0);
  const address = p.malloc(16384, 1);
  const cases = [];
  let retained;
  function add(name, size, count, windows, fn, verify, bytes = true) {
    cases.push({name, size, count, windows, fn, verify, bytes, times: []});
  }
  for (const size of [64, 256, 1024, 16384]) {
    const count = totalBytes / size;
    const source = Uint8Array.from({length: size}, (_, i) => (i * 71) & 255);
    const target = new Uint8Array(size);
    const check = () => {
      for (let i = 0; i < size; i++) if (target[i] !== source[i])
        throw Error("Copy mismatch at " + size + ":" + i);
    };
    const windows = count * Math.ceil(size / p.memoryWindowSize);
    add("window cycles " + size, size, count, windows,
      () => p.probeMemoryWindow(address, size, count), value => {
        if (value !== windows) throw Error("Wrong window count");
      }, false);
    add("host indexed copy " + size, size, count, 0, () => {
      for (let pass = 0; pass < count; pass++)
        for (let i = 0; i < size; i++) target[i] = source[i];
    }, check);
    add("host typed-array set " + size, size, count, 0, () => {
      for (let pass = 0; pass < count; pass++) target.set(source);
    }, check);
    add("allocate Uint8Array " + size, size, count, 0, () => {
      let sum = 0;
      for (let pass = 0; pass < count; pass++) {
        retained = new Uint8Array(size);
        sum += retained.length + retained[0];
      }
      return sum;
    }, sum => { if (sum !== totalBytes) throw Error("Allocation checksum mismatch"); });
    add("native write " + size, size, count, windows, () => {
      for (let pass = 0; pass < count; pass++) p.writeBytes(address, source);
    }, () => { p.readInto(address, target); check(); });
    add("native read reused " + size, size, count, windows, () => {
      for (let pass = 0; pass < count; pass++) p.readInto(address, target);
    }, check);
    add("native read allocated " + size, size, count, windows, () => {
      for (let pass = 0; pass < count; pass++) {
        retained = new Uint8Array(size);
        p.readInto(address, retained);
      }
    }, () => {
      for (let i = 0; i < size; i++) if (retained[i] !== source[i])
        throw Error("Allocated read mismatch");
    });
    // Every case prepares its own input so rotating execution order stays valid.
    for (const c of cases.slice(-7)) c.setup = () => {
      p.writeBytes(address, source);
      target.fill(0xcc);
    };
  }
  function measure(c, save) {
    c.setup();
    const start = now();
    const result = c.fn();
    const elapsed = now() - start;
    if (elapsed < 0) throw Error("Negative elapsed time");
    c.verify(result);
    if (save) c.times.push(elapsed);
  }
  await api.log("memory host benchmark v1" + (quick ? " QUICK SMOKE" : ""));
  await api.log("fw=" + api.fw + " window=" + p.memoryWindowSize + " bytes; " + totalBytes + " bytes/row; samples=" + samples);
  await api.log("Host clock minimum observed step: " + (resolution * 1000).toFixed(3) + " us");
  await api.log("One warmup/row; setup, checks, and logs excluded. Allocation rows include natural GC; buffers are hot/reused.");
  await api.log("Window cycles include loop/validation overhead; row differences are estimates, not an exact decomposition.");
  for (const c of cases) measure(c, false);
  const floors = [];
  for (let pass = 0; pass < samples; pass++) {
    const start = now();
    floors.push(now() - start);
    for (let offset = 0; offset < cases.length; offset++)
      measure(cases[(offset + pass) % cases.length], true);
    await api.log("pass " + (pass + 1) + "/" + samples + " complete");
  }
  const median = values => [...values].sort((a,b) => a-b)[Math.floor(values.length / 2)];
  const floor = Math.max(resolution, median(floors));
  await api.log("Timing floor/resolution estimate: " + (floor * 1000).toFixed(3) + " us; LOW if <10x floor");
  await api.log("case | calls | selections | median ms | min ms | max ms | us/call | MiB/s | signal");
  for (const c of cases) {
    const ms = median(c.times);
    const rate = c.bytes && ms > 0 ? (totalBytes / 1048576 / (ms / 1000)).toFixed(3) : "-";
    await api.log([c.name, c.count, c.windows, ms.toFixed(3), Math.min(...c.times).toFixed(3),
      Math.max(...c.times).toFixed(3), (ms * 1000 / c.count).toFixed(3), rate,
      ms < 10 * floor ? "LOW" : "OK"].join(" | "));
    await api.log("samples_ms," + c.name + "," + c.times.map(x => x.toFixed(3)).join(","));
  }
  await api.log("host benchmark complete; byte checks passed");
};
