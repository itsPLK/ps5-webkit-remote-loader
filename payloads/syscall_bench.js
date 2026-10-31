// Host syscall profiling through the gated worker API.
// --arg quick runs a short correctness check.
return async function(api) {
  const {p, chain} = api;
  if (!chain || typeof chain.add_syscall_ret !== 'function' || typeof chain.run !== 'function')
    throw Error('Gated batch API is required');
  if (typeof performance === 'undefined' || typeof performance.now !== 'function')
    throw Error('performance.now is required');
  const quick = (api.args || []).includes('quick');
  const samples = quick ? 2 : 5, rounds = quick ? 2 : 64;
  const now = () => performance.now();
  let previous = now(), resolution = Infinity;
  const floors = [];
  for (let i = 0; i < 10000; i++) {
    const t = now(), delta = t - previous;
    if (delta < 0) throw Error('Host clock moved backwards');
    if (delta > 0) resolution = Math.min(resolution, delta);
    previous = t;
  }
  if (!Number.isFinite(resolution)) throw Error('Cannot measure host timer resolution');
  for (let i = 0; i < 100; i++) { const t = now(); floors.push(now() - t); }
  const pid = await chain.syscall(20);
  if (!pid || pid.hi !== 0 || pid.low <= 0) throw Error('Invalid getpid result');
  const storage = p.malloc(32 * 8, 1);
  const slots = Array.from({length: 32}, (_, i) => storage.add32(i * 8));
  const check = value => {
    if (!value || value.low !== pid.low || value.hi !== pid.hi) throw Error('getpid result mismatch');
  };
  const elapsed = t => {
    const duration = now() - t;
    if (duration < 0) throw Error('Host clock moved backwards');
    return duration;
  };
  const cases = [{name: 'individual', size: 1, times: []}];
  for (const size of [1, 8, 32]) for (const clear of [false, true])
    cases.push({name: 'batch ' + size + (clear ? ' explicit clear' : ' implicit clear'),
      size, clear, times: [], build: [], execute: [], profiled: [], profileTiming: []});
  cases[0].profiled = []; cases[0].profileTiming = [];
  async function sample(c, save) {
    const work = async () => {
      let build = 0, execute = 0;
      for (let round = 0; round < rounds; round++) {
        if (c.name === 'individual') {
          const t = now();
          const result = await chain.syscall(20);
          execute += elapsed(t);
          check(result);
        } else {
          // Poison each result slot outside timing to detect skipped/stale results.
          for (let i = 0; i < c.size; i++) p.write8(slots[i], new api.int64(0));
          const t = now();
          if (c.clear) chain.clear();
          for (let i = 0; i < c.size; i++) chain.add_syscall_ret(slots[i], 20);
          build += elapsed(t);
          const start = now();
          await chain.run();
          execute += elapsed(start);
          for (let i = 0; i < c.size; i++) check(p.read8(slots[i]));
        }
      }
      return {build, execute};
    };
    if (save) {
      const ordinary = await work();
      c.times.push(ordinary.build + ordinary.execute);
      if (c.build) { c.build.push(ordinary.build); c.execute.push(ordinary.execute); }
      if (c.name === 'individual' || c.name === 'batch 32 implicit clear') {
        if (typeof p.measureWorkerCalls !== 'function')
          throw Error('Reload the updated loader: worker timing counters are unavailable');
        const measured = await p.measureWorkerCalls(work);
        c.profiled.push(measured.result.build + measured.result.execute);
        c.profileTiming.push(measured.timing);
      }
    } else {
      await work();
    }
  }
  for (const c of cases) await sample(c, false);
  for (let pass = 0; pass < samples; pass++) {
    for (let offset = 0; offset < cases.length; offset++)
      await sample(cases[(pass + offset) % cases.length], true);
  }
  const stats = values => {
    const sorted = values.slice().sort((a, b) => a - b);
    return [sorted[Math.floor(sorted.length / 2)], sorted[0], sorted[sorted.length - 1]];
  };
  await api.log('host syscall benchmark v2 (worker phase timing): ' + samples + ' samples, 1 warmup, ' + rounds + ' rounds/sample; fw=' + api.fw);
  await api.log('timer resolution ms=' + resolution + '; pair floor median/min/max ms=' + stats(floors).join('/'));
  await api.log('Counters are enabled only around selected sample callbacks; ordinary worker calls remain unprofiled. Park includes the unchanged settle guard; completion spans arm/postMessage through worker response.');
  await api.log('Profiled and unprofiled totals use the same build/execution intervals; result checks and poisoning are outside both. Their difference estimates instrumentation overhead, with clock quantization and run drift.');
  for (const c of cases) {
    const rows = [['total', c.times]];
    if (c.build) rows.push(['record', c.build], ['execute', c.execute]);
    if (c.profiled.length) rows.push(['instrumented timed', c.profiled]);
    for (const [phase, values] of rows) {
      const [med, min, max] = stats(values);
      await api.log(c.name + ' ' + phase + ' | calls/sample=' + rounds * c.size +
        ' | median/min/max ms=' + [med, min, max].map(v => v.toFixed(3)).join('/') +
        ' | us/call=' + (med * 1000 / (rounds * c.size)).toFixed(3));
      await api.log('samples_ms,' + c.name + ',' + phase + ',' + values.map(v => v.toFixed(6)).join(','));
      if (phase === 'instrumented timed') {
        const timing = c.profileTiming.map(row =>
          ['parkMs', 'setupMs', 'completionMs'].map(key => row[key]).join('/'));
        await api.log('worker_phase_samples_ms,' + c.name + ',park/setup/completion,' + timing.join(','));
        const sums = ['parkMs', 'setupMs', 'completionMs'].map(key =>
          c.profileTiming.reduce((total, row) => total + row[key], 0) / c.profileTiming.length);
        const calls = c.profileTiming.reduce((total, row) => total + row.calls, 0) / c.profileTiming.length;
        const measured = c.profileTiming.map(row => row.parkMs + row.setupMs + row.completionMs);
        const overhead = values.map((v, i) => v - measured[i]);
        const [overMed, overMin, overMax] = stats(overhead);
        await api.log('worker_phase_medians_ms,' + c.name + ',calls/sample=' + calls +
          ',park/setup/completion=' + sums.map(v => v.toFixed(3)).join('/') +
          ',outside phases median/min/max=' + [overMed, overMin, overMax].map(v => v.toFixed(3)).join('/') +
          ',completed=' + c.profileTiming.map(row => row.completed).join('/') +
          ',parkFailures=' + c.profileTiming.map(row => row.parkFailures).join('/') +
          ',timeouts=' + c.profileTiming.map(row => row.timeouts).join('/') +
          ',clockErrors=' + c.profileTiming.map(row => row.clockErrors).join('/'));
        const overheadRows = values.map((v, i) => v - c.times[i]);
        await api.log('instrumentation_overhead_ms,' + c.name + ',' + overheadRows.map(v => v.toFixed(6)).join(','));
      }
    }
  }
  await api.log('host syscall benchmark complete; all saved results verified');
};
