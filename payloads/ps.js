// List and filter processes and threads.

const SYS_GETPID = 0x014;
const SYS___SYSCTL = 0x0ca;

const CTL_KERN = 1;
const KERN_PROC = 14;
const KERN_PROC_PROC = 8;

const KINFO_PID_OFFSET = 72;
const KINFO_PPID_OFFSET = 76;
const KINFO_UID_OFFSET = 176;
const KINFO_TDNAME_OFFSET = 447;
const MIN_KINFO_BYTES = 448;

function parseOptions(argv) {
  const opts = {
    filter: null,
    pid: null,
    uid: null,
    sort: "pid",
    desc: false,
    limit: 0,
    json: false,
    help: false,
  };

  for (const raw of argv) {
    const arg = String(raw).trim();
    if (!arg) continue;

    const eq = arg.indexOf("=");
    if (eq !== -1) {
      const key = arg.slice(0, eq).toLowerCase();
      const val = arg.slice(eq + 1).trim();

      if (key === "grep" || key === "filter" || key === "name") {
        opts.filter = val;
      } else if (key === "pid") {
        const n = parseInt(val, 10);
        if (!isNaN(n)) opts.pid = n;
      } else if (key === "uid") {
        const n = parseInt(val, 10);
        if (!isNaN(n)) opts.uid = n;
      } else if (key === "sort") {
        const s = val.toLowerCase();
        if (s === "pid" || s === "name" || s === "ppid" || s === "uid") {
          opts.sort = s;
        }
      } else if (key === "limit" || key === "max") {
        const n = parseInt(val, 10);
        if (!isNaN(n) && n > 0) opts.limit = n;
      }
      continue;
    }

    const lower = arg.toLowerCase();
    if (lower === "json") {
      opts.json = true;
    } else if (lower === "desc" || lower === "reverse") {
      opts.desc = true;
    } else if (lower === "help" || lower === "-h" || lower === "--help") {
      opts.help = true;
    } else if (/^\d+$/.test(arg)) {
      opts.pid = parseInt(arg, 10);
    } else {
      opts.filter = arg;
    }
  }

  return opts;
}

return async function (api) {
  const argv = (api.args && api.args.length) ? api.args : ((api.argv && api.argv.length) ? api.argv : []);
  const opts = parseOptions(argv);

  if (opts.help) {
    await api.log("Usage: ps.js [filter] [pid=N] [uid=N] [sort=pid|name|ppid|uid] [desc] [limit=N] [json]");
    await api.log("  filter       Substring match on process name (e.g. shell, daemon, elf)");
    await api.log("  pid=N        Filter by process ID");
    await api.log("  uid=N        Filter by effective user ID");
    await api.log("  sort=KEY     Sort by pid, name, ppid, or uid (default: pid)");
    await api.log("  desc         Reverse sort order");
    await api.log("  limit=N      Display at most N matching processes");
    await api.log("  json         Output structured JSON array");
    return;
  }

  // Get current process ID
  const pidRv = await api.chain.syscall(SYS_GETPID);
  const myPid = (pidRv && typeof pidRv.low === "number") ? (pidRv.low >>> 0) : null;

  // Sysctl control buffer: [CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0]
  const scratch = api.p.malloc(0x100, 1);
  const mibPtr = scratch;
  const lenPtr = scratch.add32(0x20);

  api.p.write4(mibPtr, CTL_KERN);
  api.p.write4(mibPtr.add32(4), KERN_PROC);
  api.p.write4(mibPtr.add32(8), KERN_PROC_PROC);
  api.p.write4(mibPtr.add32(12), 0);

  api.p.write4(lenPtr, 0);
  api.p.write4(lenPtr.add32(4), 0);

  // Probe required buffer size
  let rv = await api.chain.syscall(SYS___SYSCTL, mibPtr, 4, 0, lenPtr, 0, 0);
  if (api.isFailure(rv) || rv.low !== 0) {
    await api.log(`sysctl(KERN_PROC_PROC) probe failed: ${api.describe ? api.describe(rv) : rv.low}`, "error");
    return;
  }

  const reqSize = api.p.read4(lenPtr);
  if (reqSize <= 0) {
    await api.log("sysctl(KERN_PROC_PROC) returned 0 bytes", "error");
    return;
  }

  // Allocate staging buffer with padding for processes spawned during probe
  const allocSize = reqSize + 16384;
  const buf = api.p.malloc(allocSize, 1);

  api.p.write4(lenPtr, allocSize);
  api.p.write4(lenPtr.add32(4), 0);

  rv = await api.chain.syscall(SYS___SYSCTL, mibPtr, 4, buf, lenPtr, 0, 0);
  if (api.isFailure(rv) || rv.low !== 0) {
    await api.log(`sysctl(KERN_PROC_PROC) read failed: ${api.describe ? api.describe(rv) : rv.low}`, "error");
    return;
  }

  const gotSize = api.p.read4(lenPtr);
  const allProcs = [];

  for (let off = 0; off + 4 <= gotSize; ) {
    const structSize = api.p.read4(buf.add32(off));
    if (structSize <= 0 || structSize < MIN_KINFO_BYTES || off + structSize > gotSize) {
      break;
    }

    const pid = api.p.read4(buf.add32(off + KINFO_PID_OFFSET));
    const ppid = api.p.read4(buf.add32(off + KINFO_PPID_OFFSET));
    const uid = api.p.read4(buf.add32(off + KINFO_UID_OFFSET));

    let name = "";
    for (let j = 0; j < 32; j++) {
      const c = api.p.read1(buf.add32(off + KINFO_TDNAME_OFFSET + j));
      if (c === 0) break;
      name += String.fromCharCode(c);
    }

    allProcs.push({
      pid,
      ppid,
      uid,
      name,
      self: (myPid !== null && pid === myPid),
    });

    off += structSize;
  }

  // Filter
  let filtered = allProcs.filter((p) => {
    if (opts.pid !== null && p.pid !== opts.pid) return false;
    if (opts.uid !== null && p.uid !== opts.uid) return false;
    if (opts.filter && !p.name.toLowerCase().includes(opts.filter.toLowerCase())) return false;
    return true;
  });

  // Sort
  filtered.sort((a, b) => {
    let cmp = 0;
    if (opts.sort === "name") {
      cmp = a.name.localeCompare(b.name);
    } else if (opts.sort === "ppid") {
      cmp = a.ppid - b.ppid;
    } else if (opts.sort === "uid") {
      cmp = a.uid - b.uid;
    } else {
      cmp = a.pid - b.pid;
    }
    if (cmp === 0) cmp = a.pid - b.pid;
    return opts.desc ? -cmp : cmp;
  });

  // Limit
  if (opts.limit > 0 && filtered.length > opts.limit) {
    filtered = filtered.slice(0, opts.limit);
  }

  // Output
  if (opts.json) {
    await api.log(JSON.stringify(filtered, null, 2));
    return;
  }

  const matchLabel = (filtered.length !== allProcs.length)
    ? ` (${filtered.length} matched)`
    : "";
  await api.log(`processes: ${allProcs.length} total${matchLabel}`);
  await api.log(`  PID   PPID   UID  NAME`);

  for (const p of filtered) {
    const marker = p.self ? " *" : "";
    const pidStr = String(p.pid).padStart(5, " ");
    const ppidStr = String(p.ppid).padStart(6, " ");
    const uidStr = String(p.uid).padStart(5, " ");
    await api.log(`${pidStr} ${ppidStr} ${uidStr}  ${p.name}${marker}`);
  }
};
