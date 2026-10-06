// Report filesystem capacity and mount flags.

const SYS_OPEN = 0x005;
const SYS_CLOSE = 0x006;
const SYS_FSTATFS = 0x18D;
const O_RDONLY = 0x0000;

const STATFS_SIZE = 512;

const CANDIDATE_PATHS = [
  "/",
  "/data",
  "/user",
  "/system",
  "/system_data",
  "/system_ex",
  "/dev",
  "/mnt/usb0",
  "/mnt/usb1",
  "/mnt/usb2",
  "/mnt/usb3",
  "/mnt/ext0",
  "/mnt/ext1",
  "/preinst",
  "/preinst2",
  "/update",
];

const MOUNT_FLAG_DEFS = [
  [0x00000001, "read-only"],
  [0x00000002, "synchronous"],
  [0x00000004, "noexec"],
  [0x00000008, "nosuid"],
  [0x00000010, "nfs4acls"],
  [0x00000020, "union"],
  [0x00000040, "async"],
  [0x00001000, "local"],
  [0x00002000, "quota"],
  [0x00004000, "rootfs"],
  [0x00008000, "user"],
  [0x00100000, "suiddir"],
  [0x00200000, "softdep"],
  [0x00400000, "nosymfollow"],
  [0x00800000, "ignore"],
  [0x04000000, "multilabel"],
  [0x08000000, "acls"],
  [0x80000000, "automounted"],
];

function decodeMountFlags(flagsNum) {
  const flags = [];
  for (const [mask, name] of MOUNT_FLAG_DEFS) {
    if ((flagsNum & mask) !== 0) {
      flags.push(name);
    }
  }
  return flags;
}

function formatBytes(bytes) {
  if (bytes <= 0 || isNaN(bytes)) return "0B";
  const units = ["B", "K", "M", "G", "T", "P"];
  let val = bytes;
  let unitIdx = 0;
  while (val >= 1024 && unitIdx < units.length - 1) {
    val /= 1024;
    unitIdx++;
  }
  return unitIdx === 0 ? `${Math.round(val)}B` : `${val.toFixed(1)}${units[unitIdx]}`;
}

function formatCount(num) {
  if (num <= 0 || isNaN(num)) return "0";
  const units = ["", "k", "M", "G"];
  let val = num;
  let unitIdx = 0;
  while (val >= 1000 && unitIdx < units.length - 1) {
    val /= 1000;
    unitIdx++;
  }
  const formatted = val >= 100 || val % 1 === 0 ? String(Math.round(val)) : val.toFixed(1);
  return `${formatted}${units[unitIdx]}`;
}

function readCString(p, ptr, maxLen) {
  let s = "";
  for (let i = 0; i < maxLen; i++) {
    const b = p.read1(ptr.add32(i));
    if (b === 0) break;
    if (b >= 32 && b <= 126) {
      s += String.fromCharCode(b);
    }
  }
  return s.trim();
}

function parseOptions(argv) {
  const opts = {
    paths: [],
    bytes: false,
    inodes: false,
    flags: false,
    all: false,
    json: false,
    help: false,
  };

  for (const raw of argv) {
    const arg = String(raw).trim();
    if (!arg) continue;

    const lower = arg.toLowerCase();
    if (lower === "json") {
      opts.json = true;
    } else if (lower === "bytes" || lower === "b") {
      opts.bytes = true;
    } else if (lower === "inodes" || lower === "i") {
      opts.inodes = true;
    } else if (lower === "flags") {
      opts.flags = true;
    } else if (lower === "all" || lower === "a") {
      opts.all = true;
    } else if (lower === "human" || lower === "h") {
      opts.bytes = false;
    } else if (lower === "help" || lower === "-h" || lower === "--help") {
      opts.help = true;
    } else if (arg.startsWith("/")) {
      opts.paths.push(arg);
    }
  }

  return opts;
}

return async function (api) {
  const argv = (api.args && api.args.length) ? api.args : ((api.argv && api.argv.length) ? api.argv : []);
  const opts = parseOptions(argv);

  if (opts.help) {
    await api.log("Usage: df.js [path ...] [bytes] [inodes] [flags] [all] [json]");
    await api.log("  path ...   Target path(s) to inspect (default: probe standard system & user partitions)");
    await api.log("  bytes      Display storage capacity in raw byte counts");
    await api.log("  inodes     Display filesystem inode statistics and usage");
    await api.log("  flags      Display decoded mount flags (e.g. read-only, local, nosuid)");
    await api.log("  all        Display all probed mount points, including 0-byte pseudo-filesystems");
    await api.log("  json       Output structured JSON array");
    return;
  }

  if (api.syscalls && !api.syscalls[SYS_FSTATFS]) {
    await api.log(`SYS_FSTATFS (0x${SYS_FSTATFS.toString(16)}) not present in syscall map`, "error");
    return;
  }

  const pathsToProbe = opts.paths.length > 0 ? opts.paths : CANDIDATE_PATHS;
  const statfsBuf = api.p.malloc(STATFS_SIZE, 1);
  const seenMounts = new Set();
  const mounts = [];

  for (const targetPath of pathsToProbe) {
    const pathPtr = api.p.stringify(targetPath);
    const fd = await api.chain.syscall(SYS_OPEN, pathPtr, O_RDONLY);
    if (api.isFailure(fd)) {
      if (opts.paths.length > 0) {
        await api.log(`open(${targetPath}) = ${api.describe ? api.describe(fd) : fd.low} (unmounted or inaccessible)`, "warn");
      }
      continue;
    }

    const fdNum = fd.low >>> 0;
    try {
      // Zero out buffer before call
      for (let i = 0; i < STATFS_SIZE; i += 4) {
        api.p.write4(statfsBuf.add32(i), 0);
      }

      const rv = await api.chain.syscall(SYS_FSTATFS, fdNum, statfsBuf);
      if (api.isFailure(rv) || rv.low !== 0) {
        if (opts.paths.length > 0) {
          await api.log(`fstatfs(${targetPath}) failed: ${api.describe ? api.describe(rv) : rv.low}`, "warn");
        }
        continue;
      }

      // Parse struct statfs fields
      const fType = api.p.read4(statfsBuf.add32(4)) >>> 0;

      const flagsLo = api.p.read4(statfsBuf.add32(8)) >>> 0;
      const flagsHi = api.p.read4(statfsBuf.add32(12)) >>> 0;
      const flagsNum = flagsLo;

      const bsizeLo = api.p.read4(statfsBuf.add32(16)) >>> 0;
      const bsizeHi = api.p.read4(statfsBuf.add32(20)) >>> 0;
      const bsize = bsizeLo + bsizeHi * 4294967296;

      const iosizeLo = api.p.read4(statfsBuf.add32(24)) >>> 0;
      const iosizeHi = api.p.read4(statfsBuf.add32(28)) >>> 0;
      const iosize = iosizeLo + iosizeHi * 4294967296;

      const blocksLo = api.p.read4(statfsBuf.add32(32)) >>> 0;
      const blocksHi = api.p.read4(statfsBuf.add32(36)) >>> 0;
      const totalBlocks = blocksLo + blocksHi * 4294967296;

      const bfreeLo = api.p.read4(statfsBuf.add32(40)) >>> 0;
      const bfreeHi = api.p.read4(statfsBuf.add32(44)) >>> 0;
      const freeBlocks = bfreeLo + bfreeHi * 4294967296;

      const bavailLo = api.p.read4(statfsBuf.add32(48)) >>> 0;
      const bavailHi = api.p.read4(statfsBuf.add32(52)) | 0;
      const availBlocks = Math.max(0, bavailLo + bavailHi * 4294967296);

      const filesLo = api.p.read4(statfsBuf.add32(56)) >>> 0;
      const filesHi = api.p.read4(statfsBuf.add32(60)) >>> 0;
      const totalInodes = filesLo + filesHi * 4294967296;

      const ffreeLo = api.p.read4(statfsBuf.add32(64)) >>> 0;
      const ffreeHi = api.p.read4(statfsBuf.add32(68)) | 0;
      const freeInodes = Math.max(0, ffreeLo + ffreeHi * 4294967296);

      // C strings
      const fstype = readCString(api.p, statfsBuf.add32(280), 16) || "unknown";
      const mntfrom = readCString(api.p, statfsBuf.add32(296), 88) || targetPath;
      const mnton = readCString(api.p, statfsBuf.add32(384), 88) || targetPath;

      // Deduplication: unless "all" requested, keep one record per mount point
      if (!opts.all && seenMounts.has(mnton)) {
        continue;
      }
      seenMounts.add(mnton);

      const totalBytes = totalBlocks * bsize;
      const freeBytes = freeBlocks * bsize;
      const availBytes = availBlocks * bsize;
      const usedBytes = Math.max(0, totalBytes - freeBytes);

      // Capacity percentage calculation (based on non-superuser availability)
      let capPercent = 0;
      if (usedBytes + availBytes > 0) {
        capPercent = Math.min(100, Math.round((usedBytes / (usedBytes + availBytes)) * 100));
      } else if (totalBytes > 0) {
        capPercent = Math.min(100, Math.round((usedBytes / totalBytes) * 100));
      }

      // Inode usage
      const usedInodes = Math.max(0, totalInodes - freeInodes);
      const inodePercent = totalInodes > 0 ? Math.min(100, Math.round((usedInodes / totalInodes) * 100)) : 0;

      const flagList = decodeMountFlags(flagsNum);

      mounts.push({
        targetPath,
        filesystem: mntfrom,
        mountedOn: mnton,
        type: fstype,
        bsize,
        iosize,
        totalBytes,
        usedBytes,
        availBytes,
        freeBytes,
        capacityPercent: capPercent,
        totalInodes,
        usedInodes,
        freeInodes,
        inodePercent,
        rawFlags: flagsNum,
        flags: flagList,
      });
    } finally {
      await api.chain.syscall(SYS_CLOSE, fdNum);
    }
  }

  // Filter out 0-byte pseudo-filesystems unless opts.all is requested
  const displayMounts = opts.all ? mounts : mounts.filter(m => m.totalBytes > 0 || m.mountedOn === "/dev");

  if (opts.json) {
    const jsonList = displayMounts.map(m => ({
      filesystem: m.filesystem,
      mounted_on: m.mountedOn,
      type: m.type,
      total_bytes: m.totalBytes,
      used_bytes: m.usedBytes,
      avail_bytes: m.availBytes,
      free_bytes: m.freeBytes,
      capacity_percent: m.capacityPercent,
      bsize: m.bsize,
      iosize: m.iosize,
      flags: m.flags,
      raw_flags: m.rawFlags,
      inodes: {
        total: m.totalInodes,
        used: m.usedInodes,
        free: m.freeInodes,
        percent: m.inodePercent,
      },
    }));
    await api.log(JSON.stringify(jsonList));
    return;
  }

  if (displayMounts.length === 0) {
    await api.log("No mounted filesystems found.", "warn");
    return;
  }

  await api.log(`filesystems: ${displayMounts.length} mounted partition(s) inspected`);

  if (opts.inodes) {
    // Inodes view
    const hFs = "Filesystem".padEnd(26);
    const hType = "Type".padEnd(8);
    const hTotal = "Inodes".padStart(9);
    const hUsed = "IUsed".padStart(9);
    const hFree = "IFree".padStart(9);
    const hPct = "IUse%".padStart(6);
    const hMount = "Mounted on";
    await api.log(`  ${hFs} ${hType} ${hTotal} ${hUsed} ${hFree} ${hPct}  ${hMount}`);

    for (const m of displayMounts) {
      const fsStr = (m.filesystem.length > 26 ? m.filesystem.slice(0, 23) + "..." : m.filesystem).padEnd(26);
      const typeStr = m.type.padEnd(8);
      const totalStr = formatCount(m.totalInodes).padStart(9);
      const usedStr = formatCount(m.usedInodes).padStart(9);
      const freeStr = formatCount(m.freeInodes).padStart(9);
      const pctStr = `${m.inodePercent}%`.padStart(6);
      await api.log(`  ${fsStr} ${typeStr} ${totalStr} ${usedStr} ${freeStr} ${pctStr}  ${m.mountedOn}`);
    }
  } else {
    // Standard storage capacity view
    const hFs = "Filesystem".padEnd(26);
    const hType = "Type".padEnd(8);
    const hSize = (opts.bytes ? "Size (bytes)" : "Size").padStart(opts.bytes ? 16 : 8);
    const hUsed = (opts.bytes ? "Used (bytes)" : "Used").padStart(opts.bytes ? 16 : 8);
    const hAvail = (opts.bytes ? "Avail (bytes)" : "Avail").padStart(opts.bytes ? 16 : 8);
    const hCap = "Cap%".padStart(5);
    const hMount = "Mounted on";
    const hFlags = opts.flags ? "  Flags" : "";

    await api.log(`  ${hFs} ${hType} ${hSize} ${hUsed} ${hAvail} ${hCap}  ${hMount}${hFlags}`);

    for (const m of displayMounts) {
      const fsStr = (m.filesystem.length > 26 ? m.filesystem.slice(0, 23) + "..." : m.filesystem).padEnd(26);
      const typeStr = m.type.padEnd(8);

      const sizeStr = (opts.bytes ? String(m.totalBytes) : formatBytes(m.totalBytes)).padStart(opts.bytes ? 16 : 8);
      const usedStr = (opts.bytes ? String(m.usedBytes) : formatBytes(m.usedBytes)).padStart(opts.bytes ? 16 : 8);
      const availStr = (opts.bytes ? String(m.availBytes) : formatBytes(m.availBytes)).padStart(opts.bytes ? 16 : 8);
      const capStr = `${m.capacityPercent}%`.padStart(5);

      const flagsStr = opts.flags ? `  [${m.flags.join(",") || "none"}]` : "";

      await api.log(`  ${fsStr} ${typeStr} ${sizeStr} ${usedStr} ${availStr} ${capStr}  ${m.mountedOn}${flagsStr}`);
    }
  }
};
