// Read files as text or a hex dump.

const SYS_OPEN = 0x005;
const SYS_CLOSE = 0x006;
const SYS_READ = 0x003;
const SYS_LSEEK = 0x1de; // 478
const O_RDONLY = 0;

const CHUNK = 0x1000; // 4 KiB read buffer

const PROBE_PATHS = [
  "/etc/hosts",
  "/dev/urandom",
];

function formatHexLine(offset, bytes, width = 16, showAscii = true) {
  const offStr = offset.toString(16).padStart(8, "0");
  const hexParts = [];
  let asciiStr = "";

  for (let i = 0; i < width; i++) {
    if (i < bytes.length) {
      const b = bytes[i];
      hexParts.push(b.toString(16).padStart(2, "0"));
      asciiStr += (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : ".";
    } else {
      hexParts.push("  ");
    }
  }

  let hexFormatted = "";
  if (width === 16) {
    hexFormatted = hexParts.slice(0, 8).join(" ") + "  " + hexParts.slice(8).join(" ");
  } else {
    hexFormatted = hexParts.join(" ");
  }

  if (showAscii) {
    return `${offStr}  ${hexFormatted}  |${asciiStr}|`;
  }
  return `${offStr}  ${hexFormatted}`;
}

async function readOne(api, path, options) {
  const buf = api.p.malloc(CHUNK, 1);
  const pathPtr = api.p.stringify(path);

  const fd = await api.chain.syscall(SYS_OPEN, pathPtr, O_RDONLY);
  if (api.isFailure(fd)) {
    await api.log(`open(${path}) = ${api.describe(fd)} (missing, or denied)`);
    return false;
  }
  await api.log(`open(${path}) = fd ${fd.low}`, "success");

  try {
    if (options.offset > 0) {
      const seekVal = new api.int64(options.offset >>> 0, Math.floor(options.offset / 0x100000000));
      const sres = await api.chain.syscall(SYS_LSEEK, fd, seekVal, 0);
      if (api.isFailure(sres)) {
        await api.log(`lseek(${path}, ${options.offset}) failed: ${api.describe(sres)}`, "warn");
      }
    }

    let total = 0;
    let fileOffset = options.offset;
    let hexLeftover = [];
    let textLeftover = "";
    const decoder = new TextDecoder("utf-8", { fatal: false });

    for (;;) {
      const want = options.limit > 0 ? Math.min(CHUNK, options.limit - total) : CHUNK;
      if (want <= 0) break;

      const n = await api.chain.syscall(SYS_READ, fd, buf, want);
      if (api.isFailure(n)) {
        await api.log(`read(${path}) = ${api.describe(n)} (directory or read error)`);
        break;
      }

      const got = n.low >>> 0;
      if (got === 0) break; // EOF
      total += got;

      if (options.mode === "text") {
        const bytes = new Uint8Array(got);
        for (let i = 0; i < got; i++) bytes[i] = api.p.read1(buf.add32(i));
        textLeftover += decoder.decode(bytes, { stream: true });
        const lines = textLeftover.split("\n");
        textLeftover = lines.pop() || "";
        for (const line of lines) {
          await api.log(line.replace(/\r$/, ""));
        }
      } else {
        // Hex / Hexdump mode
        for (let i = 0; i < got; i++) {
          hexLeftover.push(api.p.read1(buf.add32(i)));
        }
        while (hexLeftover.length >= options.width) {
          const row = hexLeftover.slice(0, options.width);
          hexLeftover = hexLeftover.slice(options.width);
          await api.log(formatHexLine(fileOffset, row, options.width, options.mode === "both"));
          fileOffset += options.width;
        }
      }
    }

    if (options.mode === "text") {
      if (textLeftover.replace(/\r$/, "")) {
        await api.log(textLeftover.replace(/\r$/, ""));
      }
    } else if (hexLeftover.length > 0) {
      await api.log(formatHexLine(fileOffset, hexLeftover, options.width, options.mode === "both"));
      fileOffset += hexLeftover.length;
      hexLeftover = [];
    }

    await api.log(`read ${total} bytes of ${path}`, total > 0 ? "success" : "info");
    return total > 0;
  } finally {
    await api.chain.syscall(SYS_CLOSE, fd);
  }
}

return async function (api) {
  const options = {
    mode: "both",
    width: 16,
    offset: 0,
    limit: 65536,
    paths: [],
  };

  for (const arg of api.args || []) {
    if (arg === "text" || arg === "-t") {
      options.mode = "text";
    } else if (arg === "hex") {
      options.mode = "hex";
    } else if (arg === "both" || arg === "-c" || arg === "dump") {
      options.mode = "both";
    } else if (arg.startsWith("width=") || arg.startsWith("w=")) {
      options.width = Math.max(1, Math.min(64, Number(arg.slice(arg.indexOf("=") + 1)) || 16));
    } else if (arg.startsWith("offset=") || arg.startsWith("seek=")) {
      options.offset = Math.max(0, Number(arg.slice(arg.indexOf("=") + 1)) || 0);
    } else if (arg.startsWith("limit=") || arg.startsWith("len=") || arg.startsWith("max=")) {
      options.limit = Math.max(0, Number(arg.slice(arg.indexOf("=") + 1)) || 0);
    } else if (arg === "all") {
      options.limit = 0;
    } else if (!arg.startsWith("-")) {
      options.paths.push(arg);
    }
  }

  const paths = options.paths.length ? options.paths : PROBE_PATHS;
  await api.log(options.paths.length
    ? `reading ${paths.length} path(s) (mode: ${options.mode}, width: ${options.width})`
    : `no path specified, probing ${paths.length} default paths`, "info");

  for (const path of paths) {
    if (await readOne(api, path, options)) return;
  }
  await api.log("none of those were readable", "info");
};
