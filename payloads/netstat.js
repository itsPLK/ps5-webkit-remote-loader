// List interfaces and probe TCP ports.

const SYS_CLOSE = 0x006;
const SYS_SOCKET = 0x061;
const SYS_CONNECT = 0x062;
const SYS_NETGETIFLIST = 0x07d;

const AF_INET = 2;
const SOCK_STREAM = 1;
const IF_RECORD_SIZE = 0x3c0; // 960 bytes per interface record

const KNOWN_SERVICES = {
  21: "FTP (File Transfer)",
  22: "SSH (Secure Shell)",
  23: "Telnet / Shell (shsrv)",
  53: "DNS",
  80: "HTTP Server",
  443: "HTTPS Server",
  1337: "FTP Server (Homebrew)",
  2121: "FTP Server (Alt)",
  3232: "Telnet Server (Homebrew)",
  8080: "HTTP (Proxy/Dev)",
  8081: "HTTP Alt",
  9019: "WebKit Debugger",
  9020: "WebKit Remote Loader (Alt)",
  9021: "elfldr (PS5 ELF Loader daemon)",
  9027: "ps5-webkit-remote-loader",
  9028: "Kernel Log Server (klogd)",
  9295: "PS Remote Play (TCP)",
  9296: "PS Remote Play (UDP)",
  9297: "PS Remote Play (UDP)",
  9999: "GDB / Debug Server",
  18180: "Remote Loader Installer HTTP Server",
  28280: "etaHEN Control Server",
  32323: "Remote Lua Loader",
};

const DEFAULT_PORTS = [
  21, 22, 23, 53, 80, 443, 1337, 2121, 3232, 8080, 8081,
  9019, 9020, 9021, 9027, 9028, 9295, 9296, 9297, 9999,
  18180, 28280, 32323,
];

function parseOptions(argv) {
  const opts = {
    showInterfaces: true,
    showPorts: true,
    ports: [],
    json: false,
    help: false,
  };

  let modeSpecified = false;

  for (const raw of argv) {
    const arg = String(raw).trim();
    if (!arg) continue;

    const eq = arg.indexOf("=");
    if (eq !== -1) {
      const key = arg.slice(0, eq).toLowerCase();
      const val = arg.slice(eq + 1).trim();

      if (key === "port") {
        const n = parseInt(val, 10);
        if (!isNaN(n) && n > 0 && n <= 65535) opts.ports.push(n);
        modeSpecified = true;
      } else if (key === "ports") {
        for (const part of val.split(",")) {
          const n = parseInt(part.trim(), 10);
          if (!isNaN(n) && n > 0 && n <= 65535) opts.ports.push(n);
        }
        modeSpecified = true;
      } else if (key === "range" || key === "scan") {
        const parts = val.split("-");
        if (parts.length === 2) {
          let start = parseInt(parts[0], 10);
          let end = parseInt(parts[1], 10);
          if (!isNaN(start) && !isNaN(end)) {
            if (start > end) [start, end] = [end, start];
            start = Math.max(1, start);
            end = Math.min(65535, end);
            // Cap at 2000 ports to prevent socket exhaustion/delays
            if (end - start > 2000) end = start + 2000;
            for (let p = start; p <= end; p++) opts.ports.push(p);
            modeSpecified = true;
          }
        }
      }
      continue;
    }

    const lower = arg.toLowerCase();
    if (lower === "json") {
      opts.json = true;
    } else if (lower === "-i" || lower === "interfaces" || lower === "iface") {
      opts.showInterfaces = true;
      opts.showPorts = false;
      modeSpecified = true;
    } else if (lower === "-l" || lower === "listen" || lower === "listening" || lower === "ports") {
      opts.showInterfaces = false;
      opts.showPorts = true;
      modeSpecified = true;
    } else if (lower === "-a" || lower === "all") {
      opts.showInterfaces = true;
      opts.showPorts = true;
      modeSpecified = true;
      for (let p = 1; p <= 1024; p++) {
        if (!opts.ports.includes(p)) opts.ports.push(p);
      }
    } else if (lower === "help" || lower === "-h" || lower === "--help") {
      opts.help = true;
    } else if (/^\d+$/.test(arg)) {
      const n = parseInt(arg, 10);
      if (n > 0 && n <= 65535) {
        opts.ports.push(n);
        opts.showInterfaces = false;
        opts.showPorts = true;
        modeSpecified = true;
      }
    }
  }

  if (opts.ports.length === 0) {
    opts.ports = DEFAULT_PORTS.slice();
  } else {
    opts.ports = Array.from(new Set(opts.ports)).sort((a, b) => a - b);
  }

  return opts;
}

async function getInterfaces(api) {
  const countRes = await api.chain.syscall(SYS_NETGETIFLIST, 0, 10);
  if (api.isFailure(countRes)) return [];
  const count = countRes.low | 0;
  if (count <= 0 || count > 32) return [];

  const list = api.p.malloc(IF_RECORD_SIZE * count, 1);
  const rv = await api.chain.syscall(SYS_NETGETIFLIST, list, count);
  if (api.isFailure(rv)) return [];

  const interfaces = [];
  for (let i = 0; i < count; i++) {
    const base = list.add32(IF_RECORD_SIZE * i);

    let name = "";
    for (let c = 0; c < 16; c++) {
      const ch = api.p.read1(base.add32(c));
      if (ch === 0) break;
      name += String.fromCharCode(ch);
    }
    if (!name) continue;

    const flags = api.p.read4(base.add32(0x20));
    const isUp = (flags & 1) !== 0;

    const ipBytes = [0, 1, 2, 3].map((b) => api.p.read1(base.add32(40 + b)));
    const ip = ipBytes.join(".");

    const maskBytes = [0, 1, 2, 3].map((b) => api.p.read1(base.add32(0x34 + b)));
    const netmask = maskBytes.join(".");

    const macBytes = [];
    for (let b = 0; b < 6; b++) {
      macBytes.push(api.p.read1(base.add32(0x50 + b)).toString(16).padStart(2, "0"));
    }
    const mac = isUp ? macBytes.join(":") : "-";
    const mtu = isUp ? (api.p.read4(base.add32(0x58)) >>> 0) : 0;

    interfaces.push({
      name,
      status: isUp ? "UP" : "DOWN",
      ip: (ip === "0.0.0.0" || !isUp) ? "-" : ip,
      netmask: (netmask === "0.0.0.0" || !isUp) ? "-" : netmask,
      mac,
      mtu: mtu > 0 ? mtu : "-",
    });
  }

  return interfaces;
}

async function probePorts(api, ports) {
  const scratch = api.p.malloc(0x100, 1);
  const sockaddr = scratch;
  const openPorts = [];

  for (const port of ports) {
    const sRv = await api.chain.syscall(SYS_SOCKET, AF_INET, SOCK_STREAM, 0);
    if (api.isFailure(sRv) || sRv.low < 0) continue;
    const sock = sRv.low;

    // sockaddr_in layout: sin_len (1), sin_family (1), sin_port (2), sin_addr (4), sin_zero (8)
    api.p.write1(sockaddr, 16);
    api.p.write1(sockaddr.add32(1), AF_INET);
    api.p.write1(sockaddr.add32(2), (port >> 8) & 0xff);
    api.p.write1(sockaddr.add32(3), port & 0xff);
    api.p.write1(sockaddr.add32(4), 127);
    api.p.write1(sockaddr.add32(5), 0);
    api.p.write1(sockaddr.add32(6), 0);
    api.p.write1(sockaddr.add32(7), 1);
    for (let i = 8; i < 16; i++) api.p.write1(sockaddr.add32(i), 0);

    const cRv = await api.chain.syscall(SYS_CONNECT, sock, sockaddr, 16);
    await api.chain.syscall(SYS_CLOSE, sock);

    if (cRv.low === 0) {
      openPorts.push({
        port,
        proto: "TCP",
        state: "LISTEN",
        service: KNOWN_SERVICES[port] || "unknown",
      });
    }
  }

  return openPorts;
}

return async function (api) {
  const argv = (api.args && api.args.length) ? api.args : ((api.argv && api.argv.length) ? api.argv : []);
  const opts = parseOptions(argv);

  if (opts.help) {
    await api.log("Usage: netstat.js [interfaces] [listen] [all] [port=N] [range=A-B] [json]");
    await api.log("  interfaces   Show network interfaces only");
    await api.log("  listen       Show active listening ports only");
    await api.log("  all          Scan all privileged ports (1-1024) and known services");
    await api.log("  port=N, <N>  Check a single port (e.g. 9021)");
    await api.log("  range=A-B    Check a port range (e.g. range=9000-9100)");
    await api.log("  json         Output structured JSON object");
    return;
  }

  let interfaces = [];
  if (opts.showInterfaces) {
    interfaces = await getInterfaces(api);
  }

  let openPorts = [];
  if (opts.showPorts) {
    openPorts = await probePorts(api, opts.ports);
  }

  if (opts.json) {
    const payload = {};
    if (opts.showInterfaces) payload.interfaces = interfaces;
    if (opts.showPorts) {
      payload.open_ports = openPorts;
      payload.ports_checked = opts.ports.length;
    }
    await api.log(JSON.stringify(payload, null, 2));
    return;
  }

  if (opts.showInterfaces) {
    await api.log("=== Network Interfaces ===", "info");
    await api.log("  Name    Status  IP Address       Netmask          MAC Address        MTU");
    for (const iface of interfaces) {
      const n = iface.name.padEnd(7, " ");
      const s = iface.status.padEnd(7, " ");
      const ip = iface.ip.padEnd(16, " ");
      const m = iface.netmask.padEnd(16, " ");
      const mac = iface.mac.padEnd(18, " ");
      await api.log(`  ${n} ${s} ${ip} ${m} ${mac} ${iface.mtu}`);
    }
  }

  if (opts.showPorts) {
    if (opts.showInterfaces) await api.log("");
    await api.log(`=== Active Listening Ports (${openPorts.length} open, ${opts.ports.length} scanned) ===`, "info");
    await api.log("  Port   Proto  State   Service");
    for (const op of openPorts) {
      const p = String(op.port).padStart(6, " ");
      const pr = op.proto.padEnd(6, " ");
      const st = op.state.padEnd(7, " ");
      await api.log(`  ${p} ${pr} ${st} ${op.service}`);
    }
  }
};
