// Write a PS5 toast notification to /dev/notification0.

const SYS_OPEN = 0x005;
const SYS_CLOSE = 0x006;
const SYS_WRITE = 0x004;

const O_WRONLY = 0x001;

const DEV_NOTIFICATION = "/dev/notification0";
const NOTIFY_BUFFER_SIZE = 0xc30;
const DEFAULT_ICON_URI = "cxml://psnotification/tex_icon_system";
const DEFAULT_MESSAGE = "Hello from WebKit Remote Loader!";

function writeString(p, addr, str, maxLen) {
  const enc = new TextEncoder();
  const bytes = enc.encode(str);
  const len = Math.min(bytes.length, maxLen - 1);
  for (let i = 0; i < len; i++) {
    p.write1(addr.add32(i), bytes[i]);
  }
  p.write1(addr.add32(len), 0);
}

return async function (api) {
  const message = (api.args && api.args.length) ? api.args.join(" ") : DEFAULT_MESSAGE;

  // Allocate notification request buffer (0xc30 = 3120 bytes)
  const buf = api.p.malloc(NOTIFY_BUFFER_SIZE, 1);
  for (let i = 0; i < NOTIFY_BUFFER_SIZE; i += 4) {
    api.p.write4(buf.add32(i), 0);
  }

  // Populate notification structure:
  //   +0x00: type (0 = standard notification)
  //   +0x10: target_id (-1 = default/current user)
  //   +0x2c: use_icon_image_uri (1 = use URI at +0x42d)
  //   +0x2d: message string (max 1024 bytes)
  //   +0x42d: icon URI string (max 1024 bytes)
  api.p.write4(buf.add32(0x00), 0);
  api.p.write4(buf.add32(0x10), 0xffffffff);
  api.p.write1(buf.add32(0x2c), 1);
  writeString(api.p, buf.add32(0x2d), message, 1024);
  writeString(api.p, buf.add32(0x42d), DEFAULT_ICON_URI, 1024);

  const pathPtr = api.p.stringify(DEV_NOTIFICATION);
  const fd = await api.chain.syscall(SYS_OPEN, pathPtr, O_WRONLY);
  if (api.isFailure(fd)) {
    await api.log(`open(${DEV_NOTIFICATION}) failed: ${api.describe(fd)}`, "error");
    return;
  }

  try {
    const written = await api.chain.syscall(SYS_WRITE, fd, buf, NOTIFY_BUFFER_SIZE);
    if (api.isFailure(written)) {
      await api.log(`write(${DEV_NOTIFICATION}) failed: ${api.describe(written)}`, "error");
      return;
    }
    await api.log(`notification displayed: "${message}"`, "success");
  } finally {
    await api.chain.syscall(SYS_CLOSE, fd);
  }
};
