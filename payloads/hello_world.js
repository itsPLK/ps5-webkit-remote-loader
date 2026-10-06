// Minimal loader round-trip check.

return async function (api) {
  await api.log("hello world from payload", "success");
  await api.log(`firmware: ${api.fw}`);

  const pid = await api.chain.syscall(0x014 /* SYS_GETPID */);
  await api.log(`getpid = ${pid.low}`);

  await api.log(`krw is ${api.krw ? "established" : "null (no kernel exploit needed)"}`, "info");
};
