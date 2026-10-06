#!/usr/bin/env python3
"""Embed the loader, firmware tables, worker, binaries, and payloads in one HTML file.

    python3 tools/build_standalone.py payloads/hello_world.js -o dist/ps5.html --probe

Per-payload arguments use PAYLOAD::arg1,arg2. Use --no-kexp to omit kernel binaries.
Use --css FILE and --js FILE to embed page styles and awaited startup scripts.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

if HERE not in sys.path:
    sys.path.insert(0, HERE)


CLASSIC_SCRIPTS = [
    "src/firmware.js",
    "src/main.js",
    "src/rop.js",
    "src/utils/syscalls.js",
]

# The ES module entry points. Their import graph is walked from here.
MODULE_ROOTS = ["src/site.js"]

EXTRA_MODULES = ["src/socket_test.js"]


def repo_path(rel):
    return os.path.join(ROOT, rel)


def read_text(rel):
    with open(repo_path(rel), "r", encoding="utf-8") as f:
        return f.read()


def read_bytes(rel):
    with open(repo_path(rel), "rb") as f:
        return f.read()


# --- module graph -----------------------------------------------------------

IMPORT_RE = re.compile(
    r'^\s*import\s+(?P<clause>[^;]*?)\s+from\s+["\'](?P<spec>[^"\']+)["\']\s*;?\s*$',
    re.MULTILINE | re.DOTALL,
)
BARE_IMPORT_RE = re.compile(r'^\s*import\s+["\'](?P<spec>[^"\']+)["\']\s*;?\s*$', re.MULTILINE)
EXPORT_LIST_RE = re.compile(r'^\s*export\s*\{(?P<inner>[^}]*)\}\s*;?\s*$', re.MULTILINE)
EXPORT_STAR_RE = re.compile(r'^\s*export\s*\*\s+from\s+["\'][^"\']+["\']\s*;?\s*$', re.MULTILINE)
EXPORT_DECL_RE = re.compile(
    r'^\s*export\s+(?=(?:const|let|var|function|async\s+function|class)\s)', re.MULTILINE)
DYNAMIC_IMPORT_RE = re.compile(r'\bimport\s*\(\s*(["\'])(?P<spec>[^"\']+)\1\s*\)')


def resolve_spec(spec, importer):
    """'./utils/int64.js' as written in src/loader.js -> 'src/utils/int64.js'."""
    if not spec.startswith("."):
        return None
    return os.path.normpath(os.path.join(os.path.dirname(importer), spec)).replace(os.sep, "/")


def collect_modules(roots):
    """Walk the import graph. Returns (dependency_order, edges, missing)."""
    ordered = []
    seen = set()
    missing = []
    edges = {}

    def visit(rel):
        rel = os.path.normpath(rel).replace(os.sep, "/")
        if rel in seen:
            return
        seen.add(rel)
        if not os.path.exists(repo_path(rel)):
            missing.append(rel)
            return
        body = read_text(rel)
        specs = [m.group("spec") for m in IMPORT_RE.finditer(body)]
        specs += [m.group("spec") for m in BARE_IMPORT_RE.finditer(body)]
        deps = []
        for spec in specs:
            target = resolve_spec(spec, rel)
            if target is None:
                raise SystemExit(
                    "%s imports the bare specifier %r. The single-file builder only "
                    "resolves relative paths." % (rel, spec))
            deps.append(target)
        edges[rel] = sorted(set(deps))
        for dep in edges[rel]:
            visit(dep)
        # Dependencies first, so a module's declarations exist before the module
        # that reads them does.
        ordered.append(rel)

    for root in roots:
        visit(root)
    return ordered, edges, missing


def close_over_dynamic_imports(ordered, edges, missing):
    """Add every dynamically imported module to the graph, dependencies first."""
    while True:
        order = list(ordered)
        edges = dict((rel, list(deps)) for rel, deps in edges.items())
        added = False
        for rel in order:
            for m in DYNAMIC_IMPORT_RE.finditer(read_text(rel)):
                spec = resolve_spec(m.group("spec"), rel)
                if spec is None:
                    raise SystemExit(
                        "%s dynamically imports the bare specifier %r; the single-file "
                        "builder only resolves relative paths" % (rel, m.group("spec")))
                if spec in edges or spec in missing:
                    continue
                if not os.path.exists(repo_path(spec)):
                    raise SystemExit("%s dynamically imports %s, which does not exist"
                                     % (rel, spec))
                edges[spec] = []
                ordered.append(spec)
                missing = [x for x in missing if x != spec]
                added = True
        if not added:
            return ordered, edges, missing


def flatten_module(rel, edges):
    """One module -> classic-script source: an IIFE over its exports object."""
    body = read_text(rel)
    exports = []
    imports = []
    out = body

    # export { a, b as c };
    def export_list(m):
        for part in m.group("inner").split(","):
            part = part.strip()
            if not part:
                continue
            local, _, public = part.partition(" as ")
            local, public = local.strip(), (public or local).strip()
            exports.append((public, local))
        return ""

    out = EXPORT_LIST_RE.sub(export_list, out)
    out = EXPORT_STAR_RE.sub("", out)

    # export const/let/var/function/async function/class -> bare declaration.
    for m in list(EXPORT_DECL_RE.finditer(out)):
        rest = out[m.end():]
        named = re.match(
            r'(?:async\s+function\s*\*?\s*|function\s*\*?\s*|class\s+|const\s+|let\s+|var\s+)'
            r'([A-Za-z_$][\w$]*)', rest)
        if named:
            exports.append((named.group(1), named.group(1)))
    out = EXPORT_DECL_RE.sub("", out)

    if re.search(r'^\s*export\s+default\b', out, re.MULTILINE):
        raise SystemExit(
            "%s uses `export default`, which the single-file builder does not support. "
            "Nothing in this repo does; add explicit support here rather than letting "
            "it reach the console as a syntax error." % rel)

    def import_clause(m):
        clause, spec = m.group("clause"), m.group("spec")
        target = resolve_spec(spec, rel)
        star = re.search(r'\*\s+as\s+([A-Za-z_$][\w$]*)', clause)
        if star:
            return "const %s = __req(%s);" % (star.group(1), json.dumps(target))

        brace = re.search(r'\{(?P<inner>[^}]*)\}', clause)
        if not brace:
            raise SystemExit("%s: unrecognised import clause %r" % (rel, clause.strip()))
        pairs = []
        for part in brace.group("inner").split(","):
            part = part.strip()
            if not part:
                continue
            local, _, public = part.partition(" as ")
            local = local.strip()
            public = (public or local).strip()
            pairs.append((public, local))
        if not pairs:
            return ";"
        imports.append(target)
        return "const { %s } = __req(%s);" % (
            ", ".join("%s%s" % (public, "" if public == local else ": " + local)
                      for public, local in pairs),
            json.dumps(target))

    out = IMPORT_RE.sub(import_clause, out)
    out = BARE_IMPORT_RE.sub(
        lambda m: "__req(%s);" % json.dumps(resolve_spec(m.group("spec"), rel)), out)

    out = DYNAMIC_IMPORT_RE.sub(
        lambda m: "__req.dynamic(%s)"
        % json.dumps(resolve_spec(m.group("spec"), rel) or m.group("spec")),
        out)

    leftover = re.search(r'^\s*(?:import|export)\s.*$', out, re.MULTILINE)
    if leftover:
        raise SystemExit("%s: unhandled module syntax %r -- the builder could not flatten it."
                         % (rel, leftover.group(0).strip()))

    tail = "".join("  __x[%s] = %s;\n" % (json.dumps(public), local)
                   for public, local in exports)

    source = ("// %s\n(function (__x) {\n%s%s})(__ns);\n" % (rel, out, tail))
    return source, exports


# --- offsets and binaries ---------------------------------------------------

def load_offsets():
    """Every firmware's offsets table, keyed by version string."""
    out = {}
    for name in sorted(os.listdir(repo_path("offsets"))):
        if name.endswith(".js"):
            out[name[:-3]] = read_text(os.path.join("offsets", name))
    return out


def load_binary_config():
    """The two bundled binary paths, parsed out of src/binaries.js."""
    body = read_text("src/binaries.js")
    paths = dict((m.group(1), m.group(2)) for m in
                 re.finditer(r'^\s*(KEXP_BIN|ELFLDR_ELF)\s*:\s*"([^"]+)"', body, re.MULTILINE))
    missing = {"KEXP_BIN", "ELFLDR_ELF"} - set(paths)
    if missing:
        raise SystemExit("src/binaries.js does not declare %s" % sorted(missing))
    return paths["KEXP_BIN"], paths["ELFLDR_ELF"]


# --- payloads ---------------------------------------------------------------

class Payload(object):
    def __init__(self, path, args):
        self.path = path
        self.args = args
        self.label = os.path.basename(path)
        with open(repo_path(path), "r", encoding="utf-8") as f:
            self.source = f.read()

    @property
    def byte_length(self):
        return len(self.source.encode("utf-8"))

    @property
    def sha256(self):
        return hashlib.sha256(self.source.encode("utf-8")).hexdigest()[:16]


def parse_payload_spec(spec):
    """'payloads/x.js' or 'payloads/x.js::arg1,arg2'."""
    if "::" in spec:
        path, _, argstr = spec.partition("::")
        args = [a for a in (x.strip() for x in argstr.split(",")) if a]
        return path, args
    return spec, []


def load_payloads(specs):
    payloads = []
    for spec in specs:
        path, args = parse_payload_spec(spec)
        if not os.path.exists(repo_path(path)):
            raise SystemExit("payload not found: %s" % path)
        payloads.append(Payload(path, args))
    return payloads


# --- the runtime that replaces the network and the module graph -------------

RUNTIME_JS = r"""
// === single-file runtime ====================================================
// Generated by tools/build_standalone.py. It exists because the page is one file:
// there is no module graph left to resolve and no server to fetch from.

// --- the module registry ---------------------------------------------------
//
// Each module was flattened into an IIFE taking an exports object (__x). Its
// dependencies are realised by running those IIFEs first and copying the requested
// names onto the importer's __x -- which is what an ES module import is, minus the
// live bindings and the cycle handling. Neither matters: the builder rejects a
// cycle before writing, and every import in this repo is read at call time.
(function () {
  "use strict";

  var built = {};
  var building = null;

  function namespace(rel) {
    if (built[rel]) return built[rel];
    if (building) {
      throw new Error("circular import: " + building.join(" -> ") + " -> " + rel);
    }
    building = [rel];

    // Read through window each time rather than capturing it once at the top: the
    // page defines __modules before this block runs, so a captured reference would
    // work, but reading it late means a script-order mistake shows up as "module not
    // found" rather than as a registry that silently holds nothing.
    var sources = window.__modules || {};
    var source = sources[rel];
    if (typeof source !== "string") {
      throw new Error("module not found in this page: " + rel);
    }

    var ns = {};
    // Set before running, so a module that reaches itself gets the same (partial)
    // object it will end up with rather than a second one.
    built[rel] = ns;

    // __req is the local name an import binds to, so a flattened module's
    // `const { x } = __req("...")` resolves the dependency and runs it on demand.
    // __dyn is what a dynamic import() became; it returns a promise so
    // `await import(...)` in the source still reads and works as written.
    var require = function (target) { return namespace(target); };
    require.dynamic = function (target) {
      return Promise.resolve().then(function () { return namespace(target); });
    };

    new Function("__x", "__req", "__ns", source)(ns, require, ns);
    building = null;
    return ns;
  }

  // A page that holds no reference to a module's namespace -- site.js does, because it
  // imported what it needs -- cannot reach one later. Exposed so it can: a payload
  // author inspecting the console on a device has no other way to call
  // __namespace("src/kexp.js").runKexp and see what it does. Unused by the loader.
  window.__namespace = function (rel) { return namespace(rel); };

  // Run every module, so that anything reached only by a dynamic import is
  // registered before the page needs it. Order is the builder's dependency order,
  // so a module never observes a half-built dependency.
  window.__boot = function () {
    var order = window.__order;
    for (var i = 0; i < order.length; i++) namespace(order[i]);
  };
})();
"""

INLINE_ENV_JS = r"""
// === inline environment ===================================================
//
// Three things a served page gets from the host, supplied here from the page itself.
// Generated by tools/build_standalone.py. MUST be evaluated before src/main.js, which
// reads both of these while it loads.

(function () {
  "use strict";

  // The Worker to hijack.
  //
  // A Blob URL rather than an inline <script>, because the worker has to be a real
  // thread of its own: prepareRop() finds that thread in the kernel's thread list and
  // hijacks its stack. rop_slave.js is unchanged; only the URL it comes from is.
  window.ropWorkerFactory = function () {
    if (typeof Blob !== "function" ||
        (typeof URL !== "undefined" && typeof URL.createObjectURL !== "function")) {
      throw new Error(
        "this WebKit has no Blob URLs, so the ROP worker cannot be created inline. " +
        "Serve the repository with host.py and run the payload with tools/send.py.");
    }
    var source = document.getElementById("rop-slave-source").textContent;
    var url = URL.createObjectURL(new Blob([source], { type: "text/javascript" }));
    // The object URL is deliberately not revoked: on some engines the worker has not
    // finished loading when the constructor returns, and it is a few dozen bytes for a
    // five-line script.
    return new Worker(url);
  };

  // Inject firmware offsets table into global scope via a script element.
  window.moduleLoader = function (specifier) {
    // Resolve classic script imports against the embedded module registry.
    var rel = String(specifier);
    while (rel.indexOf("./") === 0) rel = rel.slice(2);

    var keys = Object.keys(window.__modules || {});
    for (var i = 0; i < keys.length; i++) {
      if (keys[i] === specifier || keys[i].endsWith("/" + rel)) {
        return Promise.resolve(window.__namespace(keys[i]));
      }
    }
    return Promise.reject(new Error(
      "this page has no module for " + specifier + " (looked for " + keys.join(", ") +
      "). It should have been built into the file; rebuild it with " +
      "tools/build_standalone.py."));
  };

  window.offsetsInline = function (fw) {
    var tables = window.__offsets || {};
    var source = tables[fw];
    if (typeof source !== "string") {
      throw new Error(
        "no offsets are embedded for firmware " + (fw || "(unknown)") +
        ". This file carries: " + Object.keys(tables).sort().join(", "));
    }

    var script = document.createElement("script");
    script.text = source;
    document.head.appendChild(script);

    // Verify that expected offset constants were defined in global scope.
    if (__OFFSETS_MISSING_CHECK__) {
      throw new Error("offsets/" + fw + ".js evaluated but did not define: " +
        __OFFSETS_MISSING_CHECK__);
    }
    return fw;
  };
})();
"""


BOOT_JS = r"""
// === boot ==================================================================
// Runs the module graph, starting the exploit via site.js.
(function () {
  "use strict";

  function report(message, type) {
    if (window.writeLog) window.writeLog(message, type || "log");
    else console.error(message);
  }

  try {
    window.__boot();
  } catch (e) {
    report("module graph failed to load: " + (e && e.message ? e.message : e), "error");
  }
})();
"""

STARTUP_BOOT_JS = r"""
// === startup scripts, then boot ============================================
// Runs awaited startup scripts before starting the exploit via site.js.
(function () {
  "use strict";

  function report(message) {
    if (window.writeLog) {
      window.writeLog(message, "error");
      return;
    }
    console.error(message);
    var output = document.getElementById("console");
    if (output) {
      var line = document.createElement("div");
      line.className = "log-line log-error";
      line.textContent = message;
      output.appendChild(line);
    }
  }

  window.__startupReady = (async function () {
    var current = null;
    try {
      var AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
      for (var i = 0; i < window.__startupScripts.length; i++) {
        current = window.__startupScripts[i];
        await new AsyncFunction(current.source).call(window);
      }
      current = null;
      window.__boot();
      return true;
    } catch (error) {
      report((current ? "startup script " + current.path + " failed: "
                      : "module graph failed to load: ") +
        (error && error.message ? error.message : error));
      return false;
    }
  })();
})();
"""

REQUIRED_OFFSET_GLOBALS = [
    "OFFSET_wk_host_constructor_candidates",
    "OFFSET_wk_memset_import",
    "OFFSET_wk___stack_chk_guard_import",
    "OFFSET_lk___stack_chk_guard",
    "OFFSET_lk__thread_list",
    "OFFSET_lk_worker_wait_return",
    "OFFSET_lc_memset",
    "OFFSET_lc_setjmp",
    "OFFSET_lc_longjmp",
    "wk_gadgetmap",
    "syscall_map",
]


def inline_env_js():
    """Insert bare-identifier checks for classic-script lexical globals."""
    names = " || ".join(
        '(typeof %s === "undefined" && "%s")' % (name, name)
        for name in REQUIRED_OFFSET_GLOBALS)
    return INLINE_ENV_JS.replace("__OFFSETS_MISSING_CHECK__", names)


def js_string(value):
    """Encode JSON for a script element, escaping </ so the HTML parser cannot close it."""
    text = json.dumps(value, ensure_ascii=False)
    return text.replace("</", "<\\/")


def escape_html(text):
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


# --- building ---------------------------------------------------------------

def load_page_assets(paths, kind):
    assets = []
    for filename in paths or []:
        path = os.fspath(filename)
        try:
            with open(path, "r", encoding="utf-8") as f:
                source = f.read()
        except (OSError, UnicodeError) as error:
            raise SystemExit("--%s cannot read %s: %s" % (kind, path, error))
        if kind == "css" and re.search(r"</style", source, re.IGNORECASE):
            raise SystemExit("--css %s contains a closing style tag; use a CSS escape "
                             "such as \\3c /style instead" % path)
        assets.append({"path": path, "source": source})
    return assets


def build_html(payloads, title=None, include_kexp=True, embedded_files=None,
               css_files=None, js_files=None, elfldr_url=None):
    styles = load_page_assets(css_files, "css")
    startup_scripts = load_page_assets(js_files, "js")
    ordered, edges, missing = collect_modules(MODULE_ROOTS)
    if missing:
        raise SystemExit("unresolved relative imports: %s" % ", ".join(sorted(missing)))

    # A cycle flattens into code that reads a binding before its declaration, which
    # fails on the console and nowhere else.
    position = dict((rel, i) for i, rel in enumerate(ordered))
    for rel, deps in edges.items():
        for dep in deps:
            if position.get(dep, -1) > position[rel]:
                raise SystemExit("module cycle: %s is ordered after %s" % (dep, rel))

    ordered, edges, missing = close_over_dynamic_imports(ordered, edges, missing)

    # EXTRA_MODULES, for the reachability the graph walk cannot see at all.
    for rel in EXTRA_MODULES:
        if rel not in edges:
            if not os.path.exists(repo_path(rel)):
                raise SystemExit("EXTRA_MODULES names a file that does not exist: %s" % rel)
            ordered.append(rel)
            edges[rel] = []

    modules = {}
    for rel in ordered:
        modules[rel], _ = flatten_module(rel, edges)

    offsets = load_offsets()
    default_kexp_path, default_elfldr_path = load_binary_config()
    current_elfldr_path = elfldr_url or default_elfldr_path
    binaries = {}
    if include_kexp:
        for path in (default_kexp_path, current_elfldr_path):
            if path not in (embedded_files or {}):
                binaries[path] = base64.b64encode(read_bytes(path)).decode("ascii")
    # Additional resources and binary overrides use the same inline fetch as kexp.
    # Paths are virtual URLs; input files may live outside this repository.
    for path, filename in (embedded_files or {}).items():
        with open(filename, "rb") as f:
            binaries[path] = base64.b64encode(f.read()).decode("ascii")

    index_html = read_text("index.html")
    style = re.search(r"<style>(?P<body>.*?)</style>", index_html, re.DOTALL)
    body = re.search(r"<body>(?P<body>.*?)</body>", index_html, re.DOTALL)
    if not style or not body:
        raise SystemExit("index.html no longer has the <style>/<body> this tool copies")
    markup = re.sub(r"<script\b[^>]*>.*?</script>", "", body.group("body"), flags=re.DOTALL)
    # A standalone page opens no loader socket. Keep the served page's HUD and
    # its reserved console space out of the generated document.
    markup = re.sub(r"<!-- Remote-loader only -->.*?<!-- End remote-loader only -->",
                    "", markup, flags=re.DOTALL)
    page_style = re.sub(r"/\* Remote-loader only \*/.*?/\* End remote-loader only \*/",
                        "", style.group("body"), flags=re.DOTALL)

    page_title = title or (", ".join(p.label for p in payloads)[:80]) or "payloads"
    rendered_title = page_title
    if title:
        if "[[VERSION_PLACEHOLDER]]" in rendered_title or "[[BUILD_TIME_PLACEHOLDER]]" in rendered_title:
            try:
                from gen_version import get_version_info
                info = get_version_info()
                rendered_title = rendered_title.replace("[[VERSION_PLACEHOLDER]]", info.get("full", ""))
                rendered_title = rendered_title.replace("[[BUILD_TIME_PLACEHOLDER]]", info.get("build_time", ""))
            except Exception:
                pass
    queue = [{"name": p.label, "path": p.path, "args": p.args, "source": p.source}
             for p in payloads]

    out = []
    add = out.append
    add("<!DOCTYPE html>")
    add('<html lang="en">')
    add("<head>")
    add('  <meta charset="utf-8">')
    add('  <meta name="viewport" content="width=device-width, initial-scale=1">')
    add('  <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">')
    if title:
        add("  <title>%s</title>" % escape_html(rendered_title))
    else:
        add("  <title>PS5 WebKit Standalone: %s</title>" % escape_html(page_title))
    add("  <style>%s  </style>" % page_style)
    for asset in styles:
        add('  <style data-user-css="%s">\n%s\n  </style>'
            % (escape_html(asset["path"]), asset["source"]))
    add("  <!--")
    add("    Generated by tools/build_standalone.py. Do not edit; rebuild it.")
    add("    payload(s), in run order:")
    for p in payloads:
        add("      %-28s %8d bytes  sha256:%s  args:%s"
            % (p.path, p.byte_length, p.sha256, ",".join(p.args) or "(none)"))
    add("    offsets embedded: %d firmwares (%s)"
        % (len(offsets), " ".join(sorted(offsets))))
    add("    embedded files:    %s" % (", ".join(sorted(binaries)) or "NONE"))
    add("  -->")
    add("</head>")
    add("<body>")
    add(markup.strip("\n"))

    add("")
    add("  <!-- The ROP worker's source, as data. type=text/plain so the page does")
    add("       not run it on the main thread; BOOT_JS turns it into a Blob URL. -->")
    add('  <script id="rop-slave-source" type="text/plain">%s</script>'
        % read_text("src/utils/rop_slave.js").replace("</", "<\\/"))

    add("")
    add("  <!-- The embedded data: the module graph, the offsets, the binaries, the queue. -->")
    add("  <script>")
    add("  window.__modules = %s;" % js_string(modules))
    add("  window.__order = %s;" % js_string(ordered))
    add("  window.__offsets = %s;" % js_string(offsets))
    if binaries:
        add("  window.EMBEDDED_BINARIES = %s;" % js_string(binaries))
        add("  window.EMBEDDED_BINARY_INFO = %s;" % js_string({
            path: {"size": len(base64.b64decode(data)),
                   "sha256": hashlib.sha256(base64.b64decode(data)).hexdigest()}
            for path, data in binaries.items()
        }))
    if current_elfldr_path != default_elfldr_path:
        add("  window.LOADER_CONFIG = %s;"
            % js_string({"ELFLDR_ELF": current_elfldr_path}))
    add("  window.STANDALONE = %s;" % js_string({
        "title": rendered_title if title else None,
        "payloadCount": len(payloads),
        "payloadNames": [p.label for p in payloads],
        "payloads": queue,
    }))
    if startup_scripts:
        # Escape every '<', including HTML comment/script openers inside JS
        # strings, so arbitrary source survives the HTML raw-text parser.
        add("  window.__startupScripts = %s;"
            % js_string(startup_scripts).replace("<", "\\u003c"))
    add("  </script>")

    add("")
    add("  <script>")
    add("  /* === runtime === */")
    add(RUNTIME_JS.strip("\n"))
    add("  </script>")

    # Environment hooks precede classic scripts; boot runs after their globals exist.
    add("")
    add("  <script>")
    add("  /* === inline environment (must precede src/main.js) === */")
    add(inline_env_js().strip("\n"))
    add("  </script>")

    for rel in CLASSIC_SCRIPTS:
        add("")
        add("  <script>")
        add("  /* === %s === */" % rel)
        add(read_text(rel).strip("\n"))
        add("  </script>")

    add("")
    add("  <script>")
    add("  /* === boot (must come last: it runs the module graph) === */")
    add((STARTUP_BOOT_JS if startup_scripts else BOOT_JS).strip("\n"))
    add("  </script>")

    add("")
    add("</body>")
    add("</html>")
    html = "\n".join(out) + "\n"

    meta = {
        "modules": len(modules),
        "offsets": len(offsets),
        "kexp": include_kexp,
        "binaries": sorted(binaries.keys()),
        "bytes": len(html),
        "css": styles,
        "js": startup_scripts,
    }
    return html, meta


# --- verification -----------------------------------------------------------

def extract_json_assignment(html, name):
    """Pull the JSON value out of a `window.<name> = <json>;` line."""
    m = re.search(r"^\s*window\.%s\s*=\s*" % re.escape(name), html, re.MULTILINE)
    if not m:
        return None
    start = m.end()
    try:
        value, _ = json.JSONDecoder().raw_decode(html[start:])
    except ValueError as e:
        raise SystemExit("the generated window.%s assignment is not valid JSON: %s" % (name, e))
    return value


def load_module_specs():
    """The specifiers src/main.js passes to loadModule()."""
    specs = []
    for line in read_text("src/main.js").split("\n"):
        code = line.split("//", 1)[0]
        m = re.search(r'loadModule\(\s*["\']([^"\']+)["\']\s*\)', code)
        if m:
            specs.append(m.group(1))
    return specs


def find_script_close(value, path="<root>"):
    """The path to the first string in `value` containing a literal "</script"."""
    if isinstance(value, str):
        if "</script" in value.lower():
            return path
    elif isinstance(value, dict):
        for key in value:
            found = find_script_close(value[key], "%s.%s" % (path, key))
            if found:
                return found
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            found = find_script_close(item, "%s[%d]" % (path, i))
            if found:
                return found
    return None


def check_output(html, payloads, meta):
    """What can be checked without a console."""
    problems = []

    for asset in meta.get("css", []):
        expected = '<style data-user-css="%s">\n%s\n  </style>' % (
            escape_html(asset["path"]), asset["source"])
        if expected not in html[:html.find("</head>")]:
            problems.append("CSS %s was not embedded in the head" % asset["path"])
    if meta.get("js"):
        if extract_json_assignment(html, "__startupScripts") != meta["js"]:
            problems.append("startup scripts did not survive into the output byte for byte")
        if STARTUP_BOOT_JS.strip("\n") not in html:
            problems.append("the awaited startup script runner is missing")

    # The HTML parser closes script elements even inside JS strings.
    for name in ("STANDALONE", "__offsets", "__modules"):
        value = extract_json_assignment(html, name)
        if value is None:
            continue
        offender = find_script_close(value)
        if offender:
            problems.append("%s embeds a literal </script> at %s, which would truncate "
                            "the page there" % (name, offender))

    # The payloads, byte for byte, as the page will actually read them.
    standalone = extract_json_assignment(html, "STANDALONE")
    if standalone is None:
        problems.append("the output has no window.STANDALONE assignment")
    else:
        queued = standalone.get("payloads") or []
        if len(queued) != len(payloads):
            problems.append("the queue holds %d payload(s), expected %d"
                            % (len(queued), len(payloads)))
        for payload, entry in zip(payloads, queued):
            if entry.get("source") != payload.source:
                problems.append("payload %s did not survive into the output byte for byte"
                                % payload.path)
            if entry.get("name") != payload.label:
                problems.append("payload %s is queued under the wrong name" % payload.path)

    # The offsets, decoded the same way and compared against the directory. A table
    # that went in but not out is a console that boots to "no offsets are embedded".
    tables = extract_json_assignment(html, "__offsets")
    if tables is None:
        problems.append("the output has no window.__offsets assignment")
    else:
        absent = sorted(set(load_offsets()) - set(tables))
        if absent:
            problems.append("no offsets embedded for: %s" % ", ".join(absent))

    modules = extract_json_assignment(html, "__modules")
    if modules is None:
        problems.append("the output has no window.__modules assignment")
    else:
        ordered, edges, _ = collect_modules(MODULE_ROOTS)
        ordered, edges, _ = close_over_dynamic_imports(ordered, edges, [])
        absent = [rel for rel in ordered if rel not in modules]
        if absent:
            problems.append("modules missing from the output: %s" % ", ".join(absent))
        for rel in EXTRA_MODULES:
            if rel not in modules:
                problems.append("%s is in EXTRA_MODULES but not in the output" % rel)
        # A body that still says `import` or `export` would throw the moment the
        # page ran it, so the flattening is checked rather than assumed.
        for rel in sorted(modules):
            if re.search(r'^\s*(?:import|export)\s', modules[rel], re.MULTILINE):
                problems.append("%s was not fully flattened" % rel)
                break

    for spec in load_module_specs():
        resolved = resolve_spec(spec, "src/main.js")
        if resolved is None:
            problems.append("src/main.js loadModule(%r) is not a relative path" % spec)
        elif resolved not in modules:
            problems.append(
                "src/main.js loadModule(%r) resolves to %s, which is not in the page. "
                "Add it to MODULE_ROOTS or EXTRA_MODULES in tools/build_standalone.py."
                % (spec, resolved))

    for rel in CLASSIC_SCRIPTS:
        for line_no, line in enumerate(read_text(rel).split("\n"), 1):
            code = line.split("//", 1)[0]
            if re.search(r'(?<![\w.$])import\s*\(', code) and "eval" not in code:
                problems.append(
                    "%s:%d has a syntactic import(), which resolves against the "
                    "document in a single file" % (rel, line_no))

    if meta.get("kexp") and extract_json_assignment(html, "EMBEDDED_BINARIES") is None:
        problems.append("no embedded binaries")

    for rel in CLASSIC_SCRIPTS:
        if read_text(rel)[:200] not in html:
            problems.append("classic script %s is not in the output" % rel)

    for needle, why in (
        ("window.ropWorkerFactory", "no worker factory, so the ROP worker cannot be built"),
        ("window.offsetsInline", "no inline offsets loader"),
        ("window.__boot", "no module-graph boot"),
        ("runPayloadQueue", "the payload runner was not included"),
    ):
        if needle not in html:
            problems.append(why)

    inline_at = html.find("window.ropWorkerFactory")
    main_at = html.find("/* === src/main.js === */")
    boot_at = html.find("window.__boot();")
    if not (inline_at != -1 and main_at != -1 and boot_at != -1):
        problems.append("could not locate the inline-env / main.js / boot blocks")
    elif not (inline_at < main_at < boot_at):
        problems.append(
            "script order is wrong: inline environment at %d, main.js at %d, boot at %d "
            "(must be increasing)" % (inline_at, main_at, boot_at))

    return problems


# --- entry point ------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="build_standalone.py",
        description="Pack payloads into one self-contained HTML file for the PS5.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 tools/build_standalone.py payloads/hello_world.js\n"
               "  python3 tools/build_standalone.py payloads/relapse.js payloads/ps.js \\\n"
               "      -o dist/ps5.html\n"
               "  python3 tools/build_standalone.py 'payloads/ftp_server.js::port=1337' \\\n"
               "      --no-kexp\n",
    )
    p.add_argument("payloads", nargs="+", metavar="PAYLOAD",
                   help="a payload path, optionally PAYLOAD::arg1,arg2 for api.args")
    p.add_argument("-o", "--output", default=None,
                   help="output file (default: dist/<payloads>.html)")
    p.add_argument("--title", default=None,
                   help="page title (default: the payload names)")
    p.add_argument("--no-kexp", action="store_true",
                   help="omit kexp.bin and elfldr.elf: a much smaller file, but "
                        "api.launchKexp() will refuse in it")
    p.add_argument("--embed", action="append", default=[], metavar="URL=FILE",
                   help="embed a file for inline fetch, or override a bundled binary; "
                        "repeat for multiple files (FILE relative to the working directory)")
    p.add_argument("--elfldr", metavar="[URL=]FILE",
                   help="replace the bundled elfldr binary (optionally at a custom virtual URL; FILE relative to the working directory)")
    p.add_argument("--css", action="append", default=[], metavar="FILE",
                   help="inline CSS after the default styles in the head; repeat for multiple "
                        "files (FILE relative to the working directory)")
    p.add_argument("--js", action="append", default=[], metavar="FILE",
                   help="run JavaScript in an awaited async function before module boot and "
                        "the exploit; repeat to run files in order (FILE relative to the "
                        "working directory)")
    p.add_argument("--check", action="store_true",
                   help="verify the generated file and exit without writing it")
    p.add_argument("--list", action="store_true",
                   help="print what went into the file")
    p.add_argument("--probe", action="store_true",
                   help="also run tools/probe_standalone.js and tools/boot_probe.js on "
                        "the result (needs node on PATH)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    payloads = load_payloads(args.payloads)

    embedded_files = {}
    elfldr_url = None
    if args.elfldr:
        url, sep, filename = args.elfldr.partition("=")
        if sep:
            if not url or not filename or url.startswith("/") or ".." in url.split("/"):
                raise SystemExit("--elfldr expects [URL=]FILE: %s" % args.elfldr)
            elfldr_url = url
            elfldr_file = filename
        else:
            _, default_elfldr_path = load_binary_config()
            elfldr_url = default_elfldr_path
            elfldr_file = args.elfldr
        embedded_files[elfldr_url] = elfldr_file
    for spec in args.embed:
        path, sep, filename = spec.partition("=")
        if not sep or not path or not filename or path.startswith("/") or ".." in path.split("/"):
            raise SystemExit("--embed expects a relative URL=FILE: %s" % spec)
        if path in embedded_files:
            raise SystemExit("duplicate --embed URL: %s" % path)
        embedded_files[path] = filename
    html, meta = build_html(payloads, title=args.title, include_kexp=not args.no_kexp,
                            embedded_files=embedded_files, css_files=args.css, js_files=args.js,
                            elfldr_url=elfldr_url)

    problems = check_output(html, payloads, meta)
    if problems:
        for problem in problems:
            print("check failed: %s" % problem, file=sys.stderr)
        return 1

    if args.list:
        print("payloads, in run order:")
        for payload in payloads:
            print("  %-30s %8d bytes  sha256:%s  args=%s"
                  % (payload.path, payload.byte_length, payload.sha256,
                     ",".join(payload.args) or "(none)"))
        print("  %d module(s) flattened, %d offsets table(s)"
              % (meta["modules"], meta["offsets"]))
        if meta.get("binaries"):
            print("  embedded binaries: %s" % ", ".join(meta["binaries"]))
        else:
            print("  embedded binaries: %s" % ("embedded" if meta["kexp"] else "omitted (--no-kexp)"))
        for kind in ("css", "js"):
            for asset in meta[kind]:
                print("  custom %s: %s (%d bytes)" % (
                    kind, asset["path"], len(asset["source"].encode("utf-8"))))
        print("  output size:   %d bytes (%.1f KB)" % (meta["bytes"], meta["bytes"] / 1024.0))

    if args.check:
        print("check ok: %s would be %d bytes" % (args.output or "(default)", meta["bytes"]))
        return 0

    output = args.output
    if not output:
        stem = "_".join(p.label[:-3] for p in payloads[:3] if p.label.endswith(".js"))
        output = os.path.join("dist", (stem or "payloads") + ".html")
    full = os.path.join(ROOT, output)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(html)

    print("wrote %s (%.1f KB)" % (output, meta["bytes"] / 1024.0))

    if args.probe:
        if shutil.which("node") is None:
            print("probe skipped: node is not on PATH", file=sys.stderr)
            return 1
        for script in ("probe_standalone.js", "boot_probe.js"):
            print("\n--- %s %s" % (script, output))
            result = subprocess.call([shutil.which("node"), os.path.join(HERE, script), full])
            if result != 0:
                print("%s reported failures" % script, file=sys.stderr)
                return result

    print("open it on the PS5 from the User's Guide, or serve it over http first to look at it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
