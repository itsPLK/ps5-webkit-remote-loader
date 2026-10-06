#!/usr/bin/env python3
"""Generate a C file registry + cache.appcache manifest from a dist directory.

Scans <dist_dir> recursively and produces:
  - <header_out>  : file_registry.h  (FileEntry struct + extern table)
  - <source_out>  : file_registry.c  (byte arrays + lookup function)
  - <dist_dir>/cache.appcache        (AppCache manifest listing all files)

Usage: gen_installer_registry.py <dist_dir> <header_out> <source_out>
"""

import os
import posixpath
import sys
import zlib

from gen_version import get_version_info

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css",
    ".js": "application/javascript",
    ".mjs": "application/javascript",
    ".json": "application/json",
    ".webmanifest": "application/manifest+json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".appcache": "text/cache-manifest",
    ".txt": "text/plain",
    ".bin": "application/octet-stream",
    ".elf": "application/octet-stream",
}


def detect_content_type(path):
    ext = os.path.splitext(path)[1].lower()
    return CONTENT_TYPES.get(ext, "application/octet-stream")


def include_in_registry(path):
    if "/.git/" in path or path.endswith("/.git"):
        return False
    if path == "/VERSION":
        return False
    if path.endswith(".DS_Store"):
        return False
    return True


VERSION_PLACEHOLDER = b"[[VERSION_PLACEHOLDER]]"
BUILD_TIME_PLACEHOLDER = b"[[BUILD_TIME_PLACEHOLDER]]"
APP_DIR_PLACEHOLDER = b"[[APP_DIR_PLACEHOLDER]]"


def get_version_info_with_handoff(dist_dir):
    info = get_version_info()
    try:
        with open(os.path.join(dist_dir, "VERSION"), "r", encoding="utf-8") as f:
            pinned = f.read().strip()
        if pinned:
            info = dict(info)
            info["full"] = pinned
    except OSError:
        pass
    return info


def apply_placeholders(path, data, version, app_dir, build_time):
    if VERSION_PLACEHOLDER in data:
        data = data.replace(VERSION_PLACEHOLDER, version.encode("utf-8"))
    if BUILD_TIME_PLACEHOLDER in data:
        data = data.replace(BUILD_TIME_PLACEHOLDER, build_time.encode("utf-8"))
    if APP_DIR_PLACEHOLDER in data:
        data = data.replace(APP_DIR_PLACEHOLDER, version.encode("utf-8"))
    return data


def emit_c_array(out, name, data):
    out.write(f"static const unsigned char {name}[] = {{\n")
    for i in range(0, len(data), 12):
        chunk = ", ".join(f"0x{b:02x}" for b in data[i : i + 12])
        out.write(f"    {chunk},\n")
    out.write("};\n")


def compress_entry(data):
    if len(data) < 64:
        return data, False
    co = zlib.compressobj(level=9, wbits=-15)
    comp = co.compress(data) + co.flush()
    if len(comp) >= len(data):
        return data, False
    return comp, True


def build_manifest(files, version, build_time, app_dir, pointer_path, marker_path):
    lines = [
        "CACHE MANIFEST",
        f"# PS5 WebKit Remote Loader v{version} by PLK (built {build_time}) - auto-generated AppCache manifest",
        "",
        "CACHE:",
    ]
    cache_entries = [path for path, _ in files if path not in (pointer_path, marker_path)]
    cache_entries.sort()
    lines += cache_entries
    lines.append(pointer_path)
    lines.append(marker_path)
    lines += [
        "",
        "NETWORK:",
        "/install",
        "/version",
        "/logs",
        "/clear-webkit-data",
        "",
        "FALLBACK:",
    ]

    fallbacks = [
        "/ /index.html",
        "/app/ /app/index.html",
    ]
    paths = {path for path, _ in files}
    for path in sorted(paths):
        if path == "/index.html" or not path.endswith("/index.html"):
            continue
        directory = os.path.dirname(path)
        if directory != "/":
            entry = f"{directory}/ {path}"
            if entry not in fallbacks:
                fallbacks.append(entry)

    lines += fallbacks
    lines += [""]
    return "\n".join(lines)


def main():
    if len(sys.argv) != 4:
        print("Usage: gen_installer_registry.py <dist_dir> <header_out> <source_out>")
        sys.exit(1)

    dist_dir, header_out, source_out = sys.argv[1:4]

    if not os.path.isdir(dist_dir):
        print(f"Error: {dist_dir} not found or not a directory.")
        sys.exit(1)

    version_info = get_version_info_with_handoff(dist_dir)
    version = version_info["full"]
    build_time = version_info["build_time"]
    app_dir = "/app/" + version
    pointer_path = "/app/index.html"
    marker_path = app_dir + "/__complete__"

    marker_full = os.path.join(dist_dir, marker_path.lstrip("/"))
    os.makedirs(os.path.dirname(marker_full), exist_ok=True)
    with open(marker_full, "w", encoding="utf-8") as f:
        f.write(version)

    files = []
    for root, dirs, names in os.walk(dist_dir):
        dirs.sort()
        for name in sorted(names):
            if name == "cache.appcache":
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, dist_dir).replace(os.sep, "/")
            if not include_in_registry(f"/{rel}"):
                continue
            files.append((f"/{rel}", full))
    files.sort(key=lambda f: f[0])

    manifest_path = os.path.join(dist_dir, "cache.appcache")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(build_manifest(files, version, build_time, app_dir, pointer_path, marker_path))

    files.append(("/cache.appcache", manifest_path))
    files.sort(key=lambda f: f[0])

    # Header
    os.makedirs(os.path.dirname(header_out), exist_ok=True)
    with open(header_out, "w", encoding="utf-8") as out:
        out.write("/* Auto-generated by tools/gen_installer_registry.py - do not edit. */\n")
        out.write("\n")
        out.write("#ifndef FILE_REGISTRY_H\n")
        out.write("#define FILE_REGISTRY_H\n")
        out.write("\n")
        out.write("typedef struct {\n")
        out.write("    const char *path;\n")
        out.write("    const unsigned char *data;\n")
        out.write("    unsigned int size;\n")
        out.write("    unsigned int orig_size;\n")
        out.write("    unsigned char compressed;\n")
        out.write("    const char *content_type;\n")
        out.write("} FileEntry;\n")
        out.write("\n")
        out.write("extern const FileEntry file_registry[];\n")
        out.write("extern const unsigned int file_registry_count;\n")
        out.write("\n")
        out.write("const FileEntry *file_registry_find(const char *path);\n")
        out.write("\n")
        out.write("#endif /* FILE_REGISTRY_H */\n")

    # Source
    os.makedirs(os.path.dirname(source_out), exist_ok=True)
    with open(source_out, "w", encoding="utf-8") as out:
        out.write("/* Auto-generated by tools/gen_installer_registry.py - do not edit. */\n")
        out.write("\n")
        out.write('#include <string.h>\n')
        out.write('#include "file_registry.h"\n')
        out.write("\n")

        entries = []
        for i, (path, full) in enumerate(files):
            with open(full, "rb") as f:
                data = f.read()
            data = apply_placeholders(path, data, version, app_dir, build_time)
            stored, compressed = compress_entry(data)
            emit_c_array(out, f"file_{i}", stored)
            out.write("\n")
            entries.append((path, compressed, len(data), len(stored)))

        out.write("const FileEntry file_registry[] = {\n")
        for i, (path, _) in enumerate(files):
            content_type = detect_content_type(path)
            _, compressed, orig_size, stored_size = entries[i]
            out.write(
                f'    {{ "{path}", file_{i}, {stored_size}, {orig_size}, '
                f'{1 if compressed else 0}, "{content_type}" }},\n'
            )
        out.write("};\n")
        out.write("\n")
        out.write("const unsigned int file_registry_count =\n")
        out.write("    sizeof(file_registry) / sizeof(file_registry[0]);\n")
        out.write("\n")
        out.write("const FileEntry *file_registry_find(const char *path) {\n")
        out.write("    if (!path)\n")
        out.write("        return NULL;\n")
        out.write("\n")
        out.write("    for (unsigned int i = 0; i < file_registry_count; i++) {\n")
        out.write('        if (strcmp(file_registry[i].path, path) == 0)\n')
        out.write("            return &file_registry[i];\n")
        out.write("    }\n")
        out.write("\n")
        out.write("    return NULL;\n")
        out.write("}\n")

    print(f"Generated {header_out} and {source_out} ({len(files)} files)")


if __name__ == "__main__":
    main()
