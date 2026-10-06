#!/usr/bin/env python3
"""Run real shared native helpers on Linux with stubbed PS5 services.

All /user filesystem operations are redirected into a temporary directory.
Requires a native C compiler and the GNU linker's --wrap support.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import zlib

COMMON = Path(__file__).resolve().parents[1] / 'installer/common'

HARNESS = r'''
#include <assert.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "installer_support.h"
#include "installer_config.h"
#include "inflate.h"

static const char *root;
static int initialized, terminated, installed, init_error, install_error;
static int foreground = 42, user_error, browser_error, notified;
static char notification[3075], browser_uri[512];

/* GNU linker wrappers keep production filesystem code intact while ensuring
 * even an incorrect test never touches a real PS5 /user tree. */
static const char *mapped(const char *path, char *out) {
    if (strcmp(path, "/user") && strncmp(path, "/user/", 6)) return path;
    assert(snprintf(out, 2048, "%s%s", root, path) < 2048);
    return out;
}
FILE *__real_fopen(const char *, const char *);
int __real_stat(const char *, struct stat *);
int __real_mkdir(const char *, mode_t);
DIR *__real_opendir(const char *);
int __real_unlink(const char *);
int __real_rmdir(const char *);
FILE *__wrap_fopen(const char *p, const char *m) { char b[2048]; return __real_fopen(mapped(p,b),m); }
int __wrap_stat(const char *p, struct stat *s) { char b[2048]; return __real_stat(mapped(p,b),s); }
int __wrap_mkdir(const char *p, mode_t m) { char b[2048]; return __real_mkdir(mapped(p,b),m); }
DIR *__wrap_opendir(const char *p) { char b[2048]; return __real_opendir(mapped(p,b)); }
int __wrap_unlink(const char *p) { char b[2048]; return __real_unlink(mapped(p,b)); }
int __wrap_rmdir(const char *p) { char b[2048]; return __real_rmdir(mapped(p,b)); }

int kernel_dynlib_handle(int pid, const char *name, uint32_t *handle) { return -1; }
uintptr_t kernel_dynlib_resolve(int pid, uint32_t handle, const char *nid) { return 0; }
int sceAppInstUtilInitialize(void) { initialized++; return init_error; }
int sceAppInstUtilTerminate(void) { terminated++; return 0; }
int sceAppInstUtilAppInstallAll(void *arg) { installed++; return install_error; }
int sceSystemServiceLaunchWebBrowser(const char *uri) {
    snprintf(browser_uri, sizeof(browser_uri), "%s", uri); return browser_error;
}
int sceUserServiceGetForegroundUser(int *uid) { *uid = foreground; return user_error; }
int sceKernelSendNotificationRequest(int device, notify_request_t *req, size_t size, int unused) {
    assert(size == sizeof(*req)); assert(device == 0 && unused == 0);
    snprintf(notification, sizeof(notification), "%s", req->message); notified++; return 0;
}

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb"); assert(f);
    assert(fwrite(content, 1, strlen(content), f) == strlen(content)); assert(!fclose(f));
}
static void matches(const char *path, const char *expected) {
    char b[1024]; FILE *f = fopen(path, "rb"); assert(f);
    size_t n = fread(b, 1, sizeof(b), f); fclose(f);
    assert(n == strlen(expected)); assert(!memcmp(b, expected, n));
}
static void exists(const char *path, int expected) {
    struct stat s; assert((stat(path, &s) == 0) == expected);
}

int main(int argc, char **argv) {
    assert(argc == 2); root = argv[1];
    const char *param = "/user/app/" INSTALLER_TITLE_ID "/sce_sys/param.json";
    const char *icon = "/user/app/" INSTALLER_TITLE_ID "/sce_sys/icon0.png";
    assert(installer_install_app_if_needed() == 0);
    assert(installed == 1 && initialized == 1 && terminated == 1);
    assert(!strcmp(notification, INSTALLER_APP_NAME " App Ready!"));
    matches(param, TEST_PARAM); matches(icon, TEST_ICON);
    assert(installer_install_app_if_needed() == 0 && installed == 1);
    write_file(param, "stale");
    assert(installer_install_app_if_needed() == 0 && installed == 2);
    matches(param, TEST_PARAM);
    write_file(icon, "stale-icon");
    assert(installer_install_app_if_needed() == 0 && installed == 3);
    matches(icon, TEST_ICON);
    write_file(param, "stale");
    init_error = -1;
    assert(installer_install_app_if_needed() == -1 && installed == 3);
    assert(terminated == 3);
    init_error = 0; install_error = -1;
    assert(installer_install_app_if_needed() == -1 && installed == 4);
    assert(terminated == 4);

    assert(ps5_launch_browser("http://127.0.0.1:18180/?v=test") == 0);
    assert(!strcmp(browser_uri, "http://127.0.0.1:18180/?v=test"));
    browser_error = 1;
    assert(ps5_launch_browser("test://failed") == -1);
    assert(!strcmp(notification, INSTALLER_LOG_PREFIX " Failed to launch browser."));
    installer_notify("%s %d", "format", 123); assert(!strcmp(notification, "format 123"));

    assert(!mkdir("/user/home", 0755));
    assert(!mkdir("/user/home/0000002a", 0755));
    assert(!mkdir("/user/home/0000002a/webkit", 0755));
    assert(!mkdir("/user/home/0000002a/webkit/shell", 0755));
    assert(!mkdir("/user/home/0000002a/webkit/shell/nested", 0755));
    write_file("/user/home/0000002a/webkit/shell/nested/cache", "cached");
    assert(!mkdir("/user/home/0000002b", 0755));
    write_file("/user/home/0000002b/keep", "other user");
    user_error = 1;
    assert(installer_clear_webkit_data() == -1);
    exists("/user/home/0000002a/webkit/shell/nested/cache", 1);
    user_error = 0; foreground = -1;
    assert(installer_clear_webkit_data() == -1);
    foreground = 42;
    assert(installer_clear_webkit_data() == 0);
    exists("/user/home/0000002a/webkit/shell", 1);
    exists("/user/home/0000002a/webkit/shell/nested", 0);
    matches("/user/home/0000002b/keep", "other user");
    foreground = 44; assert(installer_clear_webkit_data() == 0);

    /* Drain earlier output, then exercise vsnprintf's untruncated return size. */
    size_t pos = 0; char b[131072];
    size_t n = installer_wait_logs(&pos, b, sizeof(b));
    assert(n > 0);
    char prefix[128]; snprintf(prefix, sizeof(prefix), "%s Installing", INSTALLER_LOG_PREFIX);
    assert(memmem(b, n, prefix, strlen(prefix)));
    char long_line[2001]; memset(long_line, 'x', 2000); long_line[2000] = 0;
    installer_log("%s", long_line);
    assert(installer_wait_logs(&pos, b, sizeof(b)) == 511);
    for (int i = 0; i < 511; i++) assert(b[i] == 'x');
    installer_log("tail"); assert(installer_wait_logs(&pos, b, 2) == 2);
    assert(!memcmp(b, "ta", 2)); assert(installer_wait_logs(&pos, b, 2) == 2);
    assert(!memcmp(b, "il", 2));

    unsigned char compressed[1024], output[1024];
    FILE *f = fopen("data.deflate", "rb"); assert(f);
    unsigned long input_len = fread(compressed, 1, sizeof(compressed), f); fclose(f);
    unsigned long output_len = sizeof(output);
    assert(puff(output, &output_len, compressed, &input_len) == 0);
    assert(output_len == 600);
    for (unsigned long i = 0; i < output_len; i++) assert(output[i] == "cache!"[i % 6]);
    puts("native helper behavior passed");
    return 0;
}
'''


def main():
    if not sys.platform.startswith('linux'):
        raise SystemExit('Run this test on Linux, for example inside the SDK Docker image.')
    compiler = shutil.which(os.environ.get('HOST_CC', 'clang')) or shutil.which('cc')
    if not compiler:
        raise SystemExit('A native C compiler is required.')
    with tempfile.TemporaryDirectory(prefix='installer-common-') as directory:
        work = Path(directory)
        (work / 'ps5').mkdir()
        (work / 'ps5/kernel.h').write_text(
            '#include <stdint.h>\nint kernel_dynlib_handle(int, const char *, uint32_t *);\n'
            'uintptr_t kernel_dynlib_resolve(int, uint32_t, const char *);\n')
        (work / 'test.c').write_text(HARNESS)
        compressor = zlib.compressobj(wbits=-15)
        (work / 'data.deflate').write_bytes(compressor.compress(b'cache!' * 100) + compressor.flush())
        for index in (1, 2):
            title = f'TEST0000{index}'
            name = f'Installer Test {index}'
            param, icon = f'metadata-{index}', f'icon-{index}'
            (work / 'param').write_text(param)
            (work / 'icon').write_text(icon)
            (work / 'installer_config.h').write_text(
                f'#define INSTALLER_APP_NAME "{name}"\n'
                f'#define INSTALLER_TITLE_ID "{title}"\n'
                f'#define INSTALLER_LOG_PREFIX "[TEST{index}]"\n'
                '#define INSTALLER_PARAM_JSON "param"\n'
                '#define INSTALLER_ICON0_PNG "icon"\n'
                f'#define TEST_PARAM "{param}"\n#define TEST_ICON "{icon}"\n')
            tree = work / f'user-tree-{index}'
            tree.mkdir()
            sources = ['app_installer', 'ps5_launcher', 'log', 'notification', 'inflate', 'webkit_cleaner']
            command = [compiler, '-D_GNU_SOURCE', '-Wall', '-Werror', '-pthread',
                       '-I' + str(work), '-I' + str(COMMON), str(work / 'test.c')]
            command += [str(COMMON / (name + '.c')) for name in sources]
            command += ['-Wl,--wrap=' + name for name in ('fopen', 'stat', 'mkdir', 'opendir', 'unlink', 'rmdir')]
            command += ['-o', str(work / 'test')]
            subprocess.run(command, cwd=work, check=True)
            result = subprocess.run([str(work / 'test'), str(tree)], cwd=work,
                                    capture_output=True, text=True)
            if result.returncode:
                raise SystemExit(result.stdout + result.stderr)
            print(f'{title}: install/update, identity/assets, failures, notifications, browser, '
                  'current-user cleanup, long logs and raw DEFLATE passed')


if __name__ == '__main__':
    main()
