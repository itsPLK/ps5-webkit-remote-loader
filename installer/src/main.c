/*
 * PS5 WebKit Remote Loader - Native Installer ELF Entry Point
 *
 * Runs on a jailbroken PS5. Starts a local HTTP server on port 18180,
 * launches the browser to cache the Remote Loader via HTML5 AppCache,
 * installs the homescreen app shortcut (WKRL00001) once caching is confirmed,
 * then cleanly exits.
 */

#include <microhttpd.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "wkrli.h"
#include "http_server.h"
#include "ps5_launcher.h"

static pid_t find_pid(const char *name) {
    int mib[4] = {1, 14, 8, 0};
    pid_t mypid = getpid();
    pid_t pid = -1;
    size_t buf_size;
    uint8_t *buf;

    if (sysctl(mib, 4, 0, &buf_size, 0, 0)) {
        installer_log("[WKRLI] sysctl failed\n");
        return -1;
    }

    if (!(buf = malloc(buf_size))) {
        installer_log("[WKRLI] malloc failed\n");
        return -1;
    }

    if (sysctl(mib, 4, buf, &buf_size, 0, 0)) {
        installer_log("[WKRLI] sysctl failed\n");
        free(buf);
        return -1;
    }

    for (uint8_t *ptr = buf; ptr < (buf + buf_size);) {
        int ki_structsize = *(int *)ptr;
        pid_t ki_pid = *(pid_t *)&ptr[72];
        char *ki_tdname = (char *)&ptr[447];

        ptr += ki_structsize;
        if (!strcmp(name, ki_tdname) && ki_pid != mypid) {
            pid = ki_pid;
        }
    }

    free(buf);
    return pid;
}

extern int sceNetCtlInit();
extern int sceUserServiceInitialize(void *);
extern int sceUserServiceGetForegroundUser(int *);

__attribute__((used)) volatile const char wkrli_version_sig[] =
    "WKRLI_VER:" WKRLI_FULL_VERSION;

int main(void) {
    struct MHD_Daemon *daemon;
    pid_t pid;

    syscall(SYS_thr_set_name, -1, WKRLI_THREAD_NAME);

    /* Terminate any previously running installer instances */
    while ((pid = find_pid(WKRLI_THREAD_NAME)) > 0) {
        if (kill(pid, SIGKILL)) {
            installer_log("[WKRLI] kill failed\n");
            return EXIT_FAILURE;
        }
        sleep(1);
    }

    installer_log("[WKRLI] WebKit Remote Loader Installer v%s starting on port %d...\n",
              WKRLI_FULL_VERSION, WKRLI_PORT);

    int err;
    if ((err = sceNetCtlInit()) == 0) {
        installer_log("[WKRLI] Network Controller initialized.\n");
    } else {
        installer_log("[WKRLI] sceNetCtlInit failed: 0x%08X\n", err);
    }

    int user_prio = 256;
    if ((err = sceUserServiceInitialize(&user_prio)) == 0) {
        installer_log("[WKRLI] User Service initialized.\n");
    } else {
        installer_log("[WKRLI] sceUserServiceInitialize failed: 0x%08X\n", err);
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_DEBUG,
                              WKRLI_PORT, NULL, NULL, &http_on_request,
                              NULL,
                              MHD_OPTION_THREAD_POOL_SIZE, (unsigned int)8,
                              MHD_OPTION_END);

    if (NULL == daemon) {
        installer_log("[WKRLI] Failed to start HTTP daemon!\n");
        installer_notify("WebKit Remote Loader Installer: Error\nHTTP server failed to start");
        return 1;
    }

    installer_log("[WKRLI] Server running. Launching browser to cache remote loader...\n");

    int uid = -1;
    char uid_param[32] = "";
    if (sceUserServiceGetForegroundUser(&uid) == 0 && uid > 0) {
        snprintf(uid_param, sizeof(uid_param), "&uid=%08x", (unsigned int)uid);
    }

    char browser_url[256];
    snprintf(browser_url, sizeof(browser_url),
             "http://127.0.0.1:%d/?v=%s%s", WKRLI_PORT, WKRLI_FULL_VERSION, uid_param);
    ps5_launch_browser(browser_url);

    int webkit_clear_attempts = 0;

    while (atomic_load(&http_keep_running)) {
        if (atomic_load(&webkit_data_cleared)) {
            atomic_store(&webkit_data_cleared, 0);
            webkit_clear_attempts++;

            if (webkit_clear_attempts <= 1) {
                usleep(500000);
                installer_log("[WKRLI] Re-launching browser after WebKit clear...\n");
                char retry_url[256];
                snprintf(retry_url, sizeof(retry_url),
                         "http://127.0.0.1:%d/?v=%s%s&retry=1",
                         WKRLI_PORT, WKRLI_FULL_VERSION, uid_param);
                ps5_launch_browser(retry_url);
            }
        }
        usleep(100000);
    }

    if (atomic_load(&install_completed)) {
        installer_notify("WebKit Remote Loader v%s cached successfully!", WKRLI_FULL_VERSION);
    }
    installer_log_wakeup();

    usleep(500000);

    if (daemon)
        MHD_stop_daemon(daemon);

    sleep(1);
    return 0;
}
