#pragma once

#include <stddef.h>
#include "app_installer.h"
#include "notification.h"
#include "ps5_launcher.h"
#include "webkit_cleaner.h"

/* Thread-safe screen/HTTP logging. Wait blocks for at most one second. */
void installer_log(const char *fmt, ...);
size_t installer_wait_logs(size_t *pos, char *out_buf, size_t max_len);
void installer_log_wakeup(void);
