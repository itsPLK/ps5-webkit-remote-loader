#include <stdio.h>

#include "installer_support.h"
#include "installer_config.h"
#include "ps5_launcher.h"

extern int sceSystemServiceLaunchWebBrowser(const char *uri);

int ps5_launch_browser(const char *uri) {
  installer_log(INSTALLER_LOG_PREFIX " Launching browser: %s\n", uri);
  if (sceSystemServiceLaunchWebBrowser(uri) != 0) {
    installer_notify(INSTALLER_LOG_PREFIX " Failed to launch browser.");
    return -1;
  }
  return 0;
}
