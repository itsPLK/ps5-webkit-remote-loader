#pragma once

/* Base version of PS5 WebKit Remote Loader Installer */
#define WKRLI_VERSION "0.1.1"
#define WKRL_VERSION WKRLI_VERSION

/* Full build version header */
#include "wkrli_version.h"

/* Network Settings — local HTTP server for initial AppCache staging */
#define WKRLI_PORT 18180

/* Title ID of the installed homescreen app ("WebKit Remote Loader") */
#define WKRL_TITLE_ID "WKRL00001"

/* Process identity — used to kill stale installer instances on startup */
#define WKRLI_THREAD_NAME "wkrli.elf"

/* Routes */
#define ROUTE_INDEX "/"
#define ROUTE_INDEX_HTML "/index.html"
#define ROUTE_CACHE_MANIFEST "/cache.appcache"
#define ROUTE_INSTALL "/install"
#define ROUTE_VERSION "/version"
#define ROUTE_CLEAR_WEBKIT_DATA "/clear-webkit-data"
#define ROUTE_EXIT "/exit"

#include "installer_support.h"
