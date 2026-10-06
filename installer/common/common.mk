# Consumers set INSTALLER_COMMON to this directory and provide an
# installer_config.h on their include path. Run the compiler from the consumer's
# repository root so embedded asset paths resolve against that project.
INSTALLER_COMMON_SRCS := $(addprefix $(INSTALLER_COMMON)/, \
    app_installer.c ps5_launcher.c log.c notification.c inflate.c \
    webkit_cleaner.c simulate_corrupt.c)
INSTALLER_COMMON_HEADERS := $(wildcard $(INSTALLER_COMMON)/*.h)
