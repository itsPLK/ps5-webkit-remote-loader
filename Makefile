PYTHON ?= python3

.PHONY: all version host installer test test-native clean

all: host

version:
	$(PYTHON) tools/gen_version.py

host: version
	$(PYTHON) tools/build_host.py

installer:
	@echo "Building installer ELF via Docker SDK..."
	./build_release.sh

test:
	node tools/wobkot_integration_test.mjs
	node tools/wobkot_adapter_test.mjs
	node tools/net_wobkot_test.mjs
	node tools/standalone_test.js
	node tools/df_test.js
	node tools/ps_test.js
	node tools/netstat_test.js
	node tools/readfile_test.js
	node tools/notify_test.js
	node tools/sysinfo_test.js
	node tools/klog_test.js
	$(PYTHON) tools/build_standalone.py payloads/hello_world.js --check
	$(PYTHON) tools/build_assets_test.py
	$(PYTHON) tools/build_customization_test.py

# Run on Linux or in the SDK container; PS5 services are stubbed.
test-native:
	$(PYTHON) tools/installer_common_test.py

clean:
	rm -rf dist installer/dist
	rm -f installer/include/file_registry.h installer/include/file_registry.c installer/include/.file_registry.stamp
	rm -f installer/include/wkrli_version.h installer/assets/param.json installer/assets/icon0.png installer/assets/icon.ico
	rm -f installer.elf webkit-remote-loader-installer_v*.elf webkit-remote-loader-host.py webkit-remote-loader-host_v*.py
	rm -f src/lua-vm.js
