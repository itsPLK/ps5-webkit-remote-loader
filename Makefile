PYTHON ?= python3

.PHONY: all version lua-runtime host installer test test-native clean

all: host

version:
	$(PYTHON) tools/gen_version.py

lua-runtime:
	$(PYTHON) tools/lua_runtime/build_runtime.py

host: version lua-runtime
	$(PYTHON) tools/build_host.py

installer:
	@echo "Building installer ELF via Docker SDK..."
	./build_release.sh

test: lua-runtime
	node tools/memory_bulk_test.mjs
	node tools/worker_timeout_test.mjs
	node tools/selftest.js
	node tools/standalone_test.js
	node tools/lua_runtime/test.js
	node tools/lua_runtime/routing_test.mjs
	node tools/lua_runtime/compat_test.mjs
	node tools/lua_runtime/service_test.mjs
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
