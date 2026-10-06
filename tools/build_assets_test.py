#!/usr/bin/env python3
"""Offline regression checks for external standalone assets and host packaging."""
import base64
import io
import json
import os
import tempfile
import unittest
import zipfile

import build_standalone as standalone
import build_host as host


class EmbeddedAssetsTest(unittest.TestCase):
    def test_external_assets_and_loader_override(self):
        with tempfile.TemporaryDirectory() as directory:
            asset = os.path.join(directory, 'asset.bin')
            data = b'\x00\xffexternal asset\x00'
            with open(asset, 'wb') as f:
                f.write(data)
            _, loader_key = standalone.load_binary_config()
            files = {'external/payload.elf': asset, loader_key: asset}
            payloads = standalone.load_payloads(['payloads/hello_world.js'])
            html, meta = standalone.build_html(payloads, embedded_files=files)
            self.assertEqual(standalone.check_output(html, payloads, meta), [])
            table = standalone.extract_json_assignment(html, 'EMBEDDED_BINARIES')
            info = standalone.extract_json_assignment(html, 'EMBEDDED_BINARY_INFO')
            for key in files:
                self.assertEqual(base64.b64decode(table[key]), data)
                self.assertEqual(info[key]['size'], len(data))
            html, _ = standalone.build_html(payloads, include_kexp=False,
                                             embedded_files={'external/payload.elf': asset})
            self.assertEqual(set(standalone.extract_json_assignment(html, 'EMBEDDED_BINARIES')),
                             {'external/payload.elf'})

    def test_elfldr_custom_url_override(self):
        with tempfile.TemporaryDirectory() as directory:
            asset = os.path.join(directory, 'elfldr.elf')
            data = b'\x7fELFcustom elfldr\x00'
            with open(asset, 'wb') as f:
                f.write(data)
            custom_url = 'shared/elfldr-ps5-v0.26-bb1e117.elf'
            payloads = standalone.load_payloads(['payloads/hello_world.js'])
            html, meta = standalone.build_html(
                payloads,
                embedded_files={custom_url: asset},
                elfldr_url=custom_url,
            )
            self.assertEqual(standalone.check_output(html, payloads, meta), [])
            table = standalone.extract_json_assignment(html, 'EMBEDDED_BINARIES')
            self.assertIn(custom_url, table)
            _, default_loader = standalone.load_binary_config()
            self.assertNotIn(default_loader, table)
            self.assertEqual(base4_data := base64.b64decode(table[custom_url]), data)
            cfg = standalone.extract_json_assignment(html, 'LOADER_CONFIG')
            self.assertEqual(cfg, {'ELFLDR_ELF': custom_url})

    def test_single_page_host(self):
        with tempfile.TemporaryDirectory() as directory:
            page = os.path.join(directory, 'page.html')
            output = os.path.join(directory, 'host.py')
            data = b'<!doctype html><title>External page</title>'
            with open(page, 'wb') as f:
                f.write(data)
            archive, files = host.build_zip(page)
            self.assertEqual(files, {'index.html': page})
            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                self.assertEqual(zf.namelist(), ['index.html'])
                self.assertEqual(zf.read('index.html'), data)
            self.assertEqual(host.main(['--page', page, '--output', output,
                                        '--name', 'Custom "host"', '--version', 'test']), 0)
            with open(output) as f:
                source = f.read()
            compile(source, output, 'exec')
            self.assertIn('HOST_NAME = ' + json.dumps('Custom "host"'), source)

    def test_multi_page_host_and_fw_routing(self):
        import sys
        sys.path.insert(0, host.repo_root())
        import host as live_host

        with tempfile.TemporaryDirectory() as directory:
            p_relapse = os.path.join(directory, 'relapse.html')
            p_poops = os.path.join(directory, 'poops.html')
            data_relapse = b'<!doctype html><title>Relapse</title>'
            data_poops = b'<!doctype html><title>Poops</title>'
            with open(p_relapse, 'wb') as f:
                f.write(data_relapse)
            with open(p_poops, 'wb') as f:
                f.write(data_poops)

            archive, files = host.build_zip([
                f'index.html={p_relapse}',
                f'relapse.html={p_relapse}',
                f'poops.html={p_poops}',
            ])
            self.assertEqual(sorted(files.keys()), ['index.html', 'poops.html', 'relapse.html'])

            with zipfile.ZipFile(io.BytesIO(archive)) as zf:
                self.assertEqual(sorted(zf.namelist()), ['index.html', 'poops.html', 'relapse.html'])
                self.assertEqual(zf.read('index.html'), data_relapse)
                self.assertEqual(zf.read('poops.html'), data_poops)

            # Test routing logic in GuideHandler
            old_zip = live_host._embedded_zip_cache
            old_loaded = live_host._embedded_zip_loaded
            try:
                live_host._embedded_zip_cache = zipfile.ZipFile(io.BytesIO(archive))
                live_host._embedded_zip_loaded = True

                handler = live_host.GuideHandler.__new__(live_host.GuideHandler)
                handler.allowed_host = None

                # 1. Normal PS5 FW (e.g. 7.61) -> serves index.html (Relapse)
                handler.path = '/document/en/ps5/index.html'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/7.61) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'index.html')
                self.assertEqual(res[3], data_relapse)

                # 2. PS5 FW 9.05 (incompatible with Relapse) -> routes to poops.html
                handler.path = '/document/en/ps5/index.html'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/9.05) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'poops.html')
                self.assertEqual(res[3], data_poops)

                # 3. PS5 FW 11.40 (incompatible with Relapse) -> routes to poops.html
                handler.path = '/document/en/ps5/index.html'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/11.40) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'poops.html')
                self.assertEqual(res[3], data_poops)

                # 4. Explicit query override ?exploit=poops on FW 7.61 -> routes to poops.html
                handler.path = '/document/en/ps5/index.html?exploit=poops'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/7.61) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'poops.html')
                self.assertEqual(res[3], data_poops)

                # 5. Explicit query override ?exploit=relapse on FW 9.05 -> routes to relapse.html
                handler.path = '/document/en/ps5/index.html?exploit=relapse'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/9.05) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'relapse.html')
                self.assertEqual(res[3], data_relapse)
            finally:
                live_host._embedded_zip_cache = old_zip
                live_host._embedded_zip_loaded = old_loaded

            # Test two-page host (index.html=relapse and poops.html) where relapse.html is not duplicated
            archive2, files2 = host.build_zip([
                f'index.html={p_relapse}',
                f'poops.html={p_poops}',
            ])
            self.assertEqual(sorted(files2.keys()), ['index.html', 'poops.html'])
            try:
                live_host._embedded_zip_cache = zipfile.ZipFile(io.BytesIO(archive2))
                live_host._embedded_zip_loaded = True

                handler = live_host.GuideHandler.__new__(live_host.GuideHandler)
                handler.allowed_host = None

                # 1. Normal PS5 FW -> index.html (Relapse)
                handler.path = '/document/en/ps5/index.html'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/7.61) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'index.html')
                self.assertEqual(res[3], data_relapse)

                # 2. FW 9.05 -> poops.html
                handler.path = '/document/en/ps5/index.html'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/9.05) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'poops.html')
                self.assertEqual(res[3], data_poops)

                # 3. Explicit query override ?exploit=relapse on FW 9.05 -> resolves to index.html (Relapse)
                handler.path = '/document/en/ps5/index.html?exploit=relapse'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/9.05) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'index.html')
                self.assertEqual(res[3], data_relapse)

                # 4. Explicit direct request to /relapse.html -> falls back to index.html (Relapse)
                handler.path = '/relapse.html'
                handler.headers = {'User-Agent': 'Mozilla/5.0 (PlayStation 5/7.61) AppleWebKit/605.1.15'}
                res = handler._resolve()
                self.assertEqual(res[2], 'index.html')
                self.assertEqual(res[3], data_relapse)
            finally:
                live_host._embedded_zip_cache = old_zip
                live_host._embedded_zip_loaded = old_loaded


if __name__ == '__main__':
    unittest.main()
