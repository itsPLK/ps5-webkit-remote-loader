#!/usr/bin/env python3
"""Check custom HTML assets and the actual generated startup/boot boundary."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import build_standalone as standalone


NODE_CHECK = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const html = fs.readFileSync(process.argv[1], 'utf8');
const expected = JSON.parse(process.argv[2]);
const blocks = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
let release;
const gate = new Promise(resolve => { release = resolve; });
const errors = [], lines = [];
const output = { appendChild: line => lines.push(line) };
const sandbox = {
  trace: [], gate, setTimeout,
  console: { error: message => errors.push(message) },
  document: { getElementById: () => output, createElement: () => ({}) },
};
sandbox.window = sandbox;
sandbox.__boot = () => sandbox.trace.push('boot');
vm.createContext(sandbox);
vm.runInContext(blocks.find(body => body.includes('window.__startupScripts = ')), sandbox);
vm.runInContext(blocks.at(-1), sandbox);
(async () => {
  await Promise.resolve();
  assert(!sandbox.trace.includes('boot'), 'boot must wait for the startup scripts');
  release();
  const ready = await sandbox.__startupReady;
  assert.equal(ready, expected.ready);
  assert.deepEqual([...sandbox.trace], expected.trace);
  if (expected.error) {
    assert.equal(errors.length, 1);
    assert(errors[0].includes(expected.error), errors[0]);
    assert(errors[0].includes('startup script '), errors[0]);
    assert.equal(lines.length, 1, 'startup errors must be visible before site.js loads');
    assert.equal(lines[0].className, 'log-line log-error');
  } else {
    assert.deepEqual(errors, []);
    assert.deepEqual(lines, []);
  }
  if (expected.tag) assert.equal(sandbox.tag, expected.tag);
})().catch(error => { console.error(error); process.exitCode = 1; });
'''


class CustomizationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payloads = standalone.load_payloads(['payloads/hello_world.js'])
        cls.default, _ = standalone.build_html(cls.payloads, include_kexp=False)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def asset(self, filename, source):
        path = self.directory / filename
        path.write_text(source, encoding='utf-8')
        return str(path)

    def build(self, **kwargs):
        html, meta = standalone.build_html(self.payloads, include_kexp=False, **kwargs)
        self.assertEqual(standalone.check_output(html, self.payloads, meta), [])
        # Customization must not rewrite the exploit, offsets, or queued payloads.
        for name in ('__modules', '__offsets', 'STANDALONE'):
            self.assertEqual(standalone.extract_json_assignment(html, name),
                             standalone.extract_json_assignment(self.default, name))
        return html

    def run_boot(self, html, **expected):
        node = shutil.which('node')
        if not node:
            self.skipTest('node is needed to exercise the generated startup scripts')
        path = self.directory / 'page.html'
        path.write_text(html, encoding='utf-8')
        result = subprocess.run([node, '-e', NODE_CHECK, str(path), json.dumps(expected)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_css_overrides_in_head_in_argument_order(self):
        first = self.asset('first.css', 'body { color: red; }')
        second = self.asset('second.css', 'body { color: blue; }')
        html = self.build(css_files=[first, second])
        self.assertLess(html.index('color: red'), html.index('color: blue'))
        self.assertLess(html.index('color: blue'), html.index('</head>'))
        self.assertLess(html.index('.log-setup'), html.index('color: red'))

    def test_standalone_omits_remote_hud_and_reserved_space(self):
        html = self.default
        self.assertNotIn('id="hud"', html)
        self.assertNotIn('id="hud-fw"', html)
        self.assertNotIn('id="hud-addr"', html)
        self.assertNotIn('padding-right: 200px', html)
        self.assertIn('padding: 16px;', html)
        # Socket-served pages still need the connection and firmware display.
        served = standalone.read_text('index.html')
        self.assertIn('id="hud"', served)
        self.assertIn('padding-right: 200px', served)

    def test_awaits_each_script_before_boot(self):
        first = self.asset('first.js', "window.trace.push('first-start');\n"
                           "await window.gate; window.trace.push('first-done');")
        second = self.asset('second.js', "window.trace.push('second-start');\n"
                            "return new Promise(resolve => setTimeout(() => {\n"
                            "  window.trace.push('second-done'); resolve();\n}, 5));")
        self.run_boot(self.build(js_files=[first, second]), ready=True,
                      trace=['first-start', 'first-done', 'second-start', 'second-done', 'boot'])

    def test_script_failure_stops_later_scripts_and_boot(self):
        for source in ("throw new Error('broken');", "await Promise.reject(new Error('broken'));",
                       "return Promise.reject(new Error('broken'));", "const = broken;"):
            with self.subTest(source=source):
                failed = self.asset('failed.js', source)
                later = self.asset('later.js', "window.trace.push('must-not-run');")
                self.run_boot(self.build(js_files=[failed, later]), ready=False,
                              trace=[], error='failed.js')

    def test_script_html_delimiters_and_unicode_survive(self):
        tag = '</ScRiPt><!--<script>🌐'
        script = self.asset('delimiters.js', 'window.tag = ' + json.dumps(tag) + ';\n'
                            "await window.gate; window.trace.push('done');")
        html = self.build(js_files=[script])
        self.assertNotIn(tag, html)
        self.run_boot(html, ready=True, trace=['done', 'boot'], tag=tag)

    def test_cli_files_resolve_from_working_directory(self):
        self.asset('theme.css', 'body { color: cyan; }')
        self.asset('first.js', 'window.custom = 1;')
        self.asset('second.js', 'window.custom += 1;')
        output = self.directory / 'page.html'
        result = subprocess.run([sys.executable, os.path.join(standalone.HERE, 'build_standalone.py'),
                                 'payloads/hello_world.js', '--no-kexp', '--css', 'theme.css',
                                 '--js', 'first.js', '--js', 'second.js', '-o', str(output), '--list'],
                                cwd=self.directory, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        scripts = standalone.extract_json_assignment(output.read_text(), '__startupScripts')
        self.assertEqual([script['path'] for script in scripts], ['first.js', 'second.js'])
        self.assertIn('custom css: theme.css', result.stdout)
        self.assertIn('custom js: first.js', result.stdout)

    def test_bad_assets_report_the_file(self):
        for kind in ('css', 'js'):
            with self.assertRaisesRegex(SystemExit, '--' + kind + ' cannot read'):
                standalone.build_html(self.payloads, include_kexp=False,
                                      **{kind + '_files': [str(self.directory / 'missing')]})
        broken = self.asset('broken.css', 'body::before { content: "</StYlE>"; }')
        with self.assertRaisesRegex(SystemExit, 'closing style tag'):
            standalone.build_html(self.payloads, include_kexp=False, css_files=[broken])


if __name__ == '__main__':
    unittest.main()
