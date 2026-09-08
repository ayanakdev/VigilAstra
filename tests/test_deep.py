"""Controlled vulnerable/safe applications. Server binds to loopback only."""
import html
import json
import os
import sqlite3
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vigilastra as v


class LabHandler(BaseHTTPRequestHandler):
    rate_count = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        p = urlsplit(self.path)
        params = parse_qs(p.query, keep_blank_values=True)
        status, headers, kind = 200, {}, 'text/html'
        if p.path == '/':
            body = '''<html><title>Controlled security lab</title>
            <a href="/vuln?id=1">unsafe query</a><a href="/safe?id=1">bound query</a>
            <a href="/reflect?q=hello">unsafe output</a><a href="/escaped?q=hello">escaped output</a>
            <a href="/redirect?next=/">redirect</a><a href="/cors">cors</a>
            <form method="get" action="/search"><input name="q" value="apple"></form>
            <a href="/delete?id=1">must not crawl</a><a href="https://example.org/">off scope</a>
            </html>'''
        elif p.path in ('/vuln', '/safe', '/search'):
            db = sqlite3.connect(':memory:')
            db.execute('CREATE TABLE products(id INTEGER, name TEXT)')
            db.executemany('INSERT INTO products VALUES (?,?)', [(1, 'apple'), (2, 'orange')])
            try:
                if p.path == '/vuln':
                    rows = db.execute('SELECT id,name FROM products WHERE id=' + params.get('id', ['1'])[0]).fetchall()
                elif p.path == '/safe':
                    rows = db.execute('SELECT id,name FROM products WHERE id=?', (params.get('id', ['1'])[0],)).fetchall()
                else:
                    # Emulates a search query context, including the quote error seen in SQLite-backed apps.
                    rows = db.execute("SELECT id,name FROM products WHERE name LIKE '%" + params.get('q', [''])[0] + "%'" ).fetchall()
                body, kind = json.dumps({'products': rows}), 'application/json'
            except sqlite3.Error as exc:
                status, body = 500, 'sqlite3.OperationalError: ' + str(exc)
            finally:
                db.close()
        elif p.path in ('/reflect', '/escaped'):
            value = params.get('q', [''])[0]
            body = '<html><p>Search result: ' + (html.escape(value) if p.path == '/escaped' else value) + '</p></html>'
        elif p.path == '/redirect':
            status, headers, body = 302, {'Location': params.get('next', ['/'])[0]}, ''
        elif p.path == '/cors':
            headers = {'Access-Control-Allow-Origin': self.headers.get('Origin', 'https://trusted.example'), 'Access-Control-Allow-Credentials': 'true'}
            body = 'Public CORS test response'
        elif p.path == '/rate':
            LabHandler.rate_count += 1
            status = 429 if LabHandler.rate_count >= 3 else 200
            headers, body = {'Retry-After': '60'}, 'Rate fixture'
        elif p.path == '/always-error':
            status, body = 500, 'sqlite3.OperationalError: pre-existing server error'
        elif p.path == '/delete':
            raise AssertionError('Mutation route must never be requested')
        else:
            status, body = 404, 'Not found'
        raw = body.encode()
        self.send_response(status)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(raw)))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)


class DeepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), LabHandler)
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.env = patch.dict(os.environ, {'VIGILASTRA_LAB_ORIGINS': cls.base})
        cls.env.start()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.server.shutdown()
        cls.server.server_close()

    def fetcher(self):
        return v.SafeFetcher(seconds=30, max_requests=180, interval=0)

    def target(self, path, name='id', value='1'):
        return v.ProbeTarget(self.base + path, [(name, value)])

    def test_actual_sqlite_injection_is_detected(self):
        r = v.Assessment(self.base)
        v.test_sql(self.fetcher(), self.target('/vuln'), 0, r)
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.findings[0].cwe, 'CWE-89')
        self.assertIn('repeated database errors', r.findings[0].confidence)

    def test_parameterized_query_is_not_flagged(self):
        r = v.Assessment(self.base)
        v.test_sql(self.fetcher(), self.target('/safe'), 0, r)
        self.assertFalse(r.findings)

    def test_search_context_injection(self):
        r = v.Assessment(self.base)
        v.test_sql(self.fetcher(), self.target('/search', 'q', 'apple'), 0, r)
        self.assertTrue(r.findings)

    def test_baseline_error_does_not_prove_sqli(self):
        r = v.Assessment(self.base)
        v.test_sql(self.fetcher(), self.target('/always-error'), 0, r)
        self.assertFalse(r.findings)

    def test_reflection_requires_html_interpretation(self):
        r = v.Assessment(self.base)
        v.test_reflection(self.fetcher(), self.target('/reflect', 'q', 'hello'), 0, r)
        self.assertEqual(len(r.findings), 1)
        r = v.Assessment(self.base)
        v.test_reflection(self.fetcher(), self.target('/escaped', 'q', 'hello'), 0, r)
        self.assertFalse(r.findings)

    def test_redirect_is_not_followed(self):
        r = v.Assessment(self.base)
        fetcher = self.fetcher()
        self.assertTrue(v.test_redirect(fetcher, self.target('/redirect', 'next', '/'), 0, r))
        self.assertEqual(fetcher.requests, 1)

    def test_cors_requires_two_origins(self):
        r = v.Assessment(self.base)
        fetcher = self.fetcher()
        self.assertTrue(v.test_cors(fetcher, self.target('/cors'), r))
        self.assertEqual(fetcher.requests, 2)

    def test_rate_sample_honors_429(self):
        LabHandler.rate_count = 0
        fetcher = self.fetcher()
        snap = fetcher.fetch(self.base + '/rate')
        r = v.Assessment(self.base)
        v.sample_rate_limit(fetcher, snap, r, True)
        self.assertTrue(fetcher.halted)
        self.assertEqual(r.rate_sample['statuses'][-1], 429)
        self.assertFalse(r.findings)
        with self.assertRaises(v.AuditError):
            fetcher.fetch(self.base + '/safe?id=1')

    def test_complete_deep_loop(self):
        original = v.SafeFetcher
        with patch.object(v, 'SafeFetcher', side_effect=lambda **kw: original(**kw, interval=0)):
            result = v.audit(self.base, browser=False, options=v.ScanOptions('Lab QA', 10, 3, 180, 45, True, False, False, False, 10))
        self.assertGreater(len(result.pages), 3)
        self.assertTrue(any(f.cwe == 'CWE-89' for f in result.findings))
        self.assertFalse(any('/safe' in x for f in result.findings if f.cwe == 'CWE-89' for x in f.locations))
        self.assertFalse(any('/delete' in p['URL'] for p in result.pages))
        self.assertTrue(all(f.finding_id for f in result.findings))
        self.assertTrue(v.build_pdf(result).startswith(b'%PDF-'))
        Path('tmp').mkdir(exist_ok=True)
        Path('tmp/deep_qa.json').write_text(json.dumps(v.asdict(result), indent=2), encoding='utf-8')
        Path('tmp/deep_qa.pdf').write_bytes(v.build_pdf(result))

    def test_docs_page_has_target_guidance(self):
        with self.assertRaisesRegex(v.AuditError, 'documentation page'):
            v.audit('https://owasp.org/www-project-juice-shop/', options=v.ScanOptions(active=True))

    def test_openapi_only_safe_get_operations(self):
        data = {'paths': {'/api/items': {'get': {'parameters': [{'name': 'id', 'in': 'query', 'schema': {'type': 'integer'}}]}},
                          '/delete': {'get': {}}, '/write': {'post': {}}, '/items/{id}': {'get': {}}}}
        self.assertEqual(v.openapi_seeds(data, self.base), [self.base + '/api/items?id=1'])

    def test_chat_context_redacts_keys(self):
        r = v.portfolio_demo()
        with patch.dict(os.environ, {'GEMINI': 'SYNTHETIC_SECRET_KEY'}):
            r.findings[0].evidence = 'Key: SYNTHETIC_SECRET_KEY'
            context = json.dumps(v.report_context(r, 'Explain SQL'))
        self.assertNotIn('SYNTHETIC_SECRET_KEY', context)
        self.assertIn('F001', context)


if __name__ == '__main__':
    unittest.main(verbosity=2)
