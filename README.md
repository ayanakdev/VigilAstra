# VigilAstra

A single-file Streamlit application for evidence-based, passive web security assessments. Python 3.11 or newer.

## Run on Windows

The workspace virtual environment contains the dependencies. Browser inspection can use the installed Chrome or Edge if the bundled Chromium download is unavailable. From this directory:

```powershell
.\.venv\Scripts\python -m streamlit run vigilastra.py
```

Open http://localhost:8501. Enter an authorized public HTTP(S) URL and select **Run assessment**. The sidebar controls browser inspection. Download the completed `VigilAstra_Security_Audit.pdf` from the results screen; evidence JSON is available under Coverage.

Your existing `.env.local` entry named `NVD_API` is supported. The standard `NVD_API_KEY` environment variable takes precedence. The app loads the file beside `vigilastra.py`, does not overwrite it, and never displays the key.

For a fresh installation:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python -m playwright install chromium
.\.venv\Scripts\python -m streamlit run vigilastra.py
```

All application logic, inline SVG, styles, audit code and PDF generation live in `vigilastra.py`. The optional `.streamlit/config.toml` supplies native dark theme colors, loopback binding and disabled telemetry. The app also renders its own dark styling when copied elsewhere.

## What it assesses

- Final live response: CSP, HSTS, X-Frame-Options / frame-ancestors, X-Content-Type-Options and Referrer-Policy, plus cookie attributes.
- Static script URLs, library banners, Angular DOM attributes and isolated Chromium runtime signals for jQuery, Bootstrap, React, Angular and AngularJS.
- NVD API v2 product queries, pagination, rejected-record filtering, exact versions and inclusive/exclusive version ranges. Additional platform conditions and filename-only evidence remain candidates.
- Evidence, potential impact, practical remediation, source links and published CVSS v3.1 scores where available.
- An executive PDF with a custom severity matrix, readable evidence/remediation sections, coverage notes and the required final-page notice.

Missing security headers do not have official CVSS scores. Their severity labels are explicitly analyst priorities. Component scores are published **base** scores attributed to their NVD-record source, not invented environment-specific impact scores. A matched version is not proof that the vulnerable feature is reachable. Conditional matches are counted as Unscored while retaining any published score for reference.

## Boundaries and operational behavior

This is a bounded, unauthenticated single-page assessment, not a penetration test, exhaustive crawler or SBOM scanner. Hidden versions, unknown CPE mappings, dynamic imports, server-side dependencies and unauthenticated access challenges can limit coverage. Reports explicitly retain partial results when the browser, scripts or NVD fail. A zero count does not imply a secure target.

Only public HTTP(S) on ports 80/443 is allowed. Every target/asset/redirect hostname is checked; requests connect to a validated IP with the original hostname used for TLS verification and SNI. Environment proxies and automatic redirects are disabled for these requests. TLS errors never trigger an insecure retry.

Chromium uses its sandbox. HTTP traffic is intercepted through the same validated transport, while an unreachable browser proxy blocks accidental direct HTTP egress. Non-GET requests, media, service workers and WebSockets are blocked. Response cookies are inspected as metadata and not replayed; client-created cookie metadata is listed separately. Restriction-induced rendering differences are reported. GET requests can still have side effects on poorly designed targets; use authorized targets.

Budgets: six redirects, 2 MB decoded per response, 55 page/asset requests, 15 static scripts, 12 component versions, and bounded NVD retries/pagination. Typical scans take tens of seconds; slow targets and NVD throttling take longer. The fetch deadline does not hard-interrupt an operating-system DNS lookup. Cookie values and URL query strings are omitted from evidence, but paths and response policy evidence may still be sensitive.

Remediation examples must be merged with the real server configuration and tested. CDN users must update the deployed assets and SRI hashes. Framework migrations cannot be safely reduced to a universal patch command. Consult each linked advisory before closing a finding.

For shared production hosting, add authentication, TLS termination, process/concurrency limits, an outbound firewall denying private networks, monitoring and dependency patching. The included configuration is local-first and does not provide multi-tenant identity or job isolation.

## CLI and verification

```powershell
.\.venv\Scripts\python vigilastra.py --url https://example.com --output VigilAstra_Security_Audit.pdf
.\.venv\Scripts\python vigilastra.py --url https://example.com --no-browser
.\.venv\Scripts\python -m pip install pypdf
.\.venv\Scripts\python vigilastra.py --self-test
```

The self-tests use offline fixtures for SSRF restrictions, CSP fallback, HSTS parsing, referrer fallback, version boundaries/environment conditions, cookie redaction, CVSS handling and PDF text/pagination. `--demo-pdf` creates a clearly labeled synthetic layout fixture; it is never shown as a live scan.

Verified in this workspace with Python 3.13: compilation, 13 regression tests, dependency consistency, a real NVD product lookup using the configured key, an example.com scan with rendered Chrome inspection, desktop/mobile layouts, PDF/JSON downloads, result tabs and stale-result clearing. Both synthetic and live six-page PDFs were rendered and visually reviewed. Chromium's bundled download timed out; the installed Chrome fallback completed the browser checks.

Implementation references: [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities), [CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document), [CSP reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy), [Playwright browser routing](https://playwright.dev/python/docs/api/class-browsercontext#browser-context-route), [Streamlit status](https://docs.streamlit.io/develop/api-reference/status/st.status).
