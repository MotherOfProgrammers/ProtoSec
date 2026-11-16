# ProtoSec

ProtoSec is a desktop app and command-line tool that checks a project for common security problems. It scans files on your computer and reports possible issues for you to review.

ProtoSec is a helper for finding problems early. It is not a complete security audit, and a clean scan does not guarantee that an application is secure.

## Get started

### Run the desktop app from source

```powershell
python -m pip install -r requirements.txt
python -m src.gui
```

Choose a project folder or drag it into the app, then start a scan. You can filter findings, copy a remediation prompt, and export a report as HTML or JSON.

### Scan from the command line

```powershell
python -m src.main C:\path\to\project
```

When the compiled C++ scanner is available, ProtoSec uses it. Otherwise, it uses the Python scanner, which has fewer analysis features.

## What ProtoSec checks

ProtoSec includes rules for common problems such as:

- Exposed API keys, passwords, and other likely secrets.
- Sensitive values placed in public client-side environment variables.
- Risky code patterns, including unsafe SQL construction and dynamic code execution.
- Some insecure database, authentication, and configuration patterns.
- Dependency vulnerabilities, when **Scan CVE** is enabled and an OSV database is installed.

The C++ scanner uses Tree-sitter to understand comments in JavaScript, TypeScript, Python, and SQL. It also checks for some request-input flows into SQL and dynamic-code sinks within a single function. Most other checks are rule-based heuristics.

## Features

- **Responsive desktop app:** progress updates, severity filters, searchable findings, and a layout that adapts to smaller windows.
- **Incremental scans:** a local cache helps avoid re-reading unchanged files. The cache stores metadata, hashes, and findings—not source contents—and periodically verifies file hashes.
- **CVE checks:** checks `package-lock.json` and exactly pinned entries in `requirements*.txt` against a local OSV database. Use **Tools → Update CVE database** to download or refresh it. The download requires internet; scans can use the database offline afterward. The **Scan CVE** option is off by default.
- **Safe patch previews:** offers a reviewable diff for a few fixes: enabling SQL row-level security, removing public prefixes from sensitive client-side environment names, and adding environment files to `.gitignore`. ProtoSec checks that files have not changed since the preview before applying it.
- **Live Guard:** optionally watches project files and rescans after changes. Operating-system watch limits may restrict coverage in very large projects.
- **Pre-commit hook:** can scan staged files and block a commit when findings are reported. This requires the compiled scanner and Python 3; ProtoSec will not overwrite an existing hook.
- **Git history scan:** optionally checks added lines in up to 100 local commits for secrets. It reports locations but does not rewrite history.
- **Custom rules:** the Python scanner, desktop app, and MCP tools can read local `[[rules]]` from a `.vibeguard.toml` file. The C++ scanner and pre-commit hook do not currently use these rules.
- **Local MCP server:** `python -m src.main --mcp` exposes `scan_project` and `verify_fix` over standard input/output. It does not open a network port or modify project files.
- **Local scan API:** `python -m src.main --serve` starts an optional API on `127.0.0.1`. It can clone and scan public HTTPS repositories with limits on URL format, clone size, time, and concurrent scans. Do not expose it to a network.

## Optional online checks

Some optional tools contact external services:

- Updating the CVE database downloads vulnerability data from OSV.
- Package-name checks send dependency names to the npm or PyPI registry. This may reveal private dependency names; the check is off by default.
- The security-header check sends a single `HEAD` request to the address you provide. It does not probe application routes or test for vulnerabilities.

Normal scans run on your computer; source files are not uploaded to ProtoSec. If you use the optional API, it fetches the repository URL you submit and scans the clone locally.

## Important limits

- Findings are suggestions that need review. Rules can miss issues or report false positives.
- Tree-sitter is used for comment handling and limited analysis; ProtoSec is not a full AST-based analyzer.
- Taint analysis is limited to assignments inside one function. It does not trace data across functions or verify authentication middleware order exactly.
- The Python fallback is heuristic and does not use the C++ Tree-sitter analysis.
- CVE coverage is limited to the supported manifest formats and version ranges. It does not determine whether vulnerable dependency code is reachable in your application.
- Live Guard can miss changes if the operating system cannot watch every project path.
- The header check is passive; ProtoSec does not perform dynamic exploitation or stress testing.
- The repository API validates host addresses before cloning, but does not pin the Git connection to those validated addresses. Keep the API bound to localhost.

## Build the standalone app

Install Python dependencies and build dependencies:

```powershell
python -m pip install -r requirements.txt
python -m pip install -r requirements-build.txt
python build.py
```

The build requires CMake 3.20 or newer and a C++20 compiler. The first build downloads pinned Tree-sitter sources and therefore requires internet access. The standalone app is written to `dist/`; build it separately on each operating system.

## Run tests

After building:

```powershell
ctest --test-dir build/cmake --output-on-failure
```

Or run the Python tests directly:

```powershell
python -m unittest discover -s tests
```

## Cache location

The scan cache is stored in the user's data directory by default. Set `PROTOSEC_CACHE_PATH` to use a different SQLite file, or run one scan without the cache:

```powershell
python -m src.main --no-cache C:\path\to\project
```
