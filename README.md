# ProtoSec v1.0.0

ProtoSec is a local-first source security scanner with a PyQt6 desktop dashboard and an optional C++20 scanning core. Source files are inspected on the user's machine; scanning does not upload project contents.

## Run from source

```powershell
python -m pip install -r requirements.txt
python -m src.gui
```

The GUI supports folder selection and drag-and-drop, live scan progress, a cybernetic-purple theme with an animated light/dark transition, searchable severity filters, one-click remediation prompt copying, and standalone HTML/JSON report export. The responsive layout reflows for narrower windows, collapses the sidebar on compact screens, and scrolls vertically when the available height is limited. The menu bar provides scanning, theme, CVE database, safe auto-patch, Live Guard, pre-commit hook, passive header, package reputation, and Git-history actions.

If a compiled `scanner_core` binary is found beside the app or in `build/bin` (or `build/cmake/bin`), the GUI uses it. Otherwise, it runs the Python scanner. The Python CLI is available as:

```powershell
python -m src.main C:\path\to\project
```

Project scans use an incremental per-rule cache by default. The SQLite database is stored per user under `%LOCALAPPDATA%\ProtoSec\scan-cache.sqlite3` on Windows or `$XDG_DATA_HOME/ProtoSec/scan-cache.sqlite3` (defaulting to `~/.local/share/ProtoSec/scan-cache.sqlite3`) elsewhere. Set `PROTOSEC_CACHE_PATH` to select another database file. The cache stores file hashes, line counts, and redacted findings—not source contents—and includes a schema version. Changed files rerun all active rules; a changed rule fingerprint reruns only that rule across files (plus declared dependencies such as secret suppression for entropy checks). Scan reports include per-rule cache hit statistics. Corrupt results are rescanned, and an unreadable SQLite database is preserved with a `.corrupt-*` suffix before rebuilding. Use `python -m src.main --no-cache C:\path\to\project` to bypass the cache for one scan.

The optional `python -m src.main --serve` API binds to `127.0.0.1` only. It accepts HTTPS repository URLs without embedded credentials, query strings, or fragments; repository cloning is limited to 120 seconds, scans to 180 seconds, and at most two API scans run concurrently. Do not expose this unauthenticated development API on a network interface.

## Build the standalone desktop app

Install a C++20 compiler and CMake 3.20+, then:

```powershell
python -m pip install -r requirements-build.txt
python build.py
```

The build produces a one-file, windowed PyInstaller app in `dist/` and bundles the CMake-built scanner, icon assets, and Tree-sitter license notices from `licenses/`. For convenience, `build.py` also copies `assets/` and `licenses/` next to the executable; frozen path resolution supports both embedded one-file resources and adjacent assets. The OSV database is not bundled: it is downloaded on request to the per-user data directory. CMake downloads pinned Tree-sitter runtime and grammar sources on the first build, so that build requires network access. Run the build separately on each target OS; native PyInstaller executables are not cross-compiled. The release CMake configuration enables optimized builds and link-time optimization without assuming host-specific CPU instructions.

Run `ctest --test-dir build/cmake --output-on-failure` after building to execute the native tests and, when CMake finds Python, the Python regression suite. `build.py` configures CTest to use the same Python interpreter used to package ProtoSec.

## Scanner coverage

The scanner includes 20+ high-signal line-level rules for provider/API credentials (including Slack, npm, and Shopify tokens), likely high-entropy secrets, environment files, public client secret variables, Firebase rules, SQL interpolation, dangerous HTML/code execution, unsafe deserialization, wildcard CORS, weak cryptography, and related configuration issues. Structural checks also flag SQL tables without a visible RLS enablement statement and Next.js/FastAPI mutation routes without a visible authentication check.

The C++ core uses embedded Tree-sitter grammars for JavaScript/JSX, TypeScript/TSX, Python, and SQL to identify and mask comment ranges before applying its existing heuristic checks. String contents remain analyzed. Common test, dependency, cache, and build directories are excluded. This improves comment-related false positives, but does not guarantee zero false positives.

These are heuristic static checks, not a proof of security. Findings may need human review, and a clean scan only means the enabled rules did not identify a match. The scanner does not provide interprocedural taint tracking or exact AST verification of middleware execution order. Secret-like values are redacted in finding snippets. The Python fallback remains heuristic and does not use the C++ Tree-sitter grammars.

## Optional dependency CVE scans

The **Scan CVE** checkbox is off by default. It checks `package-lock.json` and exactly pinned entries in `requirements*.txt` against a local OSV SQLite index. To create or refresh the index, choose **Tools → Update CVE database**; this explicitly downloads the official npm and PyPI OSV archives. Scanning is offline after indexing. The feed can be large, and this feature does not currently cover every package manager, manifest format, or OSV version-range form.

## Reviewed patches and Live Guard

**Auto-fix safe issues** prepares a unified-diff preview for a limited set of deterministic edits: enabling RLS in SQL migrations, removing `NEXT_PUBLIC_` from sensitive environment-variable names, and adding `.env*` to `.gitignore` while keeping common example files unignored. Review the diff before applying it. ProtoSec refuses to apply a preview if a target file changed in the meantime.

**Live Guard** is opt-in. It asynchronously watches source, environment, package-lock, and requirements files in the selected project, debounces file-change events, and runs a local scan. If findings are present, it puts the first remediation prompt on the clipboard and shows a system-tray notification when available. Operating-system watch limits may prevent monitoring every path in a very large project.

**Install pre-commit hook** is available from **Tools** when a compiled `scanner_core` is present and the selected folder is a Git worktree root. The hook snapshots staged Git blobs (not working-tree contents) into a temporary directory, scans that snapshot, and blocks the commit if any finding is reported. It refuses to overwrite an existing hook. The generated hook requires Python 3 to run.

The scanner also supports direct staged-snapshot invocation:

```powershell
scanner_core --staged-only C:\path\to\staged-snapshot
```

In this mode, findings produce a nonzero exit status for hook use; regular scans retain their existing exit behavior.

## Local MCP tools

Run `python -m src.main --mcp` to start the MCP server over standard input/output. It opens no network port and exposes only `scan_project` and `verify_fix`; both accept a local project path, and `verify_fix` simply re-scans and reports whether findings remain. The tools do not modify files.

Example client configuration:

```json
{
  "mcpServers": {
    "protosec": {
      "command": "python",
      "args": ["-m", "src.main", "--mcp"]
    }
  }
}
```

## Passive checks and supply-chain options

**Check security headers** makes one `HEAD` request to the supplied origin and reports common security headers. Localhost is allowed directly; a non-local host requires an explicit authorization confirmation. It does not follow redirects, fetch response bodies, read Supabase tables, or send request bursts; rate-limit headers are only reported if present.

**Check package names online** is off by default. When enabled for a manual scan, it sends at most 25 dependency names to the public npm or PyPI registry and checks whether each package exists, resembles a curated popular package name, or was first published within the last 30 days. Names can reveal private project dependencies, so leave this option disabled when that disclosure is not acceptable. It does not install packages or assess download counts.

**Scan Git history for secrets** is also off by default. It examines added lines in up to 100 local commits and reports commit hashes and file locations while redacting secret values. It never rewrites history; rotate exposed credentials and review any history-scrubbing operation separately.

## Local custom rules

The Python scanner, GUI, and MCP tools load optional `[[rules]]` entries from the project's `.vibeguard.toml`. Rules use `CUSTOM-...` IDs, a title, severity, regex pattern, and supported file extensions:

```toml
[[rules]]
id = "CUSTOM-001"
title = "Internal credential marker"
severity = "HIGH"
pattern = "INTERNAL_[A-Za-z0-9]{24,}"
extensions = [".py", ".ts"]
```

Rules are local—not fetched from a marketplace—and are bounded by configuration, file, regex-time, and scan-time limits. The standalone C++ CLI and staged pre-commit scanner do not currently evaluate `.vibeguard.toml`.

## Offline Pro license configuration

The app verifies signed Ed25519 license tokens locally. No signing key is included. To configure a release build, set `PROTOSEC_LICENSE_PUBLIC_KEY_HEX` to the vendor's 32-byte Ed25519 public key before packaging. The token format is `base64url(payload).base64url(signature)`; the signed UTF-8 JSON payload must contain `product: "ProtoSec"` and `tier: "PRO"`, and may contain `email`, `issued_at` (Unix seconds), and `expires_at` (Unix seconds). Keep the matching private signing key offline and out of the repository.

If no public key is configured, license activation is deliberately disabled. Offline licensing can verify signatures, but cannot prevent a determined user from modifying a locally distributed application.
