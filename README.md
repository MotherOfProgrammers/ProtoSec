# ProtoSec v1.0.0

ProtoSec is a local-first source security scanner with a PyQt6 desktop dashboard and an optional C++20 scanning core. Source files are inspected on the user's machine; scanning does not upload project contents.

## Run from source

```powershell
python -m pip install -r requirements.txt
python -m src.gui
```

The GUI supports folder selection and drag-and-drop, live scan progress, a cybernetic dark theme with an animated light/dark transition, searchable severity filters, one-click remediation prompt copying, and standalone HTML/JSON report export. Its layout reflows for narrower windows, collapses the sidebar on compact screens, and scrolls vertically when the available height is limited.

If a compiled `scanner_core` binary is found beside the app or in `build/bin` (or `build/cmake/bin`), the GUI uses it. Otherwise, it runs the Python scanner. The Python CLI is available as:

```powershell
python -m src.main C:\path\to\project
```

## Build the standalone desktop app

Install a C++20 compiler and CMake 3.20+, then:

```powershell
python -m pip install -r requirements-build.txt
python build.py
```

The build produces a one-file, windowed PyInstaller app in `dist/` and bundles the CMake-built scanner. Run the build separately on each target OS; native PyInstaller executables are not cross-compiled. The release CMake configuration enables optimized builds and link-time optimization without assuming host-specific CPU instructions.

## Scanner coverage

The scanner includes 20+ high-signal line-level rules for provider/API credentials (including Slack, npm, and Shopify tokens), likely high-entropy secrets, environment files, public client secret variables, Firebase rules, SQL interpolation, dangerous HTML/code execution, unsafe deserialization, wildcard CORS, weak cryptography, and related configuration issues. Structural checks also flag SQL tables without a visible RLS enablement statement and Next.js/FastAPI mutation routes without a visible authentication check.

These are heuristic static checks, not a proof of security. Findings may need human review, and a clean scan only means the enabled rules did not identify a match. Secret-like values are redacted in finding snippets. Common dependency, cache, and build directories are excluded.

## Offline Pro license configuration

The app verifies signed Ed25519 license tokens locally. No signing key is included. To configure a release build, set `PROTOSEC_LICENSE_PUBLIC_KEY_HEX` to the vendor's 32-byte Ed25519 public key before packaging. The token format is `base64url(payload).base64url(signature)`; the signed UTF-8 JSON payload must contain `product: "ProtoSec"` and `tier: "PRO"`, and may contain `email`, `issued_at` (Unix seconds), and `expires_at` (Unix seconds). Keep the matching private signing key offline and out of the repository.

If no public key is configured, license activation is deliberately disabled. Offline licensing can verify signatures, but cannot prevent a determined user from modifying a locally distributed application.
