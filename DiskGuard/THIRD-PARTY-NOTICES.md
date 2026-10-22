# Third-party notices

DiskGuard is a downstream GPL-3.0-or-later controller, not an official Sandboxie release.

- Sandboxie core: Copyright 2004–2020 Sandboxie Holdings, LLC; Copyright 2020–2026 David Xanatos and contributors. GPLv3; see repository `LICENSE.Classic` and `Sandboxie/COPYING`. Core code is not modified. DiskGuard 0.2 includes the unmodified official Classic x64 5.73.8 installer, with pinned SHA-256 and Authenticode verification. Complete corresponding source and build files are available at https://github.com/sandboxie-plus/Sandboxie/archive/refs/tags/v1.18.8.zip and https://github.com/sandboxie-plus/Sandboxie/tree/v1.18.8 ; see `runtime/NOTICE.md` and `runtime/runtime.lock.json` for provenance.
- Sandboxie Plus Qt UI and its assets are not used or bundled. The repository's other component licenses remain intact.
- Tauri 2 and Tauri plugins: MIT OR Apache-2.0.
- Rust serde / serde_json: MIT OR Apache-2.0; libloading: ISC; tempfile: MIT OR Apache-2.0; chrono: MIT OR Apache-2.0; csv: Unlicense OR MIT; windows-sys: MIT OR Apache-2.0.
- TypeScript: Apache-2.0; Vite: MIT. Frontend dependencies and versions are recorded in package-lock.json; Rust versions in Cargo.lock.
- Microsoft Edge WebView2 is provided by Microsoft and governed by its own runtime terms; the application does not bundle a browser engine.

Controller source is available in this Fork. Preserve component copyright headers and licenses when redistributing. The portable package contains a copy of GPLv3, these notices, and the official runtime provenance notice.
