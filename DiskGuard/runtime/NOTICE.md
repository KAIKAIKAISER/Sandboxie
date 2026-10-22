# Bundled official Sandboxie Classic runtime

This directory contains the unmodified official `Sandboxie-Classic-x64-v5.73.8.exe`, obtained from Sandboxie release `v1.18.8`. DiskGuard verifies its pinned SHA-256 and Windows Authenticode signature before offering installation. The installer deploys its Windows-signed driver and service through normal administrator authorization. Driver signing enforcement remains enabled.

Copyright 2004–2020 Sandboxie Holdings, LLC; Copyright 2020–2026 David Xanatos and contributors. Sandboxie Classic core is distributed under GPLv3. See the GPL license supplied with DiskGuard and the licenses inside the official installer.

- Official binary: https://github.com/sandboxie-plus/Sandboxie/releases/tag/v1.18.8
- Complete corresponding upstream source for this unmodified runtime: https://github.com/sandboxie-plus/Sandboxie/archive/refs/tags/v1.18.8.zip
- Source tree and build files: https://github.com/sandboxie-plus/Sandboxie/tree/v1.18.8
- DiskGuard controller source: https://github.com/KAIKAIKAISER/Sandboxie/tree/diskguard/DiskGuard

No Sandboxie Plus Qt UI is included. Existing Sandboxie installations and configurations are preserved; DiskGuard does not automatically replace, downgrade, or remove a shared runtime. Uninstalling DiskGuard leaves Sandboxie installed because other applications and sandboxes may use it. You can remove it separately through Windows Settings if no longer needed.
