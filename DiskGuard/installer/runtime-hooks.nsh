; SPDX-License-Identifier: GPL-3.0-or-later
; Tauri copies the executable and runtime/ resources before this hook.
; Installation, hash verification, Windows trust verification, and standard
; UAC elevation are shared with the application's native install command.
!ifndef DISKGUARD_BUNDLED_RUNTIME_HOOKS
!define DISKGUARD_BUNDLED_RUNTIME_HOOKS

!macro NSIS_HOOK_POSTINSTALL
  Push $R0
  ClearErrors
  DetailPrint "Checking the installed Sandboxie runtime..."
  ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --install-bundled-runtime' $R0
  IfErrors diskguard_runtime_launch_failed
  StrCmp $R0 "0" diskguard_runtime_install_complete
  StrCmp $R0 "3010" diskguard_runtime_reboot_required
  StrCmp $R0 "1223" diskguard_runtime_cancelled

  DetailPrint "Official Sandboxie runtime installation failed (exit $R0)."
  MessageBox MB_OK|MB_ICONEXCLAMATION "DiskGuard 文件已安装，但官方 Sandboxie 运行时尚未就绪（错误代码 $R0）。磁盘保护需要该运行时。可从 DiskGuard 重试安装；诊断位于当前用户的 DiskGuard runtime-install.json 日志中。" /SD IDOK
  Pop $R0
  SetErrorLevel 1
  Abort

diskguard_runtime_launch_failed:
  DetailPrint "Could not start DiskGuard's native runtime installer."
  MessageBox MB_OK|MB_ICONEXCLAMATION "DiskGuard 文件已安装，但无法启动运行时安装程序。磁盘保护尚未就绪，请从 DiskGuard 重试安装。" /SD IDOK
  Pop $R0
  SetErrorLevel 1
  Abort

diskguard_runtime_cancelled:
  DetailPrint "Sandboxie runtime elevation or installation was cancelled."
  MessageBox MB_OK|MB_ICONEXCLAMATION "已取消官方 Sandboxie 运行时的安装授权。DiskGuard 文件已安装，但磁盘保护尚未就绪；可从 DiskGuard 重新安装。" /SD IDOK
  Pop $R0
  SetErrorLevel 1223
  Abort

diskguard_runtime_reboot_required:
  DetailPrint "The official Sandboxie runtime requires a Windows restart."
  MessageBox MB_OK|MB_ICONINFORMATION "官方 Sandboxie 运行时需要重启 Windows 才能使用。安装程序不会自动重启；重启后再确认 DiskGuard 的保护状态。" /SD IDOK
  SetRebootFlag true
  Pop $R0
  SetErrorLevel 3010
  Goto diskguard_runtime_hook_done

diskguard_runtime_install_complete:
  DetailPrint "Official runtime ready, or an existing installation was preserved."
  Pop $R0

diskguard_runtime_hook_done:
!macroend

; The official runtime is shared system software. Uninstalling DiskGuard must
; not remove, downgrade, or modify an existing Sandboxie installation.
!endif
