; Visionary installer (NSIS 3, 64-bit Windows 10/11).
; Supports three editions sharing one install folder ($PROGRAMFILES64\Visionary)
; and one uninstaller, so switching editions upgrades cleanly:
;   Core (default):  makensis -DVERSION=0.2.0 -DVI_VERSION=0.2.0.0 -DBINDIR=..\dist installer\visionary.nsi
;   Lite (-DLITE):   makensis -DLITE -DVERSION=0.2.0 -DVI_VERSION=0.2.0.0 -DBINDIR=..\dist installer\visionary.nsi
;   Safe (-DSAFE):   makensis -DSAFE -DVERSION=0.2.0 -DVI_VERSION=0.2.0.0 -DBINDIR=..\dist installer\visionary.nsi
; Supports silent installs and uninstalls via /S.

Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"
!include "WinMessages.nsh"

!ifndef VERSION
  !define VERSION "0.2.0"
!endif
!ifndef VI_VERSION
  !define VI_VERSION "0.2.0.0"
!endif
!ifndef BINDIR
  !define BINDIR "..\dist"
!endif

!ifdef LITE
  !define APP "Visionary Lite"
  !define APP_DESC "Visionary Lite AI Antivirus (CPU-only CLI)"
  !ifndef OUTFILE
    !define OUTFILE "..\dist\Visionary-Lite-Setup-${VERSION}.exe"
  !endif
!else
  !ifdef SAFE
    !define APP "Visionary Safe"
    !define APP_DESC "Visionary Safe AI Protection (Low-Friction Edition)"
    !ifndef OUTFILE
      !define OUTFILE "..\dist\Visionary-Safe-Setup-${VERSION}.exe"
    !endif
  !else
    !define APP "Visionary Core"
    !define APP_DESC "Visionary Core AI Antivirus & Real-Time Protection"
    !ifndef OUTFILE
      !define OUTFILE "..\dist\Visionary-Core-Setup-${VERSION}.exe"
    !endif
  !endif
!endif

!define INSTALL_FOLDER "Visionary"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\VisionaryAV"

Name "${APP} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${INSTALL_FOLDER}"
InstallDirRegKey HKLM "Software\VisionaryAV" "InstallDir"
RequestExecutionLevel admin
; Standard zlib compression avoids high-entropy solid-LZMA heuristics in Microsoft Defender.
SetCompressor zlib
ShowInstDetails show
ShowUnInstDetails show

; Windows Explorer Properties / Authenticode metadata
VIProductVersion "${VI_VERSION}"
VIAddVersionKey /LANG=1033 "ProductName" "${APP}"
VIAddVersionKey /LANG=1033 "CompanyName" "Visionary"
VIAddVersionKey /LANG=1033 "FileDescription" "${APP_DESC} Installer"
VIAddVersionKey /LANG=1033 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "Visionary Contributors"

!define MUI_ABORTWARNING
!define MUI_COMPONENTSPAGE_SMALLDESC
!ifdef SAFE
  !define MUI_WELCOMEPAGE_TEXT "This wizard installs ${APP} ${VERSION} on your PC.$\r$\n$\r$\nVisionary Safe layers hashes, YARA rules, certificate verification, baseline learning, VirusTotal reputation, and optional local (<3B) & cloud AI triage — without Defender-triggering heuristic strings or Defender setting changes.$\r$\n$\r$\nClick Next to continue."
!else
  !define MUI_WELCOMEPAGE_TEXT "This wizard installs ${APP} ${VERSION} on your PC.$\r$\n$\r$\nVisionary layers fast local detection (hashes, YARA rules, full PE/script heuristics, certificate checks, LOLBin behaviour monitoring) with optional local (<3B) and cloud AI triage.$\r$\n$\r$\nClick Next to continue."
!endif

!ifndef LITE
  ; Launch through explorer.exe so the dashboard opens in the user's normal
  ; (non-elevated) desktop session and opens the browser cleanly.
  ; A function is used because newer NSIS/MUI2 builds mis-quote RUN_PARAMETERS
  ; (the embedded quotes make Exec receive 2 parameters and abort the build).
  !define MUI_FINISHPAGE_RUN ""
  !define MUI_FINISHPAGE_RUN_FUNCTION LaunchDashboard
  !define MUI_FINISHPAGE_RUN_TEXT "Open the ${APP} dashboard"
!endif

!ifndef LITE
Function LaunchDashboard
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\VisionaryUI.exe"'
FunctionEnd
!endif

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "Visionary needs 64-bit Windows 10 or 11."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "${APP} (required)" SecCore
  SectionIn RO
  ; Upgrading or switching editions: release running binaries before replacing.
  ${If} ${FileExists} "$INSTDIR\visionary.exe"
    nsExec::ExecToLog '"$INSTDIR\visionary.exe" service stop'
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\VisionaryUI.exe"
    nsExec::ExecToLog 'taskkill /F /IM VisionaryUI.exe'
    Sleep 400
  ${EndIf}

  SetOutPath "$INSTDIR"
!ifdef LITE
  ; Switching to Lite removes the dashboard binary and UI shortcuts.
  Delete "$INSTDIR\VisionaryUI.exe"
  Delete "$SMPROGRAMS\Visionary\Visionary.lnk"
  Delete "$DESKTOP\Visionary.lnk"
  File /oname=visionary.exe "${BINDIR}\visionary-lite.exe"
!else
  !ifdef SAFE
    File /oname=visionary.exe "${BINDIR}\visionary-safe.exe"
    File /oname=VisionaryUI.exe "${BINDIR}\VisionaryUI-Safe.exe"
  !else
    File "${BINDIR}\visionary.exe"
    File "${BINDIR}\VisionaryUI.exe"
  !endif
!endif
  File /oname=README.md "..\README.md"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\VisionaryAV" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\VisionaryAV" "Edition" "${APP}"
  WriteRegStr HKLM "Software\VisionaryAV" "Version" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "Visionary"
!ifdef LITE
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\visionary.exe"
!else
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\VisionaryUI.exe"
!endif
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" "$0"

  ; Keep one unified Start Menu folder across Core, Lite and Safe upgrades.
  RMDir /r "$SMPROGRAMS\Visionary Lite"
  CreateDirectory "$SMPROGRAMS\${INSTALL_FOLDER}"
!ifndef LITE
  CreateShortcut "$SMPROGRAMS\${INSTALL_FOLDER}\Visionary.lnk" "$INSTDIR\VisionaryUI.exe"
!endif
  CreateShortcut "$SMPROGRAMS\${INSTALL_FOLDER}\${APP} Quick Scan.lnk" "$SYSDIR\cmd.exe" '/k ""$INSTDIR\visionary.exe" scan quick --deep"' "$INSTDIR\visionary.exe"
  CreateShortcut "$SMPROGRAMS\${INSTALL_FOLDER}\Uninstall ${APP}.lnk" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Real-time protection service" SecService
  ; Starts with Windows and protects every user, before and between logins.
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" service install'
  Pop $0
  ${If} $0 != 0
    ; Already installed (upgrade): just start it again.
    nsExec::ExecToLog '"$INSTDIR\visionary.exe" service start'
  ${EndIf}
SectionEnd

!ifndef SAFE
Section "Work alongside Microsoft Defender" SecDefender
  ; Excludes Visionary's data folder (the quarantine vault) in Defender.
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" windows coexist'
SectionEnd
!endif

Section "Add the visionary command to PATH" SecPath
  ; Uses native Win32 registry APIs (no PowerShell spawn, no 1024-char truncation).
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" path add "$INSTDIR"'
  ; Notify open shells and Explorer that environment variables changed.
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=2000
SectionEnd

!ifndef LITE
Section /o "Desktop shortcut" SecDesktop
  CreateShortcut "$DESKTOP\Visionary.lnk" "$INSTDIR\VisionaryUI.exe"
SectionEnd
!endif

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!ifdef LITE
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Full detection engine and CLI without dashboard (CPU-only local AI defaults)."
!else
  !ifdef SAFE
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Low-friction AI scanner, CLI and dashboard (omits Defender-triggering heuristics and Defender setting changes)."
  !else
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Full AI scanner, heuristics, LOLBin guard, CLI and dashboard."
  !endif
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "A Windows service that keeps real-time protection running from startup."
!ifndef SAFE
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDefender} "Lets Visionary and Microsoft Defender run side by side without scanning each other's data."
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Use 'visionary' from any terminal immediately after installation."
!ifndef LITE
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "A shortcut to the dashboard on the desktop."
!endif
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  ${If} ${FileExists} "$INSTDIR\VisionaryUI.exe"
    nsExec::ExecToLog 'taskkill /F /IM VisionaryUI.exe'
  ${EndIf}
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" service uninstall'
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" preboot cancel'
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" path remove "$INSTDIR"'
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=2000

  Delete "$INSTDIR\visionary.exe"
  Delete "$INSTDIR\VisionaryUI.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  RMDir /r "$SMPROGRAMS\${INSTALL_FOLDER}"
  RMDir /r "$SMPROGRAMS\Visionary Lite"
  Delete "$DESKTOP\Visionary.lnk"
  Delete "$DESKTOP\Visionary Lite.lnk"
  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "Software\VisionaryAV"

  ; Settings, definitions and quarantined files live in ProgramData.
  IfSilent done
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete Visionary's settings, definitions and quarantined files?$\n$\n$APPDATA\VisionaryAV" IDNO done
    RMDir /r "$APPDATA\VisionaryAV"
  done:
SectionEnd
