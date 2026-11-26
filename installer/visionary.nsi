; Visionary installer (NSIS 3, 64-bit Windows 10/11).
; Build:  makensis -DVERSION=1.0.0 -DVI_VERSION=1.0.0.0 -DBINDIR=..\dist installer\visionary.nsi
; BINDIR must contain visionary.exe (console) and VisionaryUI.exe (windowed).
; Lite edition:  makensis -DLITE -DVERSION=1.0.0 -DVI_VERSION=1.0.0.0 -DBINDIR=..\dist installer\visionary.nsi
;   BINDIR then needs visionary-lite.exe only (installed as visionary.exe; no dashboard).
; Both editions share one install location ($PROGRAMFILES64\Visionary) and one uninstaller:
; installing one cleanly replaces the other. Supports silent installs via /S.

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
!ifndef OUTFILE
  !define OUTFILE "..\dist\Visionary-Setup-${VERSION}.exe"
!endif

!ifdef LITE
  !define APP "Visionary Lite"
  !define APP_DESC "Visionary Lite AI Antivirus (CPU-only CLI)"
!else
  !define APP "Visionary"
  !define APP_DESC "Visionary AI Antivirus & Real-Time Protection"
!endif
!define INSTALL_FOLDER "Visionary"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\VisionaryAV"

Name "${APP} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${INSTALL_FOLDER}"
InstallDirRegKey HKLM "Software\VisionaryAV" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
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
!define MUI_WELCOMEPAGE_TEXT "This wizard installs ${APP} ${VERSION} on your PC.$\r$\n$\r$\nVisionary layers fast local detection (hashes, YARA rules, heuristics, certificate checks, behaviour monitoring) with optional local (<3B) and cloud AI triage.$\r$\n$\r$\nClick Next to continue."
!ifndef LITE
  ; Launch through explorer.exe so the dashboard opens in the user's normal
  ; (non-elevated) desktop session and opens the browser cleanly.
  ; A function is used because newer NSIS/MUI2 builds mis-quote RUN_PARAMETERS
  ; (the embedded quotes make Exec receive 2 parameters and abort the build).
  !define MUI_FINISHPAGE_RUN ""
  !define MUI_FINISHPAGE_RUN_FUNCTION LaunchDashboard
  !define MUI_FINISHPAGE_RUN_TEXT "Open the Visionary AI Protection dashboard"
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

Section "Visionary (required)" SecCore
  SectionIn RO
  ; Upgrading or switching editions: release running binaries before replacing.
  IfFileExists "$INSTDIR\visionary.exe" 0 +2
    nsExec::ExecToLog '"$INSTDIR\visionary.exe" service stop'
  nsExec::ExecToLog 'taskkill /F /IM VisionaryUI.exe'
  Sleep 400

  SetOutPath "$INSTDIR"
!ifdef LITE
  ; Switching from Full -> Lite removes the dashboard binary and UI shortcuts.
  Delete "$INSTDIR\VisionaryUI.exe"
  Delete "$SMPROGRAMS\Visionary\Visionary.lnk"
  Delete "$DESKTOP\Visionary.lnk"
  File /oname=visionary.exe "${BINDIR}\visionary-lite.exe"
!else
  File "${BINDIR}\visionary.exe"
  File "${BINDIR}\VisionaryUI.exe"
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

  ; Keep one unified Start Menu folder across Full and Lite upgrades.
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

Section "Work alongside Microsoft Defender" SecDefender
  ; Excludes Visionary's data folder (the quarantine vault) in Defender.
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" windows coexist'
SectionEnd

Section "Add the visionary command to PATH" SecPath
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -Command "$$p=[Environment]::GetEnvironmentVariable('Path','Machine'); if (($$p -split ';') -notcontains '$INSTDIR') { [Environment]::SetEnvironmentVariable('Path', $$p.TrimEnd(';') + ';$INSTDIR', 'Machine') }"`
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
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "The scanner and the command-line tool (no dashboard, CPU-only local AI)."
!else
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "The scanner, the command-line tool and the AI protection dashboard."
!endif
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "A Windows service that keeps real-time protection running from startup."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDefender} "Lets Visionary and Microsoft Defender run side by side without scanning each other's data."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Use 'visionary' from any terminal immediately after installation."
!ifndef LITE
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "A shortcut to the dashboard on the desktop."
!endif
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  nsExec::ExecToLog 'taskkill /F /IM VisionaryUI.exe'
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" service uninstall'
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" preboot cancel'
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -Command "Remove-MpPreference -ExclusionPath '$APPDATA\VisionaryAV' -ErrorAction SilentlyContinue; $$p=[Environment]::GetEnvironmentVariable('Path','Machine'); [Environment]::SetEnvironmentVariable('Path', (($$p -split ';') | Where-Object { $$_ -and $$_ -ne '$INSTDIR' }) -join ';', 'Machine')"`
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
