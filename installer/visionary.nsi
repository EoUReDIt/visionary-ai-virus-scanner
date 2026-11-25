; Visionary installer (NSIS 3, 64-bit Windows 10/11).
; Build:  makensis -DVERSION=1.0.0 -DBINDIR=..\dist installer\visionary.nsi
; BINDIR must contain visionary.exe (console) and VisionaryUI.exe (windowed).

Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

!ifndef VERSION
  !define VERSION "0.1.0"
!endif
!ifndef BINDIR
  !define BINDIR "..\dist"
!endif
!ifndef OUTFILE
  !define OUTFILE "..\dist\Visionary-Setup-${VERSION}.exe"
!endif

!define APP "Visionary"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\VisionaryAV"

Name "${APP} ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\${APP}"
InstallDirRegKey HKLM "Software\VisionaryAV" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
ShowInstDetails show
ShowUnInstDetails show

!define MUI_ABORTWARNING
!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_FINISHPAGE_RUN "$INSTDIR\VisionaryUI.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Open the Visionary dashboard"

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
  ; Upgrading: release the running executable before replacing it.
  IfFileExists "$INSTDIR\visionary.exe" 0 +2
    nsExec::ExecToLog '"$INSTDIR\visionary.exe" service stop'
  nsExec::ExecToLog 'taskkill /F /IM VisionaryUI.exe'

  SetOutPath "$INSTDIR"
  File "${BINDIR}\visionary.exe"
  File "${BINDIR}\VisionaryUI.exe"
  File /oname=README.md "..\README.md"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "Software\VisionaryAV" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINST_KEY}" "Publisher" "Visionary"
  WriteRegStr HKLM "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\VisionaryUI.exe"
  WriteRegStr HKLM "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" "$0"

  CreateDirectory "$SMPROGRAMS\${APP}"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP}.lnk" "$INSTDIR\VisionaryUI.exe"
  CreateShortcut "$SMPROGRAMS\${APP}\${APP} Quick Scan.lnk" "$SYSDIR\cmd.exe" '/k ""$INSTDIR\visionary.exe" scan quick"' "$INSTDIR\visionary.exe"
  CreateShortcut "$SMPROGRAMS\${APP}\Uninstall ${APP}.lnk" "$INSTDIR\uninstall.exe"
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
SectionEnd

Section /o "Desktop shortcut" SecDesktop
  CreateShortcut "$DESKTOP\${APP}.lnk" "$INSTDIR\VisionaryUI.exe"
SectionEnd

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "The scanner, the command-line tool and the dashboard."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "A Windows service that keeps real-time protection running from startup."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDefender} "Lets Visionary and Microsoft Defender run side by side without scanning each other's data."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Use 'visionary' from any terminal."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "A shortcut to the dashboard on the desktop."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"
  nsExec::ExecToLog 'taskkill /F /IM VisionaryUI.exe'
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" service uninstall'
  nsExec::ExecToLog '"$INSTDIR\visionary.exe" preboot cancel'
  nsExec::ExecToLog `powershell.exe -NoProfile -NonInteractive -Command "Remove-MpPreference -ExclusionPath '$APPDATA\VisionaryAV' -ErrorAction SilentlyContinue; $$p=[Environment]::GetEnvironmentVariable('Path','Machine'); [Environment]::SetEnvironmentVariable('Path', (($$p -split ';') | Where-Object { $$_ -and $$_ -ne '$INSTDIR' }) -join ';', 'Machine')"`

  Delete "$INSTDIR\visionary.exe"
  Delete "$INSTDIR\VisionaryUI.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\${APP}\${APP}.lnk"
  Delete "$SMPROGRAMS\${APP}\${APP} Quick Scan.lnk"
  Delete "$SMPROGRAMS\${APP}\Uninstall ${APP}.lnk"
  RMDir "$SMPROGRAMS\${APP}"
  Delete "$DESKTOP\${APP}.lnk"
  DeleteRegKey HKLM "${UNINST_KEY}"
  DeleteRegKey HKLM "Software\VisionaryAV"

  ; Settings, definitions and quarantined files live in ProgramData.
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Also delete Visionary's settings, definitions and quarantined files?$\n$\n$APPDATA\VisionaryAV" IDNO done
    RMDir /r "$APPDATA\VisionaryAV"
  done:
SectionEnd
