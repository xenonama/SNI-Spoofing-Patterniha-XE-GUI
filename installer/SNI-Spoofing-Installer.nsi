; SNI Spoofing Installer
; Generated with NSIS Installer Script

!include "MUI2.nsh"

; Configuration
Name "SNI Spoofing v2.3.2"
OutFile "..\SNI-Spoofing-v2.3.2-Setup.exe"
InstallDir "$PROGRAMFILES\SNI-Spoofing"
InstallDirRegKey HKCU "Software\SNI-Spoofing" ""

; UI Settings
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

; Installer Section
Section "Install"
  SetOutPath "$INSTDIR"
  
  ; Copy executable files
  File "..\dist\cli.exe"
  File "..\dist\gui.exe"
  
  ; Create shortcuts
  CreateDirectory "$SMPROGRAMS\SNI-Spoofing"
  CreateShortCut "$SMPROGRAMS\SNI-Spoofing\SNI-Spoofing CLI.lnk" "$INSTDIR\cli.exe"
  CreateShortCut "$SMPROGRAMS\SNI-Spoofing\SNI-Spoofing GUI.lnk" "$INSTDIR\gui.exe"
  CreateShortCut "$DESKTOP\SNI-Spoofing GUI.lnk" "$INSTDIR\gui.exe"
  
  ; Write registry info
  WriteRegStr HKCU "Software\SNI-Spoofing" "" "$INSTDIR"
SectionEnd

; Uninstaller
Section "Uninstall"
  RMDir /r "$INSTDIR"
  RMDir /r "$SMPROGRAMS\SNI-Spoofing"
  Delete "$DESKTOP\SNI-Spoofing GUI.lnk"
  DeleteRegKey HKCU "Software\SNI-Spoofing"
SectionEnd
