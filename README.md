# Lid PIN Default

A small, experimental Windows utility that prefers PIN authentication while a laptop lid is closed and restores the original Windows sign-in behavior when the lid is opened.

## Install

Download `LidPinDefault.ps1`, open **Windows PowerShell as Administrator**, and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\LidPinDefault.ps1" -Install
```

Check status or uninstall:

```powershell
.\LidPinDefault.ps1 -Status
.\LidPinDefault.ps1 -Uninstall
```

## Important

- Windows 10/11 and an existing Windows Hello PIN are required.
- While the lid is closed, face and fingerprint credential providers are excluded from Windows authentication prompts; PIN/password remain available.
- Opening the lid restores the policy values saved during installation.
- Hardware, OEM software, and organization-managed policies can change the result. Test before relying on it.
- This is not a security boundary or an official Microsoft tool.

