#requires -Version 5.1

<#+
.SYNOPSIS
  Prefer the Windows Hello PIN provider while the laptop lid is closed.

.DESCRIPTION
  Installs a SYSTEM startup task that listens for the official Windows lid
  switch notification. When closed, it sets the documented Windows policy for
  the default credential provider to this computer's NGC (PIN) provider and
  temporarily excludes the face/fingerprint credential providers. When open,
  it restores the policy values that existed before installation.

  This version does not stop or disable Windows Biometric Service. While the
  lid is closed, face/fingerprint are excluded from authentication prompts;
  while the lid is open, they work normally again.

  If the earlier LidPinMode version is installed, -Install automatically stops
  it and restores the Windows Biometric Service before installing this version.
#>

[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Install')]
    [switch] $Install,

    [Parameter(ParameterSetName = 'Uninstall')]
    [switch] $Uninstall,

    [Parameter(ParameterSetName = 'Status')]
    [switch] $Status,

    [Parameter(ParameterSetName = 'Run')]
    [switch] $Run
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName = 'Lid PIN Default'
$InstallFolder = Join-Path $env:ProgramData 'LidPinDefault'
$InstalledFile = Join-Path $InstallFolder 'LidPinDefault.ps1'
$StateFile = Join-Path $InstallFolder 'original-policy-state.txt'
$LogFile = Join-Path $InstallFolder 'LidPinDefault.log'

$PolicyRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$PolicyValueName = 'DefaultCredentialProvider'
$ExcludedRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$ExcludedValueName = 'ExcludedCredentialProviders'
$ProviderRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
$PinProviderName = 'NGC Credential Provider'
$FaceProviderName = 'FaceCredentialProvider'
$FingerprintProviderName = 'WinBio Credential Provider'

$LegacyTaskName = 'Lid PIN Mode'
$LegacyFolder = Join-Path $env:ProgramData 'LidPinMode'
$LegacyStateFile = Join-Path $LegacyFolder 'original-service-state.txt'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-IsAdministrator {
    if (-not (Test-IsAdministrator)) {
        throw 'Run Windows PowerShell as Administrator, then execute this command again.'
    }
}

function Read-KeyValueFile {
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
            $values[$parts[0].Trim()] = $parts[1].Trim()
        }
    }
    return $values
}

function Get-RegisteredProviderGuid {
    param([Parameter(Mandatory)][string] $ProviderName)

    foreach ($provider in Get-ChildItem -LiteralPath $ProviderRegPath) {
        $displayName = (Get-ItemProperty -LiteralPath $provider.PSPath -ErrorAction SilentlyContinue).'(default)'
        if ($displayName -eq $ProviderName) {
            return $provider.PSChildName
        }
    }
    throw "The registered credential provider '$ProviderName' was not found."
}

function Restore-LegacyBiometricService {
    $legacyTask = Get-ScheduledTask -TaskName $LegacyTaskName -ErrorAction SilentlyContinue
    if ($null -ne $legacyTask) {
        Stop-ScheduledTask -TaskName $LegacyTaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $LegacyTaskName -Confirm:$false
        Start-Sleep -Milliseconds 500
    }

    $legacyState = Read-KeyValueFile -Path $LegacyStateFile
    if ($null -eq $legacyState -or -not $legacyState.ContainsKey('StartType')) {
        return
    }

    $startType = [int]$legacyState['StartType']
    $mode = switch ($startType) {
        2 { 'auto' }
        3 { 'demand' }
        4 { 'disabled' }
        default { throw "Unsupported saved WbioSrvc start type: $startType" }
    }

    & "$env:SystemRoot\System32\sc.exe" config WbioSrvc start= $mode | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not restore WbioSrvc (sc.exe exit code $LASTEXITCODE)."
    }

    $wasRunning = $legacyState.ContainsKey('WasRunning') -and $legacyState['WasRunning'] -eq '1'
    if ($startType -ne 4 -and $wasRunning) {
        Start-Service -Name WbioSrvc -ErrorAction Stop
    }
    else {
        Stop-Service -Name WbioSrvc -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $LegacyFolder) {
        Remove-Item -LiteralPath $LegacyFolder -Recurse -Force
    }
}

function Restore-OriginalPolicy {
    $saved = Read-KeyValueFile -Path $StateFile
    if ($null -eq $saved -or -not $saved.ContainsKey('ProviderPresent')) {
        throw "Original policy-state file not found: $StateFile"
    }

    if (-not (Test-Path -LiteralPath $PolicyRegPath)) {
        New-Item -Path $PolicyRegPath -Force | Out-Null
    }

    if ($saved['ProviderPresent'] -eq '1') {
        New-ItemProperty -LiteralPath $PolicyRegPath -Name $PolicyValueName `
            -Value $saved['ProviderValue'] -PropertyType String -Force | Out-Null
    }
    else {
        Remove-ItemProperty -LiteralPath $PolicyRegPath -Name $PolicyValueName -ErrorAction SilentlyContinue
    }

    if ($saved.ContainsKey('ExcludedPresent')) {
        if (-not (Test-Path -LiteralPath $ExcludedRegPath)) {
            New-Item -Path $ExcludedRegPath -Force | Out-Null
        }
        if ($saved['ExcludedPresent'] -eq '1') {
            New-ItemProperty -LiteralPath $ExcludedRegPath -Name $ExcludedValueName `
                -Value $saved['ExcludedValue'] -PropertyType String -Force | Out-Null
        }
        else {
            Remove-ItemProperty -LiteralPath $ExcludedRegPath -Name $ExcludedValueName -ErrorAction SilentlyContinue
        }
    }
}

function Install-LidPinDefault {
    Assert-IsAdministrator

    if (-not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
        throw 'Save this script as a .ps1 file before running -Install.'
    }

    Restore-LegacyBiometricService

    # Stop an existing v2 watcher and restore its saved baseline before taking
    # a fresh baseline for this version.
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existingTask) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        if (Test-Path -LiteralPath $StateFile) {
            Restore-OriginalPolicy
        }
    }

    $pinProviderGuid = Get-RegisteredProviderGuid -ProviderName $PinProviderName
    $faceProviderGuid = Get-RegisteredProviderGuid -ProviderName $FaceProviderName
    $fingerprintProviderGuid = Get-RegisteredProviderGuid -ProviderName $FingerprintProviderName

    New-Item -ItemType Directory -Path $InstallFolder -Force | Out-Null

    $existingValue = $null
    $providerPresent = $false
    if (Test-Path -LiteralPath $PolicyRegPath) {
        $policy = Get-ItemProperty -LiteralPath $PolicyRegPath -ErrorAction SilentlyContinue
        $property = if ($null -ne $policy) { $policy.PSObject.Properties[$PolicyValueName] } else { $null }
        if ($null -ne $property) {
            $providerPresent = $true
            $existingValue = [string]$property.Value
        }
    }

    $existingExcluded = $null
    $excludedPresent = $false
    if (Test-Path -LiteralPath $ExcludedRegPath) {
        $excludedPolicy = Get-ItemProperty -LiteralPath $ExcludedRegPath -ErrorAction SilentlyContinue
        $excludedProperty = if ($null -ne $excludedPolicy) { $excludedPolicy.PSObject.Properties[$ExcludedValueName] } else { $null }
        if ($null -ne $excludedProperty) {
            $excludedPresent = $true
            $existingExcluded = [string]$excludedProperty.Value
        }
    }

    @(
        "ProviderPresent=$([int]$providerPresent)"
        "ProviderValue=$existingValue"
        "ExcludedPresent=$([int]$excludedPresent)"
        "ExcludedValue=$existingExcluded"
        "PinProvider=$pinProviderGuid"
        "FaceProvider=$faceProviderGuid"
        "FingerprintProvider=$fingerprintProviderGuid"
    ) | Set-Content -LiteralPath $StateFile -Encoding ASCII

    Copy-Item -LiteralPath $PSCommandPath -Destination $InstalledFile -Force

    $action = New-ScheduledTaskAction `
        -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -STA -File `"$InstalledFile`" -Run"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew `
        -RestartCount 10 `
        -RestartInterval (New-TimeSpan -Minutes 1)

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName

    Start-Sleep -Milliseconds 700
    $taskInfo = Get-ScheduledTask -TaskName $TaskName
    Write-Host "Installed: $TaskName"
    Write-Host "Task state: $($taskInfo.State)"
    Write-Host "PIN provider: $pinProviderGuid"
    Write-Host "Log: $LogFile"
    Write-Host 'Lid closed: PIN is preferred and biometric providers are excluded. Lid open: original policies are restored.'
}

function Uninstall-LidPinDefault {
    Assert-IsAdministrator

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Start-Sleep -Milliseconds 300
    }

    if (Test-Path -LiteralPath $StateFile) {
        Restore-OriginalPolicy
    }
    Restore-LegacyBiometricService

    if (Test-Path -LiteralPath $InstallFolder) {
        Remove-Item -LiteralPath $InstallFolder -Recurse -Force
    }

    Write-Host 'Lid PIN Default was removed and the saved policy was restored.'
}

function Show-LidPinDefaultStatus {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        Write-Host 'New version: not installed'
    }
    else {
        Write-Host "New version: installed; watcher task is $($task.State)"
    }

    $legacyTask = Get-ScheduledTask -TaskName $LegacyTaskName -ErrorAction SilentlyContinue
    if ($null -ne $legacyTask -or (Test-Path -LiteralPath $LegacyStateFile)) {
        Write-Warning 'The old service-disabling version is still present.'
    }

    $service = Get-Service -Name WbioSrvc -ErrorAction SilentlyContinue
    if ($null -ne $service) {
        $start = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\WbioSrvc' -Name Start
        Write-Host "Biometric service: $($service.Status) (Start=$start; 2=auto, 3=manual, 4=disabled)"
    }

    $currentPolicy = $null
    if (Test-Path -LiteralPath $PolicyRegPath) {
        $policy = Get-ItemProperty -LiteralPath $PolicyRegPath -ErrorAction SilentlyContinue
        $property = if ($null -ne $policy) { $policy.PSObject.Properties[$PolicyValueName] } else { $null }
        if ($null -ne $property) {
            $currentPolicy = $property.Value
        }
    }
    Write-Host "Current default-provider policy: $currentPolicy"

    $currentExcluded = $null
    if (Test-Path -LiteralPath $ExcludedRegPath) {
        $excludedPolicy = Get-ItemProperty -LiteralPath $ExcludedRegPath -ErrorAction SilentlyContinue
        $excludedProperty = if ($null -ne $excludedPolicy) { $excludedPolicy.PSObject.Properties[$ExcludedValueName] } else { $null }
        if ($null -ne $excludedProperty) {
            $currentExcluded = $excludedProperty.Value
        }
    }
    Write-Host "Current excluded-provider policy: $currentExcluded"

    if (Test-Path -LiteralPath $LogFile) {
        Write-Host "`nRecent log:"
        Get-Content -LiteralPath $LogFile -Tail 12
    }
}

function Start-LidPinDefaultWatcher {
    if (-not (Test-IsAdministrator)) {
        throw 'The watcher must run as SYSTEM or an administrator.'
    }

    $saved = Read-KeyValueFile -Path $StateFile
    if ($null -eq $saved -or -not $saved.ContainsKey('PinProvider')) {
        throw "State file not found or invalid: $StateFile"
    }

    $source = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

internal static class LidDefaultNative
{
    internal const int WM_POWERBROADCAST = 0x0218;
    internal const int PBT_POWERSETTINGCHANGE = 0x8013;
    internal const int DEVICE_NOTIFY_WINDOW_HANDLE = 0;
    internal static readonly Guid LidSwitchGuid =
        new Guid("BA3E0F4D-B817-4094-A2D1-D56379E6A0F3");

    [StructLayout(LayoutKind.Sequential)]
    internal struct PowerBroadcastSetting
    {
        internal Guid PowerSetting;
        internal uint DataLength;
    }

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern IntPtr RegisterPowerSettingNotification(
        IntPtr recipient, ref Guid powerSettingGuid, int flags);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UnregisterPowerSettingNotification(IntPtr handle);
}

internal static class LidDefaultController
{
    private const string DefaultPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\System";
    private const string DefaultValueName = "DefaultCredentialProvider";
    private const string ExcludedPolicyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    private const string ExcludedValueName = "ExcludedCredentialProviders";
    private static readonly object SyncRoot = new object();
    private static string logFile;
    private static string pinProvider;
    private static string faceProvider;
    private static string fingerprintProvider;
    private static bool originalDefaultPresent;
    private static string originalDefaultValue;
    private static bool originalExcludedPresent;
    private static string originalExcludedValue;
    private static bool? lastClosedState;

    internal static void Configure(string statePath, string targetLogFile)
    {
        logFile = targetLogFile;
        foreach (string rawLine in File.ReadAllLines(statePath))
        {
            string[] parts = rawLine.Split(new char[] { '=' }, 2);
            if (parts.Length != 2) continue;
            if (parts[0] == "ProviderPresent") originalDefaultPresent = parts[1] == "1";
            if (parts[0] == "ProviderValue") originalDefaultValue = parts[1];
            if (parts[0] == "ExcludedPresent") originalExcludedPresent = parts[1] == "1";
            if (parts[0] == "ExcludedValue") originalExcludedValue = parts[1];
            if (parts[0] == "PinProvider") pinProvider = parts[1];
            if (parts[0] == "FaceProvider") faceProvider = parts[1];
            if (parts[0] == "FingerprintProvider") fingerprintProvider = parts[1];
        }
        if (String.IsNullOrWhiteSpace(pinProvider) ||
            String.IsNullOrWhiteSpace(faceProvider) ||
            String.IsNullOrWhiteSpace(fingerprintProvider))
            throw new InvalidDataException("One or more saved credential providers are missing.");
        Log("Watcher started. Waiting for the current lid state.");
    }

    internal static void ApplyLidState(bool isClosed)
    {
        lock (SyncRoot)
        {
            if (lastClosedState.HasValue && lastClosedState.Value == isClosed)
                return;

            try
            {
                using (RegistryKey defaultKey = Registry.LocalMachine.CreateSubKey(DefaultPolicyPath, true))
                using (RegistryKey excludedKey = Registry.LocalMachine.CreateSubKey(ExcludedPolicyPath, true))
                {
                    if (isClosed)
                    {
                        defaultKey.SetValue(DefaultValueName, pinProvider, RegistryValueKind.String);
                        excludedKey.SetValue(
                            ExcludedValueName,
                            BuildClosedExcludedList(),
                            RegistryValueKind.String);
                        Log("Lid CLOSED: PIN is the default; face and fingerprint providers are excluded.");
                    }
                    else
                    {
                        if (originalDefaultPresent)
                            defaultKey.SetValue(DefaultValueName, originalDefaultValue ?? String.Empty, RegistryValueKind.String);
                        else
                            defaultKey.DeleteValue(DefaultValueName, false);

                        if (originalExcludedPresent)
                            excludedKey.SetValue(ExcludedValueName, originalExcludedValue ?? String.Empty, RegistryValueKind.String);
                        else
                            excludedKey.DeleteValue(ExcludedValueName, false);
                        Log("Lid OPEN: original credential-provider policies restored.");
                    }
                }
                lastClosedState = isClosed;
            }
            catch (Exception ex)
            {
                Log("ERROR applying lid state: " + ex.ToString());
            }
        }
    }

    private static string BuildClosedExcludedList()
    {
        List<string> providers = new List<string>();
        if (!String.IsNullOrWhiteSpace(originalExcludedValue))
        {
            foreach (string value in originalExcludedValue.Split(','))
            {
                string trimmed = value.Trim();
                if (trimmed.Length > 0 && !ContainsIgnoreCase(providers, trimmed))
                    providers.Add(trimmed);
            }
        }
        if (!ContainsIgnoreCase(providers, faceProvider))
            providers.Add(faceProvider);
        if (!ContainsIgnoreCase(providers, fingerprintProvider))
            providers.Add(fingerprintProvider);
        return String.Join(",", providers.ToArray());
    }

    private static bool ContainsIgnoreCase(List<string> values, string target)
    {
        foreach (string value in values)
        {
            if (String.Equals(value, target, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static void Log(string message)
    {
        try
        {
            File.AppendAllText(logFile,
                DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz") + "  " +
                message + Environment.NewLine);
        }
        catch { }
    }
}

internal sealed class LidDefaultWindow : NativeWindow, IDisposable
{
    private IntPtr notificationHandle;

    internal LidDefaultWindow()
    {
        CreateHandle(new CreateParams());
        Guid guid = LidDefaultNative.LidSwitchGuid;
        notificationHandle = LidDefaultNative.RegisterPowerSettingNotification(
            Handle, ref guid, LidDefaultNative.DEVICE_NOTIFY_WINDOW_HANDLE);
        if (notificationHandle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "RegisterPowerSettingNotification failed");
    }

    protected override void WndProc(ref Message message)
    {
        if (message.Msg == LidDefaultNative.WM_POWERBROADCAST &&
            message.WParam.ToInt32() == LidDefaultNative.PBT_POWERSETTINGCHANGE &&
            message.LParam != IntPtr.Zero)
        {
            LidDefaultNative.PowerBroadcastSetting setting =
                (LidDefaultNative.PowerBroadcastSetting)Marshal.PtrToStructure(
                    message.LParam, typeof(LidDefaultNative.PowerBroadcastSetting));
            if (setting.PowerSetting == LidDefaultNative.LidSwitchGuid && setting.DataLength >= 4)
            {
                int offset = Marshal.SizeOf(typeof(LidDefaultNative.PowerBroadcastSetting));
                int lidState = Marshal.ReadInt32(message.LParam, offset);
                LidDefaultController.ApplyLidState(lidState == 0);
            }
        }
        base.WndProc(ref message);
    }

    public void Dispose()
    {
        if (notificationHandle != IntPtr.Zero)
        {
            LidDefaultNative.UnregisterPowerSettingNotification(notificationHandle);
            notificationHandle = IntPtr.Zero;
        }
        DestroyHandle();
    }
}

public static class LidPinDefaultWatcher
{
    public static void Run(string statePath, string logPath)
    {
        bool createdNew;
        using (Mutex mutex = new Mutex(true, @"Global\LidPinDefaultWatcher", out createdNew))
        {
            if (!createdNew)
                throw new InvalidOperationException("Lid PIN Default watcher is already running.");
            LidDefaultController.Configure(statePath, logPath);
            using (LidDefaultWindow window = new LidDefaultWindow())
            {
                Application.Run();
            }
        }
    }
}
'@

    Add-Type -TypeDefinition $source -ReferencedAssemblies 'System.Windows.Forms.dll'
    [LidPinDefaultWatcher]::Run($StateFile, $LogFile)
}

switch ($PSCmdlet.ParameterSetName) {
    'Install'   { Install-LidPinDefault }
    'Uninstall' { Uninstall-LidPinDefault }
    'Run'       { Start-LidPinDefaultWatcher }
    default     { Show-LidPinDefaultStatus }
}
