# Guardian.ac PowerShell Scanner

# Check if running as admin
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[!] Please run this script as Administrator!" -ForegroundColor Red
    exit
}

# Create results storage
$warnings = @()
$detections = @()
$bypasses = @()

# DLL Hijacking Detection
$dllPaths = @("C:\Windows\System32", "C:\Windows\SysWOW64")
foreach ($path in $dllPaths) {
    $suspiciousDlls = Get-ChildItem -Path $path -Filter "*.dll" | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) }
    if ($suspiciousDlls) {
        $detections += "DLL Hijacking: Recently modified DLLs found in $path"
    }
}

# Discord Hooking Detection
$discordProcesses = Get-Process | Where-Object { $_.ProcessName -match "discord" }
if ($discordProcesses) {
    $hooked = $discordProcesses | Where-Object { $_.Modules -match "d3d9.dll|winmm.dll" }
    if ($hooked) {
        $detections += "Discord Hooking: Suspicious module injections detected"
    }
}

# Fileless Bypass Detection (WMI & Registry Persistence)
$wmiSuspicious = Get-WmiObject -Namespace "root\subscription" -Class "__EventFilter" | Select-Object Name
if ($wmiSuspicious) {
    $detections += "Fileless Attack: Suspicious WMI event filters detected"
}

$regKeys = @( "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" )
foreach ($key in $regKeys) {
    $suspiciousEntries = Get-ItemProperty -Path $key | Where-Object { $_.PSObject.Properties.Name -match ".exe|.dll" }
    if ($suspiciousEntries) {
        $detections += "Fileless Attack: Suspicious registry startup entries detected"
    }
}

# BAM Manipulation Detection
$bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Bam\State\UserSettings"
if (Test-Path $bamPath) {
    $bamEntries = Get-ChildItem $bamPath
    if ($bamEntries) {
        $detections += "BAM Tampering: Unauthorized applications detected"
    }
}

# Journal Tampering Detection
$journalLog = "C:\$Recycle.Bin"
if (Test-Path $journalLog) {
    $detections += "Journal Tampering: Unauthorized changes detected in $journalLog"
}

# USB Tampering Detection
$usbDevices = Get-WmiObject Win32_USBControllerDevice | Select-Object Dependent
if ($usbDevices) {
    $warnings += "USB Devices: Recent device changes detected"
}

# Display Results in GUI
Add-Type -TypeDefinition @"
using System;
using System.Windows.Forms;
using System.Drawing;
public class ScanResults : Form {
    public ScanResults() {
        this.Text = "Guardian.ac Scanner";
        this.Size = new Size(600, 400);
        this.FormBorderStyle = FormBorderStyle.FixedDialog;
        this.MaximizeBox = false;
        
        Label warningLabel = new Label() { Text = "Warnings", Location = new Point(20, 20), AutoSize = true };
        ListBox warningList = new ListBox() { Location = new Point(20, 50), Size = new Size(150, 250) };
        foreach (string w in warnings) warningList.Items.Add(w);

        Label detectionLabel = new Label() { Text = "Detections", Location = new Point(220, 20), AutoSize = true };
        ListBox detectionList = new ListBox() { Location = new Point(220, 50), Size = new Size(150, 250) };
        foreach (string d in detections) detectionList.Items.Add(d);

        Label bypassLabel = new Label() { Text = "Bypasses", Location = new Point(420, 20), AutoSize = true };
        ListBox bypassList = new ListBox() { Location = new Point(420, 50), Size = new Size(150, 250) };
        foreach (string b in bypasses) bypassList.Items.Add(b);

        this.Controls.Add(warningLabel);
        this.Controls.Add(warningList);
        this.Controls.Add(detectionLabel);
        this.Controls.Add(detectionList);
        this.Controls.Add(bypassLabel);
        this.Controls.Add(bypassList);
    }
}
"@ -Language CSharp

$form = New-Object ScanResults
$form.ShowDialog()
