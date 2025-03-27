# Improved script for scanning with better detection accuracy

# Function to scan DLL hooks
function Check-DLLHooks {
    $hooks = @()
    $processes = Get-Process
    foreach ($process in $processes) {
        try {
            $modules = $process.Modules
            foreach ($module in $modules) {
                # Check for known malicious DLLs or hooks in the process
                if ($module.ModuleName -match "suspicious.dll" -or $module.FileName -match "hooked.dll") {
                    $hooks += "$($process.Name) loaded suspicious DLL: $($module.ModuleName)"
                }
            }
        }
        catch {
            Write-Host "Error accessing process: $($process.Name)"
        }
    }
    return $hooks
}

# Function to scan for memory tampering or injected code
function Check-MemoryTampering {
    $alerts = @()
    $processes = Get-Process
    foreach ($process in $processes) {
        try {
            $memoryRegion = Get-ProcessMemoryInfo -ProcessId $process.Id
            if ($memoryRegion -match "malicious_pattern") {
                $alerts += "Injected code detected in $($process.Name)"
            }
        }
        catch {
            Write-Host "Error reading memory for process: $($process.Name)"
        }
    }
    return $alerts
}

# Function to check for USB tampering
function Check-USB {
    $usbDevices = Get-WmiObject -Query "SELECT * FROM Win32_USBHub"
    $suspiciousDevices = @()
    foreach ($device in $usbDevices) {
        if ($device.DeviceID -match "suspiciousDevicePattern") {
            $suspiciousDevices += "Suspicious USB device detected: $($device.DeviceID)"
        }
    }
    return $suspiciousDevices
}

# Function to check for process bypass attempts (anti-debugging or VM bypass)
function Check-Bypass {
    $bypassProcesses = @()
    $processes = Get-Process
    foreach ($process in $processes) {
        if ($process.Name -match "bypass_tool" -or $process.Name -match "cheat_engine") {
            $bypassProcesses += "Bypass attempt detected in process: $($process.Name)"
        }
    }
    return $bypassProcesses
}

# Function to create a custom GUI to display scan results
function Show-ScanResults {
    param (
        $warnings,
        $detections,
        $bypasses
    )

    Add-Type -TypeDefinition @"
    using System;
    using System.Windows.Forms;
    public class ScanResults : Form {
        public ScanResults() {
            this.Text = 'Guardian AC - Scan Results';
            this.Width = 600;
            this.Height = 400;
            var labelWarnings = new Label() { Text = 'Warnings:', Location = new System.Drawing.Point(10, 10), Width = 100 };
            var labelDetections = new Label() { Text = 'Detections:', Location = new System.Drawing.Point(210, 10), Width = 100 };
            var labelBypasses = new Label() { Text = 'Bypasses:', Location = new System.Drawing.Point(410, 10), Width = 100 };

            var listWarnings = new ListBox() { Location = new System.Drawing.Point(10, 30), Width = 180, Height = 300 };
            listWarnings.Items.AddRange($warnings);
            var listDetections = new ListBox() { Location = new System.Drawing.Point(210, 30), Width = 180, Height = 300 };
            listDetections.Items.AddRange($detections);
            var listBypasses = new ListBox() { Location = new System.Drawing.Point(410, 30), Width = 180, Height = 300 };
            listBypasses.Items.AddRange($bypasses);

            this.Controls.Add(labelWarnings);
            this.Controls.Add(labelDetections);
            this.Controls.Add(labelBypasses);
            this.Controls.Add(listWarnings);
            this.Controls.Add(listDetections);
            this.Controls.Add(listBypasses);
        }
    }
    "@

    $form = New-Object ScanResults
    $form.ShowDialog()
}

# Scan and generate report
$warnings = @("No warnings detected")
$hooks = Check-DLLHooks
$alerts = Check-MemoryTampering
$usbDevices = Check-USB
$bypassAttempts = Check-Bypass

if ($hooks.Count -gt 0) {
    $warnings = $hooks
}
if ($alerts.Count -gt 0) {
    $warnings += $alerts
}
if ($usbDevices.Count -gt 0) {
    $warnings += $usbDevices
}
if ($bypassAttempts.Count -gt 0) {
    $warnings += $bypassAttempts
}

Show-ScanResults -warnings $warnings -detections $alerts -bypasses $bypassAttempts
