# Define function for showing scan results in a Windows Form
Add-Type -TypeDefinition @"
using System;
using System.Windows.Forms;

public class ScanResults : Form
{
    public ScanResults()
    {
        this.Text = "Scan Results";
        this.Width = 800;
        this.Height = 600;

        var warningsLabel = new Label() { Text = "Warnings", Top = 10, Left = 10, Width = 250 };
        var detectionsLabel = new Label() { Text = "Detections", Top = 10, Left = 270, Width = 250 };
        var bypassLabel = new Label() { Text = "Bypass Methods", Top = 10, Left = 530, Width = 250 };

        var warningsBox = new TextBox() { Top = 30, Left = 10, Width = 250, Height = 500, Multiline = true, ScrollBars = ScrollBars.Vertical };
        var detectionsBox = new TextBox() { Top = 30, Left = 270, Width = 250, Height = 500, Multiline = true, ScrollBars = ScrollBars.Vertical };
        var bypassBox = new TextBox() { Top = 30, Left = 530, Width = 250, Height = 500, Multiline = true, ScrollBars = ScrollBars.Vertical };

        this.Controls.Add(warningsLabel);
        this.Controls.Add(detectionsLabel);
        this.Controls.Add(bypassLabel);
        this.Controls.Add(warningsBox);
        this.Controls.Add(detectionsBox);
        this.Controls.Add(bypassBox);
    }
}
"@

# Function to perform system checks
function Run-Scan {
    $warnings = ""
    $detections = ""
    $bypassMethods = ""

    # Check for suspicious processes
    $processes = Get-Process
    $suspiciousProcesses = @('cheatengine', 'hacker', 'injector', 'dbg', 'csgo', 'gta5', 'fortnite', 'discordhook', 'pspy', 'fivem', 'xenos', 'winlogon')
    foreach ($process in $processes) {
        if ($suspiciousProcesses -contains $process.Name.ToLower()) {
            $warnings += "Suspicious process detected: $($process.Name)`n"
        }
    }

    # Check for known cheat files or DLLs
    $filesToCheck = @(
        'C:\Program Files\CheatEngine\cheatengine-x86_64.exe',
        'C:\Windows\System32\hook.dll',
        'C:\Windows\System32\inject.dll',
        'C:\Windows\System32\cheat.dll'
    )
    foreach ($file in $filesToCheck) {
        if (Test-Path $file) {
            $detections += "Malicious file detected: $file`n"
        }
    }

    # Detect API Hooking (e.g., DLL Injection)
    $apiHook = Get-ChildItem -Path "C:\Windows\System32" -Recurse | Where-Object { $_.Extension -eq ".dll" }
    foreach ($dll in $apiHook) {
        if ($dll.Name -match "hook|inject|bypass") {
            $bypassMethods += "Potential API hook detected: $dll`n"
        }
    }

    # Check for suspicious registry keys
    $registryPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($path in $registryPaths) {
        $regKeys = Get-ItemProperty -Path $path
        foreach ($key in $regKeys.PSObject.Properties) {
            if ($key.Name -match "cheat|inject|bypass|hack") {
                $warnings += "Suspicious registry key: $($key.Name)`n"
            }
        }
    }

    # Check for presence of anti-debugging measures
    $debuggingCheck = Get-Process | Where-Object { $_.Name -match "debugger|debug" }
    if ($debuggingCheck) {
        $warnings += "Anti-debugging measure detected: $($debuggingCheck.Name)`n"
    }

    # Check file system for common bypass tools
    $bypassTools = @(
        'xenos32.exe',
        'dxwnd.exe',
        'ollydbg.exe',
        'winject.exe',
        'fivem.exe'
    )
    foreach ($tool in $bypassTools) {
        $toolPath = "C:\Users\$env:USERNAME\AppData\Local\$tool"
        if (Test-Path $toolPath) {
            $bypassMethods += "Bypass tool found: $toolPath`n"
        }
    }

    # Check for Windows Defender and security software status
    $defenderStatus = Get-Service -Name "WinDefend"
    if ($defenderStatus.Status -ne "Running") {
        $warnings += "Windows Defender is not running.`n"
    }

    # Collect all results
    $scanResults = @{
        Warnings = $warnings
        Detections = $detections
        BypassMethods = $bypassMethods
    }

    return $scanResults
}

# Show scan results in a form
function Show-ScanResults {
    $form = New-Object ScanResults
    $form.Show()

    # Perform scan
    $results = Run-Scan

    $form.Controls[4].Text = $results.Warnings
    $form.Controls[5].Text = $results.Detections
    $form.Controls[6].Text = $results.BypassMethods
}

# Run the scan and show results
Show-ScanResults
