# Ensure System.Windows.Forms is available
Add-Type -AssemblyName System.Windows.Forms

# Function to scan for detections
function Scan-ForThreats {
    $detections = @()
    $warnings = @()
    $bypasses = @()

    # Detect Discord Hooking (checks for known hooked DLLs)
    $discordProcess = Get-Process | Where-Object { $_.ProcessName -match "discord" }
    if ($discordProcess) {
        $hookedDLLs = @("discord_hook.dll", "injector.dll")
        foreach ($dll in $hookedDLLs) {
            if (Test-Path "$env:APPDATA\Discord\$dll") {
                $detections += "Discord Hooking: $dll detected"
            }
        }
    }

    # Detect DLL Hijacking (looks for unsigned DLLs in system32)
    $system32 = "$env:SystemRoot\System32"
    $dllFiles = Get-ChildItem -Path $system32 -Filter "*.dll"
    foreach ($dll in $dllFiles) {
        $signingInfo = Get-AuthenticodeSignature $dll.FullName
        if ($signingInfo.Status -ne "Valid") {
            $warnings += "DLL Hijacking: $($dll.Name) is unsigned"
        }
    }

    # Detect BAM Manipulation (checks registry for modified BAM keys)
    $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings"
    if (Test-Path $bamPath) {
        $bamEntries = Get-Item -Path $bamPath | Get-ChildItem
        foreach ($entry in $bamEntries) {
            if ($entry.Name -match "discord|cheat|injector") {
                $detections += "BAM Manipulation: Suspicious entry in registry - $($entry.Name)"
            }
        }
    }

    # Detect Journal Tampering (checks if Windows Event logs are cleared)
    $eventLogs = Get-EventLog -LogName Security -Newest 5 -ErrorAction SilentlyContinue
    if (-not $eventLogs) {
        $detections += "Journal Tampering: Security logs missing!"
    }

    # Detect Unplugged USBs (checks event logs for recent USB disconnects)
    $usbEvents = Get-WinEvent -LogName System -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-DriverFrameworks-UserMode'] and (EventID=2100)]]" -MaxEvents 5
    if ($usbEvents) {
        $warnings += "Unplugged USBs detected!"
    }

    # Detect Fileless Execution (checks suspicious PowerShell history)
    $psHistory = Get-Content (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue
    foreach ($cmd in $psHistory) {
        if ($cmd -match "Invoke-Expression|IEX|[System.Reflection]") {
            $detections += "Fileless Execution: Suspicious PowerShell command - $cmd"
        }
    }

    # Detect Suspicious Processes
    $badProcesses = @("cheatengine", "x64dbg", "ollydbg", "processhacker")
    $runningProcesses = Get-Process | Select-Object -ExpandProperty ProcessName
    foreach ($proc in $badProcesses) {
        if ($runningProcesses -contains $proc) {
            $detections += "Suspicious Process: $proc is running"
        }
    }

    # Return scan results
    return @{
        "Warnings" = $warnings
        "Detections" = $detections
        "Bypasses" = $bypasses
    }
}

# Run the scan
$scanResults = Scan-ForThreats

# Create the GUI
$form = New-Object System.Windows.Forms.Form
$form.Text = "Guardian Scanner"
$form.Size = New-Object System.Drawing.Size(600,400)

# Create Labels
$warningsLabel = New-Object System.Windows.Forms.Label
$warningsLabel.Text = "Warnings"
$warningsLabel.Location = New-Object System.Drawing.Point(50, 20)
$warningsLabel.AutoSize = $true

$detectionsLabel = New-Object System.Windows.Forms.Label
$detectionsLabel.Text = "Detections"
$detectionsLabel.Location = New-Object System.Drawing.Point(250, 20)
$detectionsLabel.AutoSize = $true

$bypassLabel = New-Object System.Windows.Forms.Label
$bypassLabel.Text = "Bypasses"
$bypassLabel.Location = New-Object System.Drawing.Point(450, 20)
$bypassLabel.AutoSize = $true

# Create TextBoxes for results
$warningsBox = New-Object System.Windows.Forms.TextBox
$warningsBox.Multiline = $true
$warningsBox.ScrollBars = "Vertical"
$warningsBox.Size = New-Object System.Drawing.Size(150,300)
$warningsBox.Location = New-Object System.Drawing.Point(20,50)
$warningsBox.Text = ($scanResults.Warnings -join "`r`n")

$detectionsBox = New-Object System.Windows.Forms.TextBox
$detectionsBox.Multiline = $true
$detectionsBox.ScrollBars = "Vertical"
$detectionsBox.Size = New-Object System.Drawing.Size(150,300)
$detectionsBox.Location = New-Object System.Drawing.Point(220,50)
$detectionsBox.Text = ($scanResults.Detections -join "`r`n")

$bypassBox = New-Object System.Windows.Forms.TextBox
$bypassBox.Multiline = $true
$bypassBox.ScrollBars = "Vertical"
$bypassBox.Size = New-Object System.Drawing.Size(150,300)
$bypassBox.Location = New-Object System.Drawing.Point(420,50)
$bypassBox.Text = ($scanResults.Bypasses -join "`r`n")

# Add elements to the form
$form.Controls.Add($warningsLabel)
$form.Controls.Add($detectionsLabel)
$form.Controls.Add($bypassLabel)
$form.Controls.Add($warningsBox)
$form.Controls.Add($detectionsBox)
$form.Controls.Add($bypassBox)

# Show form
$form.ShowDialog()
