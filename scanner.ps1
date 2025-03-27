# Fixed scanner.ps1

# Ensure .NET Forms are available
Add-Type -AssemblyName System.Windows.Forms

# Function to check for common detections
function Scan-System {
    $detections = @()
    
    # Check for suspicious processes
    $suspiciousProcesses = @("CheatEngine", "ProcessHacker", "x64dbg", "ida64", "ida32", "Wireshark")
    foreach ($proc in Get-Process) {
        if ($suspiciousProcesses -contains $proc.ProcessName) {
            $detections += "Suspicious process detected: $($proc.ProcessName)"
        }
    }
    
    # Check for loaded DLLs related to hooking
    $suspiciousDLLs = @("ntdll.dll", "kernel32.dll", "user32.dll", "wininet.dll")
    foreach ($proc in Get-Process) {
        try {
            $modules = $proc.Modules | Select-Object ModuleName
            foreach ($mod in $modules) {
                if ($suspiciousDLLs -contains $mod.ModuleName) {
                    $detections += "Potential DLL Hooking in process: $($proc.ProcessName) - $($mod.ModuleName)"
                }
            }
        } catch {}
    }
    
    # Check for BAM (Background Activity Moderator) modifications
    $bamKey = "HKLM:\SYSTEM\CurrentControlSet\Services\BAM\State"
    if (Test-Path $bamKey) {
        $bamEntries = Get-ItemProperty -Path $bamKey
        if ($bamEntries) {
            $detections += "BAM modifications detected. Possible stealth process hiding."
        }
    }
    
    # Check for unplugged USBs (Tampering)
    $usbDevices = Get-WmiObject Win32_USBControllerDevice | ForEach-Object { $_.Dependent } 
    if ($usbDevices.Count -eq 0) {
        $detections += "No USB devices found. Possible USB removal to evade detection."
    }
    
    return $detections
}

# Run the scan
$scanResults = Scan-System

# GUI to display scan results
$form = New-Object System.Windows.Forms.Form
$form.Text = "Guardian AC - Scan Results"
$form.Size = New-Object System.Drawing.Size(500,400)
$form.StartPosition = "CenterScreen"

$label = New-Object System.Windows.Forms.Label
$label.Text = "Scan Results:"
$label.Location = New-Object System.Drawing.Point(10,10)
$label.Size = New-Object System.Drawing.Size(480,20)
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size = New-Object System.Drawing.Size(460,300)
$form.Controls.Add($listBox)

if ($scanResults.Count -gt 0) {
    foreach ($result in $scanResults) {
        $listBox.Items.Add($result)
    }
} else {
    $listBox.Items.Add("No suspicious activity detected.")
}

$closeButton = New-Object System.Windows.Forms.Button
$closeButton.Text = "Close"
$closeButton.Location = New-Object System.Drawing.Point(200,350)
$closeButton.Size = New-Object System.Drawing.Size(100,30)
$closeButton.Add_Click({ $form.Close() })
$form.Controls.Add($closeButton)

$form.ShowDialog()
