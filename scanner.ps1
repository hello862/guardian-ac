# Ensure Windows Forms is available
Add-Type -AssemblyName "System.Windows.Forms"

# Define ScanResults class for displaying results in a form
Add-Type @"
using System;
using System.Windows.Forms;
using System.Drawing;

public class ScanResults : Form {
    public TextBox tbWarnings;
    public TextBox tbDetections;
    public TextBox tbBypassMethods;
    
    public ScanResults() {
        this.Text = "Scan Results";
        this.Size = new Size(600, 400);
        
        # Create TextBoxes for displaying results
        tbWarnings = New-Object TextBox
        tbWarnings.Size = New-Object Drawing.Size(550, 50)
        tbWarnings.Location = New-Object Drawing.Point(20, 20)
        tbWarnings.Multiline = $true
        this.Controls.Add($tbWarnings)
        
        tbDetections = New-Object TextBox
        tbDetections.Size = New-Object Drawing.Size(550, 50)
        tbDetections.Location = New-Object Drawing.Point(20, 80)
        tbDetections.Multiline = $true
        this.Controls.Add($tbDetections)

        tbBypassMethods = New-Object TextBox
        tbBypassMethods.Size = New-Object Drawing.Size(550, 50)
        tbBypassMethods.Location = New-Object Drawing.Point(20, 140)
        tbBypassMethods.Multiline = $true
        this.Controls.Add($tbBypassMethods)
    }
}
"@

# Create instance of the form
$form = New-Object ScanResults
$form.Show()

# Scan for API hooks and other suspicious files in system directories
try {
    $apiHook = Get-ChildItem -Path "C:\Windows\System32" -Recurse | Where-Object { $_.Name -match "hook" }
} catch {
    Write-Host "Permission denied for $($_.Exception.Message)"
}

# Sample result structure for warnings, detections, and bypass methods
$results = @{
    Warnings = "No warnings detected."
    Detections = "No suspicious API hooks found."
    BypassMethods = "No bypass methods identified."
}

# Safely update form controls if they exist and are valid
if ($form.Controls.Count -ge 3) {
    $form.tbWarnings.Text = $results.Warnings
    $form.tbDetections.Text = $results.Detections
    $form.tbBypassMethods.Text = $results.BypassMethods
} else {
    Write-Host "Form controls not properly initialized."
}

# Optionally, include additional scanning logic here:
# Example: Checking for running processes or unauthorized DLLs
try {
    $runningProcesses = Get-Process | Where-Object { $_.Name -match "discord|cheat" }
    $results.Detections += "`nRunning suspicious processes: " + ($runningProcesses.Name -join ", ")
} catch {
    Write-Host "Failed to list running processes: $($_.Exception.Message)"
}

# More example scans
try {
    $suspiciousFiles = Get-ChildItem -Path "C:\Windows\System32" -Recurse -File | Where-Object { $_.Name -match "cheat|bypass" }
    $results.Detections += "`nSuspicious files found: " + ($suspiciousFiles.FullName -join ", ")
} catch {
    Write-Host "Failed to list suspicious files: $($_.Exception.Message)"
}

# Wait until user closes the form
while ($form.Visible) {
    Start-Sleep -Seconds 1
}
