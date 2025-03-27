# Replace this with your new personal access token
$token = "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"

# Setup headers for authorization
$headers = @{
    Authorization = "Bearer $token"
}

# Use WebClient to download the script with authentication
$scriptUrl = 'https://raw.githubusercontent.com/yourusername/guardian-scanner/main/scanner.ps1'
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("Authorization", "Bearer $token")

# Download the script
$scriptContent = $webClient.DownloadString($scriptUrl)

# Execute the script
Invoke-Expression $scriptContent

# After script execution, continue with your GUI logic
$results = scanner.ps1
Start-Sleep -Seconds 2
[System.Windows.Forms.Application]::EnableVisualStyles()
$form = New-Object System.Windows.Forms.Form
$form.Text = "Scan Results"
$form.Size = New-Object System.Drawing.Size(800, 400)
$panel = New-Object System.Windows.Forms.TableLayoutPanel
$panel.Dock = 'Fill'
$panel.ColumnCount = 3
$panel.RowCount = 1
$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33)))
$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 34)))
$panel.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33)))
$labelWarnings = New-Object System.Windows.Forms.Label
$labelWarnings.Text = "Warnings"
$labelWarnings.TextAlign = 'MiddleCenter'
$labelWarnings.Dock = 'Top'
$panel.Controls.Add($labelWarnings, 0, 0)
$labelDetections = New-Object System.Windows.Forms.Label
$labelDetections.Text = "Detections"
$labelDetections.TextAlign = 'MiddleCenter'
$labelDetections.Dock = 'Top'
$panel.Controls.Add($labelDetections, 1, 0)
$labelBypasses = New-Object System.Windows.Forms.Label
$labelBypasses.Text = "Bypasses"
$labelBypasses.TextAlign = 'MiddleCenter'
$labelBypasses.Dock = 'Top'
$panel.Controls.Add($labelBypasses, 2, 0)
$textBoxWarnings = New-Object System.Windows.Forms.TextBox
$textBoxWarnings.Multiline = $true
$textBoxWarnings.ScrollBars = 'Vertical'
$textBoxWarnings.Dock = 'Fill'
$panel.Controls.Add($textBoxWarnings, 0, 1)
$textBoxDetections = New-Object System.Windows.Forms.TextBox
$textBoxDetections.Multiline = $true
$textBoxDetections.ScrollBars = 'Vertical'
$textBoxDetections.Dock = 'Fill'
$panel.Controls.Add($textBoxDetections, 1, 1)
$textBoxBypasses = New-Object System.Windows.Forms.TextBox
$textBoxBypasses.Multiline = $true
$textBoxBypasses.ScrollBars = 'Vertical'
$textBoxBypasses.Dock = 'Fill'
$panel.Controls.Add($textBoxBypasses, 2, 1)
$form.Controls.Add($panel)
$textBoxWarnings.Text = $results.Warnings
$textBoxDetections.Text = $results.Detections
$textBoxBypasses.Text = $results.Bypasses
$form.ShowDialog()
