# Ensure System.Windows.Forms is available
Add-Type -AssemblyName System.Windows.Forms

# Create the form
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

# Add labels to form
$form.Controls.Add($warningsLabel)
$form.Controls.Add($detectionsLabel)
$form.Controls.Add($bypassLabel)

# Show form
$form.ShowDialog()
