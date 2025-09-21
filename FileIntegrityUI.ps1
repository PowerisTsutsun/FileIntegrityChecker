Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-Sha256Hex([string]$path) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $fs = [System.IO.File]::OpenRead($path)
  try {
    $hash = $sha.ComputeHash($fs)
    -join ($hash | ForEach-Object { $_.ToString("x2") })
  } finally { $fs.Dispose(); $sha.Dispose() }
}

function Record-Hash([string]$path) {
  $h = Get-Sha256Hex $path
  $sidecar = "$path.sha256"
  [IO.File]::WriteAllText($sidecar, "$h  $(Split-Path -Leaf $path)`r`n")
  return "wrote: $(Split-Path -Leaf $sidecar)"
}

function Verify-Hash([string]$path) {
  $sidecar = "$path.sha256"
  if (-not (Test-Path $sidecar)) { throw "missing sidecar .sha256" }
  $line = (Get-Content $sidecar -TotalCount 1)
  if ($line -match '^\s*([0-9a-fA-F]{64})\b') { $expected = $matches[1].ToLower() } else { throw "invalid .sha256 format" }
  $actual = (Get-Sha256Hex $path)
  if ($actual -eq $expected) { return "OK  `"$([IO.Path]::GetFileName($path))`"" }
  else { return "MISMATCH  $path`r`nexpected: $expected`r`nactual:   $actual" }
}

# ---------- UI ----------
$form = New-Object Windows.Forms.Form
$form.Text = "File Integrity Checker"
$form.Size = New-Object Drawing.Size(560,250)
$form.StartPosition = "CenterScreen"

$lbl = New-Object Windows.Forms.Label
$lbl.Text = "File:"
$lbl.Location = New-Object Drawing.Point(10,15)
$lbl.AutoSize = $true

$tb = New-Object Windows.Forms.TextBox
$tb.Size = New-Object Drawing.Size(420,25)
$tb.Location = New-Object Drawing.Point(50,10)

$btnBrowse = New-Object Windows.Forms.Button
$btnBrowse.Text = "Browse..."
$btnBrowse.Location = New-Object Drawing.Point(480,9)
$btnBrowse.Add_Click({
  $dlg = New-Object Windows.Forms.OpenFileDialog
  if ($dlg.ShowDialog() -eq "OK") { $tb.Text = $dlg.FileName }
})

$btnHash = New-Object Windows.Forms.Button
$btnHash.Text = "Hash"
$btnHash.Location = New-Object Drawing.Point(50,50)

$btnRecord = New-Object Windows.Forms.Button
$btnRecord.Text = "Record"
$btnRecord.Location = New-Object Drawing.Point(130,50)

$btnVerify = New-Object Windows.Forms.Button
$btnVerify.Text = "Verify"
$btnVerify.Location = New-Object Drawing.Point(220,50)

$out = New-Object Windows.Forms.TextBox
$out.Multiline = $true
$out.ScrollBars = "Vertical"
$out.ReadOnly = $true
$out.Location = New-Object Drawing.Point(10,90)
$out.Size = New-Object Drawing.Size(525,110)

function With-Guard([scriptblock]$work) {
  try { $out.Text = & $work }
  catch { $out.Text = "error: $($_.Exception.Message)" }
}

$btnHash.Add_Click({ With-Guard { 
  if (-not (Test-Path $tb.Text)) { throw "select a file first" }
  "$((Get-Sha256Hex $tb.Text))  $(Split-Path -Leaf $tb.Text)"
} })
$btnRecord.Add_Click({ With-Guard {
  if (-not (Test-Path $tb.Text)) { throw "select a file first" }
  Record-Hash $tb.Text
} })
$btnVerify.Add_Click({ With-Guard {
  if (-not (Test-Path $tb.Text)) { throw "select a file first" }
  Verify-Hash $tb.Text
} })

$form.Controls.AddRange(@($lbl,$tb,$btnBrowse,$btnHash,$btnRecord,$btnVerify,$out))
[Windows.Forms.Application]::EnableVisualStyles()
$form.Topmost = $true
$form.Add_Shown({ $form.Activate() })
[Windows.Forms.Application]::Run($form)
