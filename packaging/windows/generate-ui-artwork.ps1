#Requires -Version 5.1
# Regenerate the checked-in WiX bitmaps from the app's canonical PNG.
# Run on Windows only; normal MSI/CI builds consume the generated files.
# Same artwork and recipe as desktop-client (teal accent on white).
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$logo = [Drawing.Image]::FromFile((Join-Path $PSScriptRoot '..\..\assets\icon.png'))
$accent = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#0d9488'))
$panel = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#f0fdfa'))
try {
  foreach ($kind in @('dialog', 'banner')) {
    # WiX's standard dialogs stretch these over 370x234 / 370x44 dialog units.
    # Leave the text area white and keep the logo clear of all dialog controls.
    $height = if ($kind -eq 'dialog') { 312 } else { 58 }
    $bitmap = [Drawing.Bitmap]::new(493, $height, [Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
      $graphics.Clear([Drawing.Color]::White)
      $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
      $graphics.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
      if ($kind -eq 'dialog') {
        $graphics.FillRectangle($panel, 0, 0, 164, 312)
        $graphics.FillRectangle($accent, 0, 0, 5, 312)
        $graphics.DrawImage($logo, 26, 90, 112, 112)
      } else {
        $graphics.FillRectangle($accent, 489, 0, 4, 58)
        $graphics.DrawImage($logo, 436, 7, 44, 44)
      }
      $output = Join-Path $PSScriptRoot "$kind.bmp"
      $bitmap.Save($output, [Drawing.Imaging.ImageFormat]::Bmp)
      Write-Host "Generated $output (493 x $height, 24-bit BMP)"
    } finally {
      $graphics.Dispose()
      $bitmap.Dispose()
    }
  }
} finally {
  $logo.Dispose()
  $accent.Dispose()
  $panel.Dispose()
}
