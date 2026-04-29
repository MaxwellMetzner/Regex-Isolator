Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$desktopRoot = Split-Path -Parent $scriptRoot
$iconDir = Join-Path $desktopRoot "src-tauri/icons"

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class IconInterop {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern bool DestroyIcon(IntPtr handle);
}
"@

function New-RegexIsolatorBitmap {
    param(
        [int]$Size
    )

    $bitmap = New-Object System.Drawing.Bitmap $Size, $Size
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

    $background = New-Object System.Drawing.Rectangle 0, 0, $Size, $Size
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        $background,
        [System.Drawing.Color]::FromArgb(240, 107, 71),
        [System.Drawing.Color]::FromArgb(19, 98, 118),
        45
    )
    $graphics.FillRectangle($brush, $background)

    $ringPen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(245, 222, 180), [Math]::Max(4, [int]($Size * 0.07)))
    $ringInset = [Math]::Max(8, [int]($Size * 0.16))
    $graphics.DrawEllipse($ringPen, $ringInset, $ringInset, $Size - (2 * $ringInset), $Size - (2 * $ringInset))

    $slashBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(250, 247, 240))
    $slashWidth = [Math]::Max(6, [int]($Size * 0.085))
    $graphics.TranslateTransform($Size / 2, $Size / 2)
    $graphics.RotateTransform(-25)
    $graphics.FillRectangle($slashBrush, -($slashWidth / 2), -([int]($Size * 0.26)), $slashWidth, [int]($Size * 0.52))
    $graphics.ResetTransform()

    $fontSize = [Math]::Max(11, [int]($Size * 0.22))
    $font = New-Object System.Drawing.Font("Bahnschrift", $fontSize, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $textBrush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(16, 20, 25))
    $format = New-Object System.Drawing.StringFormat
    $format.Alignment = [System.Drawing.StringAlignment]::Center
    $format.LineAlignment = [System.Drawing.StringAlignment]::Far
    $textRectHeight = $Size - [int]($Size * 0.08)
    $textRect = New-Object System.Drawing.RectangleF -ArgumentList 0, 0, ([single]$Size), ([single]$textRectHeight)
    $graphics.DrawString("RI", $font, $textBrush, $textRect, $format)

    $format.Dispose()
    $font.Dispose()
    $textBrush.Dispose()
    $slashBrush.Dispose()
    $ringPen.Dispose()
    $brush.Dispose()
    $graphics.Dispose()

    return $bitmap
}

New-Item -ItemType Directory -Force -Path $iconDir | Out-Null

$pngTargets = @(
    @{ Name = "32x32.png"; Size = 32 },
    @{ Name = "128x128.png"; Size = 128 },
    @{ Name = "128x128@2x.png"; Size = 256 },
    @{ Name = "icon.png"; Size = 512 }
)

foreach ($target in $pngTargets) {
    $bitmap = New-RegexIsolatorBitmap -Size $target.Size
    try {
        $bitmap.Save((Join-Path $iconDir $target.Name), [System.Drawing.Imaging.ImageFormat]::Png)
    }
    finally {
        $bitmap.Dispose()
    }
}

$iconBitmap = New-RegexIsolatorBitmap -Size 256
try {
    $iconHandle = $iconBitmap.GetHicon()
    try {
        $icon = [System.Drawing.Icon]::FromHandle($iconHandle)
        $stream = [System.IO.File]::Open((Join-Path $iconDir "icon.ico"), [System.IO.FileMode]::Create)
        try {
            $icon.Save($stream)
        }
        finally {
            $stream.Dispose()
            $icon.Dispose()
        }
    }
    finally {
        [IconInterop]::DestroyIcon($iconHandle) | Out-Null
    }
}
finally {
    $iconBitmap.Dispose()
}

Write-Host "Generated icon set in $iconDir"