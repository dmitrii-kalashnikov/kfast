#Requires -Version 5.1
Param(
  [string]$Repo = $env:REPO -ne $null ? $env:REPO : "OWNER/REPO",  # e.g. dkalashnikov/kfast
  [string]$Bin  = $env:BIN  -ne $null ? $env:BIN  : "kfast",
  [string]$Tag  = $env:TAG  -ne $null ? $env:TAG  : "",
  [string]$Prefix = $env:PREFIX -ne $null ? $env:PREFIX : "$env:LOCALAPPDATA\Programs",
  [int]$InstallKubectl = ($env:INSTALL_KUBECTL -ne $null ? [int]$env:INSTALL_KUBECTL : 1)
)

$ErrorActionPreference = "Stop"

function Has-Cmd($name) {
  $null -ne (Get-Command $name -ErrorAction SilentlyContinue)
}

# ARCH normalize
$arch = (Get-CimInstance Win32_Processor).Architecture
switch ($arch) {
  9  { $ARCH = "amd64" }   # x64
  12 { $ARCH = "arm64" }   # ARM64
  default { throw "Unsupported arch code: $arch" }
}
$OS = "windows"

# GitHub API helper (supports GH_TOKEN)
function Invoke-GH {
  param([string]$Url)
  $Headers = @{ "Accept" = "application/vnd.github+json" }
  if ($env:GH_TOKEN) { $Headers["Authorization"] = "Bearer $($env:GH_TOKEN)" }
  Invoke-RestMethod -Uri $Url -Headers $Headers -UseBasicParsing
}

if ([string]::IsNullOrWhiteSpace($Tag)) {
  $rel = Invoke-GH "https://api.github.com/repos/$Repo/releases/latest"
  $Tag = $rel.tag_name
  if ([string]::IsNullOrWhiteSpace($Tag)) { throw "Cannot resolve latest release tag for $Repo" }
}

$Asset = "${Bin}_${OS}_${ARCH}"
$Url   = "https://github.com/$Repo/releases/download/$Tag/${Asset}.zip"
$Chk   = "https://github.com/$Repo/releases/download/$Tag/checksums.txt"

$Tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid().ToString("N")) -Force
try {
  $Zip = Join-Path $Tmp.FullName "${Asset}.zip"
  $ChkFile = Join-Path $Tmp.FullName "checksums.txt"

  Write-Host "⬇️  Downloading $Url"
  Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing

  Write-Host "⬇️  Downloading checksums"
  try {
    Invoke-WebRequest -Uri $Chk -OutFile $ChkFile -UseBasicParsing
    $line = (Select-String -Path $ChkFile -Pattern " ${Asset}\.zip$" -SimpleMatch) | Select-Object -First 1
    if ($line) {
      $expected = ($line -split "\s+")[0]
      $got = (Get-FileHash -Algorithm SHA256 -Path $Zip).Hash.ToLower()
      if ($got -ne $expected.ToLower()) { throw "Checksum mismatch for ${Asset}.zip" }
    } else {
      Write-Host "checksums.txt missing entry for ${Asset}.zip; skipping verification."
    }
  } catch {
    Write-Host "No checksums.txt found; skipping verification."
  }

  $destRoot = Join-Path $Prefix $Bin
  $destBinDir = if (Test-Path "$env:ProgramFiles") { Join-Path $destRoot "bin" } else { $destRoot }
  New-Item -ItemType Directory -Force -Path $destBinDir | Out-Null

  Write-Host "📦  Extracting..."
  Expand-Archive -Path $Zip -DestinationPath $Tmp.FullName -Force

  $srcExe = Join-Path $Tmp.FullName "$Bin.exe"
  if (-not (Test-Path $srcExe)) {
    # If the exe was nested in a folder inside the zip, try to locate it
    $found = Get-ChildItem -Path $Tmp.FullName -Recurse -Filter "$Bin.exe" | Select-Object -First 1
    if ($null -eq $found) { throw "$Bin.exe not found in archive." }
    $srcExe = $found.FullName
  }

  Copy-Item $srcExe (Join-Path $destBinDir "$Bin.exe") -Force

  # ensure PATH contains destBinDir (user-level)
  $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if ($currentPath -notlike "*$destBinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$destBinDir;$currentPath", "User")
    Write-Host "🔧 PATH updated for current user. You may need a new terminal."
  }

  Write-Host "✅ Installed $Bin to $destBinDir\$Bin.exe"

  if ($InstallKubectl -eq 1 -and -not (Has-Cmd "kubectl")) {
    Write-Host "ℹ️  kubectl not found; installing stable kubectl..."
    $stable = (Invoke-WebRequest -Uri "https://dl.k8s.io/release/stable.txt" -UseBasicParsing).Content.Trim()
    $kurl = "https://dl.k8s.io/release/$stable/bin/windows/$ARCH/kubectl.exe"
    $kexe = Join-Path $destBinDir "kubectl.exe"
    Invoke-WebRequest -Uri $kurl -OutFile $kexe -UseBasicParsing
    Write-Host "✅ Installed kubectl to $kexe"
  }

  Write-Host "🎉 Done. Try: $Bin --help"
}
finally {
  Remove-Item -Recurse -Force $Tmp | Out-Null
}
