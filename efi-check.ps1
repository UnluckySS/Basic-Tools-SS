# ==================================================
#   VERIFICADOR EFI - Análise forense UEFI / EFI
#   Autor / Author: UNLUCKY
#   Feito por UNLUCKY - Todos os créditos para UNLUCKY
# ==================================================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$ErrorActionPreference = "SilentlyContinue"

Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "            FEITO POR: UNLUCKY                    " -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "[*] Iniciando análise forense EFI avançada..." -ForegroundColor Cyan

function Get-FileEntropy {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -eq 0) { return 0 }
        $freq = @{}
        foreach ($b in $bytes) {
            if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
        }
        $entropy = 0.0
        $len = $bytes.Length
        foreach ($count in $freq.Values) {
            $p = $count / $len
            if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
        }
        return [Math]::Round($entropy, 3)
    } catch { return -1 }
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        "CRÍTICO"    { return [System.Drawing.Color]::FromArgb(255, 220, 220) }
        "ALTO"       { return [System.Drawing.Color]::FromArgb(255, 240, 200) }
        "MÉDIO"      { return [System.Drawing.Color]::FromArgb(255, 255, 210) }
        "INFO"       { return [System.Drawing.Color]::FromArgb(220, 240, 255) }
        "OK"         { return [System.Drawing.Color]::FromArgb(220, 255, 220) }
        default      { return [System.Drawing.Color]::White }
    }
}

$BootkitPatterns = @(
    "blacklotus", "especter", "lojax", "mosaic", "cosmicstrand",
    "moonbounce", "trickbot", "finspy", "vector-edk", "hacking ?team",
    "rovnix", "gapz", "thunderstrike", "dreamboot", "rkloader",
    "boothole", "baton ?drop", "eset", "kaspersky.*efi.*hack"
)
$BootkitRegex = "(" + ($BootkitPatterns -join "|") + ")"

$KnownLegitEfi = @(
    "bootmgfw.efi", "bootmgr.efi", "memtest.efi", "bootx64.efi",
    "bootia32.efi", "bootaa64.efi", "grubx64.efi", "shimx64.efi",
    "mmx64.efi", "fbia32.efi", "fbx64.efi", "wudfrd.efi",
    "securebootrecovery.efi", "bootmgr.efi.mui", "memtest.efi.mui",
    "winia32.efi", "winload.efi", "winresume.efi", "winload.efi.mui",
    "kdnet_uart16550.efi", "kdstub.efi", "kdnet.efi"
)

$espLetter = "S"
$espRoot = "${espLetter}:\"
$espMounted = Test-Path "${espLetter}:\EFI"

if (-not $espMounted) {
    Write-Host "[*] Montando partição EFI em ${espLetter}: ..." -ForegroundColor Yellow
    mountvol "${espLetter}:" /s
    Start-Sleep -Seconds 2
}

if (-not (Test-Path $espRoot)) {
    Write-Host "[ERRO] Não foi possível acessar a partição EFI." -ForegroundColor Red
    Write-Host "       Certifique-se de executar como Administrador." -ForegroundColor Red
    Read-Host "Pressione Enter para sair"
    exit
}

Write-Host "[OK] Partição EFI acessível: ${espLetter}:" -ForegroundColor Green

Write-Host "[*] Escaneando arquivos da ESP..." -ForegroundColor Cyan

$allFiles = Get-ChildItem $espRoot -Recurse -Force -File
$allDirs = Get-ChildItem $espRoot -Recurse -Force -Directory
$efiFiles = $allFiles | Where-Object { $_.Extension -ieq ".efi" }

Write-Host "[*] Analisando assinaturas, hashes e entropia de $($efiFiles.Count) arquivos .EFI..." -ForegroundColor Cyan

$efiAnalysis = foreach ($file in $efiFiles) {
    $sig = Get-AuthenticodeSignature $file.FullName
    $publisher = "SEM CERTIFICADO"
    $serialNumber = ""
    $thumbprint = ""
    $certExpiry = ""
    $certValid = $false

    if ($sig.SignerCertificate) {
        $publisher = $sig.SignerCertificate.Subject
        $serialNumber = $sig.SignerCertificate.SerialNumber
        $thumbprint = $sig.SignerCertificate.Thumbprint
        $certExpiry = $sig.SignerCertificate.NotAfter.ToString("yyyy-MM-dd")
        $certValid = ($sig.SignerCertificate.NotAfter -gt (Get-Date))
    }

    $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash
    $entropy = Get-FileEntropy $file.FullName

    $relPath = $file.FullName.Substring($espRoot.Length)

    $inNormalPath = ($relPath -like "EFI\Microsoft\*") -or ($relPath -like "EFI\Boot\*")
    $isKnownName = $KnownLegitEfi -contains $file.Name.ToLower()
    $isSuspiciousName = $file.Name -imatch $BootkitRegex

    $tsAnomaly = ($file.LastWriteTime -lt (Get-Date "2018-01-01")) -or ($file.LastWriteTime -gt (Get-Date).AddDays(1))
    $creationAnomaly = ($file.CreationTime -lt (Get-Date "2018-01-01")) -or ($file.CreationTime -gt (Get-Date).AddDays(1))

    $severity = "OK"
    $alerts = @()

    if ($sig.Status -ne "Valid") {
        $severity = "CRÍTICO"
        $alerts += "Assinatura inválida: $($sig.Status)"
    }
    if ($sig.Status -eq "Valid" -and -not ($publisher -match "Microsoft")) {
        if ($severity -eq "OK") { $severity = "MÉDIO" }
        $alerts += "Assinante não-Microsoft: $publisher"
    }
    if (-not $certValid -and $sig.SignerCertificate) {
        if ($severity -ne "CRÍTICO") { $severity = "ALTO" }
        $alerts += "Certificado expirado: $certExpiry"
    }
    if (-not $inNormalPath) {
        if ($severity -eq "OK") { $severity = "ALTO" }
        $alerts += "Fora do caminho habitual (EFI\Microsoft ou EFI\Boot)"
    }
    if (-not $isKnownName) {
        if ($severity -eq "OK") { $severity = "MÉDIO" }
        $alerts += "Nome não reconhecido como EFI legítimo padrão"
    }
    if ($isSuspiciousName) {
        $severity = "CRÍTICO"
        $alerts += "Nome corresponde a padrão de bootkit conhecido"
    }
    if ($entropy -gt 7.5) {
        if ($severity -eq "OK") { $severity = "ALTO" }
        $alerts += "Entropia alta ($entropy) - possível empacotamento/criptografia"
    }
    if ($tsAnomaly -or $creationAnomaly) {
        if ($severity -eq "OK") { $severity = "MÉDIO" }
        $alerts += "Anomalia de timestamp (data suspeita)"
    }

    if ($alerts.Count -eq 0) { $alerts += "Nenhuma anomalia detectada" }

    [PSCustomObject]@{
        Arquivo          = $file.Name
        CaminhoCompleto  = $file.FullName
        CaminhoRelativo  = $relPath
        Tamanho          = $file.Length
        Modificado       = $file.LastWriteTime
        Criado           = $file.CreationTime
        Assinatura       = $sig.Status.ToString()
        Assinante        = $publisher
        SerialCert       = $serialNumber
        Thumbprint       = $thumbprint
        CertExpira       = $certExpiry
        CertVigente      = $certValid
        SHA256           = $hash
        Entropia         = $entropy
        CaminhoNormal    = $inNormalPath
        NomeConhecido    = $isKnownName
        Severidade       = $severity
        Alertas          = ($alerts -join " | ")
    }
}
Write-Host "[*] Procurando arquivos ocultos e Alternate Data Streams..." -ForegroundColor Cyan

$hiddenFiles = $allFiles | Where-Object {
    $_.Attributes -band [System.IO.FileAttributes]::Hidden
}

# Detecção de ADS
$adsResults = @()
foreach ($f in $allFiles) {
    try {
        $streams = Get-Item $f.FullName -Stream * -ErrorAction SilentlyContinue |
            Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne '' }
        if ($streams) {
            foreach ($s in $streams) {
                $adsResults += [PSCustomObject]@{
                    Arquivo = $f.FullName
                    Stream  = $s.Stream
                    Tamanho = $s.Length
                }
            }
        }
    } catch {}
}

# --- Arquivos não-EFI suspeitos ---
$suspiciousNonEfi = $allFiles | Where-Object {
    $_.Extension -imatch "\.(dll|sys|exe|bat|cmd|ps1|vbs|js|bin|dat|cfg|inf)$" -or
    $_.Name -imatch "boot|loader|shim|grub|start|launch|hack|inject|patch|hook"
}

# --- Secure Boot ---
Write-Host "[*] Verificando o estado do Secure Boot..." -ForegroundColor Cyan

$secureBootStatus = "Desconhecido"
$secureBootColor = "MÉDIO"
try {
    $sb = Confirm-SecureBootUEFI
    if ($sb) {
        $secureBootStatus = "ATIVADO"
        $secureBootColor = "OK"
    } else {
        $secureBootStatus = "DESATIVADO"
        $secureBootColor = "CRÍTICO"
    }
} catch {
    $secureBootStatus = "Não suportado / Não disponível"
    $secureBootColor = "MÉDIO"
}

# --- Modo do Firmware ---
$firmwareType = "Desconhecido"
try {
    $firmwareType = (Get-ComputerInfo).BiosFirmwareType
} catch {}

# --- TPM ---
Write-Host "[*] Consultando o estado do TPM..." -ForegroundColor Cyan
$tpmInfo = $null
try {
    $tpmInfo = Get-Tpm -ErrorAction SilentlyContinue
} catch {}

# --- BCD ---
Write-Host "[*] Lendo a configuração do BCD..." -ForegroundColor Cyan
$bcdOutput = bcdedit /enum all 2>&1 | Out-String
$bcdFirmware = bcdedit /enum firmware 2>&1 | Out-String

Write-Host "[*] Verificando a assinatura dos binários referenciados no BCD..." -ForegroundColor Cyan
$bcdBinaries = @()

$bcdEntries = bcdedit /enum all /v 2>&1 | Out-String
$currentEntry = ""
$currentId = ""

foreach ($line in ($bcdEntries -split "`r?`n")) {
    if ($line -match "^identifier\s+(.+)$") {
        $currentId = $Matches[1].Trim()
    }
    if ($line -match "^description\s+(.+)$") {
        $currentEntry = $Matches[1].Trim()
    }
    if ($line -match "^\s*(path|systemroot)\s+(.+)$") {
        $rawPath = $Matches[2].Trim()

        $resolvedPaths = @()
        if ($rawPath -match "^\\EFI\\") {
            $resolvedPaths += "${espLetter}:$rawPath"
        }
        elseif ($rawPath -match "^\\Windows\\|^\\SystemRoot\\") {
            $sysPath = $rawPath -replace "^\\SystemRoot\\", "\Windows\"
            Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | ForEach-Object {
                $candidate = "$($_.Name):$sysPath"
                if (Test-Path $candidate) { $resolvedPaths += $candidate }
            }
        }
        elseif ($rawPath -match "^[A-Za-z]:\\") {
            $resolvedPaths += $rawPath
        }
        else {
            $candidate = "${espLetter}:$rawPath"
            if (Test-Path $candidate) { $resolvedPaths += $candidate }
            $candidate2 = "$($env:SystemDrive)$rawPath"
            if (Test-Path $candidate2) { $resolvedPaths += $candidate2 }
        }

        foreach ($resolved in $resolvedPaths) {
            if (-not (Test-Path $resolved)) { continue }
            if (($bcdBinaries | Where-Object { $_.CaminhoResolvido -eq $resolved }).Count -gt 0) { continue }

            $sig = Get-AuthenticodeSignature $resolved -ErrorAction SilentlyContinue
            $sigStatus = if ($sig) { $sig.Status.ToString() } else { "NaoDisponivel" }
            $publisher = "SEM CERTIFICADO"
            $thumbprint = ""
            if ($sig -and $sig.SignerCertificate) {
                $publisher = $sig.SignerCertificate.Subject
                $thumbprint = $sig.SignerCertificate.Thumbprint
            }
            $hash = ""
            try { $hash = (Get-FileHash $resolved -Algorithm SHA256).Hash } catch {}
            $finfo = Get-Item $resolved -Force -ErrorAction SilentlyContinue

            $severity = "OK"
            $alertas = @()
            if ($sigStatus -ne "Valid") {
                $severity = "CRÍTICO"
                $alertas += "Assinatura inválida ou ausente: $sigStatus"
            }
            if ($sigStatus -eq "Valid" -and $publisher -notmatch "Microsoft") {
                $severity = "ALTO"
                $alertas += "Assinante não-Microsoft: $publisher"
            }
            if ($alertas.Count -eq 0) { $alertas += "Assinatura válida (Microsoft)" }

            $bcdBinaries += [PSCustomObject]@{
                Entrada          = $currentEntry
                Identificador    = $currentId
                CaminhoBCD       = $rawPath
                CaminhoResolvido = $resolved
                Tamanho          = if ($finfo) { $finfo.Length } else { 0 }
                Modificado       = if ($finfo) { $finfo.LastWriteTime } else { $null }
                Assinatura       = $sigStatus
                Assinante        = $publisher
                Thumbprint       = $thumbprint
                SHA256           = $hash
                Severidade       = $severity
                Alertas          = ($alertas -join " | ")
            }
        }
    }
}

# --- Política do Secure Boot DB/DBX ---
Write-Host "[*] Consultando bancos de dados do Secure Boot (DB/DBX)..." -ForegroundColor Cyan
$dbInfo = ""
try {
    $dbVars = Get-SecureBootPolicy -ErrorAction SilentlyContinue
    if ($dbVars) { $dbInfo = $dbVars | Out-String }
} catch {}

# Se o cmdlet não existir, tenta via registro
if ([string]::IsNullOrEmpty($dbInfo)) {
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
        if (Test-Path $regPath) {
            $dbInfo = "Chaves de Registro do Secure Boot:`r`n"
            $dbInfo += (Get-ItemProperty $regPath | Out-String)
            $availUpdates = Get-ItemProperty "$regPath\AvailableUpdates" -ErrorAction SilentlyContinue
            if ($availUpdates) {
                $dbInfo += "`r`nAtualizações Disponíveis:`r`n" + ($availUpdates | Out-String)
            }
        }
    } catch {}
}

# --- Volumes FAT32 ---
$fat32Volumes = Get-Volume | Where-Object { $_.FileSystem -eq "FAT32" } |
    Select-Object DriveLetter, FileSystemLabel, FileSystem,
        @{N='TamanhoMB';E={[math]::Round($_.Size/1MB,1)}},
        @{N='LivreMB';E={[math]::Round($_.SizeRemaining/1MB,1)}}

# --- EFI em outros volumes ---
Write-Host "[*] Procurando .EFI em outros volumes..." -ForegroundColor Cyan
$otherEfi = @()
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -ne $espLetter }
foreach ($drive in $drives) {
    $root = "$($drive.Name):\"
    $found = Get-ChildItem $root -Recurse -Force -File -Filter "*.efi" -ErrorAction SilentlyContinue
    if ($found) {
        foreach ($f in $found) {
            $oSig = Get-AuthenticodeSignature $f.FullName -ErrorAction SilentlyContinue
            $oFirma = if ($oSig -and $oSig.Status -eq "Valid") { "True" } else { "False" }
            $otherEfi += [PSCustomObject]@{
                Volume     = $drive.Name
                Arquivo    = $f.FullName
                Tamanho    = $f.Length
                Modificado = $f.LastWriteTime
                Assinatura = $oFirma
            }
        }
    }
}

# --- Eventos Kernel-Boot ---
Write-Host "[*] Consultando eventos Kernel-Boot e TPM..." -ForegroundColor Cyan

$bootEvents = @()
$bootEventIds = @(32, 33, 125)
try {
    $evts = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Kernel-Boot/Operational"
        Id = $bootEventIds
    } -MaxEvents 50 -ErrorAction SilentlyContinue

    foreach ($e in $evts) {
        $bootEvents += [PSCustomObject]@{
            Data     = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventID  = $e.Id
            Tipo     = switch ($e.Id) {
                32  { "Política de Integridade de Boot" }
                33  { "Status de Carregamento do Hypervisor" }
                125 { "Validação do Secure Boot" }
            }
            Mensagem = ($e.Message -replace "`r`n"," " -replace "\s+"," ").Trim()
        }
    }
} catch {}

# Eventos de TPM do log System
$tpmEvents = @()
try {
    $tEvts = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        ProviderName = "Microsoft-Windows-TPM-WMI"
    } -MaxEvents 30 -ErrorAction SilentlyContinue

    foreach ($e in $tEvts) {
        $tpmEvents += [PSCustomObject]@{
            Data     = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventID  = $e.Id
            Nivel    = $e.LevelDisplayName
            Mensagem = ($e.Message -replace "`r`n"," " -replace "\s+"," ").Trim()
        }
    }
} catch {}

# Eventos de Measured Boot / Integridade
$measuredBootEvents = @()
try {
    $mbEvts = Get-WinEvent -FilterHashtable @{
        LogName = "System"
        ProviderName = @("Microsoft-Windows-Kernel-Boot", "Microsoft-Windows-Measured-Boot")
    } -MaxEvents 30 -ErrorAction SilentlyContinue

    foreach ($e in $mbEvts) {
        $measuredBootEvents += [PSCustomObject]@{
            Data     = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            EventID  = $e.Id
            Origem   = $e.ProviderName
            Nivel    = $e.LevelDisplayName
            Mensagem = ($e.Message -replace "`r`n"," " -replace "\s+"," ").Trim()
        }
    }
} catch {}


Write-Host "[+] Coleta concluída. Construindo a interface..." -ForegroundColor Green

# ============================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "Verificação Forense EFI - Análise Avançada - by UNLUCKY"
$form.Size = New-Object System.Drawing.Size(1280, 800)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$form.ForeColor = [System.Drawing.Color]::White
try { $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon((Get-Process -id $PID).Path) } catch {}

$fontNormal = New-Object System.Drawing.Font("Segoe UI", 9)
$fontBold = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$fontTitle = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontMono = New-Object System.Drawing.Font("Consolas", 9.5)

$darkBg = [System.Drawing.Color]::FromArgb(30, 30, 30)
$panelBg = [System.Drawing.Color]::FromArgb(45, 45, 45)
$accentBlue = [System.Drawing.Color]::FromArgb(0, 120, 215)
$textWhite = [System.Drawing.Color]::White
$textGray = [System.Drawing.Color]::FromArgb(180, 180, 180)

$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Dock = "Top"
$headerPanel.Height = 100
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 40)
$form.Controls.Add($headerPanel)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "VERIFICAÇÃO FORENSE UEFI / EFI  -  by UNLUCKY"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $accentBlue
$lblTitle.Location = New-Object System.Drawing.Point(20, 10)
$lblTitle.AutoSize = $true
$headerPanel.Controls.Add($lblTitle)

$critCount = ($efiAnalysis | Where-Object Severidade -eq "CRÍTICO").Count
$altoCount = ($efiAnalysis | Where-Object Severidade -eq "ALTO").Count
$medioCount = ($efiAnalysis | Where-Object Severidade -eq "MÉDIO").Count
$okCount = ($efiAnalysis | Where-Object Severidade -eq "OK").Count

$summaryText = "Arquivos ESP: $($allFiles.Count)  |  "
$summaryText += "EFI totais: $($efiFiles.Count)  |  "
$summaryText += "Secure Boot: $secureBootStatus  |  "
$summaryText += "Firmware: $firmwareType  |  "
$summaryText += "Ocultos: $($hiddenFiles.Count)  |  "
$summaryText += "ADS: $($adsResults.Count)"

$lblSummary = New-Object System.Windows.Forms.Label
$lblSummary.Text = $summaryText
$lblSummary.Font = $fontNormal
$lblSummary.ForeColor = $textGray
$lblSummary.Location = New-Object System.Drawing.Point(20, 45)
$lblSummary.AutoSize = $true
$headerPanel.Controls.Add($lblSummary)

$sevX = 20
$sevY = 70
foreach ($sevItem in @(
    @{Label="CRÍTICO: $critCount"; Color=[System.Drawing.Color]::FromArgb(220,50,50)},
    @{Label="ALTO: $altoCount"; Color=[System.Drawing.Color]::FromArgb(255,165,0)},
    @{Label="MÉDIO: $medioCount"; Color=[System.Drawing.Color]::FromArgb(255,220,50)},
    @{Label="OK: $okCount"; Color=[System.Drawing.Color]::FromArgb(50,200,50)}
)) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = [char]0x25CF  # círculo
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 12)
    $lbl.ForeColor = $sevItem.Color
    $lbl.Location = New-Object System.Drawing.Point($sevX, $sevY)
    $lbl.AutoSize = $true
    $headerPanel.Controls.Add($lbl)
    $sevX += 18

    $lbl2 = New-Object System.Windows.Forms.Label
    $lbl2.Text = $sevItem.Label
    $lbl2.Font = $fontBold
    $lbl2.ForeColor = $sevItem.Color
    $lbl2.Location = New-Object System.Drawing.Point($sevX, ($sevY + 2))
    $lbl2.AutoSize = $true
    $headerPanel.Controls.Add($lbl2)
    $sevX += 110
}

$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = "Fill"
$tabControl.Font = $fontBold
$tabControl.Padding = New-Object System.Drawing.Point(12, 6)
$form.Controls.Add($tabControl)
$form.Controls.SetChildIndex($tabControl, 0)


function New-StyledGrid {
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = "Fill"
    $g.AutoSizeColumnsMode = "Fill"
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.ReadOnly = $true
    $g.SelectionMode = "FullRowSelect"
    $g.BackgroundColor = [System.Drawing.Color]::FromArgb(35, 35, 35)
    $g.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $g.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $g.DefaultCellStyle.SelectionBackColor = $accentBlue
    $g.DefaultCellStyle.Font = $fontNormal
    $g.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $g.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $g.ColumnHeadersDefaultCellStyle.Font = $fontBold
    $g.EnableHeadersVisualStyles = $false
    $g.RowHeadersVisible = $false
    $g.GridColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $g.BorderStyle = "None"
    $g.CellBorderStyle = "SingleHorizontal"
    return $g
}

function Show-RowDetail {
    param(
        [System.Windows.Forms.DataGridView]$Grid,
        [int]$RowIndex,
        [string]$Title = "Detalhes"
    )
    if ($RowIndex -lt 0) { return }
    $row = $Grid.Rows[$RowIndex]

    $detForm = New-Object System.Windows.Forms.Form
    $detForm.Text = $Title
    $detForm.Size = New-Object System.Drawing.Size(850, 550)
    $detForm.StartPosition = "CenterParent"
    $detForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Multiline = $true
    $txt.ReadOnly = $true
    $txt.ScrollBars = "Both"
    $txt.Dock = "Fill"
    $txt.Font = $fontMono
    $txt.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
    $txt.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 150)
    $txt.WordWrap = $true

    $lines = "==================== DETALHES COMPLETOS ====================`r`n`r`n"
    foreach ($col in $Grid.Columns) {
        $colName = $col.Name
        $val = $row.Cells[$colName].Value
        if ($null -eq $val) { $val = "" }
        $valStr = $val.ToString()
        $padded = $colName.PadRight(18)
        if ($valStr.Length -gt 120) {
            $lines += "${padded}: `r`n$valStr`r`n`r`n"
        } else {
            $lines += "${padded}: $valStr`r`n"
        }
    }
    $lines += "`r`n=========================================================="

    $txt.Text = $lines
    $txt.SelectionStart = 0
    $txt.SelectionLength = 0
    $detForm.Controls.Add($txt)

    $btnCopy = New-Object System.Windows.Forms.Button
    $btnCopy.Text = "Copiar para a Área de Transferência"
    $btnCopy.Dock = "Bottom"
    $btnCopy.Height = 35
    $btnCopy.BackColor = [System.Drawing.Color]::FromArgb(0, 100, 180)
    $btnCopy.ForeColor = [System.Drawing.Color]::White
    $btnCopy.FlatStyle = "Flat"
    $btnCopy.Font = $fontBold
    $btnCopy.Cursor = [System.Windows.Forms.Cursors]::Hand
    $btnCopy.Add_Click({
        [System.Windows.Forms.Clipboard]::SetText($txt.Text)
        $btnCopy.Text = "Copiado!"
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 1500
        $timer.Add_Tick({ $btnCopy.Text = "Copiar para a Área de Transferência"; $timer.Stop() })
        $timer.Start()
    })
    $detForm.Controls.Add($btnCopy)

    [void]$detForm.ShowDialog()
}


$tab1 = New-Object System.Windows.Forms.TabPage
$tab1.Text = "Análise EFI"
$tab1.BackColor = $darkBg
$tabControl.TabPages.Add($tab1)

$filterPanel1 = New-Object System.Windows.Forms.Panel
$filterPanel1.Dock = "Top"
$filterPanel1.Height = 45
$filterPanel1.BackColor = $panelBg
$tab1.Controls.Add($filterPanel1)

$lblSevFilter = New-Object System.Windows.Forms.Label
$lblSevFilter.Text = "Filtrar por severidade:"
$lblSevFilter.Font = $fontBold
$lblSevFilter.ForeColor = $textWhite
$lblSevFilter.Location = New-Object System.Drawing.Point(15, 12)
$lblSevFilter.AutoSize = $true
$filterPanel1.Controls.Add($lblSevFilter)

$comboSev = New-Object System.Windows.Forms.ComboBox
$comboSev.Location = New-Object System.Drawing.Point(170, 9)
$comboSev.Width = 140
$comboSev.DropDownStyle = "DropDownList"
$comboSev.Font = $fontNormal
$comboSev.Items.AddRange(@("Todos", "CRÍTICO", "ALTO", "MÉDIO", "OK"))
$comboSev.SelectedIndex = 0
$filterPanel1.Controls.Add($comboSev)

$lblSearchEfi = New-Object System.Windows.Forms.Label
$lblSearchEfi.Text = "Pesquisar:"
$lblSearchEfi.Font = $fontBold
$lblSearchEfi.ForeColor = $textWhite
$lblSearchEfi.Location = New-Object System.Drawing.Point(330, 12)
$lblSearchEfi.AutoSize = $true
$filterPanel1.Controls.Add($lblSearchEfi)

$txtSearchEfi = New-Object System.Windows.Forms.TextBox
$txtSearchEfi.Location = New-Object System.Drawing.Point(410, 9)
$txtSearchEfi.Width = 250
$txtSearchEfi.Font = $fontNormal
$filterPanel1.Controls.Add($txtSearchEfi)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = "Exportar CSV"
$btnExport.Location = New-Object System.Drawing.Point(690, 7)
$btnExport.Size = New-Object System.Drawing.Size(120, 30)
$btnExport.BackColor = [System.Drawing.Color]::FromArgb(0, 100, 180)
$btnExport.ForeColor = $textWhite
$btnExport.FlatStyle = "Flat"
$btnExport.Font = $fontBold
$btnExport.Cursor = [System.Windows.Forms.Cursors]::Hand
$filterPanel1.Controls.Add($btnExport)

$grid1 = New-StyledGrid
$tab1.Controls.Add($grid1)
$tab1.Controls.SetChildIndex($grid1, 0)

$dt1 = New-Object System.Data.DataTable
$dt1.Columns.Add("Severidade", [string]) | Out-Null
$dt1.Columns.Add("Arquivo", [string]) | Out-Null
$dt1.Columns.Add("Caminho", [string]) | Out-Null
$dt1.Columns.Add("Tamanho", [int64]) | Out-Null
$dt1.Columns.Add("Modificado", [datetime]) | Out-Null
$dt1.Columns.Add("Assinatura", [string]) | Out-Null
$dt1.Columns.Add("Assinante", [string]) | Out-Null
$dt1.Columns.Add("Entropia", [double]) | Out-Null
$dt1.Columns.Add("SHA256", [string]) | Out-Null
$dt1.Columns.Add("Alertas", [string]) | Out-Null

foreach ($efi in $efiAnalysis) {
    $r = $dt1.NewRow()
    $r["Severidade"] = $efi.Severidade
    $r["Arquivo"] = $efi.Arquivo
    $r["Caminho"] = $efi.CaminhoRelativo
    $r["Tamanho"] = $efi.Tamanho
    $r["Modificado"] = $efi.Modificado
    $r["Assinatura"] = $efi.Assinatura
    $r["Assinante"] = $efi.Assinante
    $r["Entropia"] = $efi.Entropia
    $r["SHA256"] = $efi.SHA256
    $r["Alertas"] = $efi.Alertas
    $dt1.Rows.Add($r)
}

$dv1 = New-Object System.Data.DataView($dt1)
$grid1.DataSource = $dv1

$grid1.Add_CellFormatting({
    param($sender, $e)
    if ($e.RowIndex -ge 0 -and $sender.Columns[$e.ColumnIndex].Name -eq "Severidade") {
        $val = $sender.Rows[$e.RowIndex].Cells["Severidade"].Value
        $color = Get-SeverityColor $val
        $e.CellStyle.BackColor = $color
        $e.CellStyle.ForeColor = [System.Drawing.Color]::Black
    }
})

$grid1.Add_CellDoubleClick({
    param($sender, $e)
    if ($e.RowIndex -ge 0) {
        $row = $sender.Rows[$e.RowIndex]
        $arquivo = $row.Cells["Arquivo"].Value
        $match = $efiAnalysis | Where-Object { $_.Arquivo -eq $arquivo } | Select-Object -First 1
        if ($match) {
            $detForm = New-Object System.Windows.Forms.Form
            $detForm.Text = "Detalhes EFI: $arquivo"
            $detForm.Size = New-Object System.Drawing.Size(800, 550)
            $detForm.StartPosition = "CenterParent"
            $detForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

            $txt = New-Object System.Windows.Forms.TextBox
            $txt.Multiline = $true
            $txt.ReadOnly = $true
            $txt.ScrollBars = "Both"
            $txt.Dock = "Fill"
            $txt.Font = $fontMono
            $txt.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
            $txt.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 150)
            $txt.WordWrap = $false

            $detail = @"
================== DETALHES FORENSES ==================

Arquivo          : $($match.Arquivo)
Caminho Completo : $($match.CaminhoCompleto)
Caminho Relativo : $($match.CaminhoRelativo)
Tamanho          : $($match.Tamanho) bytes
Data de Criação  : $($match.Criado)
Data de Modific. : $($match.Modificado)

--- ASSINATURA DIGITAL ---
Estado           : $($match.Assinatura)
Assinante        : $($match.Assinante)
Serial do Cert.  : $($match.SerialCert)
Thumbprint       : $($match.Thumbprint)
Cert. Expira     : $($match.CertExpira)
Cert. Vigente    : $($match.CertVigente)

--- INTEGRIDADE ---
SHA256           : $($match.SHA256)
Entropia         : $($match.Entropia) / 8.0
Caminho Normal   : $($match.CaminhoNormal)
Nome Conhecido   : $($match.NomeConhecido)

--- VEREDITO ---
Severidade       : $($match.Severidade)
Alertas          : $($match.Alertas)

========================================================
"@
            $txt.Text = $detail
            $txt.SelectionStart = 0
            $txt.SelectionLength = 0
            $detForm.Controls.Add($txt)
            [void]$detForm.ShowDialog()
        }
    }
})

$applyEfiFilter = {
    $parts = @()
    if ($comboSev.SelectedItem -ne "Todos") {
        $parts += "Severidade = '$($comboSev.SelectedItem)'"
    }
    if (![string]::IsNullOrWhiteSpace($txtSearchEfi.Text)) {
        $s = $txtSearchEfi.Text -replace "'","''"
        $parts += "(Arquivo LIKE '%$s%' OR Caminho LIKE '%$s%' OR Assinante LIKE '%$s%' OR Alertas LIKE '%$s%' OR SHA256 LIKE '%$s%')"
    }
    if ($parts.Count -gt 0) {
        $dv1.RowFilter = $parts -join " AND "
    } else {
        $dv1.RowFilter = ""
    }
}

$comboSev.Add_SelectedIndexChanged($applyEfiFilter)
$txtSearchEfi.Add_KeyDown({ if ($_.KeyCode -eq 'Enter') { & $applyEfiFilter } })

$btnExport.Add_Click({
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "CSV (*.csv)|*.csv"
    $sfd.FileName = "efi_forense_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -eq "OK") {
        $efiAnalysis | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.Forms.MessageBox]::Show("Exportado para:`n$($sfd.FileName)", "Exportação", "OK", "Information")
    }
})


$tab2 = New-Object System.Windows.Forms.TabPage
$tab2.Text = "Alertas / Descobertas"
$tab2.BackColor = $darkBg
$tabControl.TabPages.Add($tab2)

$txtAlerts = New-Object System.Windows.Forms.TextBox
$txtAlerts.Multiline = $true
$txtAlerts.ReadOnly = $true
$txtAlerts.ScrollBars = "Both"
$txtAlerts.Dock = "Fill"
$txtAlerts.Font = $fontMono
$txtAlerts.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$txtAlerts.ForeColor = [System.Drawing.Color]::FromArgb(0, 255, 100)
$txtAlerts.WordWrap = $false

$alertText = "==================== RELATÓRIO DE DESCOBERTAS ====================`r`n"
$alertText += "Feito por: UNLUCKY`r`n"
$alertText += "Data da análise: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n"
$alertText += "Computador: $env:COMPUTERNAME`r`n"
$alertText += "==================================================================`r`n`r`n"

$alertText += "[SECURE BOOT] Estado: $secureBootStatus`r`n"
if ($secureBootStatus -ne "ATIVADO") {
    $alertText += "  >> ALERTA: O Secure Boot não está ativo. Bootkits podem ser carregados sem restrição.`r`n"
}
$alertText += "`r`n"

if ($tpmInfo) {
    $alertText += "[TPM] Presente: $($tpmInfo.TpmPresent) | Pronto: $($tpmInfo.TpmReady) | Habilitado: $($tpmInfo.TpmEnabled)`r`n"
    if (-not $tpmInfo.TpmReady) {
        $alertText += "  >> ALERTA: O TPM não está pronto. A cadeia de medição de boot pode estar comprometida.`r`n"
    }
} else {
    $alertText += "[TPM] Não foi possível consultar o estado do TPM.`r`n"
}
$alertText += "`r`n"

$alertText += "--- ARQUIVOS EFI COM ALERTAS ---`r`n`r`n"
$critEfis = $efiAnalysis | Where-Object { $_.Severidade -ne "OK" } | Sort-Object {
    switch ($_.Severidade) { "CRÍTICO" {0} "ALTO" {1} "MÉDIO" {2} default {3} }
}

if ($critEfis.Count -eq 0) {
    $alertText += "  [OK] Nenhum arquivo EFI com anomalias foi encontrado.`r`n"
} else {
    foreach ($ce in $critEfis) {
        $alertText += "  [$($ce.Severidade)] $($ce.CaminhoRelativo)`r`n"
        $alertText += "         Assinatura: $($ce.Assinatura) | Entropia: $($ce.Entropia) | SHA256: $($ce.SHA256.Substring(0,16))...`r`n"
        $alertText += "         -> $($ce.Alertas)`r`n`r`n"
    }
}

$alertText += "--- BINÁRIOS REFERENCIADOS NO BCD (CADEIA DE BOOT) ---`r`n`r`n"
$bcdBad = $bcdBinaries | Where-Object { $_.Severidade -ne "OK" }
if ($bcdBinaries.Count -eq 0) {
    $alertText += "  [INFO] Não foi possível extrair caminhos de binários do BCD.`r`n"
} elseif ($bcdBad.Count -eq 0) {
    $alertText += "  [OK] Todos os binários de boot ($($bcdBinaries.Count)) têm assinatura Microsoft válida.`r`n"
} else {
    foreach ($bb in $bcdBad) {
        $alertText += "  [$($bb.Severidade)] $($bb.CaminhoBCD)`r`n"
        $alertText += "         Entrada: $($bb.Entrada) | Assinatura: $($bb.Assinatura)`r`n"
        $alertText += "         Assinante: $($bb.Assinante)`r`n"
        $alertText += "         -> $($bb.Alertas)`r`n`r`n"
    }
}
$bcdOk = $bcdBinaries | Where-Object { $_.Severidade -eq "OK" }
if ($bcdOk.Count -gt 0) {
    $alertText += "  Binários com assinatura válida: $($bcdOk.Count)`r`n"
    foreach ($bo in $bcdOk) {
        $alertText += "    [OK] $($bo.CaminhoBCD) -> $($bo.Entrada)`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- ARQUIVOS OCULTOS NA ESP ---`r`n`r`n"
if ($hiddenFiles.Count -eq 0) {
    $alertText += "  [OK] Não há arquivos ocultos.`r`n"
} else {
    foreach ($hf in $hiddenFiles) {
        $alertText += "  [ALTO] $($hf.FullName) (Tamanho: $($hf.Length), Mod: $($hf.LastWriteTime))`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- ALTERNATE DATA STREAMS ---`r`n`r`n"
if ($adsResults.Count -eq 0) {
    $alertText += "  [OK] Nenhum ADS suspeito foi encontrado.`r`n"
} else {
    foreach ($ads in $adsResults) {
        $alertText += "  [CRÍTICO] $($ads.Arquivo) -> Stream: $($ads.Stream) (Tamanho: $($ads.Tamanho))`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- ARQUIVOS SUSPEITOS NÃO-EFI NA ESP ---`r`n`r`n"
$nonEfiList = $suspiciousNonEfi | Where-Object { $_.Extension -ine ".efi" }
if ($nonEfiList.Count -eq 0) {
    $alertText += "  [OK] Nenhum arquivo suspeito não-EFI foi encontrado.`r`n"
} else {
    foreach ($nef in $nonEfiList) {
        $alertText += "  [MÉDIO] $($nef.FullName) ($($nef.Length) bytes, Mod: $($nef.LastWriteTime))`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- .EFI EM OUTROS VOLUMES ---`r`n`r`n"
if ($otherEfi.Count -eq 0) {
    $alertText += "  [OK] Nenhum .EFI foi encontrado fora da ESP.`r`n"
} else {
    foreach ($oe in $otherEfi) {
        $alertText += "  [MÉDIO] [$($oe.Volume):] $($oe.Arquivo) ($($oe.Tamanho) bytes)`r`n"
    }
}
$alertText += "`r`n"

$alertText += "--- VOLUMES FAT32 ---`r`n`r`n"
foreach ($v in $fat32Volumes) {
    $alertText += "  $($v.DriveLetter): $($v.FileSystemLabel) - $($v.TamanhoMB) MB (Livre: $($v.LivreMB) MB)`r`n"
}

$alertText += "`r`n==================================================================`r`n"
$alertText += "FIM DO RELATÓRIO - Este script é SOMENTE leitura.`r`n"
$alertText += "Não exclui, substitui nem modifica nenhum arquivo.`r`n"
$alertText += "Ferramenta feita por UNLUCKY.`r`n"
$alertText += "==================================================================`r`n"

$txtAlerts.Text = $alertText
$tab2.Controls.Add($txtAlerts)


$tab3 = New-Object System.Windows.Forms.TabPage
$tab3.Text = "Inventário ESP"
$tab3.BackColor = $darkBg
$tabControl.TabPages.Add($tab3)

$grid3 = New-StyledGrid
$tab3.Controls.Add($grid3)

$dt3 = New-Object System.Data.DataTable
$dt3.Columns.Add("Arquivo", [string]) | Out-Null
$dt3.Columns.Add("Caminho", [string]) | Out-Null
$dt3.Columns.Add("Extensão", [string]) | Out-Null
$dt3.Columns.Add("Tamanho", [int64]) | Out-Null
$dt3.Columns.Add("Modificado", [datetime]) | Out-Null
$dt3.Columns.Add("Atributos", [string]) | Out-Null

foreach ($f in $allFiles) {
    $r3 = $dt3.NewRow()
    $r3["Arquivo"] = $f.Name
    $r3["Caminho"] = $f.FullName
    $r3["Extensão"] = $f.Extension
    $r3["Tamanho"] = $f.Length
    $r3["Modificado"] = $f.LastWriteTime
    $r3["Atributos"] = $f.Attributes.ToString()
    $dt3.Rows.Add($r3)
}

$dv3 = New-Object System.Data.DataView($dt3)
$dv3.Sort = "Caminho ASC"
$grid3.DataSource = $dv3

$grid3.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalhes do Arquivo ESP"
})


$tab4 = New-Object System.Windows.Forms.TabPage
$tab4.Text = "Pastas ESP"
$tab4.BackColor = $darkBg
$tabControl.TabPages.Add($tab4)

$grid4 = New-StyledGrid
$tab4.Controls.Add($grid4)

$dt4 = New-Object System.Data.DataTable
$dt4.Columns.Add("Pasta", [string]) | Out-Null
$dt4.Columns.Add("Modificado", [datetime]) | Out-Null

foreach ($d in $allDirs) {
    $r4 = $dt4.NewRow()
    $r4["Pasta"] = $d.FullName
    $r4["Modificado"] = $d.LastWriteTime
    $dt4.Rows.Add($r4)
}

$dv4 = New-Object System.Data.DataView($dt4)
$grid4.DataSource = $dv4

$grid4.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalhes da Pasta ESP"
})


$tab5 = New-Object System.Windows.Forms.TabPage
$tab5.Text = "BCD / Config. de Boot"
$tab5.BackColor = $darkBg
$tabControl.TabPages.Add($tab5)

$splitBCD = New-Object System.Windows.Forms.SplitContainer
$splitBCD.Dock = "Fill"
$splitBCD.Orientation = "Vertical"
$splitBCD.SplitterDistance = 600
$splitBCD.BackColor = $darkBg
$tab5.Controls.Add($splitBCD)

$txtBCD = New-Object System.Windows.Forms.TextBox
$txtBCD.Multiline = $true
$txtBCD.ReadOnly = $true
$txtBCD.ScrollBars = "Both"
$txtBCD.Dock = "Fill"
$txtBCD.Font = $fontMono
$txtBCD.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$txtBCD.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 255)
$txtBCD.WordWrap = $false
$txtBCD.Text = "===== BCDEDIT /ENUM ALL =====`r`n`r`n$bcdOutput`r`n`r`n===== BCDEDIT /ENUM FIRMWARE =====`r`n`r`n$bcdFirmware"
$splitBCD.Panel1.Controls.Add($txtBCD)

$txtSecureBoot = New-Object System.Windows.Forms.TextBox
$txtSecureBoot.Multiline = $true
$txtSecureBoot.ReadOnly = $true
$txtSecureBoot.ScrollBars = "Both"
$txtSecureBoot.Dock = "Fill"
$txtSecureBoot.Font = $fontMono
$txtSecureBoot.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
$txtSecureBoot.ForeColor = [System.Drawing.Color]::FromArgb(200, 255, 200)
$txtSecureBoot.WordWrap = $false

$sbText = "===== SECURE BOOT =====`r`n`r`n"
$sbText += "Estado: $secureBootStatus`r`n"
$sbText += "Firmware: $firmwareType`r`n`r`n"
if ($tpmInfo) {
    $sbText += "===== TPM =====`r`n`r`n"
    $sbText += "Presente  : $($tpmInfo.TpmPresent)`r`n"
    $sbText += "Pronto    : $($tpmInfo.TpmReady)`r`n"
    $sbText += "Habilitado: $($tpmInfo.TpmEnabled)`r`n"
    $sbText += "Versão    : $($tpmInfo.ManufacturerVersion)`r`n`r`n"
}
$sbText += "===== SECURE BOOT DB/DBX =====`r`n`r`n"
if ([string]::IsNullOrEmpty($dbInfo)) {
    $sbText += "Não foi possível obter informações de DB/DBX.`r`n"
} else {
    $sbText += $dbInfo
}
$txtSecureBoot.Text = $sbText
$splitBCD.Panel2.Controls.Add($txtSecureBoot)

$tabBcdBin = New-Object System.Windows.Forms.TabPage
$tabBcdBin.Text = "Assinatura Binários BCD"
$tabBcdBin.BackColor = $darkBg
$tabControl.TabPages.Add($tabBcdBin)

$lblBcdBin = New-Object System.Windows.Forms.Label
$lblBcdBin.Text = "  Binários referenciados na configuração de boot (BCD) - Verificação de assinatura Authenticode"
$lblBcdBin.Dock = "Top"
$lblBcdBin.Height = 28
$lblBcdBin.Font = $fontBold
$lblBcdBin.ForeColor = $accentBlue
$lblBcdBin.BackColor = $panelBg
$lblBcdBin.Padding = New-Object System.Windows.Forms.Padding(10, 6, 0, 0)
$tabBcdBin.Controls.Add($lblBcdBin)

$gridBcdBin = New-StyledGrid
$tabBcdBin.Controls.Add($gridBcdBin)
$tabBcdBin.Controls.SetChildIndex($gridBcdBin, 0)

$dtBcdBin = New-Object System.Data.DataTable
$dtBcdBin.Columns.Add("Severidade", [string]) | Out-Null
$dtBcdBin.Columns.Add("Entrada", [string]) | Out-Null
$dtBcdBin.Columns.Add("Caminho BCD", [string]) | Out-Null
$dtBcdBin.Columns.Add("Caminho Real", [string]) | Out-Null
$dtBcdBin.Columns.Add("Tamanho", [int64]) | Out-Null
$dtBcdBin.Columns.Add("Assinatura", [string]) | Out-Null
$dtBcdBin.Columns.Add("Assinante", [string]) | Out-Null
$dtBcdBin.Columns.Add("SHA256", [string]) | Out-Null
$dtBcdBin.Columns.Add("Alertas", [string]) | Out-Null

foreach ($bb in $bcdBinaries) {
    $rBcd = $dtBcdBin.NewRow()
    $rBcd["Severidade"] = $bb.Severidade
    $rBcd["Entrada"] = $bb.Entrada
    $rBcd["Caminho BCD"] = $bb.CaminhoBCD
    $rBcd["Caminho Real"] = $bb.CaminhoResolvido
    $rBcd["Tamanho"] = $bb.Tamanho
    $rBcd["Assinatura"] = $bb.Assinatura
    $rBcd["Assinante"] = $bb.Assinante
    $rBcd["SHA256"] = $bb.SHA256
    $rBcd["Alertas"] = $bb.Alertas
    $dtBcdBin.Rows.Add($rBcd)
}

$gridBcdBin.DataSource = $dtBcdBin

$gridBcdBin.Add_CellFormatting({
    param($sender, $e)
    if ($e.RowIndex -ge 0 -and $sender.Columns[$e.ColumnIndex].Name -eq "Severidade") {
        $val = $sender.Rows[$e.RowIndex].Cells["Severidade"].Value
        $color = Get-SeverityColor $val
        $e.CellStyle.BackColor = $color
        $e.CellStyle.ForeColor = [System.Drawing.Color]::Black
    }
})

$gridBcdBin.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalhes do Binário BCD"
})


$tab6 = New-Object System.Windows.Forms.TabPage
$tab6.Text = "Eventos Boot/TPM"
$tab6.BackColor = $darkBg
$tabControl.TabPages.Add($tab6)

$splitEvents = New-Object System.Windows.Forms.SplitContainer
$splitEvents.Dock = "Fill"
$splitEvents.Orientation = "Horizontal"
$splitEvents.SplitterDistance = 250
$splitEvents.BackColor = $darkBg
$tab6.Controls.Add($splitEvents)

$lblBootEvt = New-Object System.Windows.Forms.Label
$lblBootEvt.Text = "Eventos Kernel-Boot (IDs 32, 33, 125) - Integridade de Boot e Secure Boot"
$lblBootEvt.Dock = "Top"
$lblBootEvt.Height = 25
$lblBootEvt.Font = $fontBold
$lblBootEvt.ForeColor = $accentBlue
$lblBootEvt.BackColor = $panelBg
$lblBootEvt.Padding = New-Object System.Windows.Forms.Padding(10, 4, 0, 0)
$splitEvents.Panel1.Controls.Add($lblBootEvt)

$grid6a = New-StyledGrid
$splitEvents.Panel1.Controls.Add($grid6a)
$splitEvents.Panel1.Controls.SetChildIndex($grid6a, 0)

$dt6a = New-Object System.Data.DataTable
$dt6a.Columns.Add("Data", [string]) | Out-Null
$dt6a.Columns.Add("EventID", [int32]) | Out-Null
$dt6a.Columns.Add("Tipo", [string]) | Out-Null
$dt6a.Columns.Add("Mensagem", [string]) | Out-Null

foreach ($be in $bootEvents) {
    $r6a = $dt6a.NewRow()
    $r6a["Data"] = $be.Data
    $r6a["EventID"] = $be.EventID
    $r6a["Tipo"] = $be.Tipo
    $r6a["Mensagem"] = $be.Mensagem
    $dt6a.Rows.Add($r6a)
}
$grid6a.DataSource = $dt6a

$grid6a.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalhes do Evento Kernel-Boot"
})

$lblTpmEvt = New-Object System.Windows.Forms.Label
$lblTpmEvt.Text = "Eventos TPM e Measured Boot - Cadeia de Confiança"
$lblTpmEvt.Dock = "Top"
$lblTpmEvt.Height = 25
$lblTpmEvt.Font = $fontBold
$lblTpmEvt.ForeColor = $accentBlue
$lblTpmEvt.BackColor = $panelBg
$lblTpmEvt.Padding = New-Object System.Windows.Forms.Padding(10, 4, 0, 0)
$splitEvents.Panel2.Controls.Add($lblTpmEvt)

$grid6b = New-StyledGrid
$splitEvents.Panel2.Controls.Add($grid6b)
$splitEvents.Panel2.Controls.SetChildIndex($grid6b, 0)

$dt6b = New-Object System.Data.DataTable
$dt6b.Columns.Add("Data", [string]) | Out-Null
$dt6b.Columns.Add("EventID", [int32]) | Out-Null
$dt6b.Columns.Add("Origem", [string]) | Out-Null
$dt6b.Columns.Add("Nivel", [string]) | Out-Null
$dt6b.Columns.Add("Mensagem", [string]) | Out-Null

$allTpmMb = @()
$allTpmMb += $tpmEvents | ForEach-Object {
    [PSCustomObject]@{ Data=$_.Data; EventID=$_.EventID; Origem="TPM-WMI"; Nivel=$_.Nivel; Mensagem=$_.Mensagem }
}
$allTpmMb += $measuredBootEvents | ForEach-Object {
    [PSCustomObject]@{ Data=$_.Data; EventID=$_.EventID; Origem=$_.Origem; Nivel=$_.Nivel; Mensagem=$_.Mensagem }
}

foreach ($tm in $allTpmMb) {
    $r6b = $dt6b.NewRow()
    $r6b["Data"] = $tm.Data
    $r6b["EventID"] = $tm.EventID
    $r6b["Origem"] = $tm.Origem
    $r6b["Nivel"] = $tm.Nivel
    $r6b["Mensagem"] = $tm.Mensagem
    $dt6b.Rows.Add($r6b)
}
$grid6b.DataSource = $dt6b

$grid6b.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalhes do Evento TPM / Measured Boot"
})


$tab7 = New-Object System.Windows.Forms.TabPage
$tab7.Text = "EFI Outros Vol."
$tab7.BackColor = $darkBg
$tabControl.TabPages.Add($tab7)

$grid7 = New-StyledGrid
$tab7.Controls.Add($grid7)

$dt7 = New-Object System.Data.DataTable
$dt7.Columns.Add("Volume", [string]) | Out-Null
$dt7.Columns.Add("Arquivo", [string]) | Out-Null
$dt7.Columns.Add("Tamanho", [int64]) | Out-Null
$dt7.Columns.Add("Modificado", [datetime]) | Out-Null
$dt7.Columns.Add("Assinatura", [string]) | Out-Null

foreach ($oe in $otherEfi) {
    $r7 = $dt7.NewRow()
    $r7["Volume"] = $oe.Volume
    $r7["Arquivo"] = $oe.Arquivo
    $r7["Tamanho"] = $oe.Tamanho
    $r7["Modificado"] = $oe.Modificado
    $r7["Assinatura"] = $oe.Assinatura
    $dt7.Rows.Add($r7)
}
$grid7.DataSource = $dt7

$grid7.Add_CellFormatting({
    param($sender, $e)
    if ($e.RowIndex -ge 0 -and $sender.Columns[$e.ColumnIndex].Name -eq "Assinatura") {
        $val = $sender.Rows[$e.RowIndex].Cells["Assinatura"].Value
        if ($val -eq "True") {
            $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(220, 255, 220)
            $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(0, 100, 0)
        } elseif ($val -eq "False") {
            $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 220, 220)
            $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb(180, 0, 0)
        }
    }
})

$grid7.Add_CellDoubleClick({
    param($sender, $e)
    Show-RowDetail -Grid $sender -RowIndex $e.RowIndex -Title "Detalhes do EFI em Outro Volume"
})


$form.Add_Load({
    if ($grid1.Columns.Count -gt 0) {
        $grid1.Columns["Severidade"].FillWeight = 8
        $grid1.Columns["Arquivo"].FillWeight = 12
        $grid1.Columns["Caminho"].FillWeight = 15
        $grid1.Columns["Tamanho"].FillWeight = 7
        $grid1.Columns["Modificado"].FillWeight = 12
        $grid1.Columns["Modificado"].DefaultCellStyle.Format = "yyyy-MM-dd HH:mm"
        $grid1.Columns["Assinatura"].FillWeight = 8
        $grid1.Columns["Assinante"].FillWeight = 13
        $grid1.Columns["Entropia"].FillWeight = 7
        $grid1.Columns["SHA256"].FillWeight = 10
        $grid1.Columns["Alertas"].FillWeight = 20
    }
})

[void]$form.ShowDialog()

Write-Host "`n[*] Desmontando a partição EFI..." -ForegroundColor Yellow
mountvol S: /d 2>$null
Write-Host "[OK] Partição EFI desmontada." -ForegroundColor Green
Write-Host "[*] Análise finalizada. Ferramenta feita por UNLUCKY." -ForegroundColor Cyan
