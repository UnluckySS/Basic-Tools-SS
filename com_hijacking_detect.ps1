# ==================================================
#   AUDITOR DE COM HIJACKING E ASSINATURA DE BINÁRIOS
#   Autor / Author: UNLUCKY
#   Feito por UNLUCKY - Todos os créditos para UNLUCKY
# ==================================================

$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║     PRIVILÉGIOS DE ADMINISTRADOR NECESSÁRIOS      ║" -ForegroundColor Red
    Write-Host "║   Execute este script como Administrador!         ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
    exit
}

Clear-Host
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "            FEITO POR: UNLUCKY                    " -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "`nAUDITOR DE COM HIJACKING E ASSINATURA DE BINÁRIOS - by UNLUCKY" -ForegroundColor Cyan

$registryPaths = @(
    "Registry::HKEY_CURRENT_USER\Software\Classes\CLSID",
    "Registry::HKEY_LOCAL_MACHINE\Software\Classes\CLSID"
)

$suspiciousItems = [System.Collections.Generic.List[PSObject]]::new()
$validComExts = @(".dll", ".ocx", ".ax", ".cpl")

Write-Host "`n[*] Inspecionando entradas InprocServer32..." -ForegroundColor Gray

# Função auxiliar para verificar o cabeçalho executável PE (MZ)
function Test-IsPEHeader {
    param([string]$FilePath)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
            return $true # Cabeçalho 'MZ' detectado
        }
    } catch {}
    return $false
}

foreach ($regPath in $registryPaths) {
    if (-not (Test-Path $regPath)) { continue }

    Get-ChildItem -Path $regPath -Recurse -Depth 2 -ErrorAction SilentlyContinue | 
        Where-Object { $_.PSChildName -eq "InprocServer32" } | ForEach-Object {
            
            $key = $_
            $defaultVal = (Get-ItemProperty -LiteralPath $key.PSPath -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
            if ([string]::IsNullOrWhiteSpace($defaultVal)) { return }

            $expandedPath = [System.Environment]::ExpandEnvironmentVariables($defaultVal).Trim('"')
            $clsid = $key.PSParentPath.Split('\')[-1]
            $ext = [System.IO.Path]::GetExtension($expandedPath).ToLower()
            $isHkcu = $key.PSPath -match "HKEY_CURRENT_USER"

            # 1. Arquivo referenciado inexistente
            if (-not (Test-Path -LiteralPath $expandedPath)) {
                if ($isHkcu -or $expandedPath -match 'AppData|Temp|Downloads|Globalization') {
                    $suspiciousItems.Add([PSCustomObject]@{
                        CLSID   = $clsid
                        Path    = $expandedPath
                        Status  = "ArquivoAusente"
                        Reason  = "Payload referenciado não encontrado (Phantom Hijack / resíduo de limpeza)"
                        Signer  = "N/D"
                        Level   = "Médio"
                    })
                }
                return
            }

            # 2. Análise do cabeçalho bruto (caça a camuflagem .nls / .dat / .bin)
            $isPeBinary = Test-IsPEHeader -FilePath $expandedPath

            # 3. Análise da assinatura digital
            $sig = Get-AuthenticodeSignature -LiteralPath $expandedPath -ErrorAction SilentlyContinue
            $sigStatus = if ($sig) { $sig.Status.ToString() } else { "NotSigned" }
            $signer = if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "Nenhum" }

            $reasons = @()
            $threatLevel = "Baixo"

            # DELATOR DEFINITIVO: extensão não executável, mas com cabeçalho MZ real
            if ($ext -notin $validComExts -and $isPeBinary) {
                $reasons += "EXECUTÁVEL DISFARÇADO (cabeçalho PE/MZ em .$ext)"
                $threatLevel = "Crítico"
            } elseif ($ext -notin $validComExts) {
                $reasons += "Extensão disfarçada ($ext)"
                $threatLevel = "Alto"
            }

            # Caminhos suspeitos ou de usuário
            if ($expandedPath -match 'AppData|Temp|Users\\Public|Downloads|Globalization\\Sorting') {
                $reasons += "Diretório gravável pelo usuário ou anormal"
                if ($threatLevel -ne "Crítico") { $threatLevel = "Alto" }
            }

            # Chave registrada no HKCU
            if ($isHkcu) {
                $reasons += "Substituição no HKCU (usuário)"
                if ($threatLevel -eq "Baixo") { $threatLevel = "Médio" }
            }

            # Assinatura alterada ou corrompida
            if ($sigStatus -ne "Valid" -and $sigStatus -ne "NotSigned") {
                $reasons += "Assinatura adulterada/corrompida ($sigStatus)"
                $threatLevel = "Crítico"
            }

            # Binário não assinado
            if ($sigStatus -eq "NotSigned") {
                $reasons += "Binário não assinado"
                if ($threatLevel -eq "Baixo") { $threatLevel = "Alto" }
            } elseif ($expandedPath -match "System32" -and $signer -notmatch "Microsoft") {
                $reasons += "Assinado por terceiros no System32"
                if ($threatLevel -eq "Baixo") { $threatLevel = "Médio" }
            }

            if ($reasons.Count -gt 0) {
                $suspiciousItems.Add([PSCustomObject]@{
                    CLSID   = $clsid
                    Path    = $expandedPath
                    Status  = $sigStatus
                    Reason  = ($reasons -join " | ")
                    Signer  = $signer
                    Level   = $threatLevel
                })
            }
    }
}

if ($suspiciousItems.Count -eq 0) {
    Write-Host "`n[+] Nenhum registro COM suspeito ou binário não confiável encontrado." -ForegroundColor Green
} else {
    Write-Host ("`n[!] MÓDULOS COM SUSPEITOS / NÃO CONFIÁVEIS ENCONTRADOS ({0})" -f $suspiciousItems.Count) -ForegroundColor Red
    Write-Host "----------------------------------------------------------------------"

    foreach ($item in $suspiciousItems) {
        $color = switch ($item.Level) {
            "Crítico" { "Red" }
            "Alto"    { "Yellow" }
            "Médio"   { "Cyan" }
            Default   { "White" }
        }

        Write-Host ("`n[{0}] CLSID: {1}" -f $item.Level.ToUpper(), $item.CLSID) -ForegroundColor $color
        Write-Host ("      Caminho:    {0}" -f $item.Path) -ForegroundColor White
        Write-Host ("      Motivo:     {0}" -f $item.Reason) -ForegroundColor Gray
        Write-Host ("      Status: {0} | Assinante: {1}" -f $item.Status, $item.Signer) -ForegroundColor DarkGray
    }
}

Write-Host "`nAuditoria concluída. Ferramenta feita por UNLUCKY." -ForegroundColor Cyan
