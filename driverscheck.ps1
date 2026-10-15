# ==================================================
#   VERIFICAÇÃO DE DRIVERS - Auditoria de Drivers / LOLDrivers
#   Autor / Author: UNLUCKY
#   Feito por UNLUCKY - Todos os créditos para UNLUCKY
# ==================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "            FEITO POR: UNLUCKY                    " -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "[*] Conectando ao banco de dados do LOLDrivers..." -ForegroundColor Cyan
try {
    $lolData = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers.json" -UseBasicParsing -TimeoutSec 15
    $vulnerableHashes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $lolData) {
        if ($d.KnownVulnerableSamples) {
            foreach ($sample in $d.KnownVulnerableSamples) {
                if ($sample.SHA256) { [void]$vulnerableHashes.Add($sample.SHA256) }
            }
        }
    }
    Write-Host "[+] Banco de dados carregado: $($vulnerableHashes.Count) hashes vulneráveis." -ForegroundColor Green
} catch {
    Write-Warning "[-] Não foi possível conectar ao LOLDrivers. Serão verificadas apenas assinaturas e certificados."
    $vulnerableHashes = $null
}

Write-Host "[*] Escaneando drivers em System32\drivers..." -ForegroundColor Cyan

$driverFiles = Get-ChildItem -Path "C:\Windows\System32\drivers" -Filter *.sys -ErrorAction SilentlyContinue

$results = [System.Collections.ArrayList]::new()
foreach ($file in $driverFiles) {
    $sig = Get-AuthenticodeSignature $file.FullName
    $cert = $sig.SignerCertificate
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
    
    $isExpired = $false
    $expireDate = $null
    if ($cert) {
        $expireDate = $cert.NotAfter.ToString("dd/MM/yyyy HH:mm:ss")
        if ($cert.NotAfter -lt (Get-Date)) {
            $isExpired = $true
        }
    }

    $isVulnerable = $false
    if ($vulnerableHashes -and $vulnerableHashes.Contains($hash)) {
        $isVulnerable = $true
    }

    $obj = [PSCustomObject]@{
        Driver           = $file.Name
        AssinaturaValida = ($sig.Status -eq 'Valid')
        CertExpirado     = $isExpired
        DataExpiracao    = $expireDate
        VulneravelBYOVD  = $isVulnerable
        Assinante        = if ($cert) { $cert.Subject.Split(',')[0].Replace('CN=', '').Trim() } else { "Sem assinatura" }
        Caminho          = $file.FullName
    }
    [void]$results.Add($obj)
}

# Cria a interface gráfica WPF com cópia automática ao clicar com o botão esquerdo
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Auditoria de Drivers - by UNLUCKY - Clique com o botão esquerdo em uma linha para copiar o caminho" Height="700" Width="1250" WindowStartupLocation="CenterScreen">
    <Grid Margin="10">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        
        <DockPanel Grid.Row="0" Margin="0,0,0,10">
            <TextBlock DockPanel.Dock="Right" Text="Feito por UNLUCKY" VerticalAlignment="Center" Margin="10,0,0,0" FontWeight="Bold" Foreground="DarkMagenta"/>
            <TextBlock Text="Pesquisar:" VerticalAlignment="Center" Margin="0,0,10,0" FontWeight="Bold"/>
            <TextBox Name="txtSearch" Height="26" VerticalContentAlignment="Center" Padding="4,0,0,0"/>
        </DockPanel>

        <DataGrid Grid.Row="1" Name="gridDrivers" AutoGenerateColumns="True" IsReadOnly="True" 
                  SelectionMode="Single" HeadersVisibility="Column" GridLinesVisibility="All" AlternatingRowBackground="#F0F0F0"
                  CanUserSortColumns="True"/>

        <Border Grid.Row="2" Background="#E8E8E8" Padding="6" Margin="0,8,0,0" CornerRadius="4">
            <TextBlock Name="lblStatus" Text="Clique com o botão esquerdo em qualquer driver para copiar o caminho para a área de transferência." 
                       FontWeight="SemiBold" Foreground="#333333"/>
        </Border>
    </Grid>
</Window>
"@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [System.Windows.Markup.XamlReader]::Load($reader)

$gridDrivers = $window.FindName("gridDrivers")
$txtSearch = $window.FindName("txtSearch")
$lblStatus = $window.FindName("lblStatus")

$gridDrivers.ItemsSource = $results

# Evento: clique esquerdo seleciona e copia o caminho
$gridDrivers.add_SelectionChanged({
    $selected = $gridDrivers.SelectedItem
    if ($selected -and $selected.Caminho) {
        [System.Windows.Clipboard]::SetText($selected.Caminho)
        $lblStatus.Text = "[COPIADO PARA A ÁREA DE TRANSFERÊNCIA] " + $selected.Caminho
        $lblStatus.Foreground = [System.Windows.Media.Brushes]::DarkGreen
    }
})

# Filtro em tempo real ao digitar na barra de pesquisa
$txtSearch.add_TextChanged({
    $filter = $txtSearch.Text.Trim().ToLower()
    if ([string]::IsNullOrEmpty($filter)) {
        $gridDrivers.ItemsSource = $results
    } else {
        $filtered = $results | Where-Object {
            $_.Driver.ToLower().Contains($filter) -or
            $_.Assinante.ToLower().Contains($filter) -or
            $_.Caminho.ToLower().Contains($filter) -or
            $_.VulneravelBYOVD.ToString().ToLower().Contains($filter)
        }
        $gridDrivers.ItemsSource = @($filtered)
    }
})

$window.ShowDialog() | Out-Null
