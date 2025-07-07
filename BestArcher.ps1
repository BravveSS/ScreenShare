$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {
    [CmdletBinding()]
    param (
        [string[]]$FilePath
    )

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    $Signature = "Invalid Signature (UnknownError)"

    if ($Existence) {
        switch ($Authenticode) {
            "Valid" { $Signature = "Firma Valida" }
            "NotSigned" { $Signature = "Firma Invalida (No esta firmado)" }
            "HashMismatch" { $Signature = "Firma Invalida (HashMismatch)" }
            "NotTrusted" { $Signature = "Firma Invalida (NotTrusted)" }
            "UnknownError" { $Signature = "Firma Invalida (UnknownError)" }
        }
        return $Signature
    } else {
        return "El archivo no fue encontrado"
    }
}

Clear-Host

Write-Host ""
Write-Host ""
Write-Host -ForegroundColor Red " Tranquilo joven usuario, estas en manos de los expertos. "
Write-Host ""

# ASCII ART (CORREGIDO)
Write-Host -ForegroundColor Magenta " // +=============================================================+"
Write-Host -ForegroundColor Magenta " // | ____                                 __                     |"
Write-Host -ForegroundColor Magenta " // || __ ) _ __ __ ___   ___   _____     / /                     |"
Write-Host -ForegroundColor Magenta " // ||  _ \| '__/ _` \ \ / \ \ / / _ \   / /                      |"
Write-Host -ForegroundColor Magenta " // || |_) | | | (_| |\ V / \ V |  __/  / /                       |"
Write-Host -ForegroundColor Magenta " // ||____/|_|  \__,_| \_/   \_/ \___| /_/                        |"
Write-Host -ForegroundColor Magenta " // | ____           _      _             _                       |"
Write-Host -ForegroundColor Magenta " // || __ )  ___ ___| |_   / \   _ __ ___| |__   ___ _ __         |"
Write-Host -ForegroundColor Magenta " // ||  _ \ / _ / __| __| / _ \ | '__/ __| '_ \ / _ | '__|        |"
Write-Host -ForegroundColor Magenta " // || |_) |  __\__ \ |_ / ___ \| | | (__| | | |  __| |           |"
Write-Host -ForegroundColor Magenta " // ||____/ \___|___/\__/_/   \_|_|  \___|_| |_|\___|_|     _____ |"
Write-Host -ForegroundColor Magenta " // |                                                      |_____||"
Write-Host -ForegroundColor Magenta " // +=============================================================+"

Write-Host ""
Write-Host -ForegroundColor Cyan "Juro que voy a respetar esta SS Tool creada por BestArcher_, te agradezco por pasarla."
Write-Host ""
Write-Host -ForegroundColor DarkGreen " https://discord.gg/3HCKYGwF24 "
Write-Host ""
Write-Host ""

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "Brother ejecutalo como ADMIN :V"
    Start-Sleep 10
    Exit
}

$sw = [Diagnostics.Stopwatch]::StartNew()

if (-not (Get-PSDrive -Name HKLM -PSProvider Registry)) {
    try {
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
    } catch {
        Write-Warning "Error montando HKEY_Local_Machine"
    }
}

$bv = @("bam", "bam\State")

try {
    $Users = foreach ($ii in $bv) {
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ii\UserSettings\" | Select-Object -ExpandProperty PSChildName
    }
} catch {
    Write-Warning "Error Parseando BAM Key. Probablemente no soporta tu version de Windows :( "
    Exit
}

$rpath = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\",
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\"
)

$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias

$Bam = foreach ($Sid in $Users) {
    foreach ($rp in $rpath) {
        $BamItems = Get-Item -Path "$rp\UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        Write-Host -ForegroundColor DarkRed "Extrayendo " -NoNewLine
        Write-Host -ForegroundColor White "$rp\UserSettings\$Sid"

        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $User = ""
        }

        foreach ($Item in $BamItems) {
            $Key = Get-ItemProperty -Path "$rp\UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item
            if ($Key.Length -eq 24) {
                $Hex = [System.BitConverter]::ToString($Key[7..0]) -replace "-", ""
                $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                $Day = -([convert]::ToInt32([Convert]::ToString($UserDay,2),2))
                $TimeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).AddMinutes($Bias) -Format "yyyy-MM-dd HH:mm:ss")

                $d = if ((Split-Path -Path $Item | ConvertFrom-String -Delimiter "\\").P3 -match '\d{1}') {
                    (Split-Path -Path $Item).Remove(23).TrimStart("\Device\HarddiskVolume")
                } else { "" }

                $f = if ((Split-Path -Path $Item | ConvertFrom-String -Delimiter "\\").P3 -match '\d{1}') {
                    Split-Path -Leaf ($Item.TrimStart())
                } else { $Item }

                $cp = if ((Split-Path -Path $Item | ConvertFrom-String -Delimiter "\\").P3 -match '\d{1}') {
                    $Item.Remove(1,23)
                } else { "" }

                $path = if ((Split-Path -Path $Item | ConvertFrom-String -Delimiter "\\").P3 -match '\d{1}') {
                    Join-Path -Path "C:" -ChildPath $cp
                } else { "" }

                $sig = if ((Split-Path -Path $Item | ConvertFrom-String -Delimiter "\\").P3 -match '\d{1}') {
                    Get-Signature -FilePath $path
                } else { "" }

                [PSCustomObject]@{
                    'Tiempo del examinador' = $TimeLocal
                    'Tiempo de ultima ejecucion (UTC)' = $TimeUTC
                    'Tiempo de ultima ejecucion (Hora del usuario)' = $TimeUser
                    Application = $f
                    Path = $path
                    Signature = $sig
                    User = $User
                    SID = $Sid
                    Regpath = $rp
                }
            }
        }
    }
}

$Bam | Out-GridView -PassThru -Title "Entradas BAM: $($Bam.Count)  - Zona Horaria del Usuario: ($UserTime) -> ActiveBias: ( $Bias) - DayLightTime: ($Day)"

$sw.Stop()
$t = $sw.Elapsed.TotalMinutes
Write-Host ""
Write-Host "Se tardo $t Minutos" -ForegroundColor Yellow
