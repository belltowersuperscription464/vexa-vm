[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $Binary,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $SecretFile,

    [string] $ChannelPath = '\\.\Global\com.vexa.guest_tools.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Installer must run from an elevated PowerShell session.'
}

$serviceName = 'VexaGuestTools'
$installDirectory = Join-Path $env:ProgramFiles 'Vexa\GuestTools'
$dataDirectory = Join-Path $env:ProgramData 'Vexa\GuestTools'
$installedBinary = Join-Path $installDirectory 'vexa-guest-tools.exe'
$installedSecret = Join-Path $dataDirectory 'secret'
$configurationPath = Join-Path $dataDirectory 'config.json'
$scExecutable = Join-Path $env:WINDIR 'System32\sc.exe'
$installId = [Guid]::NewGuid().ToString('N')
$stagedBinary = Join-Path $installDirectory "vexa-guest-tools.$installId.tmp"
$stagedSecret = Join-Path $dataDirectory "secret.$installId.tmp"
$stagedConfiguration = Join-Path $dataDirectory "config.$installId.tmp"
$systemDirectoryAccess = '*S-1-5-18:(OI)(CI)(F)'
$administratorsDirectoryAccess = '*S-1-5-32-544:(OI)(CI)(F)'
$systemFileAccess = '*S-1-5-18:(F)'
$administratorsFileAccess = '*S-1-5-32-544:(F)'
$backupFiles = @{}
$published = $false
$newServiceCreated = $false
$installationSucceeded = $false
$rollbackSucceeded = $false
$sshdConfiguration = Join-Path $env:ProgramData 'ssh\sshd_config'
$sshdBackup = "$sshdConfiguration.$installId.bak"
$sshdChanged = $false
$sshdWasRunning = $false

function Invoke-ScChecked {
    param(
        [Parameter(Mandatory = $true)] [string[]] $Arguments,
        [Parameter(Mandatory = $true)] [string] $FailureMessage
    )
    & $script:scExecutable @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw $FailureMessage }
}

function Wait-VexaService {
    param(
        [Parameter(Mandatory = $true)]
        [System.ServiceProcess.ServiceControllerStatus] $State,
        [int] $Seconds = 30
    )
    $service = Get-Service -Name $script:serviceName -ErrorAction Stop
    $service.WaitForStatus($State, [TimeSpan]::FromSeconds($Seconds))
    $service.Refresh()
    if ($service.Status -ne $State) {
        throw "VexaGuestTools did not reach the expected $State state."
    }
}

function Protect-VexaFile {
    param([Parameter(Mandatory = $true)] [string] $Path)
    & icacls.exe $Path '/inheritance:r' '/grant:r' $script:systemFileAccess '/grant:r' $script:administratorsFileAccess | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to protect $Path." }
}

New-Item -ItemType Directory -Force -Path $installDirectory, $dataDirectory | Out-Null

# Protect ProgramData before placing either the per-VM secret or configuration inside it. Well-known
# SID strings keep this locale independent on non-English Windows editions.
& icacls.exe $dataDirectory '/inheritance:r' '/grant:r' $systemDirectoryAccess '/grant:r' $administratorsDirectoryAccess | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Failed to protect the guest-tools data directory.' }

$configuration = @{
    channel_path = $ChannelPath
    secret_file = $installedSecret
    max_clock_skew_seconds = 120
    replay_cache_capacity = 4096
    reconnect_delay_seconds = 2
    policy = @{
        password = $true
        hostname = $true
        dns = $true
        network = $true
        ssh_keys = $true
        power = $true
        allowed_users = @()
    }
}

try {
    # Stage the complete replacement while the old service is still available. Publication occurs
    # only after Service Control Manager confirms the old process has stopped.
    Copy-Item -LiteralPath $Binary -Destination $stagedBinary -Force
    Copy-Item -LiteralPath $SecretFile -Destination $stagedSecret -Force
    $utf8WithoutBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText(
        $stagedConfiguration,
        ($configuration | ConvertTo-Json -Depth 4 -Compress),
        $utf8WithoutBom
    )
    Protect-VexaFile -Path $stagedSecret
    Protect-VexaFile -Path $stagedConfiguration

    # Keep Vexa-managed keys outside user-writable profiles. Add the protected per-user key path
    # before each active AuthorizedKeysFile value, including the Administrators match block.
    $sshdExecutable = Join-Path $env:WINDIR 'System32\OpenSSH\sshd.exe'
    if ((Test-Path -LiteralPath $sshdConfiguration -PathType Leaf) -and (Test-Path -LiteralPath $sshdExecutable -PathType Leaf)) {
        $sshdText = [IO.File]::ReadAllText($sshdConfiguration)
        $vexaKeyPath = '__PROGRAMDATA__/Vexa/GuestTools/authorized_keys/%u'
        $pattern = '(?im)^(\s*AuthorizedKeysFile\s+)(?![^\r\n]*Vexa/GuestTools)([^\r\n]+)$'
        $updatedSshdText = [Text.RegularExpressions.Regex]::Replace(
            $sshdText,
            $pattern,
            { param($match) $match.Groups[1].Value + $vexaKeyPath + ' ' + $match.Groups[2].Value }
        )
        if ($updatedSshdText -eq $sshdText -and $sshdText -notmatch 'Vexa/GuestTools') {
            $updatedSshdText = "AuthorizedKeysFile $vexaKeyPath .ssh/authorized_keys`r`n" + $sshdText
        }
        if ($updatedSshdText -ne $sshdText) {
            Copy-Item -LiteralPath $sshdConfiguration -Destination $sshdBackup -Force
            $sshdChanged = $true
            [IO.File]::WriteAllText($sshdConfiguration, $updatedSshdText, $utf8WithoutBom)

            & $sshdExecutable -t -f $sshdConfiguration
            if ($LASTEXITCODE -ne 0) {
                throw 'OpenSSH rejected the Vexa authorized-keys configuration.'
            }
            $sshdService = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
            $sshdWasRunning = $null -ne $sshdService -and $sshdService.Status -eq 'Running'
            if ($sshdWasRunning) {
                Restart-Service -Name 'sshd'
                $sshdService.WaitForStatus(
                    [System.ServiceProcess.ServiceControllerStatus]::Running,
                    [TimeSpan]::FromSeconds(30)
                )
            }
        }
    }

    $existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($null -ne $existing -and $existing.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        Wait-VexaService -State ([System.ServiceProcess.ServiceControllerStatus]::Stopped)
    }

    foreach ($destination in @($installedBinary, $installedSecret, $configurationPath)) {
        if (Test-Path -LiteralPath $destination -PathType Leaf) {
            $backup = "$destination.$installId.bak"
            Copy-Item -LiteralPath $destination -Destination $backup -Force
            $backupFiles[$destination] = $backup
        }
    }

    $published = $true
    Copy-Item -LiteralPath $stagedBinary -Destination $installedBinary -Force
    Copy-Item -LiteralPath $stagedSecret -Destination $installedSecret -Force
    Copy-Item -LiteralPath $stagedConfiguration -Destination $configurationPath -Force
    Protect-VexaFile -Path $installedSecret
    Protect-VexaFile -Path $configurationPath

    $serviceCommand = '"{0}" --service --config "{1}"' -f $installedBinary, $configurationPath
    if ($null -eq $existing) {
        New-Service -Name $serviceName -BinaryPathName $serviceCommand -DisplayName 'Vexa Guest Tools' -Description 'Authenticated Vexa host integration over virtio-serial.' -StartupType Automatic | Out-Null
        $newServiceCreated = $true
    } else {
        Invoke-ScChecked -Arguments @('config', $serviceName, 'binPath=', $serviceCommand, 'start=', 'delayed-auto', 'DisplayName=', 'Vexa Guest Tools') -FailureMessage 'Failed to update the VexaGuestTools service configuration.'
    }

    Invoke-ScChecked -Arguments @('config', $serviceName, 'start=', 'delayed-auto') -FailureMessage 'Failed to configure delayed automatic service start.'
    Invoke-ScChecked -Arguments @('description', $serviceName, 'Authenticated Vexa host integration over virtio-serial.') -FailureMessage 'Failed to set the VexaGuestTools service description.'
    Invoke-ScChecked -Arguments @('failure', $serviceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/60000') -FailureMessage 'Failed to configure VexaGuestTools recovery actions.'
    Invoke-ScChecked -Arguments @('failureflag', $serviceName, '1') -FailureMessage 'Failed to enable VexaGuestTools recovery for non-crash failures.'

    Start-Service -Name $serviceName
    Wait-VexaService -State ([System.ServiceProcess.ServiceControllerStatus]::Running)
    Start-Sleep -Seconds 2
    $startedService = Get-Service -Name $serviceName
    if ($startedService.Status -ne 'Running') {
        throw 'VexaGuestTools exited during its post-start health window.'
    }
    $installationSucceeded = $true
} catch {
    $installError = $_
    if ($sshdChanged -and (Test-Path -LiteralPath $sshdBackup -PathType Leaf)) {
        Copy-Item -LiteralPath $sshdBackup -Destination $sshdConfiguration -Force
        if ($sshdWasRunning) {
            Restart-Service -Name 'sshd'
            (Get-Service -Name 'sshd' -ErrorAction Stop).WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Running,
                [TimeSpan]::FromSeconds(30)
            )
        }
        $sshdChanged = $false
    }
    if ($published) {
        $currentService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $currentService -and $currentService.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -Force
            Wait-VexaService -State ([System.ServiceProcess.ServiceControllerStatus]::Stopped) -Seconds 15
        }

        foreach ($destination in @($installedBinary, $installedSecret, $configurationPath)) {
            if ($backupFiles.ContainsKey($destination)) {
                Copy-Item -LiteralPath $backupFiles[$destination] -Destination $destination -Force
            } else {
                Remove-Item -LiteralPath $destination -Force -ErrorAction SilentlyContinue
            }
        }
        if (Test-Path -LiteralPath $installedSecret -PathType Leaf) {
            Protect-VexaFile -Path $installedSecret
        }
        if (Test-Path -LiteralPath $configurationPath -PathType Leaf) {
            Protect-VexaFile -Path $configurationPath
        }

        if ($newServiceCreated) {
            & $scExecutable delete $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Failed to remove the unsuccessful VexaGuestTools service.' }
        } elseif ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
            Start-Service -Name $serviceName
            Wait-VexaService -State ([System.ServiceProcess.ServiceControllerStatus]::Running) -Seconds 15
        }
    }
    $rollbackSucceeded = $true
    throw $installError
} finally {
    foreach ($path in @($stagedBinary, $stagedSecret, $stagedConfiguration)) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
    if ($installationSucceeded -or $rollbackSucceeded) {
        foreach ($backup in $backupFiles.Values) {
            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $sshdBackup -Force -ErrorAction SilentlyContinue
    }
}
