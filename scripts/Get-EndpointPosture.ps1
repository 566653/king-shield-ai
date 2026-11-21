# Read-only Windows endpoint security posture. No settings are changed.
$ErrorActionPreference = 'Stop'
$checks = [ordered]@{}
function Add-Check($Name, $Status, $Detail) {
    $checks[$Name] = [ordered]@{status=$Status; detail=$Detail}
}
try {
    $def = Get-MpComputerStatus -ErrorAction Stop
    Add-Check 'defender_realtime' $(if ($def.RealTimeProtectionEnabled) {'pass'} else {'fail'}) 'Microsoft Defender real-time protection'
    Add-Check 'defender_antivirus' $(if ($def.AntivirusEnabled) {'pass'} else {'fail'}) 'Microsoft Defender antivirus'
    $age = if ($def.AntivirusSignatureLastUpdated) { [int]((Get-Date) - $def.AntivirusSignatureLastUpdated).TotalDays } else { 999 }
    Add-Check 'defender_signatures' $(if ($age -le 7) {'pass'} else {'warn'}) "Signature age (days): $age"
} catch {
    Add-Check 'defender_realtime' 'unknown' 'Defender status unavailable (third-party antivirus or restricted access)'
    Add-Check 'defender_antivirus' 'unknown' 'Defender status unavailable'
    Add-Check 'defender_signatures' 'unknown' 'Signature status unavailable'
}
try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $disabled = @($profiles | Where-Object { -not $_.Enabled })
    Add-Check 'firewall' $(if ($disabled.Count -eq 0) {'pass'} else {'fail'}) $(if ($disabled.Count -eq 0) {'All Windows Firewall profiles enabled'} else {'One or more Windows Firewall profiles disabled'})
} catch { Add-Check 'firewall' 'unknown' 'Firewall status unavailable' }
try {
    $rdp = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
    Add-Check 'remote_desktop' $(if ($rdp -eq 1) {'pass'} else {'warn'}) $(if ($rdp -eq 1) {'Remote Desktop connections disabled'} else {'Remote Desktop enabled: verify authorization and network restrictions'})
} catch { Add-Check 'remote_desktop' 'unknown' 'Remote Desktop setting unavailable' }
try {
    $assist = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -ErrorAction Stop).fAllowToGetHelp
    Add-Check 'remote_assistance' $(if ($assist -eq 0) {'pass'} else {'warn'}) $(if ($assist -eq 0) {'Remote Assistance disabled'} else {'Remote Assistance enabled: review if needed'})
} catch { Add-Check 'remote_assistance' 'unknown' 'Remote Assistance setting unavailable' }
try {
    $loc = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name Value -ErrorAction Stop
    Add-Check 'location_consent' $(if ($loc.Value -eq 'Deny') {'pass'} else {'warn'}) "Machine location consent: $($loc.Value); per-user and application settings may differ"
} catch { Add-Check 'location_consent' 'unknown' 'Machine location consent unavailable; review Windows Privacy > Location' }
try {
    $system = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $bootAge = [int]((Get-Date) - $system.LastBootUpTime).TotalDays
    Add-Check 'restart_age' $(if ($bootAge -le 30) {'pass'} else {'warn'}) "Days since last restart: $bootAge (not a Windows Update compliance test)"
} catch { Add-Check 'restart_age' 'unknown' 'Last restart unavailable' }
[ordered]@{
    schema_version = 1
    collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    checks = $checks
} | ConvertTo-Json -Depth 5 -Compress
