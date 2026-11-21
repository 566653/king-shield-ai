# Local, read-only Security log export. No remote connections.
param(
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateRange(1,5000)][int]$MaxEvents = 250
)
$ErrorActionPreference = 'Stop'
$ids = @(4625,4720,4724,4726,4728,4732,4756,4719,1102)
try {
    $events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$ids} -MaxEvents $MaxEvents -ErrorAction Stop)
} catch {
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {
        $events = @()
    } else {
        Write-Error 'Unable to read Security log. Check authorized Windows permissions.'
        exit 2
    }
}
$lines = foreach ($entry in $events) {
    $groupName = ''
    try {
        [xml]$xml = $entry.ToXml()
        $fields = @{}
        foreach ($field in $xml.Event.EventData.Data) {
            if ($field.Name) { $fields[[string]$field.Name] = [string]$field.'#text' }
        }
        if ($fields.ContainsKey('TargetUserName')) { $groupName = $fields['TargetUserName'] }
    } catch { $groupName = '' }
    [pscustomobject]@{
        event_id = [int]$entry.Id
        source = [string]$entry.MachineName
        group = $groupName
    } | ConvertTo-Json -Compress
}
# Ensure the destination exists even when no matching events are found.
@($lines) | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output "Exported $(@($lines).Count) normalized events to $OutputPath"
