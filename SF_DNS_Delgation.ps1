[CmdletBinding()]
param(
    [string[]]$Domains = @(
        'superfriend.com.au',
        'superfriend.org.au',
        'superfriend-partners.com.au',
        'thrivingworkplaceindex.com.au'
    ),

    [string[]]$TargetNS = @(
        'dns1.cscdns.net',
        'dns2.cscdns.net'
    ),

    [string[]]$Resolvers = @(
        '1.1.1.1',
        '8.8.8.8',
        '9.9.9.9'
    ),

    [string]$Label = 'Check',

    [string]$CompareWith,

    [switch]$IncludeSoa,

    [string]$OutputPath
)

# --- Setup -------------------------------------------------------------------

if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
    Write-Warning 'Resolve-DnsName not found. Run this on Windows. Nothing was done.'
    return
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$RunTime  = Get-Date
$Stamp    = $RunTime.ToString('yyyyMMdd-HHmmss')
$TargetSet = @($TargetNS | ForEach-Object { $_.TrimEnd('.').ToLowerInvariant() } | Sort-Object)
$Rows     = New-Object System.Collections.ArrayList

# --- Helpers -----------------------------------------------------------------

function Get-NSAnswer {
    # Returns a hashtable: NS (sorted string[]), TTL (int), Error (string)
    param([string]$Name, [string]$Server)

    $out = @{ NS = @(); TTL = $null; Error = $null }

    try {
        $recs = Resolve-DnsName -Name $Name -Type NS -Server $Server -DnsOnly -NoHostsFile -ErrorAction Stop

        $ns = New-Object System.Collections.ArrayList
        foreach ($r in $recs) {
            $rtype = if ($null -ne $r.QueryType) { "$($r.QueryType)" } else { "$($r.Type)" }
            if ($rtype -eq 'NS' -and $r.NameHost) {
                [void]$ns.Add($r.NameHost.TrimEnd('.').ToLowerInvariant())
                if ($null -eq $out.TTL -and $null -ne $r.TTL) { $out.TTL = $r.TTL }
            }
        }
        $out.NS = @($ns | Sort-Object -Unique)
    }
    catch {
        $out.Error = $_.Exception.Message
    }

    return $out
}

function Get-RegistryServer {
    # Nameserver for the parent zone, e.g. com.au / org.au
    param([string]$Domain)

    $parts = $Domain -split '\.'
    if ($parts.Count -lt 3) { $tld = $parts[-1] } else { $tld = ($parts[-2..-1]) -join '.' }

    $a = Get-NSAnswer -Name $tld -Server $Resolvers[0]
    if ($a.NS.Count -gt 0) {
        return @{ Zone = $tld; Server = $a.NS[0] }
    }
    return @{ Zone = $tld; Server = $null }
}

function Get-SoaSerial {
    param([string]$Name, [string]$Server)
    try {
        $r = Resolve-DnsName -Name $Name -Type SOA -Server $Server -DnsOnly -NoHostsFile -ErrorAction Stop |
             Where-Object { $_.PSObject.Properties.Name -contains 'SerialNumber' } |
             Select-Object -First 1
        if ($r) { return "$($r.SerialNumber)" }
        return 'no SOA'
    }
    catch { return "error: $($_.Exception.Message)" }
}

function Test-MatchesTarget {
    param([string[]]$Actual)
    if (-not $Actual -or $Actual.Count -eq 0) { return 'n/a' }
    $diff = Compare-Object -ReferenceObject $TargetSet -DifferenceObject @($Actual)
    if ($diff) { return 'No' } else { return 'Yes' }
}

function Add-Row {
    param($Domain, $View, $Source, $NS, $TTL, $Match, $Note)
    [void]$Rows.Add([pscustomobject]@{
        Label        = $Label
        TimestampUtc = $RunTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        TimestampLoc = $RunTime.ToString('yyyy-MM-dd HH:mm:ss')
        Domain       = $Domain
        View         = $View
        Source       = $Source
        NameServers  = (@($NS) -join '; ')
        TTL          = $TTL
        MatchesCSC   = $Match
        Note         = $Note
    })
}

# --- Collect -----------------------------------------------------------------

Write-Host ''
Write-Host "SuperFriend nameserver snapshot - $Label" -ForegroundColor Cyan
Write-Host ("Taken {0}  |  target: {1}" -f $RunTime.ToString('ddd dd MMM yyyy HH:mm'), ($TargetSet -join ', '))
Write-Host ''

foreach ($Domain in $Domains) {

    Write-Host $Domain -ForegroundColor Yellow

    # Registry / parent view
    $reg = Get-RegistryServer -Domain $Domain
    if ($reg.Server) {
        $p = Get-NSAnswer -Name $Domain -Server $reg.Server
        if ($p.Error) {
            Add-Row $Domain 'Registry' $reg.Server @() $null 'n/a' $p.Error
            Write-Host "  registry ($($reg.Zone))  lookup failed: $($p.Error)" -ForegroundColor DarkGray
        }
        else {
            $m = Test-MatchesTarget -Actual $p.NS
            Add-Row $Domain 'Registry' $reg.Server $p.NS $p.TTL $m ''
            $c = if ($m -eq 'Yes') { 'Green' } else { 'Gray' }
            Write-Host ("  registry ({0,-6}) {1}" -f $reg.Zone, ($p.NS -join ', ')) -ForegroundColor $c
        }
    }
    else {
        Add-Row $Domain 'Registry' '' @() $null 'n/a' 'could not determine registry nameserver'
        Write-Host '  registry        could not determine nameserver' -ForegroundColor DarkGray
    }

    # Recursive resolver view
    foreach ($rv in $Resolvers) {
        $a = Get-NSAnswer -Name $Domain -Server $rv
        if ($a.Error) {
            Add-Row $Domain 'Resolver' $rv @() $null 'n/a' $a.Error
            Write-Host ("  {0,-15} lookup failed" -f $rv) -ForegroundColor DarkGray
        }
        else {
            $m = Test-MatchesTarget -Actual $a.NS
            Add-Row $Domain 'Resolver' $rv $a.NS $a.TTL $m ''
            $c = if ($m -eq 'Yes') { 'Green' } else { 'Gray' }
            Write-Host ("  {0,-15} {1}   (ttl {2})" -f $rv, ($a.NS -join ', '), $a.TTL) -ForegroundColor $c
        }
    }

    # SOA serial from the target nameservers
    if ($IncludeSoa) {
        foreach ($ns in $TargetSet) {
            $serial = Get-SoaSerial -Name $Domain -Server $ns
            Add-Row $Domain 'SOA' $ns @() $null 'n/a' "serial $serial"
            Write-Host ("  soa @{0,-18} {1}" -f $ns, $serial) -ForegroundColor DarkGray
        }
    }

    Write-Host ''
}

# --- Propagation summary -----------------------------------------------------

$summary = foreach ($Domain in $Domains) {
    $res = $Rows | Where-Object { $_.Domain -eq $Domain -and $_.View -eq 'Resolver' }
    $reg = $Rows | Where-Object { $_.Domain -eq $Domain -and $_.View -eq 'Registry' } | Select-Object -First 1
    $ok  = @($res | Where-Object { $_.MatchesCSC -eq 'Yes' }).Count

    [pscustomobject]@{
        Domain       = $Domain
        Registry     = if ($reg) { $reg.MatchesCSC } else { 'n/a' }
        ResolversOnCSC = "$ok / $(@($res).Count)"
        MaxTTL       = ($res | Measure-Object -Property TTL -Maximum).Maximum
    }
}

Write-Host 'Summary' -ForegroundColor Cyan
$summary | Format-Table -AutoSize | Out-String | Write-Host

# --- Write evidence ----------------------------------------------------------

$csvPath = Join-Path $OutputPath "NS-$Label-$Stamp.csv"
$mdPath  = Join-Path $OutputPath "NS-$Label-$Stamp.md"

$Rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

$md = New-Object System.Collections.ArrayList
[void]$md.Add("# SuperFriend nameserver snapshot - $Label")
[void]$md.Add('')
[void]$md.Add("Taken: $($RunTime.ToString('dddd dd MMMM yyyy HH:mm')) local / $($RunTime.ToUniversalTime().ToString('HH:mm')) UTC  ")
[void]$md.Add("Host: $env:COMPUTERNAME  |  User: $env:USERNAME  ")
[void]$md.Add("Target nameservers: $($TargetSet -join ', ')")
[void]$md.Add('')
[void]$md.Add('| Domain | View | Source | Nameservers | TTL | Matches CSC | Note |')
[void]$md.Add('| --- | --- | --- | --- | --- | --- | --- |')
foreach ($r in $Rows) {
    [void]$md.Add("| $($r.Domain) | $($r.View) | $($r.Source) | $($r.NameServers) | $($r.TTL) | $($r.MatchesCSC) | $($r.Note) |")
}
$md -join "`r`n" | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Host "CSV      : $csvPath"
Write-Host "Markdown : $mdPath"