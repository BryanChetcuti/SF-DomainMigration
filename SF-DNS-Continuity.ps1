[CmdletBinding()]
param(
    [string[]]$Resolvers = @('1.1.1.1','8.8.8.8','9.9.9.9'),
    [string[]]$AuthoritativeServers = @('dns1.cscdns.net','dns2.cscdns.net'),
    [string]$Label = 'ContinuityCheck',
    [string]$OutputPath,
    [switch]$SkipServiceChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
    Write-Error 'Resolve-DnsName was not found. Run this script in Windows PowerShell or PowerShell on Windows.'
    exit 2
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$RunTime = Get-Date
$Stamp = $RunTime.ToString('yyyyMMdd-HHmmss')
$Rows = [System.Collections.Generic.List[object]]::new()
$ServiceRows = [System.Collections.Generic.List[object]]::new()

# Known-good non-DKIM records from the CSC zone-file workbooks.
# TTL is deliberately excluded from pass/fail. DNS names are compared case-insensitively
# and without a trailing dot. Multi-value record order is ignored.
$ExpectedCsv = @'
Domain,Type,Key,Value,Priority,Weight,Port,Required
superfriend.com.au,A,@,199.60.103.28,,,,True
superfriend.com.au,A,itw,199.60.103.28,,,,True
superfriend.com.au,A,itwo,199.60.103.28,,,,True
superfriend.com.au,A,live,54.79.61.152,,,,True
superfriend.com.au,A,mhwt,54.79.61.152,,,,True
superfriend.com.au,A,office,203.194.52.110,,,,True
superfriend.com.au,A,re,52.237.198.242,,,,True
superfriend.com.au,A,s1,13.239.51.96,,,,True
superfriend.com.au,A,vpn,103.227.29.151,,,,True
superfriend.com.au,A,wellbeingworks,178.128.106.231,,,,True
superfriend.com.au,A,www,199.60.103.28,,,,True
superfriend.com.au,A,www.mhwt,54.79.61.152,,,,True
superfriend.com.au,CNAME,_ca3-f8e1b2600451481685528db94d3fc1c6,dcv.digicert.com.,,,,True
superfriend.com.au,CNAME,_ca3-f8e1b2600451481685528db94d3fc1c6.www,dcv.digicert.com.,,,,True
superfriend.com.au,CNAME,_fdfa8435a6b8907909531c7c12840cbe.my,_c3b16507cce6a8561ad5fae3cad9ca26.djqtsrsxkq.acm-validations.aws.,,,,True
superfriend.com.au,CNAME,_fe3bee45221bc1ccdca35ff124c6037f,6fb707fc251de54977ffdd026b46c5d4.c1b5fe7907ab2b0f7e4594620d5fab90.5ri5edo5mxrmw85x5is5.comodoca.com.,,,,True
superfriend.com.au,CNAME,_ilqhqlrqzdt5vud0o2ruk7wfkcizpm8.my,dcv.digicert.com.,,,,True
superfriend.com.au,CNAME,api.yourthrivingworkplace,sfsurveys-prod-endpoint-h7fvgahhhmhda4h5.z03.azurefd.net.,,,,True
superfriend.com.au,CNAME,autodiscover,autodiscover.outlook.com.,,,,True
superfriend.com.au,CNAME,em5620,u14633218.wl219.sendgrid.net.,,,,True
superfriend.com.au,CNAME,enterpriseenrollment,enterpriseenrollment.manage.microsoft.com.,,,,True
superfriend.com.au,CNAME,enterpriseregistration,enterpriseregistration.windows.net.,,,,True
superfriend.com.au,CNAME,fmy2xy9q36byz0yyzj2sbg0v4jq22tfm.my,dcv.digicert.com.,,,,True
superfriend.com.au,CNAME,lyncdiscover,webdir.online.lync.com.,,,,True
superfriend.com.au,CNAME,msoid,clientconfig.microsoftonline-p.net.,,,,True
superfriend.com.au,CNAME,my,cl2.myabsorb.com.au.,,,,True
superfriend.com.au,CNAME,staff,msan1.myabsorb.com.au.,,,,True
superfriend.com.au,CNAME,thrivingworkplaceindexcom,superfriend.com.au.,,,,True
superfriend.com.au,CNAME,wellbeingoncall,wocdv.wpengine.com.,,,,True
superfriend.com.au,CNAME,wrby1yhrnkd2lfc23n3zbbg5gp9flpkn.my,dcv.digicert.com.,,,,True
superfriend.com.au,CNAME,yourthrivingworkplace,sfsurveys-prod-endpoint-h7fvgahhhmhda4h5.z03.azurefd.net.,,,,True
superfriend.com.au,MX,@,superfriend-com-au.mail.protection.outlook.com.,0,,,True
superfriend.com.au,TXT,@,atlassian-domain-verification=WZDokJFdaIDxEL3k5NOIrS8hy9KGbW5OvIdzD4K1B5a5wJtPtJwogdUyNuAOaNlo,,,,True
superfriend.com.au,TXT,@,brevo-code:00530b1cca3547f57db427564e4912db,,,,True
superfriend.com.au,TXT,@,bw=pCGSKhB3igDKt7hevOXgkWBsrOi84QMR6HaFp82nZmEz,,,,True
superfriend.com.au,TXT,@,v=spf1 a mx ip4:13.239.51.96 ip4:203.194.52.110 ip4:210.11.186.243 ip4:61.14.103.136 include:customer.mailguard.com.au include:spf.protection.outlook.com include:spf-au.emailsignatures365.com include:infusionmail.com include:spf.au.exclaimer.net include:21538146.spf04.hubspotemail.net -all,,,,True
superfriend.com.au,TXT,_acme-challenge,xcVO7WMhatgv4fRS1hyj2YYW5hb2yD656R7uWKngfXM,,,,True
superfriend.com.au,TXT,_cf-custom-hostname.www,214cde11-fbe7-4460-bbc9-884b878729cb,,,,True
superfriend.com.au,TXT,_dmarc,v=DMARC1; p=none; rua=mailto:rua@dmarc.brevo.com,,,,True
superfriend.com.au,TXT,_dnsauth.api.yourthrivingworkplace,_rwy3xd4nxoegp0r741g8lt7pkggm8ct,,,,True
superfriend.com.au,TXT,_dnsauth.yourthrivingworkplace,_j1odrhtt0cn34dhuz2n3fbr4julq5gz,,,,True
superfriend.com.au,TXT,www,cz32j5qspvfbh41pf68gdn0bz0c0ttjb,,,,True
superfriend.com.au,SRV,_sip._tls,sipdir.online.lync.com.,100,1,443,True
superfriend.com.au,SRV,_sipfederationtls._tcp,sipfed.online.lync.com.,100,1,5061,True
superfriend.org.au,A,@,103.169.190.9,,,,True
superfriend.org.au,A,www,103.169.190.9,,,,True
superfriend.org.au,CNAME,autodiscover,autodiscover.outlook.com.,,,,True
superfriend.org.au,MX,@,superfriend-org-au.mail.protection.outlook.com.,0,,,True
superfriend.org.au,MX,@,ms56476332.msv1.invalid.,32767,,,True
superfriend.org.au,TXT,@,MS=ms26200955,,,,True
superfriend.org.au,TXT,@,bw=7lt5TMbw9wLwe7MyQAuB2huLoFamksFXcagVzVBWROdJ,,,,True
superfriend.org.au,TXT,@,v=spf1 include:spf.protection.outlook.com -all,,,,True
superfriend-partners.com.au,A,@,199.60.103.147,,,,True
superfriend-partners.com.au,A,@,199.60.103.47,,,,True
superfriend-partners.com.au,CNAME,_domainconnect,_domainconnect.gd.domaincontrol.com.,,,,True
superfriend-partners.com.au,CNAME,www,21538146.group46.sites.hubspot.net.,,,,True
thrivingworkplaceindex.com.au,A,@,5.22.145.155,,,,True
thrivingworkplaceindex.com.au,A,@,5.22.145.180,,,,True
thrivingworkplaceindex.com.au,A,www,5.22.145.155,,,,True
thrivingworkplaceindex.com.au,A,www,5.22.145.180,,,,True
thrivingworkplaceindex.com.au,CNAME,imap,imap.partnerconsole.net.,,,,True
thrivingworkplaceindex.com.au,CNAME,pop,pop3.partnerconsole.net.,,,,True
thrivingworkplaceindex.com.au,CNAME,pop3,pop3.partnerconsole.net.,,,,True
thrivingworkplaceindex.com.au,CNAME,smtp,smtp.partnerconsole.net.,,,,True
thrivingworkplaceindex.com.au,CNAME,webmail,webmail.partnerconsole.net.,,,,True
thrivingworkplaceindex.com.au,MX,@,mx1.mail-forwarder.io.,10,,,True
thrivingworkplaceindex.com.au,MX,@,mx2.mail-forwarder.io.,20,,,True
# mysuperfriend.com.au is intentionally commented out because it is outside this change.
# mysuperfriend.com.au,A,account,13.75.170.153,,,,True
'@
$Expected = @($ExpectedCsv -split "`r?`n" | Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') } | ConvertFrom-Csv)

$OptionalProbes = @(
    [pscustomobject]@{Domain='superfriend.com.au';Type='AAAA';Key='@'},
    [pscustomobject]@{Domain='superfriend.com.au';Type='CAA';Key='@'},
    [pscustomobject]@{Domain='superfriend.org.au';Type='AAAA';Key='@'},
    [pscustomobject]@{Domain='superfriend.org.au';Type='CAA';Key='@'},
    [pscustomobject]@{Domain='superfriend.org.au';Type='TXT';Key='_dmarc'},
    [pscustomobject]@{Domain='superfriend-partners.com.au';Type='AAAA';Key='@'},
    [pscustomobject]@{Domain='superfriend-partners.com.au';Type='CAA';Key='@'},
    [pscustomobject]@{Domain='superfriend-partners.com.au';Type='TXT';Key='_dmarc'},
    [pscustomobject]@{Domain='thrivingworkplaceindex.com.au';Type='AAAA';Key='@'},
    [pscustomobject]@{Domain='thrivingworkplaceindex.com.au';Type='CAA';Key='@'},
    [pscustomobject]@{Domain='thrivingworkplaceindex.com.au';Type='TXT';Key='_dmarc'}
)

$HttpsHosts = @(
    'superfriend.com.au','www.superfriend.com.au','itw.superfriend.com.au','itwo.superfriend.com.au',
    'live.superfriend.com.au','mhwt.superfriend.com.au','www.mhwt.superfriend.com.au',
    're.superfriend.com.au','wellbeingworks.superfriend.com.au','my.superfriend.com.au',
    'staff.superfriend.com.au','wellbeingoncall.superfriend.com.au',
    'yourthrivingworkplace.superfriend.com.au','api.yourthrivingworkplace.superfriend.com.au',
    'superfriend.org.au','www.superfriend.org.au',
    'superfriend-partners.com.au','www.superfriend-partners.com.au',
    'thrivingworkplaceindex.com.au','www.thrivingworkplaceindex.com.au','webmail.thrivingworkplaceindex.com.au'
    # 'mysuperfriend.com.au' # intentionally outside this change
)

function Normalize-DnsText([string]$Value) {
    if ($null -eq $Value) { return '' }
    return (($Value.Trim().Trim('"').TrimEnd('.')).ToLowerInvariant())
}
function Get-Fqdn([string]$Domain,[string]$Key) {
    if ([string]::IsNullOrWhiteSpace($Key) -or $Key -eq '@') { return $Domain }
    return "$Key.$Domain"
}
function Convert-AnswerToValues($Records,[string]$Type) {
    $vals = foreach ($r in @($Records)) {
        $rt = if ($null -ne $r.QueryType) { "$($r.QueryType)" } else { "$($r.Type)" }
        if ($rt -ne $Type) { continue }
        switch ($Type) {
            'A'     { if ($r.IPAddress) { Normalize-DnsText "$($r.IPAddress)" } }
            'AAAA'  { if ($r.IPAddress) { Normalize-DnsText "$($r.IPAddress)" } }
            'CNAME' { if ($r.NameHost) { Normalize-DnsText "$($r.NameHost)" } }
            'MX'    { if ($r.NameExchange) { "$(('{0:d5}' -f [int]$r.Preference))|$(Normalize-DnsText "$($r.NameExchange)")" } }
            'TXT'   { if ($r.Strings) { Normalize-DnsText (@($r.Strings) -join '') } }
            'SRV'   { if ($r.NameTarget) { "$(('{0:d5}' -f [int]$r.Priority))|$(('{0:d5}' -f [int]$r.Weight))|$(('{0:d5}' -f [int]$r.Port))|$(Normalize-DnsText "$($r.NameTarget)")" } }
            'CAA'   {
                $tag = if ($r.PSObject.Properties.Name -contains 'Tag') { "$($r.Tag)" } else { '' }
                $value = if ($r.PSObject.Properties.Name -contains 'Value') { "$($r.Value)" } else { '' }
                $flags = if ($r.PSObject.Properties.Name -contains 'Flags') { "$($r.Flags)" } else { '0' }
                if ($tag -or $value) { "$flags|$(Normalize-DnsText $tag)|$(Normalize-DnsText $value)" }
            }
        }
    }
    return @($vals | Where-Object { $_ -ne '' } | Sort-Object -Unique)
}
function Get-ExpectedValue($r) {
    switch ($r.Type) {
        'MX'  { return "$(('{0:d5}' -f [int]$r.Priority))|$(Normalize-DnsText $r.Value)" }
        'SRV' { return "$(('{0:d5}' -f [int]$r.Priority))|$(('{0:d5}' -f [int]$r.Weight))|$(('{0:d5}' -f [int]$r.Port))|$(Normalize-DnsText $r.Value)" }
        default { return Normalize-DnsText $r.Value }
    }
}
function Invoke-DnsQuery([string]$Name,[string]$Type,[string]$Server) {
    try {
        # Resolve-DnsName does not expose CAA consistently across Windows builds.
        # Numeric type 257 is attempted; unsupported CAA is returned as optional/amber.
        $queryType = if ($Type -eq 'CAA') { 257 } else { $Type }
        $records = Resolve-DnsName -Name $Name -Type $queryType -Server $Server -DnsOnly -NoHostsFile -ErrorAction Stop
        return @{ Values=(Convert-AnswerToValues $records $Type); TTL=(@($records | Where-Object TTL | Measure-Object TTL -Minimum).Minimum); Error=$null }
    }
    catch {
        return @{ Values=@(); TTL=$null; Error=$_.Exception.Message }
    }
}
function Add-DnsRow($Domain,$Name,$Type,$View,$Source,$ExpectedValues,$ActualValues,$TTL,$Status,$Note) {
    $Rows.Add([pscustomobject]@{
        Label=$Label; TimestampUtc=$RunTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss');
        Domain=$Domain; Name=$Name; Type=$Type; View=$View; Source=$Source;
        Expected=(@($ExpectedValues) -join '; '); Actual=(@($ActualValues) -join '; ');
        TTL=$TTL; Status=$Status; Note=$Note
    })
}
function Write-StatusLine([string]$Text,[string]$Status) {
    $colour = switch ($Status) { 'PASS' {'Green'} 'WARN' {'Yellow'} 'FAIL' {'Red'} default {'DarkGray'} }
    Write-Host $Text -ForegroundColor $colour
}

Write-Host ''
Write-Host "SuperFriend DNS and service continuity validation - $Label" -ForegroundColor Cyan
Write-Host ("Taken {0}" -f $RunTime.ToString('ddd dd MMM yyyy HH:mm:ss'))
Write-Host 'TTL and answer order are informational only. DKIM records are excluded.' -ForegroundColor DarkGray
Write-Host ''

$groups = $Expected | Group-Object Domain,Type,Key
foreach ($g in $groups) {
    $first = $g.Group[0]
    $domain = $first.Domain
    $type = $first.Type
    $name = Get-Fqdn $domain $first.Key
    $expectedValues = @($g.Group | ForEach-Object { Get-ExpectedValue $_ } | Sort-Object -Unique)

    foreach ($server in @($AuthoritativeServers + $Resolvers)) {
        $view = if ($AuthoritativeServers -contains $server) { 'Authoritative' } else { 'Resolver' }
        $q = Invoke-DnsQuery $name $type $server
        if ($q.Error) {
            Add-DnsRow $domain $name $type $view $server $expectedValues @() $null 'FAIL' $q.Error
            Write-StatusLine ("FAIL {0,-13} {1,-5} {2} via {3}: {4}" -f $view,$type,$name,$server,$q.Error) 'FAIL'
            continue
        }
        $diff = Compare-Object -ReferenceObject $expectedValues -DifferenceObject @($q.Values)
        $status = if ($diff) { 'FAIL' } else { 'PASS' }
        $note = if ($diff) { 'Expected and actual record sets differ' } else { '' }
        Add-DnsRow $domain $name $type $view $server $expectedValues $q.Values $q.TTL $status $note
        Write-StatusLine ("{0} {1,-13} {2,-5} {3} via {4}" -f $status,$view,$type,$name,$server) $status
    }
}

Write-Host ''
Write-Host 'Optional presence checks (absence does not fail continuity)' -ForegroundColor Cyan
foreach ($p in $OptionalProbes) {
    $name = Get-Fqdn $p.Domain $p.Key
    foreach ($server in @($AuthoritativeServers + $Resolvers)) {
        $view = if ($AuthoritativeServers -contains $server) { 'Authoritative' } else { 'Resolver' }
        $q = Invoke-DnsQuery $name $p.Type $server
        if ($q.Values.Count -gt 0) {
            Add-DnsRow $p.Domain $name $p.Type $view $server @() $q.Values $q.TTL 'INFO' 'Optional record present; no expected value supplied'
            Write-StatusLine ("INFO {0,-13} {1,-5} {2} via {3}: present" -f $view,$p.Type,$name,$server) 'INFO'
        } else {
            $note = if ($q.Error) { "Optional record absent or unsupported: $($q.Error)" } else { 'Optional record absent' }
            Add-DnsRow $p.Domain $name $p.Type $view $server @() @() $null 'WARN' $note
            Write-StatusLine ("WARN {0,-13} {1,-5} {2} via {3}: absent/unsupported" -f $view,$p.Type,$name,$server) 'WARN'
        }
    }
}

function Test-TlsAndHttp([string]$HostName) {
    $result = [ordered]@{Host=$HostName;Dns='';Tls='';CertificateExpiry='';CertificateDays='';Http='';FinalUrl='';Status='FAIL';Note=''}
    try {
        $ips = @(Resolve-DnsName -Name $HostName -Type A_AAAA -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object IPAddress | ForEach-Object IPAddress | Sort-Object -Unique)
        $result.Dns = $ips -join '; '
    } catch { $result.Note = "DNS resolution failed: $($_.Exception.Message)"; return [pscustomobject]$result }

    $tcp = $null; $ssl = $null
    try {
        $script:PolicyErrors = $null
        $callback = { param($sender,$cert,$chain,$errors) $script:PolicyErrors = $errors; return $true }
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $iar = $tcp.BeginConnect($HostName,443,$null,$null)
        if (-not $iar.AsyncWaitHandle.WaitOne(10000)) { throw 'TCP 443 connection timed out' }
        $tcp.EndConnect($iar)
        $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(),$false,$callback)
        $ssl.AuthenticateAsClient($HostName)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        $days = [math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
        $result.CertificateExpiry = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
        $result.CertificateDays = $days
        $result.Tls = if ($script:PolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None -and $days -ge 0) { 'PASS' } else { "FAIL: $script:PolicyErrors" }
    } catch { $result.Tls = "FAIL: $($_.Exception.Message)" }
    finally { if ($ssl) {$ssl.Dispose()}; if ($tcp) {$tcp.Dispose()} }

    try {
        $response = Invoke-WebRequest -Uri "https://$HostName/" -Method Head -MaximumRedirection 5 -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        $code = [int]$response.StatusCode
        $result.Http = "$code $($response.StatusDescription)"
        $result.FinalUrl = "$($response.BaseResponse.ResponseUri)"
    } catch {
        $resp = $_.Exception.Response
        if ($resp) {
            $code = [int]$resp.StatusCode
            $result.Http = "$code $($resp.StatusDescription)"
            $result.FinalUrl = "$($resp.ResponseUri)"
        } else { $result.Http = "FAIL: $($_.Exception.Message)" }
    }
    $httpCode = 0
    [void][int]::TryParse(($result.Http -split ' ')[0],[ref]$httpCode)
    if ($result.Tls -eq 'PASS' -and $httpCode -ge 200 -and $httpCode -lt 400) { $result.Status='PASS' }
    elseif ($result.Tls -eq 'PASS' -and ($httpCode -eq 401 -or $httpCode -eq 403 -or $httpCode -eq 405)) { $result.Status='WARN'; $result.Note='Endpoint and TLS reachable; HTTP response may be intentional' }
    else { $result.Status='FAIL' }
    return [pscustomobject]$result
}

if (-not $SkipServiceChecks) {
    Write-Host ''
    Write-Host 'HTTPS and certificate checks' -ForegroundColor Cyan
    foreach ($hostName in $HttpsHosts) {
        $s = Test-TlsAndHttp $hostName
        $ServiceRows.Add($s)
        Write-StatusLine ("{0} HTTPS {1,-55} TLS={2} HTTP={3}" -f $s.Status,$hostName,$s.Tls,$s.Http) $s.Status
    }
}

$dnsFail = @($Rows | Where-Object Status -eq 'FAIL').Count
$dnsWarn = @($Rows | Where-Object Status -eq 'WARN').Count
$svcFail = @($ServiceRows | Where-Object Status -eq 'FAIL').Count
$svcWarn = @($ServiceRows | Where-Object Status -eq 'WARN').Count
$overall = if (($dnsFail + $svcFail) -gt 0) { 'FAIL' } elseif (($dnsWarn + $svcWarn) -gt 0) { 'WARN' } else { 'PASS' }

Write-Host ''
Write-Host 'Summary' -ForegroundColor Cyan
Write-StatusLine ("Overall: {0} | DNS failures: {1} | DNS warnings: {2} | Service failures: {3} | Service warnings: {4}" -f $overall,$dnsFail,$dnsWarn,$svcFail,$svcWarn) $overall

$csvPath = Join-Path $OutputPath "DNS-Continuity-$Label-$Stamp.csv"
$serviceCsvPath = Join-Path $OutputPath "Service-Continuity-$Label-$Stamp.csv"
$mdPath = Join-Path $OutputPath "Continuity-$Label-$Stamp.md"
$Rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
if ($ServiceRows.Count -gt 0) { $ServiceRows | Export-Csv -LiteralPath $serviceCsvPath -NoTypeInformation -Encoding UTF8 }

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# SuperFriend DNS and service continuity - $Label")
$md.Add('')
$md.Add("Taken: $($RunTime.ToString('dddd dd MMMM yyyy HH:mm:ss')) local / $($RunTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) UTC  ")
$md.Add("Host: $env:COMPUTERNAME | User: $env:USERNAME  ")
$md.Add("Overall: **$overall**  ")
$md.Add("DNS failures: $dnsFail | DNS warnings: $dnsWarn | Service failures: $svcFail | Service warnings: $svcWarn")
$md.Add('')
$md.Add('TTL differences and record ordering are informational only. DKIM records are excluded. Optional AAAA, CAA and non-documented DMARC absence is WARN, not FAIL.')
$md.Add('')
$md.Add('## DNS results')
$md.Add('| Status | Domain | Name | Type | View | Source | Expected | Actual | TTL | Note |')
$md.Add('| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |')
foreach ($r in $Rows) {
    $safe = { param($v) ("$v" -replace '\|','\\|') }
    $md.Add("| $($r.Status) | $($r.Domain) | $($r.Name) | $($r.Type) | $($r.View) | $($r.Source) | $(& $safe $r.Expected) | $(& $safe $r.Actual) | $($r.TTL) | $(& $safe $r.Note) |")
}
if ($ServiceRows.Count -gt 0) {
    $md.Add(''); $md.Add('## HTTPS and certificate results')
    $md.Add('| Status | Host | DNS | TLS | Certificate expiry | Days | HTTP | Final URL | Note |')
    $md.Add('| --- | --- | --- | --- | --- | --- | --- | --- | --- |')
    foreach ($s in $ServiceRows) {
        $md.Add("| $($s.Status) | $($s.Host) | $($s.Dns) | $($s.Tls) | $($s.CertificateExpiry) | $($s.CertificateDays) | $($s.Http) | $($s.FinalUrl) | $($s.Note) |")
    }
}
$md -join "`r`n" | Set-Content -LiteralPath $mdPath -Encoding UTF8

Write-Host ''
Write-Host "DNS CSV     : $csvPath"
if ($ServiceRows.Count -gt 0) { Write-Host "Service CSV : $serviceCsvPath" }
Write-Host "Markdown    : $mdPath"

if ($overall -eq 'FAIL') { exit 1 }
exit 0
