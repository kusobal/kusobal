# AD_Full_Report.ps1 - Active Directory Comprehensive Reporting Tool (New Security Categories Added)

param(
    [string]$NetworkRange = "",
    [switch]$SkipNetworkDiscovery,
    [switch]$SkipHeavyTelemetry
)

# ---------------------
# STARTUP AND VARIABLE DEFINITIONS
# ---------------------
Import-Module ActiveDirectory

Write-Host "This report may take about 5 minutes to generate."
Write-Host "Bu raporun olusmasi yaklasik 5 dakika surebilir."

$Domain = "Unknown"
$InactivityThreshold = (Get-Date).AddDays(-90)
$Today = Get-Date
$SkippedDCs = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-SkippedDCRecord {
    param(
        [string]$DC,
        [string]$Section,
        [string]$Reason
    )

    if ([string]::IsNullOrWhiteSpace($DC)) { return }
    if ([string]::IsNullOrWhiteSpace($Section)) { $Section = "Unknown" }
    if ([string]::IsNullOrWhiteSpace($Reason)) { $Reason = "Unknown error" }

    $script:SkippedDCs.Add([PSCustomObject]@{
        DC = $DC
        Section = $Section
        Reason = $Reason
    })
}

# Performance settings
$FastMode = $true
$EnableNetworkDiscovery = $false
$NetworkScanInput = ""  # Examples: 172.30.15.0-254 or 172.30.15.0-172.30.15.254
$NetworkPingTimeoutMs = 220

if ($SkipNetworkDiscovery) {
    $EnableNetworkDiscovery = $false
}

if (-not [string]::IsNullOrWhiteSpace($NetworkRange)) {
    $NetworkScanInput = $NetworkRange.Trim()
}

function Convert-ADTimestamp($ts){
    if($ts){
        # LastLogonTimestamp value (Windows FileTime format) is converted to a proper date
        return [DateTime]::FromFileTime($ts).ToString("dd/MM/yyyy")
    } else {
        return "Never"
    }
}

# ---------------------
# FUNCTIONAL LEVEL INFO
# ---------------------
function Format-FunctionalLevel($mode) {
    switch ($mode) {
        "Windows2016Domain" { "Windows Server 2016" }
        "Windows2012R2Domain" { "Windows Server 2012 R2" }
        "Windows2012Domain" { "Windows Server 2012" }
        "Windows2008R2Domain" { "Windows Server 2008 R2 (EOL)" }
        "Windows2008Domain" { "Windows Server 2008 (EOL)" }
        "Windows2016Forest" { "Windows Server 2016" }
        "Windows2012R2Forest" { "Windows Server 2012 R2" }
        "Windows2012Forest" { "Windows Server 2012" }
        "Windows2008R2Forest" { "Windows Server 2008 R2 (EOL)" }
        "Windows2008Forest" { "Windows Server 2008 (EOL)" }
        default { $mode } 
    }
}

try {
    $DomainInfo = Get-ADDomain
    $ForestInfo = Get-ADForest
    $PwdPolicy = Get-ADDefaultDomainPasswordPolicy
    $Domain = $DomainInfo.DNSRoot
    
    $DFL = Format-FunctionalLevel $DomainInfo.DomainMode
    $FFL = Format-FunctionalLevel $ForestInfo.ForestMode
    
} catch {
    $DFL = "Error/Unavailable"
    $FFL = "Error/Unavailable"
    $PwdPolicy = $null
}

$OUTreeData = @()
try {
    $AllOUs = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName, Name, Description, LinkedGroupPolicyObjects, gPLink, ManagedBy -ResultSetSize $null

    $GpoMetaByGuid = @{}
    if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
        try {
            $allGposForOu = @(Get-GPO -All -ErrorAction Stop)
            foreach ($g in $allGposForOu) {
                $gid = ([string]$g.Id).ToLower()
                $GpoMetaByGuid[$gid] = [PSCustomObject]@{
                    Name = [string]$g.DisplayName
                    Status = [string]$g.GpoStatus
                }
            }
        } catch {}
    }

    $GpoLinkedOuNamesByGuid = @{}
    foreach ($ou in $AllOUs) {
        $rawGpLink = [string]$ou.gPLink
        if ([string]::IsNullOrWhiteSpace($rawGpLink)) { continue }
        $gpMatches = [regex]::Matches(
            $rawGpLink,
            '\[LDAP://CN=\{(?<Guid>[0-9A-Fa-f-]+)\},CN=Policies,CN=System,[^\]]*;(?<Opt>\d+)\]',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        foreach ($m in $gpMatches) {
            $gid = $m.Groups['Guid'].Value.ToLower()
            if (-not $GpoLinkedOuNamesByGuid.ContainsKey($gid)) { $GpoLinkedOuNamesByGuid[$gid] = @() }
            $GpoLinkedOuNamesByGuid[$gid] += [string]$ou.Name
        }
    }

    foreach ($ou in $AllOUs) {
        $rawGpLink = [string]$ou.gPLink
        $gpMatches = @()
        if (-not [string]::IsNullOrWhiteSpace($rawGpLink)) {
            $gpMatches = [regex]::Matches(
                $rawGpLink,
                '\[LDAP://CN=\{(?<Guid>[0-9A-Fa-f-]+)\},CN=Policies,CN=System,[^\]]*;(?<Opt>\d+)\]',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
        }

        $gpLinkCount = @($gpMatches).Count
        $gpNames = @()
        $gpDetails = @()

        foreach ($m in $gpMatches) {
            $gid = $m.Groups['Guid'].Value.ToLower()
            $opt = 0
            [void][int]::TryParse($m.Groups['Opt'].Value, [ref]$opt)

            $isDisabled = (($opt -band 1) -ne 0)
            $isEnforced = (($opt -band 2) -ne 0)

            $gpoName = if ($GpoMetaByGuid.ContainsKey($gid)) { [string]$GpoMetaByGuid[$gid].Name } else { "GPO {$gid}" }
            $gpoStatus = if ($GpoMetaByGuid.ContainsKey($gid)) { [string]$GpoMetaByGuid[$gid].Status } else { "Unknown" }
            $otherLinkedOus = @()
            if ($GpoLinkedOuNamesByGuid.ContainsKey($gid)) {
                $otherLinkedOus = @(
                    $GpoLinkedOuNamesByGuid[$gid] |
                        Where-Object { $_ -and ($_ -ne [string]$ou.Name) } |
                        Select-Object -Unique
                )
            }
            $alsoLinkedText = if (@($otherLinkedOus).Count -gt 0) { ($otherLinkedOus -join ', ') } else { 'Only this OU' }

            $gpNames += $gpoName
            $gpDetails += "$gpoName | Status: $gpoStatus | Link: $(if ($isDisabled) { 'Disabled' } else { 'Enabled' }) | Enforced: $(if ($isEnforced) { 'Yes' } else { 'No' }) | Also linked: $alsoLinkedText"
        }

        if ($gpLinkCount -eq 0 -and $ou.LinkedGroupPolicyObjects) {
            $fallbackLinks = @($ou.LinkedGroupPolicyObjects)
            foreach ($gpLink in $fallbackLinks) {
                $gpName = (($gpLink -split ',')[0] -replace '^CN=', '').Trim()
                if (-not [string]::IsNullOrWhiteSpace($gpName)) {
                    $gpNames += $gpName
                    $gpDetails += "$gpName | Status: Unknown | Link: Unknown | Enforced: Unknown | Also linked: Unknown"
                }
            }
            $gpLinkCount = @($fallbackLinks).Count
        }

        $gpNames = @($gpNames | Where-Object { $_ } | Select-Object -Unique)

        $OUTreeData += [PSCustomObject]@{
            DN          = $ou.DistinguishedName
            Name        = $ou.Name
            Description = if ($ou.Description) { $ou.Description } else { "" }
            GPLinks     = $gpLinkCount
            GPONames    = if (@($gpNames).Count -gt 0) { ($gpNames -join '; ') } else { "" }
            GPODetails  = @($gpDetails)
            ManagedBy   = if ($ou.ManagedBy) { ($ou.ManagedBy -split ',')[0] -replace 'CN=','' } else { "" }
        }
    }
} catch { $OUTreeData = @() }
$OUTreeJson = $OUTreeData | ConvertTo-Json -Depth 8 -Compress
if ([string]::IsNullOrWhiteSpace($OUTreeJson)) { $OUTreeJson = "[]" }
$OUTreeDomainNameJson = if ([string]::IsNullOrWhiteSpace($Domain)) { '""' } else { ($Domain | ConvertTo-Json -Compress) }
$OUTreeDomainDnJson = if ($DomainInfo -and $DomainInfo.DistinguishedName) { ($DomainInfo.DistinguishedName | ConvertTo-Json -Compress) } else { '""' }


# ---------------------
# Computers & Sites Data Calculation
# ---------------------

# 1. Fetch all Computers and DCs
# msDS-SiteName, managedBy, operatingSystem, LastLogonTimestamp are fetched.
$AllComputers = Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonTimestamp,SID,msDS-SiteName,managedBy,DistinguishedName -ResultSetSize $null

# 2. Get DC list
$DCs = Get-ADDomainController -Filter * | Select-Object Name, HostName, IPv4Address, Site

# 3. Fetch all AD Sites
$Sites = Get-ADReplicationSite -Filter * | Select-Object Name

# Main hash table for storing sites
$SiteData = @{}
foreach ($site in $Sites) {
    $SiteData[$site.Name] = @{
        DCs = @()
        Servers = @()
    }
}

# 4. Classify computers by site and role (categorization logic)
$Computers = @()
$ServerCategories = @{
    "Windows Server 2022" = @()
    "Windows Server 2019" = @()
    "Windows Server 2016" = @()
    "Windows Server 2012 / EOL" = @()
    "Windows Server 2008 / EOL" = @()
}

$ClientCategories = @{
    "Windows 11" = @()
    "Windows 10" = @()
    "Windows 8 / EOL" = @()
    "Windows 7 / EOL" = @()
    "Unknown Client" = @()
}
$UnknownTotal = @() 

foreach ($c in $AllComputers) {
    # Get Site Name
    $SiteName = $c.'msDS-SiteName'
    
    # DC Check
    $IsDC = $DCs.Name -contains $c.Name
    
    # Classify by OS
    $OS = $c.OperatingSystem
    $ComputerObject = $c | Select Name, OperatingSystem, LastLogonTimestamp
    
    $isServer = $OS -match "Server"
    $isClient = $OS -match "Windows (7|8|10|11)"
    $isClassified = $false

    # Siteya Ekleme (Sadece Server OS'lu ve DC olanlar/olmayanlar)
    if ($SiteName -and $SiteData.ContainsKey($SiteName)) {
        if ($IsDC) {
            $SiteData[$SiteName].DCs += $ComputerObject
        } elseif ($isServer) {
            # Non-DC systems running Server OS (member servers)
            $SiteData[$SiteName].Servers += $ComputerObject
        }
    }

    # OS Category Classification (Shortened)
    switch -Wildcard ($OS) {
        "*Server 2022*" { $ServerCategories["Windows Server 2022"] += $ComputerObject; $isClassified = $true }
        "*Server 2019*" { $ServerCategories["Windows Server 2019"] += $ComputerObject; $isClassified = $true }
        "*Server 2016*" { $ServerCategories["Windows Server 2016"] += $ComputerObject; $isClassified = $true }
        "*Server 2012*" { $ServerCategories["Windows Server 2012 / EOL"] += $ComputerObject; $isClassified = $true }
        "*Server 2008*" { $ServerCategories["Windows Server 2008 / EOL"] += $ComputerObject; $isClassified = $true }
        "*Windows 11*" { $ClientCategories["Windows 11"] += $ComputerObject; $isClassified = $true }
        "*Windows 10*" { $ClientCategories["Windows 10"] += $ComputerObject; $isClassified = $true }
        "*Windows 8*" { $ClientCategories["Windows 8 / EOL"] += $ComputerObject; $isClassified = $true }
        "*Windows 7*" { $ClientCategories["Windows 7 / EOL"] += $ComputerObject; $isClassified = $true }
        
        default { 
            if ($isClient) {
                $ClientCategories["Unknown Client"] += $ComputerObject; $isClassified = $true 
            } else {
                $UnknownTotal += $ComputerObject
            }
        }
    }
}

$TotalServer = ($ServerCategories.Values | Measure-Object -Property Count -Sum).Sum
$TotalClient = ($ClientCategories.Values | Measure-Object -Property Count -Sum).Sum
$TotalUnknownCount = $UnknownTotal.Count

# ---------------------
# Network Discovery (Advanced IP Scanner-like quick sweep)
# ---------------------
function Get-PreferredLocalIPv4 {
    try {
        $candidate = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object {
                $_.IPAddress -notlike '169.254.*' -and
                $_.IPAddress -notlike '127.*'
            } |
            Sort-Object -Property SkipAsSource, PrefixLength -Descending |
            Select-Object -First 1

        if ($candidate -and $candidate.IPAddress) {
            return $candidate.IPAddress
        }
    } catch {}

    try {
        $fallback = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) |
            Where-Object {
                $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
                $_.IPAddressToString -notlike '169.254.*' -and
                $_.IPAddressToString -notlike '127.*'
            } |
            Select-Object -First 1

        if ($fallback) {
            return $fallback.IPAddressToString
        }
    } catch {}

    return '192.168.1.1'
}

function Resolve-NetworkScanRange {
    param(
        [string]$InputRange,
        [string]$DefaultIPv4
    )

    $parts = @($DefaultIPv4 -split '\.')
    if ($parts.Count -lt 4) { $parts = @('192','168','1','1') }

    $prefix = "$($parts[0]).$($parts[1]).$($parts[2])"
    $startOctet = 0
    $endOctet = 254
    $source = 'Default local /24'

    $raw = "$InputRange".Trim()
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        if ($raw -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$') {
            $prefix = $matches[1]
            $startOctet = [int]$matches[2]
            $endOctet = [int]$matches[3]
            $source = 'Manual range'
        } elseif ($raw -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})$') {
            if ($matches[1] -eq $matches[3]) {
                $prefix = $matches[1]
                $startOctet = [int]$matches[2]
                $endOctet = [int]$matches[4]
                $source = 'Manual range'
            }
        }
    }

    if ($startOctet -lt 0) { $startOctet = 0 }
    if ($startOctet -gt 254) { $startOctet = 254 }
    if ($endOctet -lt 0) { $endOctet = 0 }
    if ($endOctet -gt 254) { $endOctet = 254 }
    if ($startOctet -gt $endOctet) {
        $tmp = $startOctet
        $startOctet = $endOctet
        $endOctet = $tmp
    }

    return [PSCustomObject]@{
        Prefix = $prefix
        Start = $startOctet
        End = $endOctet
        Display = "$prefix.$startOctet-$prefix.$endOctet"
        Source = $source
    }
}

function Get-NetworkMacAddress {
    param([string]$IpAddress)

    $mac = "-"

    try {
        $neighbor = Get-NetNeighbor -AddressFamily IPv4 -IPAddress $IpAddress -ErrorAction Stop |
            Where-Object {
                $_.LinkLayerAddress -and
                $_.LinkLayerAddress -notmatch '^(00[-:]00[-:]00[-:]00[-:]00[-:]00)$'
            } |
            Select-Object -First 1

        if ($neighbor -and $neighbor.LinkLayerAddress) {
            return ($neighbor.LinkLayerAddress -replace ':', '-').ToUpper()
        }
    } catch {}

    try {
        $arpOutput = arp -a $IpAddress 2>$null
        if ($arpOutput) {
            $match = [regex]::Match(($arpOutput -join "`n"), '(?i)([0-9a-f]{2}[-:]){5}[0-9a-f]{2}')
            if ($match.Success) {
                $mac = ($match.Value -replace ':', '-').ToUpper()
            }
        }
    } catch {}

    return $mac
}

function Test-NetworkHostAlive {
    param(
        [string]$IpAddress,
        [int]$TimeoutMs
    )

    $pinger = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $pinger.Send($IpAddress, $TimeoutMs)
        return ($reply -and $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success)
    } catch {
        return $false
    } finally {
        if ($pinger) { $pinger.Dispose() }
    }
}

$NetworkScanRows = @()
$NetworkScanHostCount = 0
$NetworkActiveCount = 0
$NetworkInactiveCount = 0
$NetworkScanDisplay = 'Disabled'
$NetworkScanSource = 'Disabled'

if ($EnableNetworkDiscovery) {
    $NetworkDefaultIPv4 = Get-PreferredLocalIPv4
    $NetworkScanRangeObj = Resolve-NetworkScanRange -InputRange $NetworkScanInput -DefaultIPv4 $NetworkDefaultIPv4

    if (-not $NetworkScanRangeObj -or [string]::IsNullOrWhiteSpace([string]($NetworkScanRangeObj.Prefix))) {
        $fallbackParts = @($NetworkDefaultIPv4 -split '\.')
        if ($fallbackParts.Count -lt 4) { $fallbackParts = @('192','168','1','1') }
        $fallbackPrefix = "$($fallbackParts[0]).$($fallbackParts[1]).$($fallbackParts[2])"
        $NetworkScanRangeObj = [PSCustomObject]@{
            Prefix = $fallbackPrefix
            Start = 0
            End = 254
            Display = "$fallbackPrefix.0-$fallbackPrefix.254"
            Source = 'Fallback local /24'
        }
    }

    $NetworkScanDisplay = [string]($NetworkScanRangeObj.Display)
    $NetworkScanSource = [string]($NetworkScanRangeObj.Source)
    $NetworkTotalHosts = ([int]($NetworkScanRangeObj.End) - [int]($NetworkScanRangeObj.Start)) + 1
    if ($NetworkTotalHosts -lt 1) { $NetworkTotalHosts = 1 }
    $NetworkProgressCounter = 0

    for ($octet = [int]($NetworkScanRangeObj.Start); $octet -le [int]($NetworkScanRangeObj.End); $octet++) {
        $ip = "$($NetworkScanRangeObj.Prefix).$octet"
        $NetworkScanHostCount++
        $NetworkProgressCounter++

        $status = 'Down'
        $hostname = '-'
        $macAddress = '-'

        if (Test-NetworkHostAlive -IpAddress $ip -TimeoutMs $NetworkPingTimeoutMs) {
            $status = 'Up'
            try {
                $dns = [System.Net.Dns]::GetHostEntry($ip)
                if ($dns -and $dns.HostName) { $hostname = $dns.HostName }
            } catch {}

            $macAddress = Get-NetworkMacAddress -IpAddress $ip
        }

        $NetworkScanRows += [PSCustomObject]@{
            IP = $ip
            HostName = $hostname
            MacAddress = $macAddress
            Status = $status
            IpOrder = $octet
        }

        if (($NetworkProgressCounter % 5 -eq 0) -or ($NetworkProgressCounter -eq $NetworkTotalHosts)) {
            Write-Output ("NETPROG|{0}|{1}" -f $NetworkProgressCounter, $NetworkTotalHosts)
        }
    }

    $NetworkActiveCount = @($NetworkScanRows | Where-Object { $_.Status -eq 'Up' }).Count
    $NetworkInactiveCount = $NetworkScanHostCount - $NetworkActiveCount
}


# ---------------------
# AD Users & Groups
# ---------------------
# Fetch all users once (other user lists are derived from this)
$Users = Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,LastLogonTimestamp,SamAccountName,servicePrincipalName,DistinguishedName,EmailAddress,PasswordLastSet,LockedOut,BadLogonCount |
         Where-Object { $_.Name -notmatch "^(Federated|Discovery|Health|Migration|System|Exchange Online)" } |
         Select Name, Enabled, PasswordNeverExpires, LastLogonTimestamp, SamAccountName, DistinguishedName, servicePrincipalName, EmailAddress, PasswordLastSet, LockedOut, BadLogonCount

# Fetch all Groups (Shortened)
# For performance, use group "member" attribute instead of recursive member count (direct member count).
$AllGroups = Get-ADGroup -Filter * -Properties GroupScope, GroupCategory, ManagedBy, member | 
       Select Name,
           SamAccountName,
           GroupCategory,
           GroupScope,
           @{Name="ManagedBy";Expression={$_.ManagedBy -replace '^CN=([^,]+),.*$', '$1'}},
           @{Name="MemberDNs";Expression={@($_.member)}},
           @{Name="MemberCount";Expression={@($_.member).Count}}

$SecurityGroups = $AllGroups | Where-Object {$_.GroupCategory -eq "Security"} | Sort Name
$DistributionGroups = $AllGroups | Where-Object {$_.GroupCategory -eq "Distribution"} | Sort Name

# Convert group members to JSON-like structure (for Javascript transfer)
# Group member list limit to prevent report bloat in large environments.
$MaxGroupMembersToRender = 300
$GroupMembersData = @{}
foreach ($g in $AllGroups) {
    # Fast name extraction from direct member DN list instead of recursive query.
    $Members = @(
        $g.MemberDNs |
            ForEach-Object {
                if ($_) { ($_ -replace '^CN=([^,]+),.*$', '$1') }
            } |
            Where-Object { $_ } |
            Sort-Object
    )

    if ($Members.Count -gt $MaxGroupMembersToRender) {
        $TruncatedMembers = $Members | Select-Object -First $MaxGroupMembersToRender
        $TruncatedMembers += "... (+$($Members.Count - $MaxGroupMembersToRender) more)"
        $GroupMembersData[$g.SamAccountName] = $TruncatedMembers
    } else {
        $GroupMembersData[$g.SamAccountName] = $Members
    }
}
$GroupMembersJson = $GroupMembersData | ConvertTo-Json -Compress

# ---------------------
# Privileged Groups & Critical Infrastructure Review
# ---------------------
$ObjectRiskDetailsMap = @{}

function Get-GroupReviewRow {
    param(
        [string]$GroupName,
        [string]$Priority,
        [string]$Category,
        [string]$Analysis
    )

    $row = [ordered]@{
        ObjectName = $GroupName
        Priority = $Priority
        Category = $Category
        Analysis = $Analysis
        Exists = $true
        UsersMember = 0
        ComputersMember = 0
        IndirectControl = 0
        UnresolvedMembers = 0
        Links = "None"
        DetailKey = ($GroupName -replace '[^a-zA-Z0-9_-]', '_')
        GroupSam = ""
    }

    $users = @()
    $computers = @()
    $indirectGroups = @()
    $unresolved = @()

    try {
        $group = Get-ADGroup -Identity $GroupName -Properties member,SamAccountName -ErrorAction Stop
        $row.GroupSam = $group.SamAccountName

        foreach ($memberDn in @($group.member)) {
            if ([string]::IsNullOrWhiteSpace($memberDn)) { continue }

            try {
                $obj = Get-ADObject -Identity $memberDn -Properties objectClass,sAMAccountName,name -ErrorAction Stop
                $displayName = if ($obj.sAMAccountName) { $obj.sAMAccountName } else { $obj.Name }

                switch ($obj.ObjectClass) {
                    "user" { $users += $displayName }
                    "computer" { $computers += $displayName }
                    "group" { $indirectGroups += $displayName }
                    default { }
                }
            } catch {
                $unresolved += $memberDn
            }
        }
    } catch {
        $Analysis = "$Analysis Group cannot be resolved or access is denied."
        $row.Analysis = $Analysis
        $row.Exists = $false
    }

    $row.UsersMember = @($users).Count
    $row.ComputersMember = @($computers).Count
    $row.IndirectControl = @($indirectGroups).Count
    $row.UnresolvedMembers = @($unresolved).Count

    $detailBase = $row.DetailKey
    $ObjectRiskDetailsMap["$detailBase|analysis"] = @(
        "Object: $GroupName",
        "Category: $Category",
        "Priority: $Priority",
        "Analysis: $Analysis",
        "Users Member: $($row.UsersMember)",
        "Computer Member: $($row.ComputersMember)",
        "Indirect Control (Nested Groups): $($row.IndirectControl)",
        "Unresolved Members: $($row.UnresolvedMembers)"
    )
    $ObjectRiskDetailsMap["$detailBase|users"] = if (@($users).Count -gt 0) { @($users | Sort-Object) } else { @("No user member.") }
    $ObjectRiskDetailsMap["$detailBase|computers"] = if (@($computers).Count -gt 0) { @($computers | Sort-Object) } else { @("No computer member.") }
    $ObjectRiskDetailsMap["$detailBase|indirect"] = if (@($indirectGroups).Count -gt 0) { @($indirectGroups | Sort-Object) } else { @("No indirect control group.") }
    $ObjectRiskDetailsMap["$detailBase|unresolved"] = if (@($unresolved).Count -gt 0) { @($unresolved | Sort-Object) } else { @("No unresolved member.") }

    return [PSCustomObject]$row
}

function Get-IdentityReviewRow {
    param(
        [string]$IdentityName,
        [string]$Priority,
        [string]$Category,
        [string]$Analysis,
        [string]$ObjectType
    )

    $key = ($IdentityName -replace '[^a-zA-Z0-9_-]', '_')
    $exists = $false

    try {
        switch ($ObjectType) {
            "user" { $null = Get-ADUser -Identity $IdentityName -ErrorAction Stop }
            "objectdn" { $null = Get-ADObject -Identity $IdentityName -ErrorAction Stop }
            default { }
        }
        $exists = $true
    } catch {
        $exists = $false
    }

    $ObjectRiskDetailsMap["$key|analysis"] = @(
        "Object: $IdentityName",
        "Category: $Category",
        "Priority: $Priority",
        "Status: $(if ($exists) { 'Found' } else { 'Not Found / Access Limited' })",
        "Analysis: $Analysis"
    )

    return [PSCustomObject]@{
        ObjectName = if ($ObjectType -eq "objectdn") { ($IdentityName -replace '^CN=([^,]+),.*$', '$1') } else { $IdentityName }
        Priority = $Priority
        Category = $Category
        Analysis = $Analysis
        Exists = $exists
        UsersMember = "-"
        ComputersMember = "-"
        IndirectControl = 0
        UnresolvedMembers = 0
        Links = "None"
        DetailKey = $key
        GroupSam = ""
    }
}

function Get-PrioritySeverity {
    param([string]$Priority)

    switch ($Priority) {
        "Critical" { return "Critical" }
        "High" { return "High" }
        "Medium" { return "Medium" }
        default { return "Low" }
    }
}

function Get-IntOrZero {
    param([object]$Value)

    $parsed = 0
    if ($null -ne $Value -and [int]::TryParse($Value.ToString(), [ref]$parsed)) {
        return $parsed
    }

    return 0
}

$PrivilegedGroupReviewRows = @(
    Get-GroupReviewRow -GroupName "Account Operators" -Priority "High" -Category "Admin Groups" -Analysis "Accounts with broad account-management rights should remain empty in modern tiered administration."
    Get-IdentityReviewRow -IdentityName "Administrator" -Priority "Critical" -Category "Admin Groups" -ObjectType "user" -Analysis "Built-in Administrator should be protected, monitored and rarely used."
    Get-GroupReviewRow -GroupName "Administrators" -Priority "Critical" -Category "Admin Groups" -Analysis "Builtin Administrators grants extensive control on domain controllers and critical systems."
    Get-GroupReviewRow -GroupName "Backup Operators" -Priority "High" -Category "Admin Groups" -Analysis "Backup privileges can bypass file ACL boundaries and expose sensitive data."
    Get-GroupReviewRow -GroupName "Certificate Operators" -Priority "Medium" -Category "Admin Groups" -Analysis "Certificate-related operations can impact PKI trust and authentication paths."
    Get-GroupReviewRow -GroupName "Certificate Publishers" -Priority "Other" -Category "Admin Groups" -Analysis "Publishing certificate data can indirectly affect authentication hygiene."
    Get-GroupReviewRow -GroupName "DnsAdmins" -Priority "Medium" -Category "Admin Groups" -Analysis "DNS admins can influence name resolution and potentially abuse DC plugin loading paths."
    Get-GroupReviewRow -GroupName "Domain Admins" -Priority "Critical" -Category "Admin Groups" -Analysis "Domain-wide administrative rights should be tightly limited and controlled."
    Get-GroupReviewRow -GroupName "Enterprise Admins" -Priority "Critical" -Category "Admin Groups" -Analysis "Forest-wide administrative rights should remain minimal and break-glass only."
    Get-GroupReviewRow -GroupName "Enterprise Key Admins" -Priority "Medium" -Category "Admin Groups" -Analysis "Key administration rights can affect account credentials and key material."
    Get-GroupReviewRow -GroupName "Group Policy Creator Owners" -Priority "Medium" -Category "Admin Groups" -Analysis "GPO creation rights can enable broad policy abuse if not constrained."
    Get-GroupReviewRow -GroupName "Print Operators" -Priority "High" -Category "Admin Groups" -Analysis "Print-related rights on DCs have historically enabled privilege escalation paths."
    Get-GroupReviewRow -GroupName "Server Operators" -Priority "High" -Category "Admin Groups" -Analysis "Server operators can perform service-level changes that impact domain security."
    Get-GroupReviewRow -GroupName "Schema Admins" -Priority "Critical" -Category "Admin Groups" -Analysis "Schema changes are high-impact and should be temporary, approved and audited."
    Get-GroupReviewRow -GroupName "Key Admins" -Priority "Medium" -Category "Admin Groups" -Analysis "Key admin roles should be isolated and protected by strong monitoring."
)

$CriticalInfrastructureRows = @(
    Get-IdentityReviewRow -IdentityName "CN=AdminSDHolder,CN=System,$($DomainInfo.DistinguishedName)" -Priority "Critical" -Category "Critical Infrastructure" -ObjectType "objectdn" -Analysis "AdminSDHolder ACL controls protected accounts and must be hardened."
    Get-IdentityReviewRow -IdentityName "CN=Builtin,$($DomainInfo.DistinguishedName)" -Priority "Medium" -Category "Critical Infrastructure" -ObjectType "objectdn" -Analysis "Builtin container content should be reviewed for delegated administrative access."
    Get-IdentityReviewRow -IdentityName "CN=Public Key Services,CN=Services,$($ForestInfo.ConfigurationNamingContext)" -Priority "Medium" -Category "Critical Infrastructure" -ObjectType "objectdn" -Analysis "PKI configuration objects define certificate trust behavior across the forest."
    Get-IdentityReviewRow -IdentityName "CN=Computers,$($DomainInfo.DistinguishedName)" -Priority "Medium" -Category "Critical Infrastructure" -ObjectType "objectdn" -Analysis "Default Computers container delegation should be reviewed for abuse paths."
    Get-GroupReviewRow -GroupName "Domain Controllers" -Priority "Critical" -Category "Critical Infrastructure" -Analysis "Membership should only contain legitimate domain controller computer accounts."
    Get-IdentityReviewRow -IdentityName "$($DomainInfo.DistinguishedName)" -Priority "Medium" -Category "Critical Infrastructure" -ObjectType "objectdn" -Analysis "Domain root ACL and delegated links can create indirect control paths."
    Get-GroupReviewRow -GroupName "Enterprise Read-only Domain Controllers" -Priority "Other" -Category "Critical Infrastructure" -Analysis "Review membership to ensure only intended RODC computer accounts are present."
    Get-GroupReviewRow -GroupName "Group Policy Creator Owners" -Priority "Medium" -Category "Critical Infrastructure" -Analysis "GPO creator rights should align with delegated administration boundaries."
    Get-IdentityReviewRow -IdentityName "krbtgt" -Priority "Medium" -Category "Critical Infrastructure" -ObjectType "user" -Analysis "krbtgt account lifecycle and password rotations are critical against ticket forgery."
    Get-GroupReviewRow -GroupName "Read-only Domain Controllers" -Priority "Medium" -Category "Critical Infrastructure" -Analysis "RODC group membership should reflect actual deployment and branch office design."
)

$PrivilegedReviewTotalRows = @($PrivilegedGroupReviewRows).Count + @($CriticalInfrastructureRows).Count
$ObjectRiskDetailsJson = $ObjectRiskDetailsMap | ConvertTo-Json -Depth 6 -Compress

$GroupMembersJsPath = Join-Path $PSScriptRoot "tools\groupMembersData.js"
$ObjectRiskJsPath = Join-Path $PSScriptRoot "tools\objectRiskData.js"
try {
    [System.IO.File]::WriteAllText($GroupMembersJsPath, ("window.__adcheckGroupMembers = " + $GroupMembersJson + ";"), [System.Text.UTF8Encoding]::new($false))
} catch {}
try {
    [System.IO.File]::WriteAllText($ObjectRiskJsPath, ("window.__adcheckObjectRiskDetails = " + $ObjectRiskDetailsJson + ";"), [System.Text.UTF8Encoding]::new($false))
} catch {}

# Identify Privileged Groups (for user filters)
function Get-PrivilegedGroupMembers($GroupName) {
    try {
        return Get-ADGroupMember $GroupName -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
    } catch {
        Write-Warning "Group '$GroupName' could not be retrieved: $($_.Exception.Message)"
        return @()
    }
}

$DomainAdmins = Get-PrivilegedGroupMembers "Domain Admins"
$SchemaAdmins = Get-PrivilegedGroupMembers "Schema Admins"
$EnterpriseAdmins = Get-PrivilegedGroupMembers "Enterprise Admins"

# User Filters (Shortened)
$UserFilters = @{
    "AllUsers" = $Users
    "NeverExpiresUsers" = $Users | Where-Object {$_.PasswordNeverExpires -eq $true}
    "DomainAdminsUsers" = $Users | Where-Object {$DomainAdmins -contains $_.SamAccountName}
    "SchemaAdminsUsers" = $Users | Where-Object {$SchemaAdmins -contains $_.SamAccountName}
    "EnterpriseAdminsUsers" = $Users | Where-Object {$EnterpriseAdmins -contains $_.SamAccountName}
    "DisabledUsers" = $Users | Where-Object {$_.Enabled -eq $false}
}


# ---------------------
# Other Categories (Shortened)
# ---------------------
# ... (Exchange, Locked, Password Expiry, Inactive, DC Health code remains the same)
try {
    $ExchangeUsers = Get-ADUser -Filter * -Properties EmailAddress,proxyAddresses,targetAddress,RecipientTypeDetails,RemoteRecipientType |
        Where-Object { $_.EmailAddress } |
        Select-Object Name,
                      EmailAddress,
                      @{Name="Type";Expression={
                          $target = "$(($_.targetAddress))"
                          $recipientType = "$(($_.RecipientTypeDetails))"
                          $remoteRecipient = if ($null -ne $_.RemoteRecipientType) { [int]$_.RemoteRecipientType } else { 0 }
                          $proxyJoined = (@($_.proxyAddresses) -join ";")

                          if (
                              $target -match "onmicrosoft\\.com" -or
                              $proxyJoined -match "onmicrosoft\\.com" -or
                              $recipientType -match "Remote" -or
                              $remoteRecipient -gt 0
                          ) {
                              "O365 User"
                          } else {
                              "Exchange User"
                          }
                      }}
} catch {
    # Fallback: if Exchange attributes cannot be read, build a basic view from existing user list.
    $ExchangeUsers = $Users |
        Where-Object { $_.EmailAddress } |
        Select-Object Name,
                      EmailAddress,
                      @{Name="Type";Expression={"Exchange User"}}
}

$LockedAccounts = $Users |
          Where-Object { $_.LockedOut -eq $true } |
          Select Name,
              @{Name="LockoutTime";Expression={"N/A"}},
              @{Name="BadPwdCount";Expression={if ($_.BadLogonCount -ne $null) { $_.BadLogonCount } else { "N/A" }}}

$PwdExpiry = $Users |
             Select-Object Name, 
                            @{Name="PasswordLastSet";Expression={if ($_.PasswordLastSet) {$_.PasswordLastSet.ToString("dd/MM/yyyy")} else {"Never"}}}, 
                            @{Name="PasswordExpiryDate";Expression={
                                if ($_.PasswordNeverExpires -or -not $_.Enabled) {
                                    return "N/A"
                                }
                                
                                if ($_.PasswordLastSet -and $PwdPolicy) {
                                    $ExpiryDate = $_.PasswordLastSet + $PwdPolicy.MaxPasswordAge
                                    
                                    if ($ExpiryDate -lt $Today) {
                                        return "Expired"
                                    }
                                    
                                    return $ExpiryDate.ToString("dd/MM/yyyy")
                                } 
                                return "N/A"
                            }}

$InactiveUsers = $Users |
                Where-Object { -not $_.LastLogonTimestamp -or $_.LastLogonTimestamp -lt $InactivityThreshold.ToFileTimeUtc() } |
                Select Name, @{Name="LastLogon";Expression={Convert-ADTimestamp $_.LastLogonTimestamp}}
                
$InactiveComputers = $AllComputers |
                    Where-Object { -not $_.LastLogonTimestamp -or $_.LastLogonTimestamp -lt $InactivityThreshold.ToFileTimeUtc() } |
                    Select Name, @{Name="LastLogon";Expression={Convert-ADTimestamp $_.LastLogonTimestamp}}, OperatingSystem

$InactiveVeryStaleThreshold = (Get-Date).AddDays(-180).ToFileTimeUtc()
$InactiveUsersNeverLogonCount = @($Users | Where-Object { -not $_.LastLogonTimestamp }).Count
$InactiveUsersVeryStaleCount = @($Users | Where-Object { $_.LastLogonTimestamp -and $_.LastLogonTimestamp -lt $InactiveVeryStaleThreshold }).Count
$InactiveComputersNeverLogonCount = @($AllComputers | Where-Object { -not $_.LastLogonTimestamp }).Count
$InactiveComputersVeryStaleCount = @($AllComputers | Where-Object { $_.LastLogonTimestamp -and $_.LastLogonTimestamp -lt $InactiveVeryStaleThreshold }).Count

# ---------------------
# AD User Risk Level (Authentication Telemetry)
# ---------------------
$UserRiskLookbackDays = 7
$UserRiskEventStart = (Get-Date).AddDays(-$UserRiskLookbackDays)
$UserRiskFailedMaxEventsPerDc = 10000
$UserRiskFailedMaxEventsPerEndpoint = 2000
$UserRiskEndpointMaxHosts = 150

$UserRiskLockoutEvents = @()
$UserRiskEndpointLookbackDays = 30

$UserRiskLockoutEvents = @()
$UserRiskFailedEvents = @()
$UserRiskUserDeviceEvents = @()

$UserRiskDcs = if ($SkipHeavyTelemetry) { @() } else { $DCs }
$DcNameList = @($DCs | ForEach-Object { [string]$_.Name } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$UserRiskEndpointCandidates = if ($SkipHeavyTelemetry) {
    @()
$EndpointLookbackStart = (Get-Date).AddDays(-$UserRiskEndpointLookbackDays)
} else {
    @(
        $AllComputers |
            Where-Object {
                $name = [string]$_.Name
                if ([string]::IsNullOrWhiteSpace($name)) { return $false }
                if ($DcNameList -contains $name) { return $false }
                if (-not $_.LastLogonTimestamp) { return $false }

                try {
                    $lastSeen = [DateTime]::FromFileTime([int64]$_.LastLogonTimestamp)
                    return $lastSeen -ge $EndpointLookbackStart
                } catch {
                    return $false
                }
            } |
            Sort-Object Name |
            Select-Object -ExpandProperty Name -First $UserRiskEndpointMaxHosts
    )
}

foreach ($dc in $UserRiskDcs) {
    # Lockout events (4740)
    try {
        $LockoutData = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            param($StartTime, $MaxEvents)

            Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=$StartTime} -ErrorAction Stop |
                Select-Object -First $MaxEvents |
                ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $eventData = @{}
                    foreach ($node in $xml.Event.EventData.Data) {
                        $eventData[$node.Name] = [string]$node.'#text'
                    }

                    $targetUser = $eventData['TargetUserName']
                    $sourceComputer = $eventData['CallerComputerName']
                    if ([string]::IsNullOrWhiteSpace($targetUser)) { return }

                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        TargetUser = $targetUser
                        Source = if ([string]::IsNullOrWhiteSpace($sourceComputer)) { '-' } else { $sourceComputer }
                        DC = $env:COMPUTERNAME
                    }
                }
        } -ArgumentList $UserRiskEventStart, 300 -ErrorAction Stop

        if ($LockoutData) { $UserRiskLockoutEvents += $LockoutData }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "User Risk 4740" -Reason $_.Exception.Message
    }

    # Failed logon events (4625)
    try {
        $FailedData = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            param($StartTime, $MaxEvents)

            Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$StartTime} -ErrorAction Stop |
                Select-Object -First $MaxEvents |
                ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $eventData = @{}
                    foreach ($node in $xml.Event.EventData.Data) {
                        $eventData[$node.Name] = [string]$node.'#text'
                    }

                    $targetUser = $eventData['TargetUserName']
                    $workstation = $eventData['WorkstationName']
                    $ipAddress = $eventData['IpAddress']
                    $source = if (-not [string]::IsNullOrWhiteSpace($workstation)) { $workstation } elseif (-not [string]::IsNullOrWhiteSpace($ipAddress)) { $ipAddress } else { '-' }

                    if (
                        [string]::IsNullOrWhiteSpace($targetUser) -or
                        $targetUser -eq '-' -or
                        $targetUser -eq 'ANONYMOUS LOGON' -or
                        $targetUser.EndsWith('$')
                    ) { return }

                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        TargetUser = $targetUser
                        Source = $source
                        DC = $env:COMPUTERNAME
                    }
                }
        } -ArgumentList $UserRiskEventStart, $UserRiskFailedMaxEventsPerDc -ErrorAction Stop

        if ($FailedData) { $UserRiskFailedEvents += $FailedData }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "User Risk 4625" -Reason $_.Exception.Message
    }

    # User-device visibility from successful logons (4624)
    try {
        $UserDeviceData = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            param($StartTime, $MaxEvents)

            Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$StartTime} -ErrorAction Stop |
                Select-Object -First $MaxEvents |
                ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $eventData = @{}
                    foreach ($node in $xml.Event.EventData.Data) {
                        $eventData[$node.Name] = [string]$node.'#text'
                    }

                    $targetUser = $eventData['TargetUserName']
                    $logonType = $eventData['LogonType']
                    $workstation = $eventData['WorkstationName']
                    $ipAddress = $eventData['IpAddress']
                    $source = if (-not [string]::IsNullOrWhiteSpace($workstation)) { $workstation } elseif (-not [string]::IsNullOrWhiteSpace($ipAddress)) { $ipAddress } else { '' }
                    $normalizedUser = if ([string]::IsNullOrWhiteSpace($targetUser)) { '' } else { $targetUser.ToLowerInvariant() }
                    $normalizedSource = if ([string]::IsNullOrWhiteSpace($source)) { '' } else { $source.ToLowerInvariant() }
                    $isNoiseUser = (
                        $normalizedUser -match '(^|\\)healthmailbox' -or
                        $normalizedUser -match '(^|\\)dwm-\d+$' -or
                        $normalizedUser -match '(^|\\)umfd-\d+$' -or
                        $normalizedUser -match '(^|\\)umdf-\d+$' -or
                        $normalizedUser -eq 'defaultaccount' -or
                        $normalizedUser -eq 'wdagutilityaccount'
                    )
                    $isNoiseSource = (
                        $normalizedSource -match '(^|\\)dwm-\d+$' -or
                        $normalizedSource -match '(^|\\)umfd-\d+$' -or
                        $normalizedSource -match '(^|\\)umdf-\d+$'
                    )

                    if (
                        [string]::IsNullOrWhiteSpace($targetUser) -or
                        $targetUser -eq '-' -or
                        $targetUser -eq 'ANONYMOUS LOGON' -or
                        $targetUser.EndsWith('$') -or
                        $isNoiseUser -or
                        [string]::IsNullOrWhiteSpace($source) -or
                        $source -eq '-' -or
                        $isNoiseSource -or
                        ($logonType -notin @('2', '3', '7', '10', '11'))
                    ) { return }

                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        TargetUser = $targetUser
                        Source = $source
                        LogonType = $logonType
                        DC = $env:COMPUTERNAME
                    }
                }
        } -ArgumentList $UserRiskEventStart, 1500 -ErrorAction Stop

        if ($UserDeviceData) { $UserRiskUserDeviceEvents += $UserDeviceData }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "User Risk 4624" -Reason $_.Exception.Message
    }
}

# Failed logon events (4625) from active member endpoints (e.g., SCCM/application servers/workstations)
foreach ($endpoint in $UserRiskEndpointCandidates) {
    try {
        $EndpointFailedData = Invoke-Command -ComputerName $endpoint -ScriptBlock {
            param($StartTime, $MaxEvents)

            Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$StartTime} -ErrorAction Stop |
                Select-Object -First $MaxEvents |
                ForEach-Object {
                    $xml = [xml]$_.ToXml()
                    $eventData = @{}
                    foreach ($node in $xml.Event.EventData.Data) {
                        $eventData[$node.Name] = [string]$node.'#text'
                    }

                    $targetUser = $eventData['TargetUserName']
                    $workstation = $eventData['WorkstationName']
                    $ipAddress = $eventData['IpAddress']
                    $source = if (-not [string]::IsNullOrWhiteSpace($workstation)) { $workstation } elseif (-not [string]::IsNullOrWhiteSpace($ipAddress)) { $ipAddress } else { '-' }

                    if (
                        [string]::IsNullOrWhiteSpace($targetUser) -or
                        $targetUser -eq '-' -or
                        $targetUser -eq 'ANONYMOUS LOGON' -or
                        $targetUser.EndsWith('$')
                    ) { return }

                    [PSCustomObject]@{
                        TimeCreated = $_.TimeCreated
                        TargetUser = $targetUser
                        Source = $source
                        DC = $env:COMPUTERNAME
                    }
                }
        } -ArgumentList $UserRiskEventStart, $UserRiskFailedMaxEventsPerEndpoint -ErrorAction Stop

        if ($EndpointFailedData) { $UserRiskFailedEvents += $EndpointFailedData }
    } catch {
        Add-SkippedDCRecord -DC $endpoint -Section "User Risk 4625 Endpoint" -Reason $_.Exception.Message
    }
}

$UserRiskFailedEvents = @(
    $UserRiskFailedEvents |
        Where-Object { $_ } |
        Group-Object {
            $ts = if ($_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { '-' }
            "$ts|$($_.TargetUser)|$($_.Source)|$($_.DC)"
        } |
        ForEach-Object { $_.Group | Select-Object -First 1 }
)

function Test-IsNoiseUserRiskIdentity {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()

    return (
        $v -imatch '(^|\\)healthmailbox' -or
        $v -imatch '(^|\\)dwm-\d+$' -or
        $v -imatch '(^|\\)umfd-\d+$' -or
        $v -imatch '(^|\\)umdf-\d+$' -or
        $v -ieq 'defaultaccount' -or
        $v -ieq 'wdagutilityaccount'
    )
}

function Test-IsNoiseUserRiskEndpoint {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $v = $Value.Trim()

    return (
        $v -imatch '(^|\\)dwm-\d+$' -or
        $v -imatch '(^|\\)umfd-\d+$' -or
        $v -imatch '(^|\\)umdf-\d+$'
    )
}

$UserRiskUserDeviceEvents = @(
    $UserRiskUserDeviceEvents |
        Where-Object {
            -not (Test-IsNoiseUserRiskIdentity $_.TargetUser) -and
            -not (Test-IsNoiseUserRiskEndpoint $_.Source)
        }
)

$UserRiskLockoutTimeline = @($UserRiskLockoutEvents | Sort-Object TimeCreated -Descending | Select-Object -First 200)

$UserRiskFailedByUser = @(
    $UserRiskFailedEvents |
        Group-Object TargetUser |
        ForEach-Object {
            $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $topSources = $_.Group | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name }
            [PSCustomObject]@{
                TargetUser = $_.Name
                FailedCount = $_.Count
                LastSeen = if ($latest) { $latest.TimeCreated } else { $null }
                TopSources = if ($topSources) { $topSources -join ', ' } else { '-' }
            }
        } |
        Sort-Object -Property FailedCount, LastSeen -Descending |
        Select-Object -First 100
)

$UserRiskFailedBySource = @(
    $UserRiskFailedEvents |
        Group-Object Source |
        ForEach-Object {
            $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $topUsers = $_.Group | Group-Object TargetUser | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name }
            [PSCustomObject]@{
                Source = if ([string]::IsNullOrWhiteSpace($_.Name)) { '-' } else { $_.Name }
                FailedCount = $_.Count
                LastSeen = if ($latest) { $latest.TimeCreated } else { $null }
                TopUsers = if ($topUsers) { $topUsers -join ', ' } else { '-' }
            }
        } |
        Sort-Object -Property FailedCount, LastSeen -Descending |
        Select-Object -First 100
)

$PrivilegedIdentityNames = @(
    $DomainAdmins + $SchemaAdmins + $EnterpriseAdmins |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)

$PrivilegedWatchlistRowsRaw = @(
    foreach ($privUser in $PrivilegedIdentityNames) {
        $privFailedEvents = @($UserRiskFailedEvents | Where-Object { $_.TargetUser -eq $privUser })
        $privLockouts = @($UserRiskLockoutEvents | Where-Object { $_.TargetUser -eq $privUser })
        $privActivity = @($UserRiskActivityRows | Where-Object { $_.TargetUser -eq $privUser })
        $latest = $privActivity | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $topSources = $privFailedEvents | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name }
        $memberGroups = @()
        if ($DomainAdmins -contains $privUser) { $memberGroups += 'Domain Admins' }
        if ($SchemaAdmins -contains $privUser) { $memberGroups += 'Schema Admins' }
        if ($EnterpriseAdmins -contains $privUser) { $memberGroups += 'Enterprise Admins' }

        [PSCustomObject]@{
            TargetUser = $privUser
            Groups = if ($memberGroups) { $memberGroups -join ', ' } else { 'Privileged' }
            FailedCount = $privFailedEvents.Count
            LockoutCount = $privLockouts.Count
            EventCount = $privActivity.Count
            LastSeen = if ($latest) { $latest.TimeCreated } else { $null }
            TopSources = if ($topSources) { $topSources -join ', ' } else { '-' }
            RiskScore = ($privFailedEvents.Count * 3) + ($privLockouts.Count * 5)
        }
    }
)
$PrivilegedWatchlistRows = @($PrivilegedWatchlistRowsRaw | Sort-Object -Property RiskScore, FailedCount, LockoutCount, LastSeen -Descending | Select-Object -First 50)

$PasswordSprayRowsRaw = @(
    foreach ($sourceGroup in ($UserRiskFailedEvents | Group-Object Source)) {
        $failedItems = @($sourceGroup.Group)
        $distinctUsers = @($failedItems.TargetUser | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        if ($distinctUsers.Count -lt 5 -or $failedItems.Count -lt 10) { continue }

        $latest = $failedItems | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $first = $failedItems | Sort-Object TimeCreated | Select-Object -First 1
        $topUsers = $failedItems | Group-Object TargetUser | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name }
        $windowMinutes = if ($first -and $latest) { [math]::Round(($latest.TimeCreated - $first.TimeCreated).TotalMinutes, 1) } else { 0 }

        [PSCustomObject]@{
            Source = if ([string]::IsNullOrWhiteSpace($sourceGroup.Name)) { '-' } else { $sourceGroup.Name }
            FailedCount = $failedItems.Count
            DistinctUsers = $distinctUsers.Count
            WindowMinutes = $windowMinutes
            FirstSeen = if ($first) { $first.TimeCreated } else { $null }
            LastSeen = if ($latest) { $latest.TimeCreated } else { $null }
            TopUsers = if ($topUsers) { $topUsers -join ', ' } else { '-' }
        }
    }
)
$PasswordSprayRows = @($PasswordSprayRowsRaw | Sort-Object -Property DistinctUsers, FailedCount, LastSeen -Descending | Select-Object -First 50)

$LockoutCorrelationRowsRaw = @(
    foreach ($lockout in $UserRiskLockoutTimeline) {
        if (-not $lockout.TargetUser -or -not $lockout.TimeCreated) { continue }

        $failedWindow = @(
            $UserRiskFailedEvents |
                Where-Object {
                    $_.TargetUser -eq $lockout.TargetUser -and
                    $_.TimeCreated -le $lockout.TimeCreated -and
                    $_.TimeCreated -ge $lockout.TimeCreated.AddMinutes(-30)
                }
        )

        if (-not $failedWindow.Count) { continue }

        $firstFailed = $failedWindow | Sort-Object TimeCreated | Select-Object -First 1
        $sourceGroups = $failedWindow | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 3
        $likelySources = if ($sourceGroups) { ($sourceGroups | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ' } else { '-' }

        [PSCustomObject]@{
            TargetUser = $lockout.TargetUser
            LockoutTime = $lockout.TimeCreated
            FailedBefore = $failedWindow.Count
            MinutesToLockout = if ($firstFailed) { [math]::Round(($lockout.TimeCreated - $firstFailed.TimeCreated).TotalMinutes, 1) } else { 0 }
            LikelySources = $likelySources
            FirstFailed = if ($firstFailed) { $firstFailed.TimeCreated } else { $null }
        }
    }
)
$LockoutCorrelationRows = @($LockoutCorrelationRowsRaw | Sort-Object -Property LockoutTime -Descending | Select-Object -First 50)

$UserRiskUserDeviceMap = @(
    $UserRiskUserDeviceEvents |
        Group-Object { "$($_.TargetUser)|$($_.Source)|$($_.LogonType)" } |
        ForEach-Object {
            $parts = $_.Name -split '\|', 3
            $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            [PSCustomObject]@{
                TargetUser = $parts[0]
                Source = if ($parts.Count -gt 1) { $parts[1] } else { '-' }
                LogonType = if ($parts.Count -gt 2) { $parts[2] } else { '-' }
                SeenCount = $_.Count
                LastSeen = if ($latest) { $latest.TimeCreated } else { $null }
                DC = if ($latest) { $latest.DC } else { '-' }
            }
        } |
        Sort-Object -Property SeenCount, LastSeen -Descending |
        Select-Object -First 150
)

function Split-UserRiskEndpoint {
    param([string]$Endpoint)

    $value = "$Endpoint".Trim()
    if ([string]::IsNullOrWhiteSpace($value) -or $value -eq "-") {
        return [PSCustomObject]@{ Host = "-"; IP = "-" }
    }

    $ipRegex = '^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$'
    if ($value -match $ipRegex) {
        return [PSCustomObject]@{ Host = "-"; IP = $value }
    }

    return [PSCustomObject]@{ Host = $value; IP = "-" }
}

function Convert-ToHtmlText {
    param([object]$Value)

    if ($null -eq $Value) { return "-" }
    $text = [string]$Value
    return [System.Net.WebUtility]::HtmlEncode($text)
}

function Convert-ToJsDoubleQuoted {
    param([object]$Value)

    if ($null -eq $Value) { return "" }
    $text = [string]$Value
    $text = $text -replace '\\', '\\\\'
    $text = $text -replace '"', '\\"'
    $text = $text -replace "`r", '\\r'
    $text = $text -replace "`n", '\\n'
    return $text
}
foreach ($ev in $UserRiskSuccessExplorerEvents) {
    $sourceParts = Split-UserRiskEndpoint $ev.Source
    $successReason = if ($ev.SuccessCount -gt 1) { "Aggregated success x$($ev.SuccessCount)" } else { "-" }
    $UserRiskActivityRows += [PSCustomObject]@{
        TimeCreated = $ev.TimeCreated
        EventStatus = "Success"
        TargetUser = $ev.TargetUser
        SourceHost = $sourceParts.Host
        SourceIP = $sourceParts.IP
        DestinationHost = $ev.DC
        DestinationIP = if ($DcIpMap.ContainsKey($ev.DC)) { $DcIpMap[$ev.DC] } else { "-" }
        LogonType = if ([string]::IsNullOrWhiteSpace($ev.LogonType)) { "-" } else { "$($ev.LogonType)" }
        FailureReason = $successReason
    }
}

foreach ($ev in $UserRiskLockoutEvents) {
    $sourceParts = Split-UserRiskEndpoint $ev.Source
    $UserRiskActivityRows += [PSCustomObject]@{
        TimeCreated = $ev.TimeCreated
        EventStatus = "Locked"
        TargetUser = $ev.TargetUser
        SourceHost = $sourceParts.Host
        SourceIP = $sourceParts.IP
        DestinationHost = $ev.DC
        DestinationIP = if ($DcIpMap.ContainsKey($ev.DC)) { $DcIpMap[$ev.DC] } else { "-" }
        LogonType = "-"
        FailureReason = "Account lockout"
    }
}

$UserRiskActivityRows = @($UserRiskActivityRows | Sort-Object TimeCreated -Descending | Select-Object -First 4000)

$UserRiskActivityForJs = @(
    $UserRiskActivityRows | ForEach-Object {
        [PSCustomObject]@{
            TimeIso = if ($_.TimeCreated) { $_.TimeCreated.ToString("o") } else { "" }
            TimeDisplay = if ($_.TimeCreated) { $_.TimeCreated.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
            Status = $_.EventStatus
            User = $_.TargetUser
            SourceHost = $_.SourceHost
            SourceIP = $_.SourceIP
            DestinationHost = $_.DestinationHost
            DestinationIP = $_.DestinationIP
            LogonType = $_.LogonType
            Reason = $_.FailureReason
        }
    }
)

$UserRiskFailedByUserForJs = @(
    $UserRiskFailedByUser | ForEach-Object {
        [PSCustomObject]@{
            TargetUser = if ([string]::IsNullOrWhiteSpace($_.TargetUser)) { "-" } else { "$($_.TargetUser)" }
            FailedCount = [int]$_.FailedCount
            LastSeenIso = if ($_.LastSeen) { $_.LastSeen.ToString("o") } else { "" }
            LastSeenDisplay = if ($_.LastSeen) { $_.LastSeen.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
            TopSources = if ([string]::IsNullOrWhiteSpace($_.TopSources)) { "-" } else { "$($_.TopSources)" }
        }
    }
)

$UserRiskFailedBySourceForJs = @(
    $UserRiskFailedBySource | ForEach-Object {
        [PSCustomObject]@{
            Source = if ([string]::IsNullOrWhiteSpace($_.Source)) { "-" } else { "$($_.Source)" }
            FailedCount = [int]$_.FailedCount
            LastSeenIso = if ($_.LastSeen) { $_.LastSeen.ToString("o") } else { "" }
            LastSeenDisplay = if ($_.LastSeen) { $_.LastSeen.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
            TopUsers = if ([string]::IsNullOrWhiteSpace($_.TopUsers)) { "-" } else { "$($_.TopUsers)" }
        }
    }
)
$UserRiskCachePath = Join-Path $PSScriptRoot "tools\user_risk_activity_cache.json"
$CurrentUserRiskRows = @($UserRiskActivityForJs).Count

if ($CurrentUserRiskRows -eq 0 -and (Test-Path $UserRiskCachePath)) {
    try {
        $cacheRaw = Get-Content -Path $UserRiskCachePath -Raw -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($cacheRaw)) {
            $cacheObj = $cacheRaw | ConvertFrom-Json -ErrorAction Stop
            if ($cacheObj) {
                if ($cacheObj.Activity) { $UserRiskActivityForJs = @($cacheObj.Activity) }
                if ($cacheObj.FailedByUser) { $UserRiskFailedByUserForJs = @($cacheObj.FailedByUser) }
                if ($cacheObj.FailedBySource) { $UserRiskFailedBySourceForJs = @($cacheObj.FailedBySource) }
            }
        }
    } catch {
        # Best effort cache restore; continue with empty datasets on parse/read errors.
    }
}

if (-not $SkipHeavyTelemetry -and @($UserRiskActivityForJs).Count -gt 0) {
    try {
        $cachePayload = [PSCustomObject]@{
            GeneratedAt = (Get-Date).ToString("o")
            Activity = @($UserRiskActivityForJs)
            FailedByUser = @($UserRiskFailedByUserForJs)
            FailedBySource = @($UserRiskFailedBySourceForJs)
        }
        $cachePayload | ConvertTo-Json -Depth 6 | Set-Content -Path $UserRiskCachePath -Encoding UTF8
    } catch {
        # Cache write failures should not block report generation.
    }
}

$UserRiskActivityJson = $UserRiskActivityForJs | ConvertTo-Json -Depth 5 -Compress
if ([string]::IsNullOrWhiteSpace($UserRiskActivityJson)) {
    $UserRiskActivityJson = "[]"
}

$UserRiskFailedByUserJson = $UserRiskFailedByUserForJs | ConvertTo-Json -Depth 5 -Compress
if ([string]::IsNullOrWhiteSpace($UserRiskFailedByUserJson)) {
    $UserRiskFailedByUserJson = "[]"
}

$UserRiskFailedBySourceJson = $UserRiskFailedBySourceForJs | ConvertTo-Json -Depth 5 -Compress
if ([string]::IsNullOrWhiteSpace($UserRiskFailedBySourceJson)) {
    $UserRiskFailedBySourceJson = "[]"
}

$UserRiskLookbackLabel = "Last $UserRiskLookbackDays days"
$UserRiskLockoutCountForBadge = @($UserRiskActivityForJs | Where-Object { [string]$_.Status -eq 'Locked' }).Count
$UserRiskPrivilegedAlertCount = @($PrivilegedWatchlistRows | Where-Object { $_.RiskScore -gt 0 }).Count
$UserRiskAlertCount = $UserRiskLockoutCountForBadge + @($UserRiskFailedByUserForJs).Count + @($PasswordSprayRows).Count + $UserRiskPrivilegedAlertCount + @($LockoutCorrelationRows).Count

$TrendNow = Get-Date
$Trend7Start = $TrendNow.AddDays(-7)
$Trend14Start = $TrendNow.AddDays(-14)

function Get-UserRiskTrendRateText {
    param(
        [int]$Count,
        [int]$Days
    )

    if ($Days -le 0) { return "0.00/day" }
    return ("{0:N2}/day" -f ($Count / [double]$Days))
}

$UserRiskTrendRows = @()
$TrendStatusMap = @(
    @{ Key = "Failed"; Label = "Failed Logons" },
    @{ Key = "Locked"; Label = "Lockouts" },
    @{ Key = "Success"; Label = "Success Logons" }
)

foreach ($ts in $TrendStatusMap) {
    $c7 = @($UserRiskActivityRows | Where-Object { $_.EventStatus -eq $ts.Key -and $_.TimeCreated -ge $Trend7Start }).Count
    $c14 = @($UserRiskActivityRows | Where-Object { $_.EventStatus -eq $ts.Key -and $_.TimeCreated -ge $Trend14Start }).Count
    $r7 = if ($c7 -gt 0) { $c7 / 7.0 } else { 0.0 }
    $r14 = if ($c14 -gt 0) { $c14 / 7.0 } else { 0.0 }

    if ($r14 -gt 0) {
        $deltaPct = [math]::Round((($r7 - $r14) / $r14) * 100, 1)
    } elseif ($r7 -gt 0) {
        $deltaPct = 100.0
    } else {
        $deltaPct = 0.0
    }

    $UserRiskTrendRows += [PSCustomObject]@{
        Metric = $ts.Label
        Count7 = $c7
        Count14 = $c14
        Rate7Text = Get-UserRiskTrendRateText -Count $c7 -Days 7
        Rate14Text = Get-UserRiskTrendRateText -Count $c14 -Days 7
        DeltaPct = $deltaPct
    }
}

$c7Actionable = @($UserRiskActivityRows | Where-Object { $_.EventStatus -in @('Failed','Locked') -and $_.TimeCreated -ge $Trend7Start }).Count
$c14Actionable = @($UserRiskActivityRows | Where-Object { $_.EventStatus -in @('Failed','Locked') -and $_.TimeCreated -ge $Trend14Start }).Count
$r7Actionable = if ($c7Actionable -gt 0) { $c7Actionable / 7.0 } else { 0.0 }
$r14Actionable = if ($c14Actionable -gt 0) { $c14Actionable / 7.0 } else { 0.0 }
if ($r14Actionable -gt 0) {
    $deltaActionable = [math]::Round((($r7Actionable - $r14Actionable) / $r14Actionable) * 100, 1)
} elseif ($r7Actionable -gt 0) {
    $deltaActionable = 100.0
} else {
    $deltaActionable = 0.0
}
$UserRiskTrendRows += [PSCustomObject]@{
    Metric = "Actionable (Failed+Locked)"
    Count7 = $c7Actionable
    Count14 = $c14Actionable
    Rate7Text = Get-UserRiskTrendRateText -Count $c7Actionable -Days 7
    Rate14Text = Get-UserRiskTrendRateText -Count $c14Actionable -Days 7
    DeltaPct = $deltaActionable
}

$HeatmapStart = $TrendNow.AddHours(-24)
$HeatmapEvents = @($UserRiskActivityRows | Where-Object {
    $_.TimeCreated -and $_.TimeCreated -ge $HeatmapStart -and $_.DestinationHost -and $_.DestinationHost -ne '-'
})

$UserRiskDcHeatmapRows = @()
$UserRiskDcHeatmapMax = 0
foreach ($dcName in @($DCs.Name | Sort-Object)) {
    $dcRows = @($HeatmapEvents | Where-Object { $_.DestinationHost -eq $dcName })
    $hourCounts = @{}
    $riskCounts = @{}

    for ($h = 0; $h -le 23; $h++) {
        $hourCounts[$h] = 0
        $riskCounts[$h] = 0
    }

    foreach ($r in $dcRows) {
        $h = [int]$r.TimeCreated.Hour
        $hourCounts[$h] += 1
        if ($r.EventStatus -ne 'Success') {
            $riskCounts[$h] += 1
        }
    }

    foreach ($h in 0..23) {
        if ($hourCounts[$h] -gt $UserRiskDcHeatmapMax) {
            $UserRiskDcHeatmapMax = $hourCounts[$h]
        }
    }

    $UserRiskDcHeatmapRows += [PSCustomObject]@{
        DC = $dcName
        HourCounts = $hourCounts
        RiskCounts = $riskCounts
        Total = @($dcRows).Count
    }
}

function Get-HeatCellClass {
    param(
        [int]$Count,
        [int]$Max
    )

    if ($Count -le 0 -or $Max -le 0) { return 'heat-cell-l0' }
    $ratio = $Count / [double]$Max
    if ($ratio -ge 0.75) { return 'heat-cell-l4' }
    if ($ratio -ge 0.50) { return 'heat-cell-l3' }
    if ($ratio -ge 0.25) { return 'heat-cell-l2' }
    return 'heat-cell-l1'
}

# ---------------------
# PingCastle-Style Risks (Focused and Actionable)
# ---------------------
$PingCastleFindings = @()
$PingCastleDetails = @()

function Add-PingFinding {
    param(
        [string]$Category,
        [string]$Rule,
        [string]$Severity,
        [object]$Count,
        [string]$Sample,
        [string]$Recommendation
    )

    $script:PingCastleFindings += [PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Rule = $Rule
        Count = $Count
        Sample = $Sample
        Recommendation = $Recommendation
    }
}

function Add-PingDetail {
    param(
        [string]$Category,
        [string]$Rule,
        [string]$Target,
        [string]$Detail,
        [string]$Severity
    )

    $script:PingCastleDetails += [PSCustomObject]@{
        Category = $Category
        Rule = $Rule
        Target = $Target
        Detail = $Detail
        Severity = $Severity
    }
}

function Get-CountComparableValue {
    param([object]$Value)

    if ($null -eq $Value) { return "" }

    $number = 0
    if ([double]::TryParse($Value.ToString(), [ref]$number)) {
        return [math]::Round($number, 2)
    }

    return $Value.ToString().Trim()
}

function Get-PingSeverityScore {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return 100 }
        "High" { return 85 }
        "Medium" { return 55 }
        "Low" { return 20 }
        default { return 0 }
    }
}

function Get-PingSeverityRank {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return 4 }
        "High" { return 3 }
        "Medium" { return 2 }
        "Low" { return 1 }
        default { return 0 }
    }
}

function Test-PingFindingMatched {
    param([object]$Finding)

    if ($null -eq $Finding) { return $false }

    $countComparable = Get-CountComparableValue $Finding.Count
    if ($countComparable -is [double] -or $countComparable -is [int] -or $countComparable -is [decimal]) {
        return ([double]$countComparable -gt 0)
    }

    $countText = "$countComparable".Trim()
    if (-not $countText -or $countText -eq "N/A" -or $countText -eq "0") {
        return $false
    }

    return ($Finding.Severity -in @("Critical", "High", "Medium"))
}

function Get-PingRuleInfo {
    param([string]$Rule)

    $Rule = ([string]$Rule).Trim()

    switch ($Rule) {
        "Trust posture" {
            return [PSCustomObject]@{ About = "Trust security configuration risk"; Source = "Get-ADTrust: SIDFiltering/TGTDelegation/SelectiveAuthentication"; Action = "Enable SID filtering, disable unnecessary TGT delegation, and review selective authentication." }
        }
        "SIDHistory usage" {
            return [PSCustomObject]@{ About = "SIDHistory residual abuse risk"; Source = "Get-ADUser/Get-ADGroup SIDHistory attribute"; Action = "Clean unnecessary SIDHistory values and remove migration leftovers." }
        }
        "AS-REP roastable users" {
            return [PSCustomObject]@{ About = "Offline cracking risk for pre-auth disabled accounts"; Source = "Get-ADUser LDAP: DONT_REQ_PREAUTH bit"; Action = "Require pre-authentication and harden password policy." }
        }
        "krbtgt password age" {
            return [PSCustomObject]@{ About = "Golden Ticket risk tied to krbtgt password age"; Source = "Get-ADUser krbtgt PasswordLastSet"; Action = "Apply a planned two-step krbtgt rotation procedure." }
        }
        "Privileged account with SPN" {
            return [PSCustomObject]@{ About = "Kerberoast exposure on privileged accounts"; Source = "Privileged group membership + servicePrincipalName"; Action = "Move SPNs to gMSA/service accounts." }
        }
        "Unconstrained delegation" {
            return [PSCustomObject]@{ About = "High lateral movement risk via ticket forwarding"; Source = "TrustedForDelegation and UAC delegation flags"; Action = "Remove unconstrained delegation and move to constrained model." }
        }
        "Constrained delegation" {
            return [PSCustomObject]@{ About = "Delegation path exposure"; Source = "msDS-AllowedToDelegateTo"; Action = "Remove unnecessary SPN delegation paths." }
        }
        "RBCD exposure" {
            return [PSCustomObject]@{ About = "Resource-based constrained delegation risk"; Source = "msDS-AllowedToActOnBehalfOfOtherIdentity"; Action = "Limit RBCD ACLs with least privilege." }
        }
        "GPP cpassword remnants" {
            return [PSCustomObject]@{ About = "Credential residue risk inside SYSVOL"; Source = "SYSVOL Policies XML search for cpassword"; Action = "Remove GPP password entries and rotate affected credentials." }
        }
        "LAPS coverage" {
            return [PSCustomObject]@{ About = "Endpoint local admin password coverage risk"; Source = "msLAPS/ms-Mcs-AdmPwdExpirationTime attributes"; Action = "Increase LAPS coverage and enforce expiration tracking." }
        }
        "Weak Kerberos encryption" {
            return [PSCustomObject]@{ About = "Legacy Kerberos encryption usage"; Source = "msDS-SupportedEncryptionTypes"; Action = "Move to AES-focused encryption settings and disable DES/legacy." }
        }
        "Password never expires (enabled users)" {
            return [PSCustomObject]@{ About = "Persistent password risk"; Source = "Enabled + PasswordNeverExpires attributes"; Action = "Remove password-never-expires from non-exception accounts." }
        }
        "adminCount drift" {
            return [PSCustomObject]@{ About = "Protected ACL residue / privilege drift"; Source = "adminCount=1 compared to privileged baseline"; Action = "Review and remediate accounts with privilege drift in adminCount=1 list." }
        }
        "Privileged accounts delegatable" {
            return [PSCustomObject]@{ About = "Privileged account delegation exposure"; Source = "Privileged account AccountNotDelegated flag"; Action = "Set AccountNotDelegated for privileged users and review delegation requirements." }
        }
        "Protected Users coverage" {
            return [PSCustomObject]@{ About = "Privileged users outside Protected Users group"; Source = "Protected Users group membership vs privileged baseline"; Action = "Add eligible privileged users to Protected Users and validate compatibility." }
        }
        "Schema Admins populated" {
            return [PSCustomObject]@{ About = "Schema Admins contains user accounts"; Source = "Schema Admins group membership"; Action = "Keep Schema Admins empty during normal operations and use temporary elevation when needed." }
        }
        "Recycle Bin disabled" {
            return [PSCustomObject]@{ About = "AD Recycle Bin is not enabled"; Source = "Recycle Bin optional feature enabled scopes"; Action = "Enable AD Recycle Bin after impact assessment and backup validation." }
        }
        "Machine account quota" {
            return [PSCustomObject]@{ About = "Non-admins can create machine accounts"; Source = "ms-DS-MachineAccountQuota"; Action = "Set machine account quota to 0 unless a controlled join process requires otherwise." }
        }
        "Minimum password length" {
            return [PSCustomObject]@{ About = "Domain minimum password length policy"; Source = "Get-ADDefaultDomainPasswordPolicy MinPasswordLength"; Action = "Set minimum password length to at least 12 and apply stronger policy for service accounts." }
        }
        "Native admin recent login" {
            return [PSCustomObject]@{ About = "Builtin Administrator account was used recently"; Source = "Builtin admin (RID 500) LastLogonTimestamp"; Action = "Avoid daily use of builtin admin and use tiered/jit admin accounts." }
        }
        "AD backup age" {
            return [PSCustomObject]@{ About = "Potentially outdated AD backup posture"; Source = "Microsoft-Windows-Backup events on domain controllers"; Action = "Validate system state backup schedule and monitor last successful backup age." }
        }
        "DC spooler exposure" {
            return [PSCustomObject]@{ About = "Spooler service running on domain controllers"; Source = "Win32_Service Spooler status on DCs"; Action = "Disable spooler on DCs unless strictly required." }
        }
        "DC coercion exposure" {
            return [PSCustomObject]@{ About = "Domain controllers exposed to common coercion prerequisites"; Source = "Spooler remote status indicator on DCs"; Action = "Harden coercion paths and disable unnecessary RPC attack surfaces." }
        }
        "DC audit posture" {
            return [PSCustomObject]@{ About = "Domain controller audit policy may be incomplete"; Source = "auditpol /get /category:* on DCs"; Action = "Enable advanced audit coverage for account logon, DS access and policy change." }
        }
        "Old NTLM posture" {
            return [PSCustomObject]@{ About = "LM/NTLMv1 compatibility may still be allowed"; Source = "LmCompatibilityLevel on DC registry"; Action = "Set LmCompatibilityLevel to 5 and phase out legacy NTLM." }
        }
        "Shadow admin exposure" {
            return [PSCustomObject]@{ About = "Delegated operator groups may provide indirect privileged control"; Source = "Privileged group review rows (operators, DNS/GPO/key admins)"; Action = "Empty high-risk delegated groups and restrict delegated rights with tiered admin model." }
        }
        "LDAP signing posture" {
            return [PSCustomObject]@{ About = "LDAP signing is not strictly enforced on all domain controllers"; Source = "LDAPServerIntegrity under NTDS parameters"; Action = "Set LDAP signing requirement to enforce signed LDAP binds across DCs." }
        }
        "LDAP channel binding posture" {
            return [PSCustomObject]@{ About = "LDAP channel binding may not be enforced"; Source = "LdapEnforceChannelBinding under NTDS parameters"; Action = "Enable LDAP channel binding policy and validate application compatibility." }
        }
        "Tiering violations" {
            return [PSCustomObject]@{ About = "Privileged accounts authenticate from non-tiered endpoints"; Source = "4624 user-device visibility map filtered by privileged identities"; Action = "Restrict privileged logons to PAWs/DC administration tier and block workstation usage." }
        }
        "Tier0: ESC1 - Enrollee supplies subject" {
            return [PSCustomObject]@{ About = "AD CS template allows subject supply with auth EKU and risky enrollment flags"; Source = "Certificate Templates in Configuration partition"; Action = "Disable enrollee-supplied subject on authentication templates and tighten enrollment controls." }
        }
        "Tier0: ESC4 - Template ACL write abuse" {
            return [PSCustomObject]@{ About = "Broad principals can modify certificate template ACL/owner/rights"; Source = "nTSecurityDescriptor on certificate templates"; Action = "Remove dangerous write rights from broad groups and delegate template management to dedicated PKI admins." }
        }
        "Tier0: ESC6 - SAN attribute injection flag" {
            return [PSCustomObject]@{ About = "CA EditFlags allows SAN injection through request attributes"; Source = "CA registry EditFlags on CertSvc"; Action = "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 and enforce SAN via template/approved issuance policy only." }
        }
        "Tier1: ESC8 - AD CS HTTP relay surface" {
            return [PSCustomObject]@{ About = "AD CS web enrollment endpoint can expose NTLM relay surface"; Source = "CA network reachability + /certsrv endpoint check"; Action = "Disable legacy web enrollment when possible and enforce EPA/TLS hardening where required." }
        }
        "Tier1: GPO owner anomalies" {
            return [PSCustomObject]@{ About = "GPO objects owned by broad identities can enable policy takeover"; Source = "GPO owner from AD ACL"; Action = "Set secure ownership for GPO objects and remove broad principals from owner chain." }
        }
        "Tier1: GPO write permission abuse" {
            return [PSCustomObject]@{ About = "Non-privileged identities can edit or modify GPO security"; Source = "Get-GPPermission delegated rights"; Action = "Remove unsafe GPO edit/modify-security delegations and enforce least privilege delegation model." }
        }
        "Tier0: DCSync rights exposure" {
            return [PSCustomObject]@{ About = "Non-replication principals have directory replication rights"; Source = "ACL extended rights on naming contexts"; Action = "Restrict DS replication rights to built-in replication principals only." }
        }
        "Tier0: Kerberoastable normal users" {
            return [PSCustomObject]@{ About = "Non-privileged user accounts expose SPN/TGS cracking paths"; Source = "User objects with servicePrincipalName"; Action = "Move SPNs to gMSA/service identities and harden passwords." }
        }
        "Tier0: Dangerous ACE on critical objects" {
            return [PSCustomObject]@{ About = "Critical AD objects grant risky write rights to non-approved principals"; Source = "ACL review of Tier-0 directory objects"; Action = "Remove GenericAll/GenericWrite/WriteDacl/WriteOwner from non-essential principals." }
        }
        "Tier0: NTLMv1 active usage" {
            return [PSCustomObject]@{ About = "Observed NTLMv1 authentication in DC security logs"; Source = "Security event 4624 LM package values"; Action = "Identify legacy clients and enforce NTLM hardening to eliminate NTLMv1." }
        }
        "Tier0: Tier model violations" {
            return [PSCustomObject]@{ About = "Privileged identities authenticate from non-tier endpoints"; Source = "Privileged user-device authentication telemetry"; Action = "Enforce tiered admin model and privileged access workstation boundaries." }
        }
        "Tier1: Shadow credentials exposure" {
            return [PSCustomObject]@{ About = "Objects carry key credentials that may allow stealthy auth abuse"; Source = "msDS-KeyCredentialLink on users/computers"; Action = "Audit key credentials and restrict write access to msDS-KeyCredentialLink." }
        }
        "Tier1: Pre-Windows 2000 compatible access" {
            return [PSCustomObject]@{ About = "Legacy compatibility group contains broad principals"; Source = "Pre-Windows 2000 Compatible Access group membership"; Action = "Remove broad identities and keep legacy access disabled." }
        }
        "Tier1: DNS admin and zone transfer" {
            return [PSCustomObject]@{ About = "DNS administration and zone transfer posture can enable domain takeover paths"; Source = "DnsAdmins membership + DNS zone transfer settings"; Action = "Reduce DnsAdmins membership and enforce secure secondaries/no transfer." }
        }
        "Tier1: Inactive or orphan service accounts" {
            return [PSCustomObject]@{ About = "Dormant SPN accounts increase credential theft and persistence risk"; Source = "SPN user account status and logon recency"; Action = "Disable unused SPN accounts and migrate to managed service accounts." }
        }
        "Tier1: gMSA adoption" {
            return [PSCustomObject]@{ About = "Low gMSA adoption indicates password-managed service account debt"; Source = "gMSA inventory compared to SPN user accounts"; Action = "Increase gMSA coverage for eligible services." }
        }
        "Tier1: SYSVOL and NETLOGON posture" {
            return [PSCustomObject]@{ About = "SYSVOL/NETLOGON may contain insecure replication or credential residue"; Source = "FRS service state + sensitive content scan"; Action = "Use DFS-R only and remove sensitive scripts/config from shared policy paths." }
        }
        "Tier2: FGPP coverage for privileged accounts" {
            return [PSCustomObject]@{ About = "Privileged accounts may not be covered by stricter fine-grained policies"; Source = "Resultant FGPP checks on privileged identities"; Action = "Apply dedicated FGPP to privileged users." }
        }
        "Tier2: SMB and LDAP signing baseline" {
            return [PSCustomObject]@{ About = "Transport/integrity hardening baseline is incomplete on DCs"; Source = "SMB signing and LDAP signing/channel binding registry checks"; Action = "Enforce SMB signing and LDAP signing/channel binding domain-wide." }
        }
        "Tier2: Orphan and disabled GPO posture" {
            return [PSCustomObject]@{ About = "Unlinked or disabled GPOs create management drift and hidden risk"; Source = "GPO status and link inventory"; Action = "Clean unused GPOs and maintain a minimal active policy set." }
        }
        "Tier2: Computer object owner anomalies" {
            return [PSCustomObject]@{ About = "Unexpected owners on DC computer objects indicate delegation drift"; Source = "DC computer object ACL owner values"; Action = "Reset owner principals to approved Tier-0 administrators." }
        }
        "Tier2: WinRM and RDP authorization scope" {
            return [PSCustomObject]@{ About = "Remote admin local groups on DCs may be broader than intended"; Source = "Remote Management Users and Remote Desktop Users local groups"; Action = "Restrict remote admin group membership to approved operators only." }
        }
        "Tier2: CredSSP exposure" {
            return [PSCustomObject]@{ About = "CredSSP on DCs increases credential relay/exposure scenarios"; Source = "WSMan CredSSP service auth setting"; Action = "Disable CredSSP where not strictly required." }
        }
        default {
            if ($Rule -like "Tier0:*") {
                return [PSCustomObject]@{ About = "Tier-0 control violation affecting core identity trust boundary"; Source = "Tier-0 security control set"; Action = "Prioritize immediate containment and remediation for this Tier-0 exposure." }
            }
            if ($Rule -like "Tier1:*") {
                return [PSCustomObject]@{ About = "Tier-1 hardening control deviation"; Source = "Tier-1 security hygiene and delegation checks"; Action = "Reduce delegation and harden configuration in the current remediation cycle." }
            }
            if ($Rule -like "Tier2:*") {
                return [PSCustomObject]@{ About = "Tier-2 posture and baseline drift finding"; Source = "Tier-2 operational hardening checks"; Action = "Track and remediate as part of baseline improvement backlog." }
            }
            return [PSCustomObject]@{ About = "AD security finding"; Source = "Directory attributes and related checks"; Action = "Apply remediation steps based on the specific rule context." }
        }
    }
}

function Get-PingRuleReference {
    param([string]$Rule)

    $Rule = ([string]$Rule).Trim()

    switch ($Rule) {
        "AS-REP roastable users" { return "CIS AD Benchmark: 1.1.5 / MITRE ATT&CK: T1558.004" }
        "krbtgt password age" { return "ANSSI AD Security Guide / MITRE ATT&CK: T1558.001" }
        "Unconstrained delegation" { return "CIS AD Benchmark: 1.1.8 / MITRE ATT&CK: T1558.003" }
        "Trust posture" { return "MITRE ATT&CK: T1484.002" }
        "DCSync rights exposure" { return "MITRE ATT&CK: T1003.006" }
        "Tier0: DCSync rights exposure" { return "MITRE ATT&CK: T1003.006" }
        "LAPS coverage" { return "CIS AD Benchmark: 1.1.3" }
        "GPP cpassword remnants" { return "CVE-2014-1812 / MITRE ATT&CK: T1552.006" }
        "Tier0: ESC1 - Enrollee supplies subject" { return "SpecterOps ESC1 / MITRE ATT&CK: T1552, T1649" }
        "Tier0: ESC4 - Template ACL write abuse" { return "SpecterOps ESC4 / MITRE ATT&CK: T1484.001" }
        "Tier0: ESC6 - SAN attribute injection flag" { return "SpecterOps ESC6 / MITRE ATT&CK: T1550" }
        "Tier1: ESC8 - AD CS HTTP relay surface" { return "SpecterOps ESC8 / MITRE ATT&CK: T1557.001" }
        "Tier1: GPO owner anomalies" { return "CIS Controls v8: 4.7 / MITRE ATT&CK: T1484.001" }
        "Tier1: GPO write permission abuse" { return "MITRE ATT&CK: T1484.001" }
        default {
            if ($Rule -like "Tier0:*") { return "Tier-0 AD Security Control / MITRE ATT&CK technique mapping required" }
            if ($Rule -like "Tier1:*") { return "Tier-1 AD Hardening Control / MITRE ATT&CK mapping required" }
            if ($Rule -like "Tier2:*") { return "Tier-2 AD Baseline Control / MITRE ATT&CK mapping required" }
            return "CIS AD Benchmark / MITRE ATT&CK mapping review required"
        }
    }
}

$PrivilegedSamAccounts = @($DomainAdmins + $SchemaAdmins + $EnterpriseAdmins | Sort-Object -Unique)

# 1) Trust posture
$TrustIssueDetails = @()
try {
    $Trusts = Get-ADTrust -Filter * -Properties *
} catch {
    $Trusts = @()
}

foreach ($t in $Trusts) {
    $sidFilteringEnabled = $null
    if ($null -ne $t.SIDFilteringQuarantined) {
        $sidFilteringEnabled = [bool]$t.SIDFilteringQuarantined
    } elseif ($null -ne $t.SIDFilteringForestAware) {
        $sidFilteringEnabled = [bool]$t.SIDFilteringForestAware
    }

    if ($sidFilteringEnabled -eq $false) {
        $TrustIssueDetails += [PSCustomObject]@{ TrustName = $t.Name; Issue = "SID filtering disabled"; Risk = "High" }
    }
    if ($t.TGTDelegation -eq $true) {
        $TrustIssueDetails += [PSCustomObject]@{ TrustName = $t.Name; Issue = "TGT delegation enabled"; Risk = "High" }
    }
    if ($t.SelectiveAuthentication -eq $false) {
        $TrustIssueDetails += [PSCustomObject]@{ TrustName = $t.Name; Issue = "Selective authentication disabled"; Risk = "Medium" }
    }
}

$TrustIssueCount = $TrustIssueDetails.Count
$TrustSample = if ($TrustIssueCount -gt 0) {
    ($TrustIssueDetails | Select-Object -First 3 | ForEach-Object { "$($_.TrustName): $($_.Issue)" }) -join "; "
} elseif ($Trusts.Count -gt 0) {
    "No trust misconfiguration detected"
} else {
    "No trust relation found or trust data unavailable"
}
$TrustSeverity = if ($TrustIssueCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Trusts" -Rule "Trust posture" -Severity $TrustSeverity -Count $TrustIssueCount -Sample $TrustSample -Recommendation "Enable SID filtering, disable unnecessary TGT delegation, and review selective authentication."
foreach ($ti in $TrustIssueDetails) {
    Add-PingDetail -Category "Trusts" -Rule "Trust posture" -Target $ti.TrustName -Detail $ti.Issue -Severity $ti.Risk
}

# 2) SIDHistory presence
try {
    $SidHistoryUsers = Get-ADUser -Filter * -Properties SIDHistory, SamAccountName | Where-Object { $_.SIDHistory -and $_.SIDHistory.Count -gt 0 }
} catch {
    $SidHistoryUsers = @()
}
try {
    $SidHistoryGroups = Get-ADGroup -Filter * -Properties SIDHistory, SamAccountName | Where-Object { $_.SIDHistory -and $_.SIDHistory.Count -gt 0 }
} catch {
    $SidHistoryGroups = @()
}

$SidHistoryCount = $SidHistoryUsers.Count + $SidHistoryGroups.Count
$SidHistorySample = if ($SidHistoryCount -gt 0) {
    (@($SidHistoryUsers | Select-Object -First 2 -ExpandProperty SamAccountName) + @($SidHistoryGroups | Select-Object -First 2 -ExpandProperty SamAccountName)) -join ", "
} else {
    "No SIDHistory usage detected"
}
$SidHistorySeverity = if ($SidHistoryCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Trusts" -Rule "SIDHistory usage" -Severity $SidHistorySeverity -Count $SidHistoryCount -Sample $SidHistorySample -Recommendation "Review and remove unnecessary SIDHistory values, especially after migration projects."
foreach ($u in $SidHistoryUsers | Select-Object -First 50) {
    Add-PingDetail -Category "Trusts" -Rule "SIDHistory usage" -Target $u.SamAccountName -Detail "SIDHistory count: $($u.SIDHistory.Count)" -Severity "High"
}
foreach ($g in $SidHistoryGroups | Select-Object -First 50) {
    Add-PingDetail -Category "Trusts" -Rule "SIDHistory usage" -Target $g.SamAccountName -Detail "Group SIDHistory count: $($g.SIDHistory.Count)" -Severity "High"
}

# 3) AS-REP roastable users
try {
    $AsRepRoastableUsers = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties SamAccountName |
                           Select-Object Name, SamAccountName
} catch {
    $AsRepRoastableUsers = @()
}

$AsRepCount = $AsRepRoastableUsers.Count
$AsRepSample = if ($AsRepCount -gt 0) {
    ($AsRepRoastableUsers | Select-Object -First 4 -ExpandProperty SamAccountName) -join ", "
} else {
    "No AS-REP roastable user"
}
$AsRepSeverity = if ($AsRepCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Anomalies" -Rule "AS-REP roastable users" -Severity $AsRepSeverity -Count $AsRepCount -Sample $AsRepSample -Recommendation "Disable DONT_REQ_PREAUTH on regular users and enforce strong password policy."
foreach ($ar in $AsRepRoastableUsers | Select-Object -First 100) {
    Add-PingDetail -Category "Anomalies" -Rule "AS-REP roastable users" -Target $ar.SamAccountName -Detail "Pre-authentication not required" -Severity "High"
}

# 4) krbtgt password age
try {
    $Krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, SamAccountName
} catch {
    $Krbtgt = $null
}

$KrbtgtAgeDays = if ($Krbtgt -and $Krbtgt.PasswordLastSet) {
    [int](New-TimeSpan -Start $Krbtgt.PasswordLastSet -End $Today).TotalDays
} else {
    -1
}

$KrbtgtSeverity = if ($KrbtgtAgeDays -ge 365) { "Critical" } elseif ($KrbtgtAgeDays -ge 180) { "High" } elseif ($KrbtgtAgeDays -ge 90) { "Medium" } else { "Low" }
$KrbtgtSample = if ($KrbtgtAgeDays -ge 0) { "krbtgt password age: $KrbtgtAgeDays days" } else { "krbtgt information unavailable" }
$KrbtgtCount = if ($KrbtgtAgeDays -ge 0) { $KrbtgtAgeDays } else { "N/A" }
Add-PingFinding -Category "Anomalies" -Rule "krbtgt password age" -Severity $KrbtgtSeverity -Count $KrbtgtCount -Sample $KrbtgtSample -Recommendation "Rotate krbtgt password in a controlled 2-step process and document rotation cadence."
if ($KrbtgtAgeDays -ge 0) {
    Add-PingDetail -Category "Anomalies" -Rule "krbtgt password age" -Target "krbtgt" -Detail "$KrbtgtAgeDays days since last password set" -Severity $KrbtgtSeverity
}

# 5) Privileged + SPN intersection
$PrivilegedSpnUsers = $Users |
    Where-Object {
        $PrivilegedSamAccounts -contains $_.SamAccountName -and
        $_.servicePrincipalName -ne $null -and
        $_.servicePrincipalName.Count -gt 0
    } |
    Select-Object Name, SamAccountName, servicePrincipalName

$PrivSpnCount = $PrivilegedSpnUsers.Count
$PrivSpnSample = if ($PrivSpnCount -gt 0) { ($PrivilegedSpnUsers | Select-Object -First 4 -ExpandProperty SamAccountName) -join ", " } else { "No privileged account with SPN" }
$PrivSpnSeverity = if ($PrivSpnCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Privileged Accounts" -Rule "Privileged account with SPN" -Severity $PrivSpnSeverity -Count $PrivSpnCount -Sample $PrivSpnSample -Recommendation "Move SPNs to gMSA/service accounts and keep privileged users free from SPN when possible."
foreach ($ps in $PrivilegedSpnUsers | Select-Object -First 100) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Privileged account with SPN" -Target $ps.SamAccountName -Detail "SPN count: $($ps.servicePrincipalName.Count)" -Severity "High"
}

# 6) Delegation - unconstrained
try {
    $UnconstrainedDelegationComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select-Object Name
} catch {
    $UnconstrainedDelegationComputers = @()
}
try {
    $UnconstrainedDelegationUsers = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -Properties SamAccountName | Select-Object SamAccountName
} catch {
    $UnconstrainedDelegationUsers = @()
}

$UnconstrainedCount = $UnconstrainedDelegationComputers.Count + $UnconstrainedDelegationUsers.Count
$UnconstrainedSample = if ($UnconstrainedCount -gt 0) {
    (@($UnconstrainedDelegationComputers | Select-Object -First 2 -ExpandProperty Name) + @($UnconstrainedDelegationUsers | Select-Object -First 2 -ExpandProperty SamAccountName)) -join ", "
} else {
    "No unconstrained delegation object"
}
$UnconstrainedSeverity = if ($UnconstrainedCount -gt 0) { "Critical" } else { "Low" }
Add-PingFinding -Category "Privileged Accounts" -Rule "Unconstrained delegation" -Severity $UnconstrainedSeverity -Count $UnconstrainedCount -Sample $UnconstrainedSample -Recommendation "Remove unconstrained delegation and use constrained delegation or gMSA patterns."
foreach ($o in $UnconstrainedDelegationComputers | Select-Object -First 50) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Unconstrained delegation" -Target $o.Name -Detail "Computer trusted for delegation" -Severity "Critical"
}
foreach ($o in $UnconstrainedDelegationUsers | Select-Object -First 50) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Unconstrained delegation" -Target $o.SamAccountName -Detail "User trusted for delegation" -Severity "Critical"
}

# 7) Delegation - constrained
try {
    $ConstrainedDelegationComputers = Get-ADComputer -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties msDS-AllowedToDelegateTo | Select-Object Name, msDS-AllowedToDelegateTo
} catch {
    $ConstrainedDelegationComputers = @()
}
try {
    $ConstrainedDelegationUsers = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(msDS-AllowedToDelegateTo=*))" -Properties SamAccountName, msDS-AllowedToDelegateTo | Select-Object SamAccountName, msDS-AllowedToDelegateTo
} catch {
    $ConstrainedDelegationUsers = @()
}

$ConstrainedCount = $ConstrainedDelegationComputers.Count + $ConstrainedDelegationUsers.Count
$ConstrainedSample = if ($ConstrainedCount -gt 0) {
    (@($ConstrainedDelegationComputers | Select-Object -First 2 -ExpandProperty Name) + @($ConstrainedDelegationUsers | Select-Object -First 2 -ExpandProperty SamAccountName)) -join ", "
} else {
    "No constrained delegation object"
}
$ConstrainedSeverity = if ($ConstrainedCount -gt 0) { "Medium" } else { "Low" }
Add-PingFinding -Category "Privileged Accounts" -Rule "Constrained delegation" -Severity $ConstrainedSeverity -Count $ConstrainedCount -Sample $ConstrainedSample -Recommendation "Review all constrained delegation paths and restrict to necessary SPNs only."
foreach ($o in $ConstrainedDelegationComputers | Select-Object -First 50) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Constrained delegation" -Target $o.Name -Detail "Delegates to: $(@($o.'msDS-AllowedToDelegateTo').Count) SPN(s)" -Severity "Medium"
}
foreach ($o in $ConstrainedDelegationUsers | Select-Object -First 50) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Constrained delegation" -Target $o.SamAccountName -Detail "Delegates to: $(@($o.'msDS-AllowedToDelegateTo').Count) SPN(s)" -Severity "Medium"
}

# 8) Resource-based constrained delegation (RBCD)
try {
    $RbcdObjects = Get-ADComputer -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object Name
} catch {
    $RbcdObjects = @()
}

$RbcdCount = $RbcdObjects.Count
$RbcdSample = if ($RbcdCount -gt 0) { ($RbcdObjects | Select-Object -First 4 -ExpandProperty Name) -join ", " } else { "No RBCD object detected" }
$RbcdSeverity = if ($RbcdCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Privileged Accounts" -Rule "RBCD exposure" -Severity $RbcdSeverity -Count $RbcdCount -Sample $RbcdSample -Recommendation "Review and minimize msDS-AllowedToActOnBehalfOfOtherIdentity on servers and especially DC-adjacent assets."
foreach ($r in $RbcdObjects | Select-Object -First 100) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "RBCD exposure" -Target $r.Name -Detail "RBCD ACL present" -Severity "High"
}

# 9) GPP cpassword traces in SYSVOL
$GppCpasswordFiles = @()
try {
    $SysvolPath = "\\$Domain\SYSVOL\$Domain\Policies"
    if (Test-Path $SysvolPath) {
        $GppCpasswordFiles = Get-ChildItem -Path $SysvolPath -Recurse -Include *.xml -ErrorAction SilentlyContinue |
                            Select-String -Pattern "cpassword" -SimpleMatch -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty Path -Unique
    }
} catch {
    $GppCpasswordFiles = @()
}

$GppCount = @($GppCpasswordFiles).Count
$GppSample = if ($GppCount -gt 0) { ($GppCpasswordFiles | Select-Object -First 2) -join "; " } else { "No cpassword pattern in SYSVOL XML" }
$GppSeverity = if ($GppCount -gt 0) { "Critical" } else { "Low" }
Add-PingFinding -Category "Anomalies" -Rule "GPP cpassword remnants" -Severity $GppSeverity -Count $GppCount -Sample $GppSample -Recommendation "Remove GPP password entries and rotate any potentially exposed credentials immediately."
foreach ($f in $GppCpasswordFiles | Select-Object -First 40) {
    Add-PingDetail -Category "Anomalies" -Rule "GPP cpassword remnants" -Target "SYSVOL" -Detail $f -Severity "Critical"
}

# 10) LAPS coverage
$LapsDataAvailable = $true
try {
    $LapsComputers = Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwdExpirationTime','msLAPS-Password','msLAPS-PasswordExpirationTime','msLAPS-EncryptedPassword' |
                    Select-Object Name,'ms-Mcs-AdmPwdExpirationTime','msLAPS-Password','msLAPS-PasswordExpirationTime','msLAPS-EncryptedPassword'
} catch {
    $LapsDataAvailable = $false
    $LapsComputers = @()
}

$LapsLegacyManaged = @($LapsComputers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' -ne $null }).Count
$LapsV2Managed = @($LapsComputers | Where-Object { $_.'msLAPS-PasswordExpirationTime' -ne $null -or $_.'msLAPS-Password' -ne $null -or $_.'msLAPS-EncryptedPassword' -ne $null }).Count
$LapsManaged = @($LapsComputers | Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' -ne $null -or $_.'msLAPS-PasswordExpirationTime' -ne $null -or $_.'msLAPS-Password' -ne $null -or $_.'msLAPS-EncryptedPassword' -ne $null }).Count
$LapsTotal = @($LapsComputers).Count
$LapsUnmanaged = if ($LapsTotal -gt 0) { $LapsTotal - $LapsManaged } else { 0 }
$LapsSample = if ($LapsTotal -gt 0) { "Legacy LAPS=$LapsLegacyManaged; Windows LAPS v2=$LapsV2Managed; Managed total=$LapsManaged / $LapsTotal" } else { "LAPS data unavailable" }
$LapsSeverity = if (-not $LapsDataAvailable) { "Low" } elseif (($LapsLegacyManaged -eq 0) -and ($LapsV2Managed -eq 0)) { "Critical" } elseif ($LapsUnmanaged -gt 0) { "Medium" } else { "Low" }
$LapsSample = if (-not $LapsDataAvailable) { "LAPS check could not be completed" } else { $LapsSample }
Add-PingFinding -Category "Stale Objects" -Rule "LAPS coverage" -Severity $LapsSeverity -Count $LapsUnmanaged -Sample $LapsSample -Recommendation "Track Legacy LAPS and Windows LAPS v2 separately and enforce endpoint coverage with expiration monitoring."

# 11) Weak Kerberos encryption settings on SPN users
try {
    $KerberosSpnUsers = Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(objectCategory=person)(objectClass=user))" -Properties SamAccountName,msDS-SupportedEncryptionTypes |
                        Select-Object SamAccountName,msDS-SupportedEncryptionTypes
} catch {
    $KerberosSpnUsers = @()
}

$WeakKerberosUsers = $KerberosSpnUsers | Where-Object {
    $enc = $_.'msDS-SupportedEncryptionTypes'
    if ($null -eq $enc) { return $true }
    ($enc -band 1) -or ($enc -band 2) -or (($enc -band 24) -eq 0)
}

$WeakKerberosCount = @($WeakKerberosUsers).Count
$WeakKerberosSample = if ($WeakKerberosCount -gt 0) { ($WeakKerberosUsers | Select-Object -First 4 -ExpandProperty SamAccountName) -join ", " } else { "No weak kerberos encryption setting on SPN users" }
$WeakKerberosSeverity = if ($WeakKerberosCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Stale Objects" -Rule "Weak Kerberos encryption" -Severity $WeakKerberosSeverity -Count $WeakKerberosCount -Sample $WeakKerberosSample -Recommendation "Prefer AES encryption types and remove DES/legacy settings from service accounts."
foreach ($wk in $WeakKerberosUsers | Select-Object -First 100) {
    Add-PingDetail -Category "Stale Objects" -Rule "Weak Kerberos encryption" -Target $wk.SamAccountName -Detail "msDS-SupportedEncryptionTypes: $($wk.'msDS-SupportedEncryptionTypes')" -Severity "High"
}

# 12) Password never expires on enabled users
$PasswordNeverExpireEnabled = $Users | Where-Object { $_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $true } | Select-Object SamAccountName
$PwdNeverExpireCount = @($PasswordNeverExpireEnabled).Count
$PwdNeverExpireSample = if ($PwdNeverExpireCount -gt 0) { ($PasswordNeverExpireEnabled | Select-Object -First 4 -ExpandProperty SamAccountName) -join ", " } else { "No enabled user with password never expires" }
$PwdNeverExpireSeverity = if ($PwdNeverExpireCount -gt 0) { "Medium" } else { "Low" }
Add-PingFinding -Category "Hygiene" -Rule "Password never expires (enabled users)" -Severity $PwdNeverExpireSeverity -Count $PwdNeverExpireCount -Sample $PwdNeverExpireSample -Recommendation "Remove password-never-expires from regular accounts and apply exception process only where required."

# 13) adminCount=1 drift
try {
    $AdminCountUsers = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(adminCount=1))" -Properties SamAccountName | Select-Object SamAccountName
} catch {
    $AdminCountUsers = @()
}

$AdminCountDriftUsers = $AdminCountUsers | Where-Object { $PrivilegedSamAccounts -notcontains $_.SamAccountName }
$AdminCountDriftCount = @($AdminCountDriftUsers).Count
$AdminCountSample = if ($AdminCountDriftCount -gt 0) { ($AdminCountDriftUsers | Select-Object -First 4 -ExpandProperty SamAccountName) -join ", " } else { "No adminCount drift detected" }
$AdminCountSeverity = if ($AdminCountDriftCount -gt 0) { "Medium" } else { "Low" }
Add-PingFinding -Category "Privileged Accounts" -Rule "adminCount drift" -Severity $AdminCountSeverity -Count $AdminCountDriftCount -Sample $AdminCountSample -Recommendation "Review adminCount=1 accounts outside privileged groups and fix ACL inheritance where applicable."
foreach ($ad in $AdminCountDriftUsers | Select-Object -First 100) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "adminCount drift" -Target $ad.SamAccountName -Detail "adminCount=1 but not in DA/EA/SA baseline list" -Severity "Medium"
}

# 14) Privileged users without AccountNotDelegated
try {
    $PrivilegedUsers = Get-ADUser -Filter * -Properties SamAccountName,Enabled,AccountNotDelegated |
        Where-Object { $PrivilegedSamAccounts -contains $_.SamAccountName }
} catch {
    $PrivilegedUsers = @()
}

$DelegatablePrivileged = @($PrivilegedUsers | Where-Object { $_.Enabled -eq $true -and $_.AccountNotDelegated -ne $true })
$DelegatablePrivilegedCount = $DelegatablePrivileged.Count
$DelegatablePrivilegedSample = if ($DelegatablePrivilegedCount -gt 0) {
    ($DelegatablePrivileged | Select-Object -First 4 -ExpandProperty SamAccountName) -join ", "
} else {
    "No enabled privileged account is delegatable"
}
$DelegatablePrivilegedSeverity = if ($DelegatablePrivilegedCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Privileged Accounts" -Rule "Privileged accounts delegatable" -Severity $DelegatablePrivilegedSeverity -Count $DelegatablePrivilegedCount -Sample $DelegatablePrivilegedSample -Recommendation "Set AccountNotDelegated for privileged accounts unless explicitly required."
foreach ($u in $DelegatablePrivileged | Select-Object -First 100) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Privileged accounts delegatable" -Target $u.SamAccountName -Detail "Enabled privileged account can be delegated" -Severity "High"
}

# 15) Protected Users coverage for privileged accounts
try {
    $ProtectedUsersMembers = Get-ADGroupMember -Identity "Protected Users" -Recursive -ErrorAction Stop |
        Where-Object { $_.objectClass -eq "user" } |
        Select-Object -ExpandProperty SamAccountName
} catch {
    $ProtectedUsersMembers = @()
}

$PrivilegedEnabledUsers = @($PrivilegedUsers | Where-Object { $_.Enabled -eq $true })
$MissingProtectedUsers = @($PrivilegedEnabledUsers | Where-Object { $ProtectedUsersMembers -notcontains $_.SamAccountName })
$MissingProtectedUsersCount = $MissingProtectedUsers.Count
$MissingProtectedUsersSample = if ($MissingProtectedUsersCount -gt 0) {
    ($MissingProtectedUsers | Select-Object -First 4 -ExpandProperty SamAccountName) -join ", "
} else {
    "All enabled privileged users are in Protected Users"
}
$MissingProtectedUsersSeverity = if ($MissingProtectedUsersCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Privileged Accounts" -Rule "Protected Users coverage" -Severity $MissingProtectedUsersSeverity -Count $MissingProtectedUsersCount -Sample $MissingProtectedUsersSample -Recommendation "Review privileged users not in Protected Users and add compatible accounts."
foreach ($u in $MissingProtectedUsers | Select-Object -First 100) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Protected Users coverage" -Target $u.SamAccountName -Detail "Enabled privileged user is not in Protected Users" -Severity "High"
}

# 16) Schema Admins group population
$SchemaAdminCount = @($SchemaAdmins).Count
$SchemaAdminSample = if ($SchemaAdminCount -gt 0) {
    ($SchemaAdmins | Select-Object -First 4) -join ", "
} else {
    "Schema Admins is empty"
}
$SchemaAdminSeverity = if ($SchemaAdminCount -gt 0) { "Medium" } else { "Low" }
Add-PingFinding -Category "Privileged Accounts" -Rule "Schema Admins populated" -Severity $SchemaAdminSeverity -Count $SchemaAdminCount -Sample $SchemaAdminSample -Recommendation "Keep Schema Admins empty by default and use JIT elevation for schema operations."
foreach ($u in $SchemaAdmins | Select-Object -First 50) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Schema Admins populated" -Target $u -Detail "Member of Schema Admins" -Severity "Medium"
}

# 17) AD Recycle Bin status
try {
    $RecycleBinFeature = Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' -ErrorAction Stop | Select-Object -First 1
    $RecycleBinEnabled = $RecycleBinFeature -and @($RecycleBinFeature.EnabledScopes).Count -gt 0
} catch {
    $RecycleBinEnabled = $false
}

$RecycleBinCount = if ($RecycleBinEnabled) { 0 } else { 1 }
$RecycleBinSample = if ($RecycleBinEnabled) { "AD Recycle Bin is enabled" } else { "AD Recycle Bin is not enabled" }
$RecycleBinSeverity = if ($RecycleBinEnabled) { "Low" } else { "Medium" }
Add-PingFinding -Category "Privileged Accounts" -Rule "Recycle Bin disabled" -Severity $RecycleBinSeverity -Count $RecycleBinCount -Sample $RecycleBinSample -Recommendation "Enable AD Recycle Bin after change control and backup validation."
if (-not $RecycleBinEnabled) {
    Add-PingDetail -Category "Privileged Accounts" -Rule "Recycle Bin disabled" -Target "Forest" -Detail "Recycle Bin optional feature is not enabled" -Severity "Medium"
}

# 18) Machine account quota policy
try {
    $MachineAccountQuota = (Get-ADDomain -Identity $Domain -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
} catch {
    $MachineAccountQuota = $null
}

$MachineAccountQuotaCount = if ($null -eq $MachineAccountQuota) { "N/A" } else { [int]$MachineAccountQuota }
$MachineAccountQuotaSample = if ($null -eq $MachineAccountQuota) {
    "Machine account quota unavailable"
} else {
    "ms-DS-MachineAccountQuota: $MachineAccountQuota"
}
$MachineAccountQuotaSeverity = if ($null -eq $MachineAccountQuota) {
    "Low"
} elseif ([int]$MachineAccountQuota -gt 0) {
    "Medium"
} else {
    "Low"
}
Add-PingFinding -Category "Stale Objects" -Rule "Machine account quota" -Severity $MachineAccountQuotaSeverity -Count $MachineAccountQuotaCount -Sample $MachineAccountQuotaSample -Recommendation "Set machine account quota to 0 when possible and use controlled join workflows."
if ($null -ne $MachineAccountQuota -and [int]$MachineAccountQuota -gt 0) {
    Add-PingDetail -Category "Stale Objects" -Rule "Machine account quota" -Target "Domain" -Detail "Non-admin users can add up to $MachineAccountQuota machine account(s)" -Severity "Medium"
}

# 19) Minimum password length policy
$MinPwdLength = if ($PwdPolicy) { [int]$PwdPolicy.MinPasswordLength } else { -1 }
$MinPwdLengthCount = if ($MinPwdLength -ge 0) { $MinPwdLength } else { "N/A" }
$MinPwdLengthSample = if ($MinPwdLength -ge 0) {
    "Minimum password length: $MinPwdLength"
} else {
    "Password policy unavailable"
}
$MinPwdLengthSeverity = if ($MinPwdLength -lt 0) {
    "Low"
} elseif ($MinPwdLength -lt 8) {
    "High"
} elseif ($MinPwdLength -lt 12) {
    "Medium"
} else {
    "Low"
}
Add-PingFinding -Category "Anomalies" -Rule "Minimum password length" -Severity $MinPwdLengthSeverity -Count $MinPwdLengthCount -Sample $MinPwdLengthSample -Recommendation "Increase minimum password length (preferably 12+) and apply stronger fine-grained policies where needed."
if ($MinPwdLength -ge 0) {
    Add-PingDetail -Category "Anomalies" -Rule "Minimum password length" -Target "Default Domain Password Policy" -Detail "MinPasswordLength = $MinPwdLength" -Severity $MinPwdLengthSeverity
}

# 20) Builtin administrator recent login (RID 500)
try {
    $DomainSidValue = (Get-ADDomain -Identity $Domain).DomainSID.Value
    $BuiltinAdminSid = "$DomainSidValue-500"
    $BuiltinAdmin = Get-ADUser -Filter * -Properties SID,SamAccountName,Name,LastLogonTimestamp |
        Where-Object { $_.SID.Value -eq $BuiltinAdminSid } |
        Select-Object -First 1
} catch {
    $BuiltinAdmin = $null
}

$BuiltinAdminDays = -1
if ($BuiltinAdmin -and $BuiltinAdmin.LastLogonTimestamp) {
    try {
        $BuiltinAdminLastLogon = [DateTime]::FromFileTime([int64]$BuiltinAdmin.LastLogonTimestamp)
        $BuiltinAdminDays = [int](New-TimeSpan -Start $BuiltinAdminLastLogon -End $Today).TotalDays
    } catch {
        $BuiltinAdminDays = -1
    }
}

$BuiltinAdminSeverity = if ($BuiltinAdminDays -lt 0) { "Low" } elseif ($BuiltinAdminDays -le 7) { "High" } elseif ($BuiltinAdminDays -le 30) { "Medium" } else { "Low" }
$BuiltinAdminCount = if ($BuiltinAdminDays -lt 0) { "N/A" } else { $BuiltinAdminDays }
$BuiltinAdminSample = if ($BuiltinAdminDays -lt 0) {
    "Builtin Administrator last logon unavailable"
} else {
    "Builtin admin last logon: $BuiltinAdminDays day(s) ago"
}
Add-PingFinding -Category "Privileged Accounts" -Rule "Native admin recent login" -Severity $BuiltinAdminSeverity -Count $BuiltinAdminCount -Sample $BuiltinAdminSample -Recommendation "Limit usage of builtin admin and prefer dedicated tiered admin accounts."
if ($BuiltinAdminDays -ge 0) {
    $BuiltinAdminTarget = if ($BuiltinAdmin.SamAccountName) { $BuiltinAdmin.SamAccountName } else { "RID-500 Administrator" }
    Add-PingDetail -Category "Privileged Accounts" -Rule "Native admin recent login" -Target $BuiltinAdminTarget -Detail "$BuiltinAdminDays day(s) since last logon" -Severity $BuiltinAdminSeverity
}

# 21) AD backup age (best-effort from backup event logs on DCs)
$DcBackupLastDates = @()
foreach ($dc in $DCs) {
    try {
        $dcLastBackup = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            try {
                $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Backup'; Id = 4 } -MaxEvents 1 -ErrorAction Stop
                if ($ev) { return $ev.TimeCreated }
            } catch {}
            return $null
        } -ErrorAction Stop

        if ($dcLastBackup) {
            $DcBackupLastDates += [PSCustomObject]@{ DC = $dc.Name; LastBackup = [datetime]$dcLastBackup }
        }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "AD Backup Age" -Reason $_.Exception.Message
    }
}

$BackupAgeDays = -1
if ($DcBackupLastDates.Count -gt 0) {
    $MostRecentBackup = ($DcBackupLastDates | Sort-Object LastBackup -Descending | Select-Object -First 1).LastBackup
    $BackupAgeDays = [int](New-TimeSpan -Start $MostRecentBackup -End $Today).TotalDays
}

$BackupAgeSeverity = if ($BackupAgeDays -lt 0) { "Low" } elseif ($BackupAgeDays -ge 365) { "High" } elseif ($BackupAgeDays -ge 180) { "Medium" } else { "Low" }
$BackupAgeCount = if ($BackupAgeDays -lt 0) { "N/A" } else { $BackupAgeDays }
$BackupAgeSample = if ($BackupAgeDays -lt 0) {
    "Backup metadata unavailable from DC event logs"
} else {
    "Most recent detected DC backup: $BackupAgeDays day(s) ago"
}
Add-PingFinding -Category "Anomalies" -Rule "AD backup age" -Severity $BackupAgeSeverity -Count $BackupAgeCount -Sample $BackupAgeSample -Recommendation "Run and monitor regular system state backups for domain controllers."
if ($BackupAgeDays -ge 0) {
    foreach ($b in $DcBackupLastDates | Select-Object -First 10) {
        Add-PingDetail -Category "Anomalies" -Rule "AD backup age" -Target $b.DC -Detail ("Last detected backup: {0}" -f $b.LastBackup.ToString("yyyy-MM-dd HH:mm")) -Severity $BackupAgeSeverity
    }
}

# 22) DC spooler exposure
$DcSpoolerRunning = @()
$DcSpoolerUnknown = @()
foreach ($dc in $DCs) {
    try {
        $spooler = Get-CimInstance -ClassName Win32_Service -ComputerName $dc.Name -Filter "Name='Spooler'" -ErrorAction Stop
        if ($spooler -and $spooler.State -eq "Running") {
            $DcSpoolerRunning += $dc.Name
        }
    } catch {
        $DcSpoolerUnknown += $dc.Name
    }
}

$DcSpoolerCount = $DcSpoolerRunning.Count
$DcSpoolerSample = if ($DcSpoolerCount -gt 0) {
    ($DcSpoolerRunning | Select-Object -First 4) -join ", "
} elseif ($DcSpoolerUnknown.Count -gt 0) {
    "Spooler state unavailable on: $((($DcSpoolerUnknown | Select-Object -First 3) -join ', '))"
} else {
    "No DC with running spooler detected"
}
$DcSpoolerSeverity = if ($DcSpoolerCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "DC spooler exposure" -Severity $DcSpoolerSeverity -Count $DcSpoolerCount -Sample $DcSpoolerSample -Recommendation "Disable print spooler service on domain controllers."
foreach ($name in $DcSpoolerRunning | Select-Object -First 20) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "DC spooler exposure" -Target $name -Detail "Spooler service is running" -Severity "High"
}

# 23) DC coercion exposure (best-effort indicator)
$DcCoerceCount = $DcSpoolerRunning.Count
$DcCoerceSample = if ($DcCoerceCount -gt 0) {
    "Potential coercion path indicator (spooler running): $((($DcSpoolerRunning | Select-Object -First 4) -join ', '))"
} elseif ($DcSpoolerUnknown.Count -gt 0) {
    "Coercion indicator unavailable on some DCs"
} else {
    "No spooler-based coercion indicator detected"
}
$DcCoerceSeverity = if ($DcCoerceCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Anomalies" -Rule "DC coercion exposure" -Severity $DcCoerceSeverity -Count $DcCoerceCount -Sample $DcCoerceSample -Recommendation "Harden RPC coercion paths and reduce exposed printer-related interfaces."
foreach ($name in $DcSpoolerRunning | Select-Object -First 20) {
    Add-PingDetail -Category "Anomalies" -Rule "DC coercion exposure" -Target $name -Detail "Spooler status indicates common coercion precondition" -Severity "High"
}

# 24) DC audit posture (best-effort)
$AuditCoverageMissing = @()
foreach ($dc in $DCs) {
    try {
        $auditOutput = Invoke-Command -ComputerName $dc.Name -ScriptBlock { auditpol /get /category:* } -ErrorAction Stop
        $auditText = ($auditOutput | Out-String)
        if (-not $auditText -or $auditText -notmatch 'Success and Failure|Success') {
            $AuditCoverageMissing += $dc.Name
        }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "DC Audit Posture" -Reason $_.Exception.Message
        $AuditCoverageMissing += $dc.Name
    }
}

$AuditMissingCount = $AuditCoverageMissing.Count
$AuditSample = if ($AuditMissingCount -gt 0) {
    "Audit coverage missing/unverified on: $((($AuditCoverageMissing | Select-Object -First 4) -join ', '))"
} else {
    "Audit policy appears present on reachable DCs"
}
$AuditSeverity = if ($AuditMissingCount -gt 0) { "Medium" } else { "Low" }
Add-PingFinding -Category "Anomalies" -Rule "DC audit posture" -Severity $AuditSeverity -Count $AuditMissingCount -Sample $AuditSample -Recommendation "Enable and verify advanced audit policy baseline on all domain controllers."
foreach ($name in $AuditCoverageMissing | Select-Object -First 20) {
    Add-PingDetail -Category "Anomalies" -Rule "DC audit posture" -Target $name -Detail "Audit policy could not be validated or appears incomplete" -Severity "Medium"
}

# 25) Old NTLM posture (LmCompatibilityLevel)
$OldNtlmDcs = @()
foreach ($dc in $DCs) {
    try {
        $lmValue = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            try {
                (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction Stop).LmCompatibilityLevel
            } catch {
                $null
            }
        } -ErrorAction Stop

        if ($null -eq $lmValue -or [int]$lmValue -lt 5) {
            $OldNtlmDcs += [PSCustomObject]@{ DC = $dc.Name; LmCompatibilityLevel = $lmValue }
        }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "Old NTLM Posture" -Reason $_.Exception.Message
        $OldNtlmDcs += [PSCustomObject]@{ DC = $dc.Name; LmCompatibilityLevel = $null }
    }
}

$OldNtlmCount = $OldNtlmDcs.Count
$OldNtlmSample = if ($OldNtlmCount -gt 0) {
    ($OldNtlmDcs | Select-Object -First 4 | ForEach-Object { "$($_.DC): LmCompatibilityLevel=$($_.LmCompatibilityLevel)" }) -join "; "
} else {
    "No DC with old NTLM compatibility detected"
}
$OldNtlmSeverity = if ($OldNtlmCount -gt 0) { "High" } else { "Low" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Old NTLM posture" -Severity $OldNtlmSeverity -Count $OldNtlmCount -Sample $OldNtlmSample -Recommendation "Set LmCompatibilityLevel to 5 on DCs and disable legacy NTLM protocols."
foreach ($item in $OldNtlmDcs | Select-Object -First 20) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Old NTLM posture" -Target $item.DC -Detail "LmCompatibilityLevel: $($item.LmCompatibilityLevel)" -Severity "High"
}

# 26) LDAP signing and channel binding posture
$LdapSigningIssues = @()
$LdapChannelBindingIssues = @()
foreach ($dc in $DCs) {
    try {
        $ldapPosture = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            $ntdsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

            $signing = $null
            $channelBinding = $null

            try {
                $signing = (Get-ItemProperty -Path $ntdsPath -Name LDAPServerIntegrity -ErrorAction Stop).LDAPServerIntegrity
            } catch {}

            try {
                $channelBinding = (Get-ItemProperty -Path $ntdsPath -Name LdapEnforceChannelBinding -ErrorAction Stop).LdapEnforceChannelBinding
            } catch {}

            [PSCustomObject]@{
                LDAPServerIntegrity = $signing
                LdapEnforceChannelBinding = $channelBinding
            }
        } -ErrorAction Stop

        if ($null -eq $ldapPosture.LDAPServerIntegrity -or [int]$ldapPosture.LDAPServerIntegrity -lt 2) {
            $issueSeverity = if ($null -eq $ldapPosture.LDAPServerIntegrity -or [int]$ldapPosture.LDAPServerIntegrity -lt 1) { "High" } else { "Medium" }
            $LdapSigningIssues += [PSCustomObject]@{ DC = $dc.Name; Value = $ldapPosture.LDAPServerIntegrity; Severity = $issueSeverity }
        }

        if ($null -eq $ldapPosture.LdapEnforceChannelBinding -or [int]$ldapPosture.LdapEnforceChannelBinding -lt 1) {
            $LdapChannelBindingIssues += [PSCustomObject]@{ DC = $dc.Name; Value = $ldapPosture.LdapEnforceChannelBinding; Severity = "High" }
        }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "LDAP Signing Posture" -Reason $_.Exception.Message
        $LdapSigningIssues += [PSCustomObject]@{ DC = $dc.Name; Value = $null; Severity = "Medium" }
        $LdapChannelBindingIssues += [PSCustomObject]@{ DC = $dc.Name; Value = $null; Severity = "Medium" }
    }
}

$LdapSigningCount = @($LdapSigningIssues).Count
$LdapSigningSeverity = if ($LdapSigningCount -gt 0) {
    if (@($LdapSigningIssues | Where-Object { $_.Severity -eq "High" }).Count -gt 0) { "High" } else { "Medium" }
} else {
    "Low"
}
$LdapSigningSample = if ($LdapSigningCount -gt 0) {
    (@($LdapSigningIssues | Select-Object -First 4 | ForEach-Object { "$($_.DC): LDAPServerIntegrity=$($_.Value)" })) -join "; "
} else {
    "LDAP signing appears enforced on reachable DCs"
}
Add-PingFinding -Category "Privileged Infrastructure" -Rule "LDAP signing posture" -Severity $LdapSigningSeverity -Count $LdapSigningCount -Sample $LdapSigningSample -Recommendation "Set LDAPServerIntegrity to enforce LDAP signing on domain controllers."
foreach ($issue in $LdapSigningIssues | Select-Object -First 20) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "LDAP signing posture" -Target $issue.DC -Detail "LDAPServerIntegrity: $($issue.Value)" -Severity $issue.Severity
}

$LdapChannelBindingCount = @($LdapChannelBindingIssues).Count
$LdapChannelBindingSeverity = if ($LdapChannelBindingCount -gt 0) {
    if (@($LdapChannelBindingIssues | Where-Object { $_.Severity -eq "High" }).Count -gt 0) { "High" } else { "Medium" }
} else {
    "Low"
}
$LdapChannelBindingSample = if ($LdapChannelBindingCount -gt 0) {
    (@($LdapChannelBindingIssues | Select-Object -First 4 | ForEach-Object { "$($_.DC): LdapEnforceChannelBinding=$($_.Value)" })) -join "; "
} else {
    "LDAP channel binding appears enforced on reachable DCs"
}
Add-PingFinding -Category "Privileged Infrastructure" -Rule "LDAP channel binding posture" -Severity $LdapChannelBindingSeverity -Count $LdapChannelBindingCount -Sample $LdapChannelBindingSample -Recommendation "Set LdapEnforceChannelBinding to a protected mode and validate client compatibility."
foreach ($issue in $LdapChannelBindingIssues | Select-Object -First 20) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "LDAP channel binding posture" -Target $issue.DC -Detail "LdapEnforceChannelBinding: $($issue.Value)" -Severity $issue.Severity
}

# 27) Shadow admin exposure (delegated operator paths)
$ShadowAdminGroupNames = @(
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners",
    "Enterprise Key Admins",
    "Key Admins",
    "Certificate Operators",
    "Certificate Publishers"
)

$ShadowAdminExposures = @()
foreach ($row in $PrivilegedGroupReviewRows | Where-Object { $ShadowAdminGroupNames -contains $_.ObjectName }) {
    $usersCount = Get-IntOrZero $row.UsersMember
    $computerCount = Get-IntOrZero $row.ComputersMember
    $indirectCount = Get-IntOrZero $row.IndirectControl
    $unresolvedCount = Get-IntOrZero $row.UnresolvedMembers
    $exposureCount = $usersCount + $computerCount + $indirectCount + $unresolvedCount

    if ($exposureCount -gt 0) {
        $ShadowAdminExposures += [PSCustomObject]@{
            GroupName = $row.ObjectName
            Exposure = $exposureCount
            Users = $usersCount
            Computers = $computerCount
            Indirect = $indirectCount
            Unresolved = $unresolvedCount
        }
    }
}

$ShadowAdminCount = @($ShadowAdminExposures | Measure-Object -Property Exposure -Sum).Sum
if ($null -eq $ShadowAdminCount) { $ShadowAdminCount = 0 }
$ShadowAdminSeverity = if ($ShadowAdminCount -gt 0) { "High" } else { "Low" }
$ShadowAdminSample = if ($ShadowAdminCount -gt 0) {
    (@($ShadowAdminExposures | Sort-Object Exposure -Descending | Select-Object -First 4 | ForEach-Object { "$($_.GroupName): exposure=$($_.Exposure)" })) -join "; "
} else {
    "No delegated operator group exposure detected"
}
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Shadow admin exposure" -Severity $ShadowAdminSeverity -Count $ShadowAdminCount -Sample $ShadowAdminSample -Recommendation "Review delegated operator groups and remove non-essential members and nested control paths."
foreach ($item in $ShadowAdminExposures | Sort-Object Exposure -Descending | Select-Object -First 20) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Shadow admin exposure" -Target $item.GroupName -Detail "Users=$($item.Users), Computers=$($item.Computers), Indirect=$($item.Indirect), Unresolved=$($item.Unresolved)" -Severity "High"
}

# 28) Tiering violations (privileged logon from non-DC endpoints)
$PrivilegedSamLookup = @{}
foreach ($sam in $PrivilegedSamAccounts) {
    if (-not [string]::IsNullOrWhiteSpace($sam)) {
        $PrivilegedSamLookup[$sam.ToLowerInvariant()] = $true
    }
}

$DcHostLookup = @{}
$DcIpLookup = @{}
foreach ($dc in $DCs) {
    if (-not [string]::IsNullOrWhiteSpace($dc.Name)) {
        $dcNameLower = $dc.Name.ToLowerInvariant()
        $DcHostLookup[$dcNameLower] = $true
        $DcHostLookup[($dcNameLower -split '\.')[0]] = $true
    }
    if (-not [string]::IsNullOrWhiteSpace($dc.IPv4Address)) {
        $DcIpLookup[$dc.IPv4Address] = $true
    }
}

$TieringViolationsRaw = @()
foreach ($ev in $UserRiskUserDeviceEvents) {
    $targetUser = "$($ev.TargetUser)".Trim()
    if ([string]::IsNullOrWhiteSpace($targetUser)) { continue }

    if ($targetUser -match '\\') {
        $targetUser = ($targetUser -split '\\')[-1]
    }
    if ($targetUser -match '@') {
        $targetUser = ($targetUser -split '@')[0]
    }
    $targetUser = $targetUser.ToLowerInvariant()

    if (-not $PrivilegedSamLookup.ContainsKey($targetUser)) { continue }

    $sourceParts = Split-UserRiskEndpoint $ev.Source
    $sourceHost = "$($sourceParts.Host)".Trim()
    $sourceIp = "$($sourceParts.IP)".Trim()

    $isDcSource = $false
    if (-not [string]::IsNullOrWhiteSpace($sourceHost) -and $sourceHost -ne "-") {
        $hostLower = $sourceHost.ToLowerInvariant()
        $hostShort = ($hostLower -split '\.')[0]
        if ($DcHostLookup.ContainsKey($hostLower) -or $DcHostLookup.ContainsKey($hostShort)) {
            $isDcSource = $true
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($sourceIp) -and $sourceIp -ne "-") {
        if ($DcIpLookup.ContainsKey($sourceIp)) {
            $isDcSource = $true
        }
    }

    if (-not $isDcSource) {
        $TieringViolationsRaw += [PSCustomObject]@{
            User = $targetUser
            Source = if ([string]::IsNullOrWhiteSpace($ev.Source)) { "-" } else { $ev.Source }
            LogonType = if ([string]::IsNullOrWhiteSpace($ev.LogonType)) { "-" } else { $ev.LogonType }
            LastSeen = $ev.TimeCreated
        }
    }
}

$TieringViolationRows = @(
    $TieringViolationsRaw |
        Group-Object { "$($_.User)|$($_.Source)|$($_.LogonType)" } |
        ForEach-Object {
            $parts = $_.Name -split '\|', 3
            $latest = $_.Group | Sort-Object LastSeen -Descending | Select-Object -First 1
            [PSCustomObject]@{
                User = if ($parts.Count -gt 0) { $parts[0] } else { "-" }
                Source = if ($parts.Count -gt 1) { $parts[1] } else { "-" }
                LogonType = if ($parts.Count -gt 2) { $parts[2] } else { "-" }
                Count = $_.Count
                LastSeen = if ($latest) { $latest.LastSeen } else { $null }
            }
        } |
        Sort-Object Count, LastSeen -Descending |
        Select-Object -First 100
)

$TieringViolationCount = @($TieringViolationRows).Count
$TieringViolationSeverity = if ($TieringViolationCount -gt 0) { "High" } else { "Low" }
$TieringViolationSample = if ($TieringViolationCount -gt 0) {
    (@($TieringViolationRows | Select-Object -First 4 | ForEach-Object { "$($_.User) from $($_.Source) (type $($_.LogonType))" })) -join "; "
} else {
    "No privileged logon detected from non-DC endpoints in lookback window"
}
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tiering violations" -Severity $TieringViolationSeverity -Count $TieringViolationCount -Sample $TieringViolationSample -Recommendation "Restrict privileged account logons to tiered admin workstations and domain controllers only."
foreach ($row in $TieringViolationRows | Select-Object -First 20) {
    $lastSeenText = if ($row.LastSeen) { $row.LastSeen.ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tiering violations" -Target $row.User -Detail "Source=$($row.Source), LogonType=$($row.LogonType), Seen=$($row.Count), LastSeen=$lastSeenText" -Severity "High"
}

# 29) Tier 0 - DCSync rights exposure
$DcsyncRightGuids = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c"  # DS-Replication-Get-Changes-In-Filtered-Set
)
$DcsyncAllowList = @("NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators")
$DcsyncExposures = @()
try {
    $rootDse = Get-ADRootDSE
    $namingContexts = @($rootDse.defaultNamingContext, $rootDse.configurationNamingContext, $rootDse.schemaNamingContext) | Where-Object { $_ } | Select-Object -Unique
    foreach ($nc in $namingContexts) {
        try {
            $acl = Get-Acl -Path ("AD:" + $nc)
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne "Allow") { continue }
                if (-not ($ace.ActiveDirectoryRights.ToString() -match "ExtendedRight")) { continue }
                $objType = "$($ace.ObjectType)".ToLowerInvariant()
                if ($DcsyncRightGuids -notcontains $objType) { continue }

                $principal = "$($ace.IdentityReference)"
                if ($DcsyncAllowList -contains $principal) { continue }

                $DcsyncExposures += [PSCustomObject]@{ NamingContext = $nc; Principal = $principal; RightGuid = $objType }
            }
        } catch {}
    }
} catch {}

$DcsyncUnique = @($DcsyncExposures | Select-Object -ExpandProperty Principal -Unique)
$DcsyncCount = @($DcsyncUnique).Count
$DcsyncSample = if ($DcsyncCount -gt 0) { ($DcsyncUnique | Select-Object -First 5) -join "; " } else { "No unexpected DCSync ACL principal detected" }
$DcsyncSeverity = if ($DcsyncCount -gt 0) { "Critical" } else { "Low" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: DCSync rights exposure" -Severity $DcsyncSeverity -Count $DcsyncCount -Sample $DcsyncSample -Recommendation "Restrict DS replication rights to built-in replication principals and remove delegated DCSync paths."
foreach ($item in $DcsyncExposures | Select-Object -First 30) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier0: DCSync rights exposure" -Target $item.Principal -Detail "NC=$($item.NamingContext), Right=$($item.RightGuid)" -Severity "Critical"
}

# 30) Tier 0 - Kerberoastable normal users
$AllSpnUsers = @()
try {
    $AllSpnUsers = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(samAccountName=krbtgt)))" -Properties Enabled,PasswordLastSet,SamAccountName,servicePrincipalName
} catch {
    $AllSpnUsers = @()
}
$NormalSpnUsers = @($AllSpnUsers | Where-Object { $_.Enabled -eq $true -and -not $PrivilegedSamAccounts.Contains($_.SamAccountName) })
$KerberoastRiskRows = @()
foreach ($u in $NormalSpnUsers) {
    $pwdAge = if ($u.PasswordLastSet) { [int](New-TimeSpan -Start $u.PasswordLastSet -End $Today).TotalDays } else { 9999 }
    $sev = if ($pwdAge -ge 365) { "Critical" } elseif ($pwdAge -ge 180) { "High" } else { "Medium" }
    $KerberoastRiskRows += [PSCustomObject]@{ Sam = $u.SamAccountName; PwdAge = $pwdAge; Severity = $sev }
}
$KerberoastCount = @($KerberoastRiskRows).Count
$KerberoastSev = if (@($KerberoastRiskRows | Where-Object { $_.Severity -eq "Critical" }).Count -gt 0) { "Critical" } elseif ($KerberoastCount -gt 0) { "High" } else { "Low" }
$KerberoastSample = if ($KerberoastCount -gt 0) { (@($KerberoastRiskRows | Sort-Object PwdAge -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Sam): pwdAge=$($_.PwdAge)d" })) -join "; " } else { "No non-privileged SPN user found" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: Kerberoastable normal users" -Severity $KerberoastSev -Count $KerberoastCount -Sample $KerberoastSample -Recommendation "Migrate service identities to gMSA, rotate stale passwords, and remove unnecessary SPNs."
foreach ($k in $KerberoastRiskRows | Sort-Object PwdAge -Descending | Select-Object -First 30) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier0: Kerberoastable normal users" -Target $k.Sam -Detail "Password age days=$($k.PwdAge)" -Severity $k.Severity
}

# 31) Tier 0 - Dangerous ACE on critical objects
$DangerousAceRows = @()
$DangerousRightNames = @("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner")
$CriticalObjectDns = @(
    $DomainInfo.DistinguishedName,
    "CN=AdminSDHolder,CN=System,$($DomainInfo.DistinguishedName)",
    "CN=Policies,CN=System,$($DomainInfo.DistinguishedName)"
) | Where-Object { $_ } | Select-Object -Unique
foreach ($dc in $DCs) {
    if ($dc.ComputerObjectDN) { $CriticalObjectDns += $dc.ComputerObjectDN }
}
$DangerousAllowList = @("NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators")
foreach ($dn in $CriticalObjectDns | Select-Object -Unique) {
    try {
        $acl = Get-Acl -Path ("AD:" + $dn)
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne "Allow") { continue }
            $principal = "$($ace.IdentityReference)"
            if ($DangerousAllowList -contains $principal) { continue }

            $rightsText = $ace.ActiveDirectoryRights.ToString()
            $matchedRights = @($DangerousRightNames | Where-Object { $rightsText -match $_ })
            if (@($matchedRights).Count -eq 0) { continue }

            $DangerousAceRows += [PSCustomObject]@{ DN = $dn; Principal = $principal; Rights = ($matchedRights -join ",") }
        }
    } catch {}
}
$DangerousAceCount = @($DangerousAceRows).Count
$DangerousAceSeverity = if ($DangerousAceCount -gt 0) { "Critical" } else { "Low" }
$DangerousAceSample = if ($DangerousAceCount -gt 0) { (@($DangerousAceRows | Select-Object -First 5 | ForEach-Object { "$($_.Principal) on $($_.DN) [$($_.Rights)]" })) -join "; " } else { "No dangerous ACE detected on monitored critical objects" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: Dangerous ACE on critical objects" -Severity $DangerousAceSeverity -Count $DangerousAceCount -Sample $DangerousAceSample -Recommendation "Remove non-essential GenericAll/GenericWrite/WriteDacl/WriteOwner ACEs from Tier-0 objects."
foreach ($rowAce in $DangerousAceRows | Select-Object -First 30) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier0: Dangerous ACE on critical objects" -Target $rowAce.Principal -Detail "Object=$($rowAce.DN), Rights=$($rowAce.Rights)" -Severity "Critical"
}

# 32) Tier 0 - NTLMv1 active usage from Security events
$NtlmV1Rows = @()
foreach ($dc in $DCs) {
    try {
        $events = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            param($StartTime)
            Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$StartTime} -ErrorAction Stop | Select-Object -First 1500 | ForEach-Object {
                $xml = [xml]$_.ToXml()
                $eventData = @{}
                foreach ($node in $xml.Event.EventData.Data) { $eventData[$node.Name] = [string]$node.'#text' }
                [PSCustomObject]@{
                    TimeCreated = $_.TimeCreated
                    LogonType = $eventData['LogonType']
                    AuthPackage = $eventData['AuthenticationPackageName']
                    LmPackage = $eventData['LmPackageName']
                    TargetUser = $eventData['TargetUserName']
                    Workstation = $eventData['WorkstationName']
                    IpAddress = $eventData['IpAddress']
                }
            }
        } -ArgumentList (Get-Date).AddDays(-30) -ErrorAction Stop

        $hits = @($events | Where-Object {
            $_.LogonType -eq '3' -and
            $_.AuthPackage -match 'NTLM' -and
            ($_.LmPackage -match 'NTLM V1' -or $_.LmPackage -match '^LM$')
        })

        foreach ($h in $hits) {
            $src = if (-not [string]::IsNullOrWhiteSpace($h.Workstation)) { $h.Workstation } elseif (-not [string]::IsNullOrWhiteSpace($h.IpAddress)) { $h.IpAddress } else { '-' }
            $NtlmV1Rows += [PSCustomObject]@{ DC = $dc.Name; User = $h.TargetUser; Source = $src; Time = $h.TimeCreated; LmPackage = $h.LmPackage }
        }
    } catch {}
}
$NtlmV1Count = @($NtlmV1Rows).Count
$NtlmV1Severity = if ($NtlmV1Count -gt 0) { "Critical" } else { "Low" }
$NtlmV1Sample = if ($NtlmV1Count -gt 0) { (@($NtlmV1Rows | Select-Object -First 5 | ForEach-Object { "$($_.User) from $($_.Source) on $($_.DC)" })) -join "; " } else { "No NTLMv1 logon evidence in sampled 4624 events" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: NTLMv1 active usage" -Severity $NtlmV1Severity -Count $NtlmV1Count -Sample $NtlmV1Sample -Recommendation "Identify NTLMv1 clients, enforce NTLM hardening and eliminate legacy authentication paths."
foreach ($n in $NtlmV1Rows | Select-Object -First 30) {
    $tm = if ($n.Time) { $n.Time.ToString("yyyy-MM-dd HH:mm") } else { "N/A" }
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier0: NTLMv1 active usage" -Target $n.User -Detail "Source=$($n.Source), DC=$($n.DC), LmPackage=$($n.LmPackage), Time=$tm" -Severity "Critical"
}

# 33) Tier 0 - Explicit tier model finding (same data source)
$TierModelSeverity = if ($TieringViolationCount -gt 0) { "Critical" } else { "Low" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: Tier model violations" -Severity $TierModelSeverity -Count $TieringViolationCount -Sample $TieringViolationSample -Recommendation "Separate Tier-0 and Tier-1 administration paths and enforce PAW usage for privileged identities."

# 34) Tier 1 - Shadow Credentials (msDS-KeyCredentialLink)
$ShadowCredentialRows = @()
try {
    $scUsers = Get-ADUser -LDAPFilter "(&(objectCategory=person)(objectClass=user)(msDS-KeyCredentialLink=*))" -Properties SamAccountName,msDS-KeyCredentialLink
    foreach ($u in $scUsers) {
        $ShadowCredentialRows += [PSCustomObject]@{ Obj = $u.SamAccountName; Type = "User"; Count = @($u.'msDS-KeyCredentialLink').Count }
    }
} catch {}
try {
    $scComputers = Get-ADComputer -LDAPFilter "(&(objectClass=computer)(msDS-KeyCredentialLink=*))" -Properties Name,msDS-KeyCredentialLink
    foreach ($c in $scComputers) {
        $ShadowCredentialRows += [PSCustomObject]@{ Obj = $c.Name; Type = "Computer"; Count = @($c.'msDS-KeyCredentialLink').Count }
    }
} catch {}
$ShadowCredentialCount = @($ShadowCredentialRows).Count
$ShadowCredentialSeverity = if ($ShadowCredentialCount -gt 0) { "High" } else { "Low" }
$ShadowCredentialSample = if ($ShadowCredentialCount -gt 0) { (@($ShadowCredentialRows | Select-Object -First 5 | ForEach-Object { "$($_.Obj) ($($_.Type))" })) -join "; " } else { "No object with msDS-KeyCredentialLink found" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: Shadow credentials exposure" -Severity $ShadowCredentialSeverity -Count $ShadowCredentialCount -Sample $ShadowCredentialSample -Recommendation "Review WHfB key credentials and restrict write permissions to msDS-KeyCredentialLink."
foreach ($sc in $ShadowCredentialRows | Select-Object -First 30) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier1: Shadow credentials exposure" -Target $sc.Obj -Detail "ObjectType=$($sc.Type), KeyCredentialCount=$($sc.Count)" -Severity "High"
}

# 35) Tier 1 - Pre-Windows 2000 compatible access
$PreWinFindings = @()
try {
    $preMembers = Get-ADGroupMember -Identity "Pre-Windows 2000 Compatible Access" -ErrorAction Stop
    foreach ($m in $preMembers) {
        $name = if ($m.SamAccountName) { $m.SamAccountName } else { $m.Name }
        if ($name -match 'Authenticated Users|Anonymous Logon|Everyone') {
            $PreWinFindings += "$name"
        }
    }
} catch {}
$PreWinCount = @($PreWinFindings).Count
$PreWinSeverity = if ($PreWinCount -gt 0) { "High" } else { "Low" }
$PreWinSample = if ($PreWinCount -gt 0) { ($PreWinFindings | Select-Object -First 4) -join ", " } else { "No risky principal found in Pre-Windows 2000 Compatible Access" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: Pre-Windows 2000 compatible access" -Severity $PreWinSeverity -Count $PreWinCount -Sample $PreWinSample -Recommendation "Remove broad identities from Pre-Windows 2000 Compatible Access group."

# 36) Tier 1 - DNS Admin and zone transfer posture
$DnsAdmins = @()
try { $DnsAdmins = Get-ADGroupMember -Identity "DnsAdmins" -ErrorAction Stop } catch { $DnsAdmins = @() }
$DnsAdminCount = @($DnsAdmins).Count
$DnsZoneTransferRisk = 0
$DnsZoneTransferSample = "DNS zone transfer posture unavailable"
try {
    $dnsChecks = Invoke-Command -ComputerName $DCs[0].Name -ScriptBlock {
        if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
            Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName, ZoneType, IsAutoCreated, IsDsIntegrated, SecureSecondaries
        }
    } -ErrorAction Stop
    if ($dnsChecks) {
        $riskyZones = @($dnsChecks | Where-Object { $_.SecureSecondaries -notin @("TransferToSecureServers", "NoTransfer") })
        $DnsZoneTransferRisk = @($riskyZones).Count
        $DnsZoneTransferSample = if ($DnsZoneTransferRisk -gt 0) { (@($riskyZones | Select-Object -First 4 -ExpandProperty ZoneName)) -join ", " } else { "No obvious risky zone transfer setting detected" }
    }
} catch {
    $dnsProbeDc = if (@($DCs).Count -gt 0) { [string]$DCs[0].Name } else { "Unknown" }
    Add-SkippedDCRecord -DC $dnsProbeDc -Section "DNS Admin and Zone Transfer" -Reason $_.Exception.Message
}
$DnsRiskTotal = $DnsAdminCount + $DnsZoneTransferRisk
$DnsSeverity = if ($DnsRiskTotal -gt 0) { "High" } else { "Low" }
$DnsSample = "DnsAdmins=$DnsAdminCount; ZoneTransferRisk=$DnsZoneTransferRisk; $DnsZoneTransferSample"
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: DNS admin and zone transfer" -Severity $DnsSeverity -Count $DnsRiskTotal -Sample $DnsSample -Recommendation "Minimize DnsAdmins membership and enforce secure zone transfer configuration."

# 37) Tier 1 - Inactive or orphan service accounts
$OrphanServiceRows = @()
foreach ($u in $AllSpnUsers) {
    $lastLogonDate = if ($u.LastLogonTimestamp) { [DateTime]::FromFileTime([int64]$u.LastLogonTimestamp) } else { [datetime]::MinValue }
    $stale = ($lastLogonDate -eq [datetime]::MinValue -or $lastLogonDate -lt (Get-Date).AddDays(-90))
    $disabled = ($u.Enabled -eq $false)
    if (-not ($stale -or $disabled)) { continue }
    $OrphanServiceRows += [PSCustomObject]@{ Sam = $u.SamAccountName; Disabled = $disabled; LastLogon = $lastLogonDate }
}
$OrphanServiceCount = @($OrphanServiceRows).Count
$OrphanServiceSeverity = if ($OrphanServiceCount -gt 0) { "High" } else { "Low" }
$OrphanServiceSample = if ($OrphanServiceCount -gt 0) { (@($OrphanServiceRows | Select-Object -First 5 | ForEach-Object { "$($_.Sam)" })) -join ", " } else { "No stale/disabled SPN service account detected" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: Inactive or orphan service accounts" -Severity $OrphanServiceSeverity -Count $OrphanServiceCount -Sample $OrphanServiceSample -Recommendation "Disable or clean stale SPN accounts and migrate service identities to managed models."

# 38) Tier 1 - gMSA adoption ratio
$gmsaCount = 0
try {
    if (Get-Command Get-ADServiceAccount -ErrorAction SilentlyContinue) {
        $gmsaCount = @(Get-ADServiceAccount -Filter * -ErrorAction Stop).Count
    }
} catch {}
$spnServiceCount = @($AllSpnUsers).Count
$legacyServiceCount = [math]::Max($spnServiceCount - $gmsaCount, 0)
$gmsaSeverity = if ($legacyServiceCount -gt 0) { "High" } elseif ($spnServiceCount -gt 0) { "Medium" } else { "Low" }
$gmsaSample = "gMSA=$gmsaCount, SPN users=$spnServiceCount, legacy service identities=$legacyServiceCount"
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: gMSA adoption" -Severity $gmsaSeverity -Count $legacyServiceCount -Sample $gmsaSample -Recommendation "Increase gMSA usage and reduce password-managed service accounts."

# 39) Tier 1 - SYSVOL/NETLOGON posture
$frsRiskCount = 0
$frsRiskDcs = @()
foreach ($dc in $DCs) {
    try {
        $frs = Get-CimInstance -ClassName Win32_Service -ComputerName $dc.Name -Filter "Name='NtFrs'" -ErrorAction Stop
        if ($frs -and $frs.State -eq "Running") {
            $frsRiskCount++
            $frsRiskDcs += $dc.Name
        }
    } catch {}
}
$netlogonSensitiveCount = 0
try {
    $netlogonPath = "\\$Domain\\NETLOGON"
    if (Test-Path $netlogonPath) {
        $netlogonSensitiveCount = @(
            Get-ChildItem -Path $netlogonPath -Recurse -File -ErrorAction SilentlyContinue |
                Select-String -Pattern "password|passwd|secret|credential" -SimpleMatch -ErrorAction SilentlyContinue
        ).Count
    }
} catch {}
$sysvolRiskCount = $frsRiskCount + $GppCount + $netlogonSensitiveCount
$sysvolSeverity = if ($sysvolRiskCount -gt 0) { "High" } else { "Low" }
$sysvolSample = "FRS running on $frsRiskCount DC(s); GPP cpassword files=$GppCount; NETLOGON sensitive hits=$netlogonSensitiveCount"
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: SYSVOL and NETLOGON posture" -Severity $sysvolSeverity -Count $sysvolRiskCount -Sample $sysvolSample -Recommendation "Use DFS-R only, remove credential residues from SYSVOL/NETLOGON, and monitor script shares."

# 40) Tier 1 - Privileged account 24h anomalies
$Priv24Rows = @()
$last24 = (Get-Date).AddHours(-24)
foreach ($ev in $UserRiskUserDeviceEvents | Where-Object { $_.TimeCreated -ge $last24 }) {
    $u = "$($ev.TargetUser)"
    if ($u -match '\\') { $u = ($u -split '\\')[-1] }
    if ($u -match '@') { $u = ($u -split '@')[0] }
    if (-not $PrivilegedSamLookup.ContainsKey($u.ToLowerInvariant())) { continue }

    $hour = if ($ev.TimeCreated) { [int]$ev.TimeCreated.Hour } else { 12 }
    $offHours = ($hour -lt 6 -or $hour -gt 20)
    if ($offHours) {
        $Priv24Rows += [PSCustomObject]@{ User = $u; Source = $ev.Source; Time = $ev.TimeCreated; Kind = "OffHours" }
    }
}
$Priv24Count = @($Priv24Rows).Count
$Priv24Severity = if ($Priv24Count -gt 0) { "High" } else { "Low" }
$Priv24Sample = if ($Priv24Count -gt 0) { (@($Priv24Rows | Select-Object -First 5 | ForEach-Object { "$($_.User) from $($_.Source)" })) -join "; " } else { "No off-hours privileged logon anomaly in last 24h" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: Privileged 24h behavior anomalies" -Severity $Priv24Severity -Count $Priv24Count -Sample $Priv24Sample -Recommendation "Investigate off-hours privileged activity and enforce just-in-time administrative sessions."

# 41) Tier 2 - Fine-grained password policy coverage
$FgppMissing = @()
try {
    $fgppPolicies = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop)
    if ($fgppPolicies.Count -gt 0) {
        foreach ($sam in $PrivilegedSamAccounts) {
            try {
                $rp = Get-ADUserResultantPasswordPolicy -Identity $sam -ErrorAction Stop
                if (-not $rp) { $FgppMissing += $sam }
            } catch {
                $FgppMissing += $sam
            }
        }
    }
} catch {}
$FgppCount = @($FgppMissing | Select-Object -Unique).Count
$FgppSeverity = if ($FgppCount -gt 0) { "Medium" } else { "Low" }
$FgppSample = if ($FgppCount -gt 0) { (@($FgppMissing | Select-Object -Unique | Select-Object -First 5)) -join ", " } else { "FGPP coverage appears acceptable or no FGPP configured" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier2: FGPP coverage for privileged accounts" -Severity $FgppSeverity -Count $FgppCount -Sample $FgppSample -Recommendation "Apply stricter fine-grained password policies to privileged identities."

# 42) Tier 2 - SMB/LDAP signing baseline on DCs
$SmbSigningIssues = @()
foreach ($dc in $DCs) {
    try {
        $smbReq = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            try {
                (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -ErrorAction Stop).RequireSecuritySignature
            } catch { $null }
        } -ErrorAction Stop
        if ($null -eq $smbReq -or [int]$smbReq -ne 1) {
            $SmbSigningIssues += [PSCustomObject]@{ DC = $dc.Name; Value = $smbReq }
        }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "SMB Signing Baseline" -Reason $_.Exception.Message
        $SmbSigningIssues += [PSCustomObject]@{ DC = $dc.Name; Value = $null }
    }
}
$SmbLdapCount = @($SmbSigningIssues).Count + $LdapSigningCount + $LdapChannelBindingCount
$SmbLdapSeverity = if ($SmbLdapCount -gt 0) { "Medium" } else { "Low" }
$SmbLdapSample = "SMB signing issues=$(@($SmbSigningIssues).Count); LDAP signing issues=$LdapSigningCount; LDAP channel binding issues=$LdapChannelBindingCount"
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier2: SMB and LDAP signing baseline" -Severity $SmbLdapSeverity -Count $SmbLdapCount -Sample $SmbLdapSample -Recommendation "Enforce SMB signing, LDAP signing and channel binding across all domain controllers."

# 43) Tier 2 - Orphan and unlinked GPOs
$OrphanGpoCount = 0
$DisabledGpoCount = 0
$NeverLinkedGpoNames = @()
$GpoOwnerAnomalyRows = @()
$GpoWriteAbuseRows = @()
try {
    if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
        $allGpos = @(Get-GPO -All -ErrorAction Stop)
        foreach ($g in $allGpos) {
            try {
                $xml = [xml](Get-GPOReport -Guid $g.Id -ReportType Xml -ErrorAction Stop)
                $links = @($xml.GPO.LinksTo)
                if (@($links).Count -eq 0) {
                    $OrphanGpoCount++
                    $NeverLinkedGpoNames += [string]$g.DisplayName
                }
                if ($g.GpoStatus -ne "AllSettingsEnabled") { $DisabledGpoCount++ }

                try {
                    $owner = (Get-Acl ("AD:" + $g.Path)).Owner
                    if ($owner -match "Domain Users|Authenticated Users|Everyone") {
                        $GpoOwnerAnomalyRows += [PSCustomObject]@{ GPO = $g.DisplayName; Owner = $owner }
                    }
                } catch {}

                try {
                    $perms = @(Get-GPPermission -Guid $g.Id -All -ErrorAction Stop)
                    foreach ($perm in $perms) {
                        $permName = [string]$perm.Permission
                        $trusteeName = [string]$perm.Trustee.Name
                        if ([string]::IsNullOrWhiteSpace($trusteeName)) { continue }

                        $isWriteAbuse = ($permName -match "GpoEditDeleteModifySecurity|GpoEdit")
                        if (-not $isWriteAbuse) { continue }

                        $isBroadPrincipal = $trusteeName -match "Domain Users|Authenticated Users|Everyone"
                        $isTier0Admin = $trusteeName -match "Domain Admins|Enterprise Admins|Administrators|SYSTEM"

                        if ($isBroadPrincipal -or -not $isTier0Admin) {
                            $GpoWriteAbuseRows += [PSCustomObject]@{ GPO = $g.DisplayName; Trustee = $trusteeName; Permission = $permName }
                        }
                    }
                } catch {}
            } catch {}
        }
    }
} catch {}

$GpoOwnerAnomalyCount = @($GpoOwnerAnomalyRows).Count
$GpoOwnerAnomalySample = if ($GpoOwnerAnomalyCount -gt 0) {
    (@($GpoOwnerAnomalyRows | Select-Object -First 5 | ForEach-Object { "$($_.GPO):$($_.Owner)" })) -join "; "
} else {
    "No Domain Users/Authenticated Users/Everyone GPO owner anomaly"
}
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: GPO owner anomalies" -Severity $(if ($GpoOwnerAnomalyCount -gt 0) { "High" } else { "Low" }) -Count $GpoOwnerAnomalyCount -Sample $GpoOwnerAnomalySample -Recommendation "Set secure GPO ownership and remove broad principals from GPO owner chain."
foreach ($gpoOwner in $GpoOwnerAnomalyRows | Select-Object -First 40) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier1: GPO owner anomalies" -Target $gpoOwner.GPO -Detail "Owner=$($gpoOwner.Owner)" -Severity "High"
}

$GpoWriteAbuseCount = @($GpoWriteAbuseRows).Count
$GpoWriteAbuseSample = if ($GpoWriteAbuseCount -gt 0) {
    (@($GpoWriteAbuseRows | Select-Object -First 5 | ForEach-Object { "$($_.Trustee) on $($_.GPO) ($($_.Permission))" })) -join "; "
} else {
    "No risky GPO write delegation detected"
}
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: GPO write permission abuse" -Severity $(if ($GpoWriteAbuseCount -gt 0) { "High" } else { "Low" }) -Count $GpoWriteAbuseCount -Sample $GpoWriteAbuseSample -Recommendation "Remove unsafe GPO edit and modify-security rights from non-admin principals."
foreach ($gpoPerm in $GpoWriteAbuseRows | Select-Object -First 40) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier1: GPO write permission abuse" -Target $gpoPerm.GPO -Detail "Trustee=$($gpoPerm.Trustee), Permission=$($gpoPerm.Permission)" -Severity "High"
}

$GpoNoiseCount = $OrphanGpoCount + $DisabledGpoCount
$GpoNoiseSeverity = if ($GpoNoiseCount -gt 0) { "Medium" } else { "Low" }
$NeverLinkedSample = if (@($NeverLinkedGpoNames).Count -gt 0) { (@($NeverLinkedGpoNames | Select-Object -First 5)) -join ", " } else { "None" }
$GpoNoiseSample = "Unlinked (never linked) GPO=$OrphanGpoCount; Disabled/partial GPO=$DisabledGpoCount; Sample=$NeverLinkedSample"
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier2: Orphan and disabled GPO posture" -Severity $GpoNoiseSeverity -Count $GpoNoiseCount -Sample $GpoNoiseSample -Recommendation "Clean unlinked/disabled GPOs and reduce policy management noise."
foreach ($gpoName in $NeverLinkedGpoNames | Select-Object -First 40) {
    Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier2: Orphan and disabled GPO posture" -Target $gpoName -Detail "GPO has no links (never linked)" -Severity "Medium"
}

# 44) Tier 2 - Computer object owner anomalies (DC objects)
$OwnerAnomalyRows = @()
foreach ($dc in $DCs) {
    if (-not $dc.ComputerObjectDN) { continue }
    try {
        $owner = (Get-Acl -Path ("AD:" + $dc.ComputerObjectDN)).Owner
        if ($owner -notmatch "Domain Admins|Administrators|SYSTEM") {
            $OwnerAnomalyRows += [PSCustomObject]@{ DC = $dc.Name; Owner = $owner }
        }
    } catch {}
}
$OwnerAnomalyCount = @($OwnerAnomalyRows).Count
$OwnerAnomalySeverity = if ($OwnerAnomalyCount -gt 0) { "Medium" } else { "Low" }
$OwnerAnomalySample = if ($OwnerAnomalyCount -gt 0) { (@($OwnerAnomalyRows | Select-Object -First 4 | ForEach-Object { "$($_.DC):$($_.Owner)" })) -join "; " } else { "No DC computer object owner anomaly detected" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier2: Computer object owner anomalies" -Severity $OwnerAnomalySeverity -Count $OwnerAnomalyCount -Sample $OwnerAnomalySample -Recommendation "Set expected owner principals for Tier-0 computer objects and review delegated ACL changes."

# 45) Tier 2 - WinRM/RDP authorization scope on DCs
$RemoteAccessRows = @()
foreach ($dc in $DCs) {
    try {
        $groups = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            $rm = @()
            $rdp = @()
            try { $rm = net localgroup "Remote Management Users" | Out-String } catch {}
            try { $rdp = net localgroup "Remote Desktop Users" | Out-String } catch {}
            [PSCustomObject]@{ RM = $rm; RDP = $rdp }
        } -ErrorAction Stop
        $rmHits = if ($groups.RM -and $groups.RM -notmatch "There are no members") { 1 } else { 0 }
        $rdpHits = if ($groups.RDP -and $groups.RDP -notmatch "There are no members") { 1 } else { 0 }
        if (($rmHits + $rdpHits) -gt 0) {
            $RemoteAccessRows += [PSCustomObject]@{ DC = $dc.Name; RM = $rmHits; RDP = $rdpHits }
        }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "WinRM and RDP Authorization" -Reason $_.Exception.Message
    }
}
$RemoteAccessCount = @($RemoteAccessRows).Count
$RemoteAccessSeverity = if ($RemoteAccessCount -gt 0) { "Medium" } else { "Low" }
$RemoteAccessSample = if ($RemoteAccessCount -gt 0) { (@($RemoteAccessRows | Select-Object -First 4 | ForEach-Object { "$($_.DC): RM=$($_.RM),RDP=$($_.RDP)" })) -join "; " } else { "No non-empty Remote Management/Remote Desktop local groups detected on sampled DCs" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier2: WinRM and RDP authorization scope" -Severity $RemoteAccessSeverity -Count $RemoteAccessCount -Sample $RemoteAccessSample -Recommendation "Limit WinRM/RDP local group membership on domain controllers to approved admins only."

# 46) Tier 2 - CredSSP usage exposure
$CredSspRows = @()
foreach ($dc in $DCs) {
    try {
        $credSspEnabled = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
            try {
                $v = (Get-Item -Path WSMan:\localhost\Service\Auth\CredSSP -ErrorAction Stop).Value
                if ("$v" -eq "true") { return $true }
            } catch {}
            return $false
        } -ErrorAction Stop
        if ($credSspEnabled) { $CredSspRows += $dc.Name }
    } catch {
        Add-SkippedDCRecord -DC $dc.Name -Section "CredSSP Exposure" -Reason $_.Exception.Message
    }
}
$CredSspCount = @($CredSspRows).Count
$CredSspSeverity = if ($CredSspCount -gt 0) { "Medium" } else { "Low" }
$CredSspSample = if ($CredSspCount -gt 0) { ($CredSspRows | Select-Object -First 5) -join ", " } else { "No CredSSP enabled DC detected" }
Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier2: CredSSP exposure" -Severity $CredSspSeverity -Count $CredSspCount -Sample $CredSspSample -Recommendation "Disable CredSSP where not required and prefer Kerberos constrained delegation patterns."

# 47) ADCS / PKI - ESC checks
$CaServers = @()
try {
    $enrollmentBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$($ForestInfo.ConfigurationNamingContext)"
    $CaServers = @(
        Get-ADObject -SearchBase $enrollmentBase -LDAPFilter "(objectClass=pKIEnrollmentService)" -Properties dNSHostName,cn -ErrorAction Stop |
            ForEach-Object {
                if ($_.dNSHostName) { [string]$_.dNSHostName } elseif ($_.cn) { [string]$_.cn } else { $null }
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )
} catch {
    $CaServers = @()
}

# ESC1 / ESC4 on certificate templates
try {
    $templatesBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$($ForestInfo.ConfigurationNamingContext)"
    $CertTemplates = @(Get-ADObject -SearchBase $templatesBase -Filter * -Properties msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pkiExtendedKeyUsage,nTSecurityDescriptor,displayName -ErrorAction Stop)

    $Esc1Rows = @()
    $Esc4Rows = @()
    foreach ($t in $CertTemplates) {
        $ekuList = @($t.pkiExtendedKeyUsage)
        $nameFlag = 0
        $enrollmentFlag = 0
        try { $nameFlag = [int]$t.'msPKI-Certificate-Name-Flag' } catch { $nameFlag = 0 }
        try { $enrollmentFlag = [int]$t.'msPKI-Enrollment-Flag' } catch { $enrollmentFlag = 0 }

        $esc1Matched = (($nameFlag -band 0x00000001) -ne 0) -and (($enrollmentFlag -band 0x00000020) -ne 0) -and (('1.3.6.1.5.5.7.3.2' -in $ekuList) -or ('2.5.29.37.0' -in $ekuList))
        if ($esc1Matched) {
            $Esc1Rows += [PSCustomObject]@{ Template = [string]$t.DisplayName; NameFlag = $nameFlag; EnrollmentFlag = $enrollmentFlag }
        }

        $acl = $null
        try { $acl = $t.nTSecurityDescriptor } catch { $acl = $null }
        if ($acl -and $acl.DiscretionaryAcl) {
            foreach ($ace in $acl.DiscretionaryAcl) {
                $sidValue = ""
                try { $sidValue = [string]$ace.SecurityIdentifier.Value } catch { $sidValue = "" }
                $isBroadPrincipal = ($sidValue -eq 'S-1-1-0' -or $sidValue -eq 'S-1-5-11' -or $sidValue -match '-513$')
                if (-not $isBroadPrincipal) { continue }

                $rights = $ace.ActiveDirectoryRights
                $hasDangerousRight = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -or ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -or ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)
                if ($hasDangerousRight) {
                    $Esc4Rows += [PSCustomObject]@{
                        Template = [string]$t.DisplayName
                        PrincipalSid = $sidValue
                        Rights = [string]$rights
                    }
                }
            }
        }
    }

    $Esc1Count = @($Esc1Rows).Count
    $Esc1Sample = if ($Esc1Count -gt 0) { (@($Esc1Rows | Select-Object -First 5 | ForEach-Object { $_.Template })) -join ", " } else { "No ESC1 pattern detected" }
    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: ESC1 - Enrollee supplies subject" -Severity $(if ($Esc1Count -gt 0) { "Critical" } else { "Low" }) -Count $Esc1Count -Sample $Esc1Sample -Recommendation "Disable enrollee supplied subject and tighten authentication template controls."
    foreach ($r in $Esc1Rows | Select-Object -First 40) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier0: ESC1 - Enrollee supplies subject" -Target $r.Template -Detail "NameFlag=$($r.NameFlag), EnrollmentFlag=$($r.EnrollmentFlag)" -Severity "Critical"
    }

    $Esc4Count = @($Esc4Rows).Count
    $Esc4Sample = if ($Esc4Count -gt 0) { (@($Esc4Rows | Select-Object -First 5 | ForEach-Object { "$($_.Template):$($_.PrincipalSid)" })) -join "; " } else { "No ESC4 ACL write-abuse pattern detected" }
    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: ESC4 - Template ACL write abuse" -Severity $(if ($Esc4Count -gt 0) { "Critical" } else { "Low" }) -Count $Esc4Count -Sample $Esc4Sample -Recommendation "Remove template write/owner/ACL rights from broad principals and enforce PKI least privilege."
    foreach ($r in $Esc4Rows | Select-Object -First 40) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier0: ESC4 - Template ACL write abuse" -Target $r.Template -Detail "Principal SID=$($r.PrincipalSid), Rights=$($r.Rights)" -Severity "Critical"
    }
} catch {
    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: ESC1 - Enrollee supplies subject" -Severity "Low" -Count 0 -Sample "Check could not be completed" -Recommendation "Control unavailable: verify certificate template ESC1 conditions manually."
    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: ESC4 - Template ACL write abuse" -Severity "Low" -Count 0 -Sample "Check could not be completed" -Recommendation "Control unavailable: review template ACL permissions manually."
}

# ESC6 registry flag on CA servers
try {
    $Esc6Rows = @()
    foreach ($ca in $CaServers) {
        try {
            $esc6Flag = Invoke-Command -ComputerName $ca -ScriptBlock {
                (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\*" -ErrorAction SilentlyContinue).EditFlags -band 0x00040000
            } -ErrorAction Stop

            $flagEnabled = $false
            if ($esc6Flag -is [array]) {
                $flagEnabled = @($esc6Flag | Where-Object { [int]$_ -ne 0 }).Count -gt 0
            } elseif ($null -ne $esc6Flag) {
                $flagEnabled = ([int]$esc6Flag -ne 0)
            }

            if ($flagEnabled) {
                $Esc6Rows += [PSCustomObject]@{ CAServer = $ca }
            }
        } catch {
            Add-SkippedDCRecord -DC $ca -Section "ADCS ESC6" -Reason $_.Exception.Message
        }
    }

    $Esc6Count = @($Esc6Rows).Count
    $Esc6Sample = if ($Esc6Count -gt 0) { (@($Esc6Rows | Select-Object -First 5 -ExpandProperty CAServer)) -join ", " } else { "No ESC6 flag detected on reachable CA servers" }
    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: ESC6 - SAN attribute injection flag" -Severity $(if ($Esc6Count -gt 0) { "Critical" } else { "Low" }) -Count $Esc6Count -Sample $Esc6Sample -Recommendation "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on enterprise CAs unless strictly required and governed."
    foreach ($r in $Esc6Rows | Select-Object -First 40) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier0: ESC6 - SAN attribute injection flag" -Target $r.CAServer -Detail "EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled" -Severity "Critical"
    }
} catch {
    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier0: ESC6 - SAN attribute injection flag" -Severity "Low" -Count 0 -Sample "Check could not be completed" -Recommendation "Control unavailable: verify CA EditFlags manually."
}

# ESC8 web enrollment relay surface
try {
    $Esc8Rows = @()
    foreach ($ca in $CaServers) {
        $portReachable = $false
        $urlHit = $false
        try {
            $t80 = Test-NetConnection -ComputerName $ca -Port 80 -WarningAction SilentlyContinue
            if ($t80 -and $t80.TcpTestSucceeded) { $portReachable = $true }
        } catch {}
        if (-not $portReachable) {
            try {
                $t443 = Test-NetConnection -ComputerName $ca -Port 443 -WarningAction SilentlyContinue
                if ($t443 -and $t443.TcpTestSucceeded) { $portReachable = $true }
            } catch {}
        }

        if ($portReachable) {
            try {
                $resp = Invoke-WebRequest -Uri ("http://{0}/certsrv/" -f $ca) -UseBasicParsing -Method Get -TimeoutSec 6 -ErrorAction Stop
                if ($resp -and $resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500) { $urlHit = $true }
            } catch {
                try {
                    $respTls = Invoke-WebRequest -Uri ("https://{0}/certsrv/" -f $ca) -UseBasicParsing -Method Get -TimeoutSec 6 -ErrorAction Stop
                    if ($respTls -and $respTls.StatusCode -ge 200 -and $respTls.StatusCode -lt 500) { $urlHit = $true }
                } catch {
                    Add-SkippedDCRecord -DC $ca -Section "ADCS ESC8" -Reason $_.Exception.Message
                }
            }
        }

        if ($portReachable -and $urlHit) {
            $Esc8Rows += [PSCustomObject]@{ CAServer = $ca }
        }
    }

    $Esc8Count = @($Esc8Rows).Count
    $Esc8Sample = if ($Esc8Count -gt 0) { (@($Esc8Rows | Select-Object -First 5 -ExpandProperty CAServer)) -join ", " } else { "No reachable AD CS /certsrv endpoint detected" }
    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: ESC8 - AD CS HTTP relay surface" -Severity $(if ($Esc8Count -gt 0) { "High" } else { "Low" }) -Count $Esc8Count -Sample $Esc8Sample -Recommendation "Limit or disable AD CS web enrollment and harden NTLM relay protections on CA web endpoints."
    foreach ($r in $Esc8Rows | Select-Object -First 40) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Tier1: ESC8 - AD CS HTTP relay surface" -Target $r.CAServer -Detail "HTTP(S) /certsrv endpoint reachable" -Severity "High"
    }
} catch {
    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Tier1: ESC8 - AD CS HTTP relay surface" -Severity "Low" -Count 0 -Sample "Check could not be completed" -Recommendation "Control unavailable: validate CA HTTP enrollment exposure manually."
}

# Privileged groups and critical infrastructure are also scored as part of AD Risk Dashboard
$PrivilegedRiskRows = @($PrivilegedGroupReviewRows + $CriticalInfrastructureRows)
foreach ($row in $PrivilegedRiskRows) {
    $severity = Get-PrioritySeverity $row.Priority
    $usersCount = Get-IntOrZero $row.UsersMember
    $computerCount = Get-IntOrZero $row.ComputersMember
    $indirectCount = Get-IntOrZero $row.IndirectControl
    $unresolvedCount = Get-IntOrZero $row.UnresolvedMembers
    $exposureCount = $usersCount + $computerCount + $indirectCount + $unresolvedCount

    if (-not $row.Exists) {
        if ($severity -eq "Low") { $severity = "Medium" }
        if ($exposureCount -lt 1) { $exposureCount = 1 }
    }

    $sample = if (-not $row.Exists) {
        "Object not found or inaccessible"
    } else {
        "Users=$usersCount, Computers=$computerCount, Indirect=$indirectCount, Unresolved=$unresolvedCount"
    }

    Add-PingFinding -Category "Privileged Infrastructure" -Rule "Privileged Review: $($row.ObjectName)" -Severity $severity -Count $exposureCount -Sample $sample -Recommendation $row.Analysis

    if (-not $row.Exists) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Privileged Review: $($row.ObjectName)" -Target $row.ObjectName -Detail "Object could not be validated in directory" -Severity $severity
        continue
    }

    if ($usersCount -gt 0) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Privileged Review: $($row.ObjectName)" -Target $row.ObjectName -Detail "User members: $usersCount" -Severity $severity
    }
    if ($computerCount -gt 0) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Privileged Review: $($row.ObjectName)" -Target $row.ObjectName -Detail "Computer members: $computerCount" -Severity $severity
    }
    if ($indirectCount -gt 0) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Privileged Review: $($row.ObjectName)" -Target $row.ObjectName -Detail "Indirect control groups: $indirectCount" -Severity $severity
    }
    if ($unresolvedCount -gt 0) {
        Add-PingDetail -Category "Privileged Infrastructure" -Rule "Privileged Review: $($row.ObjectName)" -Target $row.ObjectName -Detail "Unresolved members: $unresolvedCount" -Severity $severity
    }
}

# Certificate Authority (AD CS / PKI) focused findings (virtual category for riskboard scoring)
$CARiskFindings = @(
    $PingCastleFindings |
        Where-Object {
            (Test-PingFindingMatched $_) -and (
                ([string]$_.Rule -match '(?i)esc[0-9]+|ad\s*cs|certificate|certificat|pki|template|enrollee|san') -or
                ([string]$_.Recommendation -match '(?i)certificate|ad\s*cs|pki|template|ca')
            )
        } |
        Sort-Object @{ Expression = { Get-PingSeverityRank $_.Severity }; Descending = $true }, @{ Expression = {
            $tmpCount = 0
            [void][int]::TryParse([string]$_.Count, [ref]$tmpCount)
            $tmpCount
        }; Descending = $true }
)

# Risk score model (PingCastle-like weighted summary)
$PingScoreCategoriesAll = @("Stale Objects", "Privileged Accounts", "Privileged Infrastructure", "Certificate Authority", "Trusts", "Anomalies", "Hygiene")
$PingScoreCategoriesPrimary = @("Stale Objects", "Privileged Accounts", "Privileged Infrastructure", "Certificate Authority", "Trusts", "Anomalies")
$PingCategoryScoreMap = @{}
$PingCategoryMatchedCountMap = @{}
$PingCategoryFindingsSortedMap = @{}
$CategoryPenaltyMap = @{}

foreach ($cat in $PingScoreCategoriesAll) {
    $catFindings = if ($cat -eq "Certificate Authority") {
        @($CARiskFindings)
    } else {
        @($PingCastleFindings | Where-Object { $_.Category -eq $cat })
    }
    $PingCategoryFindingsSortedMap[$cat] = @(
        $catFindings | Sort-Object @{ Expression = { Get-PingSeverityRank $_.Severity }; Descending = $true }, Rule
    )

    $catMatched = @($catFindings | Where-Object { Test-PingFindingMatched $_ })
    $PingCategoryMatchedCountMap[$cat] = $catMatched.Count

    if ($catMatched.Count -eq 0) {
        $PingCategoryScoreMap[$cat] = 0
    } else {
        $catScore = ($catMatched | ForEach-Object { Get-PingSeverityScore $_.Severity } | Measure-Object -Maximum).Maximum
        $PingCategoryScoreMap[$cat] = [int]$catScore
    }

    $CategoryPenaltyMap[$cat] = 0
}

$ScoreWeights = @{ "Critical" = 25; "High" = 10; "Medium" = 4; "Low" = 1 }
$RawPenalty = (
    $PingCastleFindings |
        Where-Object {
            $tmpVal = 0.0
            $cmp = (Get-CountComparableValue $_.Count)
            [void][double]::TryParse([string]$cmp, [ref]$tmpVal)
            ($tmpVal -gt 0) -and $ScoreWeights.ContainsKey($_.Severity)
        } |
        ForEach-Object {
            $CategoryPenaltyMap[$_.Category] = [int]($CategoryPenaltyMap[$_.Category]) + [int]($ScoreWeights[$_.Severity])
            [int]$ScoreWeights[$_.Severity]
        } |
        Measure-Object -Sum
).Sum
if ($null -eq $RawPenalty) { $RawPenalty = 0 }

foreach ($cf in $CARiskFindings) {
    if ($ScoreWeights.ContainsKey($cf.Severity)) {
        $CategoryPenaltyMap["Certificate Authority"] = [int]($CategoryPenaltyMap["Certificate Authority"]) + [int]($ScoreWeights[$cf.Severity])
    }
}

$CategoryThresholdMap = @{
    "Stale Objects" = 80
    "Privileged Accounts" = 100
    "Privileged Infrastructure" = 120
    "Certificate Authority" = 80
    "Trusts" = 60
    "Anomalies" = 80
    "Hygiene" = 60
}

$CategoryWeightMap = @{
    "Stale Objects" = 20
    "Privileged Accounts" = 20
    "Privileged Infrastructure" = 20
    "Certificate Authority" = 20
    "Trusts" = 20
    "Anomalies" = 20
}

$CategoryRiskPctMap = @{}
foreach ($cat in $PingScoreCategoriesAll) {
    $threshold = [double]$CategoryThresholdMap[$cat]
    if ($threshold -le 0) { $threshold = 100.0 }
    $catPenalty = [double]$CategoryPenaltyMap[$cat]
    $catRiskPct = [math]::Round([math]::Min(100.0, ($catPenalty / $threshold) * 100.0), 1)
    if ($catRiskPct -lt 0) { $catRiskPct = 0.0 }
    $CategoryRiskPctMap[$cat] = $catRiskPct
}

$weightedSum = 0.0
$weightTotal = 0.0
foreach ($cat in $PingScoreCategoriesPrimary) {
    $w = [double]$CategoryWeightMap[$cat]
    $weightedSum += ([double]$CategoryRiskPctMap[$cat] * $w)
    $weightTotal += $w
}
if ($weightTotal -le 0) { $weightTotal = 1.0 }

$DomainRiskScore = [int][math]::Round($weightedSum / $weightTotal, 0)
$DomainRiskScore = [Math]::Max(0, [Math]::Min(100, $DomainRiskScore))
$RiskRating = switch ($DomainRiskScore) {
    { $_ -ge 80 } { "Critical" }
    { $_ -ge 60 } { "Poor" }
    { $_ -ge 40 } { "Acceptable" }
    default { "Good" }
}

$SkippedControlCount = @($SkippedDCs).Count
$SkippedHostCount = @(
    @($SkippedDCs |
        ForEach-Object { [string]$_.DC } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique)
).Count

if ($SkippedControlCount -eq 0) {
    $RiskConfidenceLevel = "High"
    $RiskConfidenceNote = "No skipped/unreachable control execution detected."
} elseif ($SkippedControlCount -le 5) {
    $RiskConfidenceLevel = "Medium"
    $RiskConfidenceNote = "Some controls were skipped ($SkippedControlCount controls on $SkippedHostCount host(s)); review skipped checks before final sign-off."
} else {
    $RiskConfidenceLevel = "Low"
    $RiskConfidenceNote = "Many controls were skipped ($SkippedControlCount controls on $SkippedHostCount host(s)); risk score may be optimistic until connectivity is restored."
}

$PingGlobalRiskScore = $DomainRiskScore
$CategoryPenaltyRows = @($PingScoreCategoriesAll | ForEach-Object {
    [PSCustomObject]@{
        Category = $_
        Penalty = [int]($CategoryPenaltyMap[$_])
        Matched = [int]($PingCategoryMatchedCountMap[$_])
        RiskPct = [double]($CategoryRiskPctMap[$_])
    }
})
$CategoryPenaltyRows = @($CategoryPenaltyRows | Sort-Object -Property Penalty -Descending)

$RemediationCategoryActionMap = @{
    "Privileged Infrastructure" = "Harden Tier-0 assets first: lock down Domain Controllers, sensitive groups, and certificate infrastructure delegation."
    "Certificate Authority" = "Harden AD CS/CA quickly: close ESC paths, narrow template ACLs, and restrict enrollment scope to least privilege."
    "Privileged Accounts" = "Reduce standing privilege: remove unnecessary admin rights, enforce PAW/JIT model, and rotate privileged credentials."
    "Anomalies" = "Investigate unusual identity/permission patterns and close unintended paths that allow privilege escalation."
    "Trusts" = "Review trust direction/filtering and remove legacy or overly permissive trust configurations."
    "Stale Objects" = "Disable and clean stale users/computers after business validation to shrink attack surface."
    "Hygiene" = "Improve baseline hygiene: enforce naming/ownership standards, remove orphaned settings, and maintain secure defaults."
}

$TopRiskCategories = @(
    $CategoryPenaltyRows |
        Where-Object { [double]$_.RiskPct -gt 0 } |
        Sort-Object @{ Expression = { [double]$_.RiskPct }; Descending = $true }, @{ Expression = { [int]$_.Matched }; Descending = $true } |
        Select-Object -First 3
)

$TopRiskCategorySummary = if ($TopRiskCategories.Count -gt 0) {
    ($TopRiskCategories | ForEach-Object { "{0} ({1}%)" -f $_.Category, $_.RiskPct }) -join ", "
} else {
    "No active risk pressure detected in scored categories."
}

$PingSnapshotFile = Join-Path $PSScriptRoot "tools\pingcastle_baseline_snapshot.json"
$RemediationStateMap = @{}
if (Test-Path $PingSnapshotFile) {
    try {
        $prevSnap = Get-Content $PingSnapshotFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($prevSnap.PSObject.Properties.Name -contains 'RemediationStates') {
            foreach ($rs in @($prevSnap.RemediationStates)) {
                if (-not $rs) { continue }
                $RemediationStateMap[[string]$rs.Key] = [PSCustomObject]@{
                    Status = [string]$rs.Status
                    Note = [string]$rs.Note
                    UpdatedAt = [string]$rs.UpdatedAt
                }
            }
        }
    } catch {}
}

$QuickRemediationItems = @()
foreach ($catRow in $TopRiskCategories) {
    $catName = [string]$catRow.Category
    $nextAction = if ($RemediationCategoryActionMap.ContainsKey($catName)) {
        [string]$RemediationCategoryActionMap[$catName]
    } else {
        "Review findings in this category and apply least-privilege and hardening controls."
    }

    $itemKey = "$catName|$nextAction"
    $savedState = if ($RemediationStateMap.ContainsKey($itemKey)) { $RemediationStateMap[$itemKey] } else { $null }

    $QuickRemediationItems += [PSCustomObject]@{
        Key = $itemKey
        Category = $catName
        RiskPct = [double]$catRow.RiskPct
        Action = $nextAction
        CurrentStatus = if ($savedState) { [string]$savedState.Status } else { 'open' }
        CurrentNote = if ($savedState) { [string]$savedState.Note } else { '' }
        UpdatedAt = if ($savedState) { [string]$savedState.UpdatedAt } else { '' }
    }
}

$PriorityRiskFindings = @(
    $PingCastleFindings |
        Where-Object {
            (Test-PingFindingMatched $_) -and ($_.Severity -eq "Critical" -or $_.Severity -eq "High")
        } |
        Sort-Object @{ Expression = { Get-PingSeverityRank $_.Severity }; Descending = $true }, @{ Expression = {
            $tmpCount = 0
            [void][int]::TryParse([string]$_.Count, [ref]$tmpCount)
            $tmpCount
        }; Descending = $true } |
        Select-Object -First 5
)

$QuickRemediationJson = @($QuickRemediationItems) | ConvertTo-Json -Depth 5 -Compress
if ([string]::IsNullOrWhiteSpace($QuickRemediationJson)) { $QuickRemediationJson = "[]" }
$PriorityRiskFindingsJson = @($PriorityRiskFindings) | ConvertTo-Json -Depth 6 -Compress
if ([string]::IsNullOrWhiteSpace($PriorityRiskFindingsJson)) { $PriorityRiskFindingsJson = "[]" }

$CARiskFindingsJson = @($CARiskFindings) | ConvertTo-Json -Depth 6 -Compress
if ([string]::IsNullOrWhiteSpace($CARiskFindingsJson)) { $CARiskFindingsJson = "[]" }

$MitreTacticMap = @{
    "Privileged Accounts" = @("TA0003 Persistence", "TA0004 Privilege Escalation", "TA0006 Credential Access")
    "Privileged Infrastructure" = @("TA0003 Persistence", "TA0004 Privilege Escalation", "TA0005 Defense Evasion")
    "Certificate Authority" = @("TA0004 Privilege Escalation", "TA0005 Defense Evasion", "TA0008 Lateral Movement")
    "Trusts" = @("TA0008 Lateral Movement", "TA0001 Initial Access")
    "Anomalies" = @("TA0005 Defense Evasion", "TA0007 Discovery")
    "Stale Objects" = @("TA0003 Persistence", "TA0008 Lateral Movement")
    "Hygiene" = @("TA0005 Defense Evasion", "TA0007 Discovery")
}

$MitreTechniqueSeedMap = @{
    "Privileged Accounts" = @("T1078 Valid Accounts", "T1098 Account Manipulation")
    "Privileged Infrastructure" = @("T1484 Domain Policy Modification", "T1558 Steal or Forge Kerberos Tickets")
    "Certificate Authority" = @("T1649 Steal or Forge Authentication Certificates", "T1550 Use Alternate Authentication Material")
    "Trusts" = @("T1021 Remote Services", "T1133 External Remote Services")
    "Anomalies" = @("T1069 Permission Groups Discovery", "T1087 Account Discovery")
    "Stale Objects" = @("T1078 Valid Accounts", "T1136 Create Account")
    "Hygiene" = @("T1562 Impair Defenses", "T1070 Indicator Removal")
}

$MitreRows = @()
foreach ($f in ($PingCastleFindings | Where-Object { Test-PingFindingMatched $_ })) {
    $cat = [string]$f.Category
    $tactics = if ($MitreTacticMap.ContainsKey($cat)) { @($MitreTacticMap[$cat]) } else { @("TA0005 Defense Evasion") }
    $techniques = if ($MitreTechniqueSeedMap.ContainsKey($cat)) { @($MitreTechniqueSeedMap[$cat]) } else { @("T1078 Valid Accounts") }
    $MitreRows += [PSCustomObject]@{
        Category = $cat
        Rule = [string]$f.Rule
        Severity = [string]$f.Severity
        Tactics = $tactics
        Techniques = $techniques
    }
}
$MitreRowsJson = @($MitreRows) | ConvertTo-Json -Depth 7 -Compress
if ([string]::IsNullOrWhiteSpace($MitreRowsJson)) { $MitreRowsJson = "[]" }

$ThreatPriorityRows = @()
foreach ($m in $MitreRows) {
    $severityText = [string]$m.Severity
    $priorityScore = switch ($severityText) {
        "Critical" { 100 }
        "High" { 80 }
        "Medium" { 55 }
        default { 35 }
    }
    foreach ($tech in @($m.Techniques)) {
        $ThreatPriorityRows += [PSCustomObject]@{
            Rule = [string]$m.Rule
            Category = [string]$m.Category
            Severity = $severityText
            Tactics = (@($m.Tactics) -join ", ")
            Technique = [string]$tech
            PriorityScore = $priorityScore
        }
    }
}
$ThreatPriorityRows = @(
    $ThreatPriorityRows | Sort-Object @{ Expression = { [int]$_.PriorityScore }; Descending = $true }, Technique, Rule
)
$ThreatPriorityRowsJson = @($ThreatPriorityRows) | ConvertTo-Json -Depth 7 -Compress
if ([string]::IsNullOrWhiteSpace($ThreatPriorityRowsJson)) { $ThreatPriorityRowsJson = "[]" }

$AttackChainNodes = @()
foreach ($f in ($PriorityRiskFindings | Select-Object -First 6)) {
    $AttackChainNodes += [PSCustomObject]@{
        Category = [string]$f.Category
        Rule = [string]$f.Rule
        Severity = [string]$f.Severity
    }
}
$AttackChainNodesJson = @($AttackChainNodes) | ConvertTo-Json -Depth 6 -Compress
if ([string]::IsNullOrWhiteSpace($AttackChainNodesJson)) { $AttackChainNodesJson = "[]" }

$AttackChainScenariosJson = "[]"
try {
    function Test-FindingActive {
        param([string]$ruleName)

        $f = $PingCastleFindings | Where-Object {
            $countVal = 0
            [void][int]::TryParse([string]$_.Count, [ref]$countVal)
            $_.Rule -eq $ruleName -and $countVal -gt 0
        } | Select-Object -First 1
        return ($null -ne $f)
    }

    function Test-AnyFindingActive {
        param([string[]]$ruleNames)

        foreach ($ruleName in @($ruleNames)) {
            if (Test-FindingActive $ruleName) { return $true }
        }
        return $false
    }

    function Get-ActiveFindingMatches {
        param([string[]]$ruleNames)

        $matched = @()
        foreach ($ruleName in @($ruleNames)) {
            if (Test-FindingActive $ruleName) { $matched += [string]$ruleName }
        }
        return @($matched | Select-Object -Unique)
    }

    $AttackChainScenarios = @(
        [PSCustomObject]@{
            ScenarioName = "Coercion to DA"
            Steps = @("DC spooler exposure", "Unconstrained delegation", "krbtgt password age")
            Risk = "Critical"
            Description = "Spooler + unconstrained delegation = NTLM coercion to TGT capture path with DA takeover potential."
            Matched = $false
            Evidence = @()
        },
        [PSCustomObject]@{
            ScenarioName = "Kerberoast to Privilege Escalation"
            Steps = @("SPN-backed account", "Weak Kerberos encryption", "Kerberoast", "DA")
            Risk = "Critical"
            Description = "SPN exposure combined with weak Kerberos encryption enables practical Kerberoast cracking and privilege escalation."
            Matched = $false
            Evidence = @()
        },
        [PSCustomObject]@{
            ScenarioName = "ADCS Certificate Abuse"
            Steps = @("ESC1/ESC4 exposure", "Forged certificate", "Domain authentication")
            Risk = "Critical"
            Description = "ESC1 or ESC4 weaknesses can allow forged authentication certificates and domain-level identity abuse."
            Matched = $false
            Evidence = @()
        },
        [PSCustomObject]@{
            ScenarioName = "Shadow Admin Path"
            Steps = @("Shadow admin exposure", "adminCount drift", "DCSync", "domain takeover")
            Risk = "Critical"
            Description = "Shadow admin posture plus adminCount or DCSync drift creates a hidden domain takeover route."
            Matched = $false
            Evidence = @()
        },
        [PSCustomObject]@{
            ScenarioName = "GPO Takeover"
            Steps = @("GPO write", "policy push", "privileged execution", "tier violation")
            Risk = "High"
            Description = "GPO ownership/write abuse combined with tiering violations can push malicious policy into privileged paths."
            Matched = $false
            Evidence = @()
        },
        [PSCustomObject]@{
            ScenarioName = "Legacy Auth Relay"
            Steps = @("NTLM legacy posture", "LDAP relay weakness", "credential capture")
            Risk = "High"
            Description = "Legacy NTLM posture with LDAP signing/channel-binding weakness allows relay and credential capture opportunities."
            Matched = $false
            Evidence = @()
        },
        [PSCustomObject]@{
            ScenarioName = "Stale Account Takeover"
            Steps = @("AS-REP roastable users", "password never expires", "long-lived session abuse")
            Risk = "High"
            Description = "AS-REP roastable identities plus non-expiring passwords increase long-lived credential replay risk."
            Matched = $false
            Evidence = @()
        }
    )

    $scenarioObjA = $AttackChainScenarios | Where-Object { $_.ScenarioName -eq "Coercion to DA" } | Select-Object -First 1
    $scenarioA = (Test-AnyFindingActive @("DC spooler exposure", "DC coercion exposure")) -and (Test-AnyFindingActive @("Unconstrained delegation"))
    if ($scenarioA) {
        $scenarioObjA.Matched = $true
        $scenarioObjA.Evidence = @(
            (Get-ActiveFindingMatches @("DC spooler exposure", "DC coercion exposure")) +
            (Get-ActiveFindingMatches @("Unconstrained delegation"))
        )
    }

    $scenarioObjB = $AttackChainScenarios | Where-Object { $_.ScenarioName -eq "Kerberoast to Privilege Escalation" } | Select-Object -First 1
    $scenarioB = (Test-AnyFindingActive @("Tier0: Kerberoastable normal users", "Privileged account with SPN")) -and (Test-AnyFindingActive @("Weak Kerberos encryption"))
    if ($scenarioB) {
        $scenarioObjB.Matched = $true
        $scenarioObjB.Evidence = @(
            (Get-ActiveFindingMatches @("Tier0: Kerberoastable normal users", "Privileged account with SPN")) +
            (Get-ActiveFindingMatches @("Weak Kerberos encryption"))
        )
    }

    $scenarioObjC = $AttackChainScenarios | Where-Object { $_.ScenarioName -eq "ADCS Certificate Abuse" } | Select-Object -First 1
    $scenarioC = (Test-AnyFindingActive @("Tier0: ESC1 - Enrollee supplies subject", "Tier0: ESC4 - Template ACL write abuse"))
    if ($scenarioC) {
        $scenarioObjC.Matched = $true
        $scenarioObjC.Evidence = @(Get-ActiveFindingMatches @("Tier0: ESC1 - Enrollee supplies subject", "Tier0: ESC4 - Template ACL write abuse"))
    }

    $scenarioObjD = $AttackChainScenarios | Where-Object { $_.ScenarioName -eq "Shadow Admin Path" } | Select-Object -First 1
    $scenarioD = (Test-AnyFindingActive @("Shadow admin exposure")) -and (Test-AnyFindingActive @("adminCount drift", "AdminCount drift", "DCSync rights exposure"))
    if ($scenarioD) {
        $scenarioObjD.Matched = $true
        $scenarioObjD.Evidence = @(
            (Get-ActiveFindingMatches @("Shadow admin exposure")) +
            (Get-ActiveFindingMatches @("adminCount drift", "AdminCount drift", "DCSync rights exposure"))
        )
    }

    $scenarioObjE = $AttackChainScenarios | Where-Object { $_.ScenarioName -eq "GPO Takeover" } | Select-Object -First 1
    $scenarioE = (Test-AnyFindingActive @("Tier1: GPO owner anomalies", "Tier1: GPO write permission abuse")) -and (Test-AnyFindingActive @("Tiering violations", "Tier0: Tier model violations"))
    if ($scenarioE) {
        $scenarioObjE.Matched = $true
        $scenarioObjE.Evidence = @(
            (Get-ActiveFindingMatches @("Tier1: GPO owner anomalies", "Tier1: GPO write permission abuse")) +
            (Get-ActiveFindingMatches @("Tiering violations", "Tier0: Tier model violations"))
        )
    }

    $scenarioObjF = $AttackChainScenarios | Where-Object { $_.ScenarioName -eq "Legacy Auth Relay" } | Select-Object -First 1
    $scenarioF = (Test-AnyFindingActive @("Old NTLM posture", "Tier0: NTLMv1 active usage")) -and (Test-AnyFindingActive @("LDAP signing posture", "LDAP channel binding posture"))
    if ($scenarioF) {
        $scenarioObjF.Matched = $true
        $scenarioObjF.Evidence = @(
            (Get-ActiveFindingMatches @("Old NTLM posture", "Tier0: NTLMv1 active usage")) +
            (Get-ActiveFindingMatches @("LDAP signing posture", "LDAP channel binding posture"))
        )
    }

    $scenarioObjG = $AttackChainScenarios | Where-Object { $_.ScenarioName -eq "Stale Account Takeover" } | Select-Object -First 1
    $scenarioG = (Test-AnyFindingActive @("AS-REP roastable users")) -and (Test-AnyFindingActive @("Password never expires (enabled users)"))
    if ($scenarioG) {
        $scenarioObjG.Matched = $true
        $scenarioObjG.Evidence = @(
            (Get-ActiveFindingMatches @("AS-REP roastable users")) +
            (Get-ActiveFindingMatches @("Password never expires (enabled users)"))
        )
    }

    $AttackChainScenariosJson = @($AttackChainScenarios | Where-Object { $_.Matched }) | ConvertTo-Json -Depth 6 -Compress
    if ([string]::IsNullOrWhiteSpace($AttackChainScenariosJson)) { $AttackChainScenariosJson = "[]" }
} catch {
    $AttackChainScenariosJson = "[]"
}

$PingModelMaxRows = 0
foreach ($cat in $PingScoreCategoriesPrimary) {
    $catRowCount = @($PingCategoryFindingsSortedMap[$cat]).Count
    if ($catRowCount -gt $PingModelMaxRows) { $PingModelMaxRows = $catRowCount }
}

# Build lookup data so each risk row can show actionable detail on click.
$PingRuleDetailsMap = @{}
$defaultAbout = "AD security finding"
$defaultSource = "Directory attributes and related checks"
$defaultAction = "Apply remediation steps based on the specific rule context."
foreach ($f in $PingCastleFindings) {
    $ruleInfo = Get-PingRuleInfo $f.Rule
    $ruleReference = Get-PingRuleReference $f.Rule
    $detailRows = @($PingCastleDetails | Where-Object { $_.Category -eq $f.Category -and $_.Rule -eq $f.Rule })
    $detailLines = @()
    foreach ($d in $detailRows | Select-Object -First 80) {
        $detailLines += "$($d.Target): $($d.Detail) [$($d.Severity)]"
    }

    $key = "$($f.Category)||$($f.Rule)"
    $entry = [ordered]@{
        c = $f.Category
        r = $f.Rule
        s = $f.Severity
        n = $f.Count
        m = $f.Sample
        p = $f.Recommendation
        f = $ruleReference
        d = @($detailLines)
    }
    if ($ruleInfo.About -ne $defaultAbout) { $entry.a = $ruleInfo.About }
    if ($ruleInfo.Source -ne $defaultSource) { $entry.o = $ruleInfo.Source }
    if ($ruleInfo.Action -ne $defaultAction) { $entry.u = $ruleInfo.Action }
    $PingRuleDetailsMap[$key] = [PSCustomObject]$entry
}
$PingRuleDetailsJson = $PingRuleDetailsMap | ConvertTo-Json -Depth 8 -Compress
if ([string]::IsNullOrWhiteSpace($PingRuleDetailsJson)) {
    $PingRuleDetailsJson = "{}"
}

# 26) Baseline snapshot and diff for PingCastle-style findings
$PingSnapshotFile = Join-Path $PSScriptRoot "tools\\pingcastle_baseline_snapshot.json"
$PingBaselinePreviousDate = "N/A"
$PingBaselinePreviousScore = "N/A"
$PingBaselineCurrentDate = $Today.ToString("yyyy-MM-dd HH:mm:ss")
$PingDiffRows = @()

$CurrentPingSnapshot = [PSCustomObject]@{
    GeneratedAt = $PingBaselineCurrentDate
    DomainRiskScore = $DomainRiskScore
    RiskRating = $RiskRating
    CategoryRisk = @($CategoryPenaltyRows)
    RemediationStates = @(
        $RemediationStateMap.GetEnumerator() | ForEach-Object {
            [PSCustomObject]@{
                Key = $_.Key
                Status = $_.Value.Status
                Note = $_.Value.Note
                UpdatedAt = $_.Value.UpdatedAt
            }
        }
    )
    Findings = @($PingCastleFindings | ForEach-Object {
        [PSCustomObject]@{
            Category = $_.Category
            Rule = $_.Rule
            Severity = $_.Severity
            Count = $_.Count
            Sample = $_.Sample
            Recommendation = $_.Recommendation
        }
    })
}

$CurrentByKey = @{}
foreach ($f in $CurrentPingSnapshot.Findings) {
    $key = "$($f.Category)|$($f.Rule)"
    $CurrentByKey[$key] = $f
}

$PreviousSnapshot = $null
if (Test-Path $PingSnapshotFile) {
    try {
        $PreviousSnapshot = Get-Content $PingSnapshotFile -Raw | ConvertFrom-Json
        if ($PreviousSnapshot.GeneratedAt) {
            $PingBaselinePreviousDate = $PreviousSnapshot.GeneratedAt
        }
        if ($PreviousSnapshot.PSObject.Properties.Name -contains 'DomainRiskScore') {
            $PingBaselinePreviousScore = [string]$PreviousSnapshot.DomainRiskScore
        }
    } catch {
        $PreviousSnapshot = $null
    }
}

$PreviousByKey = @{}
if ($PreviousSnapshot -and $PreviousSnapshot.Findings) {
    foreach ($f in $PreviousSnapshot.Findings) {
        $key = "$($f.Category)|$($f.Rule)"
        $PreviousByKey[$key] = $f
    }
}

foreach ($key in $CurrentByKey.Keys) {
    if (-not $PreviousByKey.ContainsKey($key)) {
        $curr = $CurrentByKey[$key]
        $PingDiffRows += [PSCustomObject]@{
            ChangeType = "New"
            Category = $curr.Category
            Rule = $curr.Rule
            PreviousSeverity = "N/A"
            CurrentSeverity = $curr.Severity
            PreviousCount = "N/A"
            CurrentCount = $curr.Count
            PreviousRecommendation = "N/A"
            CurrentRecommendation = $curr.Recommendation
            Notes = "New rule in current snapshot"
        }
        continue
    }

    $prev = $PreviousByKey[$key]
    $curr = $CurrentByKey[$key]

    $prevCountComparable = Get-CountComparableValue $prev.Count
    $currCountComparable = Get-CountComparableValue $curr.Count
    $isChanged = ($prev.Severity -ne $curr.Severity) -or ($prevCountComparable -ne $currCountComparable) -or ($prev.Recommendation -ne $curr.Recommendation)

    if ($isChanged) {
        $notes = @()
        if ($prev.Severity -ne $curr.Severity) {
            $notes += "Severity: $($prev.Severity) -> $($curr.Severity)"
        }
        if ($prevCountComparable -ne $currCountComparable) {
            $notes += "Count: $($prev.Count) -> $($curr.Count)"
        }
        if ($prev.Recommendation -ne $curr.Recommendation) {
            $notes += "Recommendation updated"
        }

        $PingDiffRows += [PSCustomObject]@{
            ChangeType = "Changed"
            Category = $curr.Category
            Rule = $curr.Rule
            PreviousSeverity = $prev.Severity
            CurrentSeverity = $curr.Severity
            PreviousCount = $prev.Count
            CurrentCount = $curr.Count
            PreviousRecommendation = $prev.Recommendation
            CurrentRecommendation = $curr.Recommendation
            Notes = ($notes -join " | ")
        }
    }
}

foreach ($key in $PreviousByKey.Keys) {
    if ($CurrentByKey.ContainsKey($key)) { continue }

    $prev = $PreviousByKey[$key]
    $PingDiffRows += [PSCustomObject]@{
        ChangeType = "Resolved"
        Category = $prev.Category
        Rule = $prev.Rule
        PreviousSeverity = $prev.Severity
        CurrentSeverity = "N/A"
        PreviousCount = $prev.Count
        CurrentCount = "N/A"
        PreviousRecommendation = $prev.Recommendation
        CurrentRecommendation = "N/A"
        Notes = "Rule not present in current snapshot"
    }
}

$PingDiffRows = @($PingDiffRows | Sort-Object Category, Rule, ChangeType)
$PingDiffNewCount = @($PingDiffRows | Where-Object { $_.ChangeType -eq "New" }).Count
$PingDiffChangedCount = @($PingDiffRows | Where-Object { $_.ChangeType -eq "Changed" }).Count
$PingDiffResolvedCount = @($PingDiffRows | Where-Object { $_.ChangeType -eq "Resolved" }).Count
$PingDiffNewPct = if ($PingDiffRows.Count -gt 0) { [math]::Round(($PingDiffNewCount * 100.0) / $PingDiffRows.Count, 1) } else { 0 }
$PingDiffChangedPct = if ($PingDiffRows.Count -gt 0) { [math]::Round(($PingDiffChangedCount * 100.0) / $PingDiffRows.Count, 1) } else { 0 }
$PingDiffResolvedPct = if ($PingDiffRows.Count -gt 0) { [math]::Round(($PingDiffResolvedCount * 100.0) / $PingDiffRows.Count, 1) } else { 0 }
$PingBaselineTopCategories = @(
    $PingDiffRows |
    Group-Object Category |
    Sort-Object Count -Descending |
    Select-Object -First 6 |
    ForEach-Object {
        [PSCustomObject]@{
            Category = $_.Name
            Count = $_.Count
            Percent = if ($PingDiffRows.Count -gt 0) { [math]::Round(($_.Count * 100.0) / $PingDiffRows.Count, 1) } else { 0 }
        }
    }
)
$PingTopNewRows = @($PingDiffRows | Where-Object { $_.ChangeType -eq 'New' } | Select-Object -First 5)
$PingTopChangedRows = @($PingDiffRows | Where-Object { $_.ChangeType -eq 'Changed' } | Select-Object -First 5)
$PingTopResolvedRows = @($PingDiffRows | Where-Object { $_.ChangeType -eq 'Resolved' } | Select-Object -First 5)

$PingBaselineSummary = [PSCustomObject]@{
    PreviousSnapshot = $PingBaselinePreviousDate
    CurrentSnapshot = $PingBaselineCurrentDate
    NewFindings = $PingDiffNewCount
    ChangedFindings = $PingDiffChangedCount
    ResolvedFindings = $PingDiffResolvedCount
    TotalDifferences = $PingDiffRows.Count
}

$PingTopNewRule = @($PingDiffRows | Where-Object { $_.ChangeType -eq 'New' } | Select-Object -First 1).Rule
if ([string]::IsNullOrWhiteSpace($PingTopNewRule)) { $PingTopNewRule = '-' }
$PingTopChangedRule = @($PingDiffRows | Where-Object { $_.ChangeType -eq 'Changed' } | Select-Object -First 1).Rule
if ([string]::IsNullOrWhiteSpace($PingTopChangedRule)) { $PingTopChangedRule = '-' }
$PingTopResolvedRule = @($PingDiffRows | Where-Object { $_.ChangeType -eq 'Resolved' } | Select-Object -First 1).Rule
if ([string]::IsNullOrWhiteSpace($PingTopResolvedRule)) { $PingTopResolvedRule = '-' }

$PingBaselineTimelineFile = Join-Path $PSScriptRoot "tools\pingcastle_baseline_timeline.json"
$PingBaselineTimelineRows = @()
if (Test-Path $PingBaselineTimelineFile) {
    try {
        $rawTimeline = Get-Content $PingBaselineTimelineFile -Raw | ConvertFrom-Json
        if ($rawTimeline -is [System.Array]) { $PingBaselineTimelineRows = @($rawTimeline) }
        elseif ($rawTimeline) { $PingBaselineTimelineRows = @($rawTimeline) }
    } catch {
        $PingBaselineTimelineRows = @()
    }
}

$PingBaselineTimelineRows += [PSCustomObject]@{
    GeneratedAt = $PingBaselineCurrentDate
    PreviousSnapshot = $PingBaselinePreviousDate
    TotalDifferences = $PingBaselineSummary.TotalDifferences
    NewFindings = $PingBaselineSummary.NewFindings
    ChangedFindings = $PingBaselineSummary.ChangedFindings
    ResolvedFindings = $PingBaselineSummary.ResolvedFindings
    DomainRiskScore = $DomainRiskScore
    RiskRating = $RiskRating
}

if ($PingBaselineTimelineRows.Count -gt 60) {
    $PingBaselineTimelineRows = @($PingBaselineTimelineRows | Select-Object -Last 60)
}

$PingBaselineTimelineRows | ConvertTo-Json -Depth 6 | Out-File -FilePath $PingBaselineTimelineFile -Encoding UTF8
$PingBaselineTimelineRecentRows = @($PingBaselineTimelineRows | Select-Object -Last 12)

$CurrentPingSnapshot | ConvertTo-Json -Depth 5 | Out-File -FilePath $PingSnapshotFile -Encoding UTF8
$RemediationStatesJson = @(
    $RemediationStateMap.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            Key = $_.Key
            Status = $_.Value.Status
            Note = $_.Value.Note
            UpdatedAt = $_.Value.UpdatedAt
        }
    }
) | ConvertTo-Json -Depth 4 -Compress
if ([string]::IsNullOrWhiteSpace($RemediationStatesJson)) { $RemediationStatesJson = "[]" }

$RiskHistoryFile = Join-Path $PSScriptRoot "tools\pingcastle_risk_history.json"
$RiskHistoryRows = @()
if (Test-Path $RiskHistoryFile) {
    try {
        $rawHistory = Get-Content $RiskHistoryFile -Raw | ConvertFrom-Json
        if ($rawHistory -is [System.Array]) { $RiskHistoryRows = @($rawHistory) }
        elseif ($rawHistory) { $RiskHistoryRows = @($rawHistory) }
    } catch {
        $RiskHistoryRows = @()
    }
}

$RiskHistoryRows += [PSCustomObject]@{
    GeneratedAt = $PingBaselineCurrentDate
    DomainRiskScore = $DomainRiskScore
    RiskRating = $RiskRating
    Critical = @($PingCastleFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    High = @($PingCastleFindings | Where-Object { $_.Severity -eq 'High' }).Count
    Medium = @($PingCastleFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
}

if ($RiskHistoryRows.Count -gt 36) {
    $RiskHistoryRows = @($RiskHistoryRows | Select-Object -Last 36)
}

$RiskHistoryRows | ConvertTo-Json -Depth 6 | Out-File -FilePath $RiskHistoryFile -Encoding UTF8
$RiskTrendJson = @($RiskHistoryRows | Select-Object GeneratedAt, DomainRiskScore, RiskRating, Critical, High, Medium) | ConvertTo-Json -Depth 5 -Compress
if ([string]::IsNullOrWhiteSpace($RiskTrendJson)) { $RiskTrendJson = "[]" }

# DC HEALTH & INFO (Shortened)
$FSMOOwner = @{}
$DomainFSMOs = if ($DomainInfo) { $DomainInfo | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster } else { $null }
$ForestFSMOs = if ($ForestInfo) { $ForestInfo | Select-Object SchemaMaster, DomainNamingMaster } else { $null }

if ($DomainFSMOs -and $DomainFSMOs.PDCEmulator) { $PdcOwner = ($DomainFSMOs.PDCEmulator.Split('.')[0]).Trim() } else { $PdcOwner = "Bilinmiyor" }
if ($DomainFSMOs -and $DomainFSMOs.RIDMaster) { $RidOwner = ($DomainFSMOs.RIDMaster.Split('.')[0]).Trim() } else { $RidOwner = "Bilinmiyor" }
if ($DomainFSMOs -and $DomainFSMOs.InfrastructureMaster) { $InfraOwner = ($DomainFSMOs.InfrastructureMaster.Split('.')[0]).Trim() } else { $InfraOwner = "Bilinmiyor" }
if ($ForestFSMOs -and $ForestFSMOs.SchemaMaster) { $SchemaOwner = ($ForestFSMOs.SchemaMaster.Split('.')[0]).Trim() } else { $SchemaOwner = "Bilinmiyor" }
if ($ForestFSMOs -and $ForestFSMOs.DomainNamingMaster) { $NamingOwner = ($ForestFSMOs.DomainNamingMaster.Split('.')[0]).Trim() } else { $NamingOwner = "Bilinmiyor" }

$FSMOOwner.Add("PDC", $PdcOwner)
$FSMOOwner.Add("RID", $RidOwner)
$FSMOOwner.Add("Infra", $InfraOwner)
$FSMOOwner.Add("Schema", $SchemaOwner)
$FSMOOwner.Add("Naming", $NamingOwner)

$DCHealth = @()
$ReplicationFailureEvents = @()
$ReplicationTopologyLinks = @()
$ReplicationLookbackHours = 6

function Get-ReplicationPartnerLabel {
    param([string]$PartnerRaw)

    $value = "$PartnerRaw"
    if ([string]::IsNullOrWhiteSpace($value)) { return "UnknownPartner" }

    if ($value -match 'CN=([^,]+),CN=Servers') {
        return $matches[1]
    }

    if ($value -match '^[^,]+$') {
        return ($value.Split('.')[0]).Trim()
    }

    return $value
}
# DC Health Loop (Shortened)
foreach ($dc in $DCs) {
    # 1. Uptime Check (WMI/CIM ile)
    try {
        $OsInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $dc.Name -ErrorAction Stop
        $LastBoot = [datetime]$OsInfo.LastBootUpTime

        # Prefer remote clock to avoid timezone/skew artifacts when computing uptime.
        $NowRef = $null
        try {
            $NowRef = Invoke-Command -ComputerName $dc.Name -ScriptBlock { Get-Date } -ErrorAction Stop
        } catch {
            $NowRef = Get-Date
        }

        $Uptime = $NowRef - $LastBoot
        if ($Uptime.TotalMinutes -lt 0) {
            $Uptime = [timespan]::Zero
        }

        $UptimeString = "{0} Days, {1} Hours, {2} Mins" -f ([int]$Uptime.TotalDays), $Uptime.Hours, $Uptime.Minutes
    } catch {
        $UptimeString = "Error/Offline (WMI Access Error)"
    }

    # 2. Sysvol Replikasyon Durumu
    $DCInfo = $AllComputers | Where-Object {$_.Name -eq $dc.Name} | Select -First 1
    $SysvolStatus = if ($DCInfo.OperatingSystem -match "2008|2012|2016|2019|2022") {
        "DFSR (OK)"
    } else {
        "FRS (EOL/Riskli)"
    }

    # 3. FSMO Roles Check
    $FSMOString = @()
    if ($FSMOOwner["PDC"] -eq $dc.Name) { $FSMOString += "PDC" }
    if ($FSMOOwner["RID"] -eq $dc.Name) { $FSMOString += "RID" }
    if ($FSMOOwner["Infra"] -eq $dc.Name) { $FSMOString += "Infra" }
    if ($FSMOOwner["Schema"] -eq $dc.Name) { $FSMOString += "Schema" }
    if ($FSMOOwner["Naming"] -eq $dc.Name) { $FSMOString += "Naming" }
    
    $FSMOString = if ($FSMOString.Count -gt 0) { $FSMOString -join ", " } else { "None" }
    
    # 4. Global Catalog
    $GCStatus = if ((Get-ADDomainController -Identity $dc.Name -ErrorAction SilentlyContinue).IsGlobalCatalog) { "Yes" } else { "No" }
    
    # 5. DC DNS Server List and Check (network setting check)
    $DC_IP = $dc.IPv4Address
    $DNS_Check_Status = "OK" # Default
    $DNS_Servers_String = ""
    try {
        # Fetch only network adapters where IPEnabled = True
        $NetAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ComputerName $dc.Name -Filter "IPEnabled = 'True'" -ErrorAction Stop | Select-Object -First 1
        $DNS_Servers = $NetAdapter.DNSServerSearchOrder
        $DNS_Servers_String = $DNS_Servers -join ", "
        
        # Policy update: primary DNS self-order warning is intentionally suppressed.
        if ($DNS_Servers.Count -gt 1) {
             # Secondary DNS should point to another DC or loopback.
             $OtherDC_IPs = $DCs | Where-Object {$_.IPv4Address -ne $DC_IP} | Select -ExpandProperty IPv4Address
             if (-not ($OtherDC_IPs -contains $DNS_Servers[1]) -and $DNS_Servers[1] -notmatch "127.0.0.1") {
                 $DNS_Check_Status = "ERROR (Secondary Not DC/Loopback)"
             }
        }
    } catch {
        $DNS_Servers_String = "Access Error"
        $DNS_Check_Status = "Access Error"
    }

    # 6. AD replication failure posture (last 6 hours)
    $Replication6hStatus = "OK (Last 6h)"
    $Replication6hDetail = "No replication failure detected in the last $ReplicationLookbackHours hour(s)."
    try {
        $repFailures = @()
        try {
            $repFailures = @(Get-ADReplicationFailure -Target $dc.Name -Scope Server -ErrorAction Stop)
        } catch {
            $repFailures = @()
        }

        $recentFailures = @()
        foreach ($rf in $repFailures) {
            $failureTime = $null
            foreach ($propName in @("FirstFailureTime", "FailureTime", "LastFailureTime", "LastErrorTime", "TimeOfLastFailure")) {
                if ($rf.PSObject.Properties[$propName] -and $rf.$propName) {
                    try {
                        $failureTime = [datetime]$rf.$propName
                        break
                    } catch {}
                }
            }

            $partnerRaw = if ($rf.PSObject.Properties["Partner"] -and $rf.Partner) { "$($rf.Partner)" } else { "UnknownPartner" }
            $partner = Get-ReplicationPartnerLabel $partnerRaw
            $lastErr = if ($rf.PSObject.Properties["LastError"] -and $rf.LastError) { "$($rf.LastError)" } else { "UnknownError" }
            $failCount = if ($rf.PSObject.Properties["FailureCount"] -and $rf.FailureCount) { "$($rf.FailureCount)" } else { "N/A" }

            if ($failureTime) {
                $ReplicationFailureEvents += [PSCustomObject]@{
                    Source = $dc.Name
                    Partner = $partner
                    Time = $failureTime
                    LastError = $lastErr
                    FailureCount = $failCount
                }
            }

            if ($failureTime -and $failureTime -ge (Get-Date).AddHours(-$ReplicationLookbackHours)) {
                $recentFailures += [PSCustomObject]@{
                    Partner = $partner
                    Time = $failureTime
                    LastError = $lastErr
                    FailureCount = $failCount
                }
            }
        }

        if ($recentFailures.Count -gt 0) {
            $Replication6hStatus = "ERROR ($($recentFailures.Count) in 6h)"
            $Replication6hDetail = (@($recentFailures | Select-Object -First 3 | ForEach-Object {
                "$($_.Partner) @ $($_.Time.ToString('yyyy-MM-dd HH:mm')) (FailCount=$($_.FailureCount), Err=$($_.LastError))"
            })) -join "; "
        } elseif ($repFailures.Count -gt 0) {
            $lastKnown = $null
            foreach ($rf in $repFailures) {
                foreach ($propName in @("FirstFailureTime", "FailureTime", "LastFailureTime", "LastErrorTime", "TimeOfLastFailure")) {
                    if ($rf.PSObject.Properties[$propName] -and $rf.$propName) {
                        try {
                            $candidate = [datetime]$rf.$propName
                            if (-not $lastKnown -or $candidate -gt $lastKnown) { $lastKnown = $candidate }
                        } catch {}
                    }
                }
            }
            if ($lastKnown) {
                $Replication6hStatus = "OK (Last 6h)"
                $Replication6hDetail = "No failure in last $ReplicationLookbackHours hour(s). Last known failure: $($lastKnown.ToString('yyyy-MM-dd HH:mm'))."
            }
        }
    } catch {
        $Replication6hStatus = "Access Error"
        $Replication6hDetail = "Replication status could not be collected: $($_.Exception.Message)"
    }

    try {
        $partnerRows = @(Get-ADReplicationPartnerMetadata -Target $dc.Name -Scope Server -ErrorAction Stop)
    } catch {
        $partnerRows = @()
    }

    foreach ($pr in $partnerRows) {
        $partnerName = Get-ReplicationPartnerLabel "$($pr.Partner)"

        $lastSuccess = $null
        if ($pr.PSObject.Properties["LastReplicationSuccess"] -and $pr.LastReplicationSuccess) {
            try { $lastSuccess = [datetime]$pr.LastReplicationSuccess } catch {}
        }

        $lastAttempt = $null
        if ($pr.PSObject.Properties["LastReplicationAttempt"] -and $pr.LastReplicationAttempt) {
            try { $lastAttempt = [datetime]$pr.LastReplicationAttempt } catch {}
        }

        $lastResult = $null
        if ($pr.PSObject.Properties["LastReplicationResult"]) {
            try { $lastResult = [int]$pr.LastReplicationResult } catch {}
        }

        $consecutiveFailures = 0
        if ($pr.PSObject.Properties["ConsecutiveReplicationFailures"] -and $pr.ConsecutiveReplicationFailures -ne $null) {
            try { $consecutiveFailures = [int]$pr.ConsecutiveReplicationFailures } catch { $consecutiveFailures = 0 }
        }

        $ReplicationTopologyLinks += [PSCustomObject]@{
            SourceDC = $dc.Name
            PartnerDC = $partnerName
            LastSuccess = $lastSuccess
            LastAttempt = $lastAttempt
            LastResult = $lastResult
            ConsecutiveFailures = $consecutiveFailures
        }
    }
    
    $DCHealth += [PSCustomObject]@{
        Name = $dc.Name
        OperatingSystem = $DCInfo.OperatingSystem
        Uptime = $UptimeString
        Sysvol = $SysvolStatus
        FSMORoles = $FSMOString
        IsGC = $GCStatus
        IPv4Address = $dc.IPv4Address
        DNS_Servers = $DNS_Servers_String
        DNS_Health = $DNS_Check_Status
        Replication_6h = $Replication6hStatus
        Replication_6h_Detail = $Replication6hDetail
    }
}

# ---------------------
# HTML Start (Shortened)
# ---------------------
$ExecPingCriticalCount = @($PingCastleFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
$ExecPingHighCount = @($PingCastleFindings | Where-Object { $_.Severity -eq 'High' }).Count
$ExecPingMediumCount = @($PingCastleFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
$ExecPingLowCount = @($PingCastleFindings | Where-Object { $_.Severity -eq 'Low' }).Count

$Html = @"
<html>
<head>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Active Directory Overview</title>
<link rel='preconnect' href='https://fonts.googleapis.com'>
<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>
<link href='https://fonts.googleapis.com/css2?family=Public+Sans:wght@400;500;600;700;800&display=swap' rel='stylesheet'>
<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css'>
<style>
/* ... (CSS STİLLERİ AYNI) ... */
:root{
    --primary:#12324A;
    --primary-2:#1E4D6B;
    --accent:#0EA5A2;
    --accent-2:#F59E0B;
    --text:#0f2538;
    --surface:#ffffff;
    --surface-2:#EEF3F8;
    --line:#C9D6E3;
}
body{font-family:'Bahnschrift', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;background:radial-gradient(circle at 0% 0%, #f4f7fb 0%, #eef3f8 40%, #e8eff7 100%); margin:0;padding:20px;color:var(--text);font-size:14px;}
.layout{display:flex;gap:18px;align-items:flex-start;}
.side-panel{flex-shrink:0; width:230px;}
.main-panel{flex:1;display:flex;flex-direction:column;gap:18px;overflow:auto; position: relative;}

/* Global compact mode: reduces overall visual scale for 100% browser zoom */
body.compact-mode{padding:14px;font-size:13px;}
body.compact-mode .layout{gap:14px;}
body.compact-mode .side-panel{width:210px;}
body.compact-mode .main-panel{gap:14px;}
body.compact-mode .logo{height:44px;}
body.compact-mode .header-frame{padding:14px 18px;gap:12px;margin-bottom:12px;}
body.compact-mode .header-frame h1{font-size:24px;}
body.compact-mode .header-frame h3{font-size:13px;}
body.compact-mode .side-menu{padding:9px;gap:5px;}
body.compact-mode .main-btn{padding:6px 9px;font-size:11px;}
body.compact-mode .sub-btn{padding:7px 8px;font-size:12px;}
body.compact-mode .content-card{padding:12px;}
body.compact-mode .content-card h2{font-size:18px;}
body.compact-mode .table-wrapper{margin-top:10px;max-height:420px;}
body.compact-mode .user-table th,
body.compact-mode .user-table td{padding:8px;font-size:12px;}
body.compact-mode .risk-model-title{font-size:20px;margin-top:14px;}

/* HEADER AND LOGO */
.logo{height:52px;filter:drop-shadow(0 2px 4px rgba(0,0,0,0.15));}
.header-frame{background:linear-gradient(125deg,var(--primary) 0%, #184260 52%, var(--primary-2) 100%);border:1px solid #2f5f81;border-bottom:6px solid var(--accent-2); border-radius:16px;padding:18px 24px;display:flex;align-items:center;gap:16px;box-shadow:0 18px 34px rgba(14,42,67,0.32);margin-bottom:16px;}
.header-frame h1{margin:0;font-size:28px;color:#f3f9ff;letter-spacing:0.2px;}
.header-frame h3{margin:0;font-size:15px;color:#c7e2ff;}

/* LOADING OVERLAY */
#loadingOverlay {
    position: fixed; 
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(255, 255, 255, 0.9); 
    z-index: 1000; 
    display: none; 
    align-items: center;
    justify-content: center;
    transition: opacity 0.3s ease-in-out;
    opacity: 0;
}
#loadingOverlay.visible {
    opacity: 1;
}
.loading-logo {
    width: 300px;
    height: 300px;
    opacity: 0.7; 
    background: url('tools/kuso_logo.png') no-repeat center center;
    background-size: contain;
    animation: pulse 1.5s infinite alternate; 
}
@keyframes pulse {
    from { transform: scale(0.95); opacity: 0.5; }
    to { transform: scale(1.05); opacity: 0.7; }
}
/* END LOADING OVERLAY */


/* SIDE MENU */
.side-menu{display:flex;flex-direction:column;gap:6px;padding:10px;background:#f0f2f5;border-radius:16px;border:1px solid #d7dee6;box-shadow:0 14px 24px rgba(28,46,64,0.14);position:sticky;top:12px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#b8c3d1 #eef2f7;}
.main-btn{padding:6px 9px;font-size:11px;border:1px solid #dde3ea;border-radius:15px;background:#ffffff;color:#6b7280;cursor:pointer;text-align:left;transition:all 0.22s ease;font-weight:700;display:flex;align-items:center;justify-content:space-between;gap:7px;}
.main-btn:hover{background:#f8fbff;border-color:#cfd9e5;transform:translateY(-1px);box-shadow:0 8px 16px rgba(42,66,92,0.14);color:#3f4f62;}
.main-btn.active-sidebar{background:#e7f1ff;border-color:#c4dafc;color:#1f4f7a;box-shadow:0 8px 16px rgba(27,79,124,0.16);}
.main-btn.active-sidebar .main-btn-icon{color:#1f4f7a;}
.main-btn-content{display:flex;align-items:center;gap:7px;min-width:0;}
.main-btn-icon{width:14px;text-align:center;font-size:11px;color:#6b7280;transition:color .2s ease;flex-shrink:0;}
.main-btn-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.main-btn-badge{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:19px;padding:0 6px;border-radius:999px;background:#4b5563;color:#fff;font-size:10px;font-weight:800;line-height:1;flex-shrink:0;}
.main-btn-badge-critical{background:#d83a35;}
.main-btn:focus,.sub-btn:focus{outline:3px solid rgba(10,79,152,0.25);outline-offset:2px;}

.side-panel-controls{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px;}
.panel-toggle-btn{padding:6px 9px;border:1px solid #b9c8d8;border-radius:10px;background:#ffffff;color:#35526f;font-size:12px;font-weight:700;cursor:pointer;}
.panel-toggle-btn:hover{background:#f7fbff;border-color:#9fb6ce;}

/* NEW STYLE FOR SUB BUTTONS */
.sub-buttons{display:none;flex-direction:column;gap:6px;padding:8px 0 8px 14px;}
.sub-btn{padding:8px 10px;font-size:13px;border:1px solid #9bb5d3;border-radius:8px;background:linear-gradient(135deg,#dce8f7,#c7d8ec); color:#203b59;cursor:pointer;text-align:left;transition:all 0.25s ease;font-weight:700;box-shadow:0 5px 10px rgba(65,96,132,0.18);}
.sub-btn:hover{background:linear-gradient(135deg,#e6f0fc,#d3e3f5);border-color:#7f9fc3;transform:translateY(-1px);}

/* CONTENT BOXES (CONTENT CARD) */
.container{display:none;flex-direction:column;flex:1;animation:fadeInCard .24s ease-out;}
.os-grid { 
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
    gap: 18px;
}
.content-card{ 
    background:linear-gradient(180deg,#ffffff 0%,#f4f9ff 100%);
    border:1px solid #c7d7e7;
    border-top:4px solid var(--accent);
    border-radius:14px;
    box-shadow:0 14px 26px rgba(8,44,87,0.14);
    padding:16px;
}
/* WRAPPER DIV HOLDING TABLE CONTENT */
.table-wrapper {
    overflow: auto;
    max-height: 450px; 
    margin-top: 15px;
    position: relative;
    border:1px solid #d5e0ec;
    border-radius:10px;
    background:#fbfdff;
}
.content-card h2{
    color:#0f2f4f;
    border-bottom:2px solid #d0dfef;
    padding-bottom:10px;
    margin-top:0;
    font-size: 20px;
}
.section-intro{margin:6px 0 8px 0;color:#51657a;font-size:13px;}
.section-stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:8px 0 10px 0;}
.section-stat-card{border:1px solid #c9daee;border-radius:10px;background:linear-gradient(180deg,#ffffff,#f2f8ff);padding:8px 10px;box-shadow:0 6px 12px rgba(8,44,87,0.08);}
.section-stat-label{font-size:11px;color:#5a6f84;text-transform:uppercase;letter-spacing:.04em;font-weight:700;}
.section-stat-value{font-size:20px;line-height:1.2;color:#0f2f4f;font-weight:900;margin-top:2px;}
.section-stat-note{font-size:11px;color:#48627c;margin-top:2px;}
.section-note-pill{display:inline-block;border:1px solid #c9daee;border-radius:999px;background:#edf4fc;color:#1f4f7a;font-size:12px;font-weight:700;padding:5px 10px;margin:2px 0 4px 0;}
.network-controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 8px 0;}
.network-controls input{border:1px solid #b8cce2;border-radius:8px;padding:7px 9px;font-size:12px;background:#fff;min-width:260px;}
.network-controls button{padding:7px 10px;border:none;border-radius:8px;background:linear-gradient(135deg,#1b4f7c,#0f2f4f);color:#fff;font-size:12px;font-weight:700;cursor:pointer;}
.network-controls button.secondary{background:linear-gradient(135deg,#7b91aa,#5f748c);}
.os-section-header {
    color: #0f2f4f;
    font-size: 24px;
    margin-top: 25px;
    margin-bottom: 15px;
    padding-bottom: 8px;
    border-bottom: 2px solid #9fc0df;
}
/* DC FFL/DFL Info Box */
.dc-info-box {
    background: linear-gradient(145deg,#f5fbff,#eaf4fd);
    border: 1px solid #bed3e8;
    border-radius: 8px;
    padding: 15px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-around;
    align-items: center;
    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
}
.dc-info-item {
    text-align: center;
    padding: 0 20px;
}
.dc-info-item h4 {
    margin-top: 0;
    margin-bottom: 5px;
    color: #0f2f4f;
    font-size: 16px;
    font-weight: 700;
}
.dc-info-item span {
    font-size: 18px;
    font-weight: 600;
    color: #495057;
    background: #dfeaf7;
    padding: 5px 10px;
    border-radius: 4px;
}

/* TABLE STYLES */
.user-table{
    border-collapse:collapse; 
    width:100%;
    border-radius:8px;
}
.user-table th, .user-table td{
    padding:10px;
    text-align:left;
    font-size:13px;
    border:1px solid #e3ebf5;
}
.user-table th{
    background:linear-gradient(135deg,#0f2f4f,#1b4f7c);
    color:white;
    position:sticky; 
    top:0; 
    z-index:99; 
    cursor:pointer;
    letter-spacing:0.2px;
}
.user-table tr:nth-child(even){background:#f6f9fc;}
.user-table tr:hover{background:#def1ff; cursor:pointer;}
/* Group Name Cell */
.group-name-cell {
    cursor: pointer;
    font-weight: bold;
    color: #1b4f7c;
    text-decoration: underline; 
}
.group-name-cell:hover {
    color: #0f2f4f;
}
/* Expired Row Color */
.expired-row td {
    background-color: #ffcccc !important; /* Light red */
    color: #cc0000;
    font-weight: bold;
}
/* DC DNS HEALTH STATUS */
.status-ok { background-color: #d4edda !important; color: #155724; font-weight: 600; }
.status-uyari { background-color: #fff3cd !important; color: #856404; font-weight: 600; }
.status-hata { background-color: #f8d7da !important; color: #721c24; font-weight: 600; }
.repl-link-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px;margin-top:10px;}
.repl-link-card{border:1px solid #c9daee;border-radius:10px;background:#fff;padding:10px;box-shadow:0 4px 10px rgba(8,44,87,0.08);}
.repl-link-title{font-size:13px;font-weight:800;color:#0f2f4f;margin-bottom:6px;}
.repl-link-meta{font-size:12px;color:#506579;line-height:1.45;}
.repl-badge{display:inline-block;border-radius:999px;padding:3px 8px;font-size:11px;font-weight:800;margin-bottom:6px;}
.repl-badge-ok{background:#d4edda;color:#155724;}
.repl-badge-warn{background:#fff3cd;color:#856404;}
.repl-badge-err{background:#f8d7da;color:#721c24;}
.repl-legend{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 10px 0;}
.repl-legend-item{display:inline-block;border:1px solid #c9daee;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:700;background:#fff;}
.repl-diagram-wrap{margin-top:8px;border:1px solid #c9daee;border-radius:12px;background:linear-gradient(180deg,#ffffff,#f4f9ff);padding:10px;overflow:auto;}
.repl-diagram-note{margin-top:8px;font-size:12px;color:#4a5f75;}


.risk-overview-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin:10px 0 16px 0;}
.risk-score-card{border:1px solid #d4e1ef;border-radius:12px;background:linear-gradient(180deg,#ffffff,#f4f9ff);padding:14px;box-shadow:0 6px 14px rgba(8,44,87,0.08);}
.risk-score-main{display:flex;gap:14px;align-items:center;flex-wrap:wrap;}
.risk-score-text h3{margin:0 0 4px 0;color:#0f2f4f;font-size:18px;}
.risk-score-text p{margin:0;color:#51657a;font-size:13px;}
.risk-chip{display:inline-block;padding:4px 8px;border-radius:999px;font-size:12px;font-weight:700;}
.risk-chip-high{background:#f8d7da;color:#721c24;}
.risk-chip-med{background:#fff3cd;color:#856404;}
.risk-chip-poor{background:#ffd4a6;color:#7a4100;}
.risk-chip-low{background:#d4edda;color:#155724;}
.risk-confidence-chip{display:inline-block;padding:4px 8px;border-radius:999px;font-size:12px;font-weight:700;border:1px solid transparent;margin-left:6px;}
.risk-confidence-high{background:#d4edda;color:#155724;border-color:#9fcbab;}
.risk-confidence-medium{background:#fff3cd;color:#856404;border-color:#e7d483;}
.risk-confidence-low{background:#f8d7da;color:#721c24;border-color:#e2aeb6;}
.risk-confidence-note{margin-top:6px !important;font-size:12px !important;color:#5a6f84 !important;}
.risk-score-badge{width:86px;height:86px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f2f4f,#1b4f7c);color:#fff;box-shadow:0 10px 18px rgba(8,44,87,0.25);font-size:30px;font-weight:900;letter-spacing:.2px;position:relative;}
.risk-score-badge::after{content:"";position:absolute;inset:-6px;border:2px dashed rgba(27,79,124,0.35);border-radius:50%;animation:scorePulse 2.6s ease-in-out infinite;}
.risk-gauge-wrap{display:flex;align-items:center;justify-content:center;position:relative;width:170px;height:170px;}
.risk-gauge-svg{width:170px;height:170px;transform:rotate(-90deg);}
.risk-gauge-bg{fill:none;stroke:#d8e4f1;stroke-width:14;}
.risk-gauge-good{fill:none;stroke:#3fb950;stroke-width:14;stroke-linecap:round;transition:stroke-dashoffset .5s ease;}
.risk-gauge-acceptable{fill:none;stroke:#d0a000;stroke-width:14;stroke-linecap:round;transition:stroke-dashoffset .5s ease;}
.risk-gauge-poor{fill:none;stroke:#f08c2e;stroke-width:14;stroke-linecap:round;transition:stroke-dashoffset .5s ease;}
.risk-gauge-critical{fill:none;stroke:#d83a35;stroke-width:14;stroke-linecap:round;transition:stroke-dashoffset .5s ease;}
.risk-gauge-center{position:absolute;text-align:center;color:#0f2f4f;}
.risk-gauge-score{font-size:34px;font-weight:900;line-height:1;}
.risk-gauge-max{font-size:12px;color:#6b7f93;}
.risk-breakdown-table{width:100%;border-collapse:collapse;border:1px solid #b8cbe0;margin-top:10px;}
.risk-breakdown-table th,.risk-breakdown-table td{border:1px solid #b8cbe0;padding:8px 10px;font-size:13px;}
.risk-breakdown-table th{background:#edf4fc;color:#0f2f4f;text-align:left;}
@keyframes scorePulse{0%{transform:scale(1);opacity:.45;}50%{transform:scale(1.08);opacity:.15;}100%{transform:scale(1);opacity:.45;}}
.risk-meter{min-width:280px;flex:1;position:relative;padding-top:6px;}
.risk-meter-track{display:grid;grid-template-columns:repeat(20,minmax(10px,1fr));gap:4px;background:#e7eef7;padding:8px;border-radius:10px;border:1px solid #ccd9e8;}
.risk-meter-seg{height:14px;border-radius:4px;background:#d7e2ef;opacity:.45;transition:all .25s ease;}
.risk-meter-seg-filled{opacity:1;box-shadow:0 0 0 1px rgba(255,255,255,0.35) inset;}
.risk-meter-low{background:#7adf46;}
.risk-meter-medium{background:#f2d207;}
.risk-meter-high{background:#ff8605;}
.risk-meter-critical{background:#ef2b2d;}
.risk-meter-pointer{position:absolute;top:-1px;width:12px;height:12px;background:#1a1b46;border-radius:50%;box-shadow:0 3px 8px rgba(0,0,0,0.25);}
.risk-meter-pointer::after{content:"";position:absolute;left:5px;top:11px;width:2px;height:10px;background:#1a1b46;}
.risk-meter-scale{display:flex;justify-content:space-between;font-size:11px;color:#5a6f84;padding:6px 4px 0 4px;}
.risk-mini-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;margin-top:10px;}
.risk-mini-card{border:1px solid #d4e1ef;border-radius:10px;background:#fff;padding:10px;cursor:pointer;transition:all .18s ease;}
.risk-mini-card:hover{transform:translateY(-1px);box-shadow:0 8px 14px rgba(8,44,87,0.12);}
.risk-mini-card.active{border-color:#1b4f7c;background:linear-gradient(180deg,#eef6ff,#ffffff);box-shadow:0 8px 14px rgba(8,44,87,0.12);}
.risk-mini-card h4{margin:0 0 8px 0;color:#0f2f4f;font-size:15px;}
.risk-mini-meta{font-size:12px;color:#5a6f84;display:flex;justify-content:space-between;gap:8px;}
.user-risk-section{display:none;}

/* AD User Risk mini cards: make them feel like clear action buttons */
.risk-mini-card.user-risk-card{
    border:1px solid #8db3d9;
    border-radius:12px;
    color:#0a2d4f;
    background:linear-gradient(135deg,#f4f9ff 0%, #e8f2ff 100%);
    box-shadow:0 8px 18px rgba(14,62,110,0.15);
}
.risk-mini-card.user-risk-card h4{
    font-size:16px;
    font-weight:800;
    margin-bottom:6px;
}
.risk-mini-card.user-risk-card .risk-mini-meta{
    font-size:13px;
    font-weight:700;
    color:#1f4f7a;
}
.risk-mini-card.user-risk-card:hover{
    transform:translateY(-2px);
    border-color:#4f8cc7;
    box-shadow:0 14px 24px rgba(14,62,110,0.22);
}
.risk-mini-card.user-risk-card.active{
    border-color:#0b5fb7;
    background:linear-gradient(135deg,#dceeff 0%, #cfe6ff 100%);
    box-shadow:0 16px 28px rgba(12,76,139,0.28);
}
.user-risk-icon{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:50%;background:rgba(255,255,255,0.6);margin-right:6px;font-size:12px;line-height:1;vertical-align:middle;}

.user-risk-explorer{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:12px;align-items:start;}
.user-risk-main{min-width:0;}
.user-risk-filters{border:1px solid #c9daee;border-radius:12px;background:linear-gradient(180deg,#f7fbff,#edf5ff);padding:12px;position:sticky;top:12px;box-shadow:0 6px 14px rgba(8,44,87,0.09);}
.user-risk-filters h4{margin:0 0 10px 0;color:#0f2f4f;font-size:15px;}
.user-risk-filter-group{display:flex;flex-direction:column;gap:5px;margin-bottom:10px;}
.user-risk-filter-group label{font-size:12px;font-weight:700;color:#1f4f7a;}
.user-risk-filter-group input,.user-risk-filter-group select{border:1px solid #b8cce2;border-radius:8px;padding:7px 8px;font-size:12px;background:#fff;}
.user-risk-filter-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;}
.user-risk-btn{padding:7px 10px;border:none;border-radius:8px;background:linear-gradient(135deg,#1b4f7c,#0f2f4f);color:#fff;font-size:12px;font-weight:700;cursor:pointer;}
.user-risk-btn.secondary{background:linear-gradient(135deg,#7b91aa,#5f748c);}
.user-risk-filter-summary{margin-top:10px;font-size:12px;color:#4a5f75;background:#e8f0fa;border-radius:8px;padding:8px;}
.user-risk-kpi-row{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 4px 0;}
.user-risk-kpi-chip{display:inline-flex;align-items:center;gap:6px;padding:7px 10px;border-radius:999px;border:1px solid #c9daee;background:#f3f8ff;color:#0f2f4f;font-size:12px;font-weight:700;}
.user-risk-kpi-chip b{font-size:13px;color:#0a355d;}
.heatmap-table th,.heatmap-table td{text-align:center;font-size:11px;padding:6px;}
.heatmap-table th:first-child,.heatmap-table td:first-child{text-align:left;min-width:100px;font-weight:700;}
.heat-cell-l0{background:#f4f7fb;color:#6b7f95;}
.heat-cell-l1{background:#e3f2ff;color:#164572;}
.heat-cell-l2{background:#cde8ff;color:#0f3f69;}
.heat-cell-l3{background:#ffd9a8;color:#7a4100;}
.heat-cell-l4{background:#f8c7c7;color:#7d1d1d;}
.user-risk-status{font-size:11px;font-weight:800;border-radius:999px;padding:4px 8px;display:inline-block;}
.user-risk-status-failed{background:#ffd9d9;color:#8f1c1c;}
.user-risk-status-success{background:#d8f6e3;color:#14532d;}
.user-risk-status-locked{background:#ffe7c2;color:#8a4b00;}
.user-risk-preset-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:6px;}
.user-risk-preset-btn{padding:6px 8px;border:1px solid #99b5d3;border-radius:8px;background:#f4f9ff;color:#0f2f4f;font-size:11px;font-weight:700;cursor:pointer;text-align:left;}
.user-risk-preset-btn:hover{background:#e7f1ff;border-color:#6e9ecf;}
.user-risk-user-link{color:#0b5fb7;font-weight:700;cursor:pointer;text-decoration:underline;}
.user-risk-user-link:hover{color:#094e96;}
.user-risk-insights{margin-top:12px;display:grid;grid-template-columns:2fr 1fr;gap:12px;align-items:start;}
.user-risk-insights .content-card-lite{border:1px solid #c9daee;border-radius:10px;background:#f9fcff;padding:10px;}
.user-risk-insights h4{margin:0 0 8px 0;color:#0f2f4f;font-size:14px;}
.user-risk-profile-meta{display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;color:#33485f;}
.user-risk-profile-meta div{background:#edf4fc;border-radius:8px;padding:6px 8px;}
.user-risk-profile-timeline{margin-top:8px;max-height:260px;overflow:auto;border:1px solid #d5e3f3;border-radius:8px;background:#fff;}
.user-risk-timeline-row{display:grid;grid-template-columns:130px 70px minmax(0,1fr);gap:8px;padding:7px 8px;border-bottom:1px solid #eef3f9;font-size:12px;align-items:center;}
.user-risk-timeline-row:last-child{border-bottom:none;}
.user-risk-timeline-time{color:#435a73;font-weight:600;}
.user-risk-timeline-path{color:#17324f;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}

@media (max-width: 1080px){
    .user-risk-explorer{grid-template-columns:1fr;}
    .user-risk-filters{position:static;}
    .user-risk-insights{grid-template-columns:1fr;}
    .baseline-layout{grid-template-columns:1fr;}
}

#userRiskCardLockouts{background:linear-gradient(135deg,#fff4ef 0%, #ffe1d2 100%);border-color:#e6b39a;}
#userRiskCardFailedUsers{background:linear-gradient(135deg,#fff1f1 0%, #ffd9d9 100%);border-color:#e5a3a3;}
#userRiskCardFailedSources{background:linear-gradient(135deg,#fff9ee 0%, #ffecc7 100%);border-color:#e5cb8f;}
#userRiskCardUserDevice{background:linear-gradient(135deg,#eefaf3 0%, #d9f4e6 100%);border-color:#9bcfad;}
.risk-model-title{margin:18px 0 8px 0;color:#0f2f4f;font-size:22px;border-bottom:2px solid #d0dfef;padding-bottom:6px;}
.risk-model-note{margin:0 0 10px 0;color:#5a6f84;font-size:13px;}
.risk-exec-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:12px 0 10px 0;}
.risk-exec-card{border:1px solid #c7d8ea;border-radius:10px;background:linear-gradient(180deg,#f8fbff,#eef5fd);padding:10px;}
.risk-exec-label{font-size:11px;color:#5a6f84;text-transform:uppercase;letter-spacing:.04em;font-weight:700;}
.risk-exec-value{font-size:24px;color:#0f2f4f;font-weight:800;line-height:1.2;margin-top:3px;}
.risk-exec-note{font-size:12px;color:#344b63;margin-top:2px;}
.risk-focus-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 10px 0;}
.risk-focus-chip{padding:6px 10px;border:1px solid #9bb8d6;border-radius:999px;background:#f4f9ff;color:#0f2f4f;font-size:12px;font-weight:700;cursor:pointer;}
.risk-focus-chip:hover{background:#e8f2ff;border-color:#7da6cf;}
.risk-focus-chip.active{background:#0f2f4f;color:#fff;border-color:#0f2f4f;}
.risk-focus-summary{font-size:12px;color:#4b627a;background:#e8f0fa;border-radius:999px;padding:6px 10px;}
.side-panel-controls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px;}
.panel-toggle-btn{padding:7px 10px;border:1px solid #9bb8d6;border-radius:8px;background:#f4f9ff;color:#0f2f4f;font-size:12px;font-weight:700;cursor:pointer;}
.panel-toggle-btn:hover{background:#e8f2ff;border-color:#7da6cf;}
.risk-command-hero{border:1px solid #7eaad0;border-radius:14px;background:linear-gradient(130deg,#f7fbff 0%,#e1efff 42%,#d5e8fb 100%);padding:14px 14px 12px 14px;box-shadow:0 14px 24px rgba(4,35,66,.19);margin:6px 0 12px 0;position:relative;overflow:hidden;}
.risk-command-hero::after{content:"";position:absolute;right:-30px;top:-26px;width:220px;height:140px;background:linear-gradient(135deg,rgba(0,209,255,.25),rgba(255,176,0,.16));transform:rotate(-8deg);pointer-events:none;}
.risk-command-kicker{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#1b5b88;font-weight:900;position:relative;z-index:1;}
.risk-command-title{margin:4px 0 5px 0;color:#0a2f52;font-size:28px;line-height:1.05;font-weight:900;position:relative;z-index:1;}
.risk-command-sub{margin:0;color:#2f5374;font-size:13px;max-width:900px;position:relative;z-index:1;}
.risk-story-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:12px 0 6px 0;}
.risk-story-step{border:1px solid #88b2d8;border-radius:10px;background:linear-gradient(180deg,#ffffff,#ecf6ff);padding:10px;text-align:left;cursor:pointer;transition:all .18s ease;}
.risk-story-step:hover{transform:translateY(-1px);box-shadow:0 10px 16px rgba(6,52,93,.2);border-color:#3b8ad1;}
.risk-story-step b{display:block;font-size:11px;color:#3b678f;text-transform:uppercase;letter-spacing:.06em;}
.risk-story-step span{display:block;margin-top:3px;color:#0f3961;font-size:14px;font-weight:800;}
.risk-quick-nav{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 12px 0;padding:10px 12px;border:1px solid #c8d9ec;border-radius:14px;background:linear-gradient(135deg,#f8fbff,#eef5fd);position:fixed;top:10px;left:270px;right:22px;z-index:45;box-shadow:0 10px 20px rgba(8,44,87,.16),0 1px 0 rgba(255,255,255,.75) inset;backdrop-filter:blur(8px);}
.risk-quick-nav-label{font-size:11px;font-weight:900;letter-spacing:.1em;text-transform:uppercase;color:#2b4d6f;margin-right:4px;padding:5px 10px;border:1px solid #b9cde2;border-radius:999px;background:linear-gradient(180deg,#ffffff,#edf4fc);}
.risk-quick-jump{padding:6px 12px;border:1px solid #9bb8d6;border-radius:999px;background:linear-gradient(180deg,#ffffff,#edf4fc);color:#0f2f4f;font-size:11px;font-weight:900;cursor:pointer;line-height:1.2;box-shadow:0 2px 0 rgba(255,255,255,.9) inset,0 3px 8px rgba(8,44,87,.18);transition:all .16s ease;}
.risk-quick-jump:hover{background:linear-gradient(180deg,#ffffff,#e6f0fb);border-color:#7da6cf;color:#0b2a47;transform:translateY(-1px) scale(1.02);box-shadow:0 0 0 2px rgba(125,166,207,.22),0 10px 18px rgba(8,44,87,.24);}
.risk-quick-jump:active{transform:translateY(0) scale(1);box-shadow:0 2px 8px rgba(8,44,87,.24) inset;}
.risk-quick-jump:focus{outline:2px solid rgba(125,166,207,.75);outline-offset:2px;}
#pingCastleRisksContainer>.content-card{padding-top:64px;}
#riskNowAnchor,#riskModelAnchor,#riskFindingsAnchor,#riskActionAnchor,#caRiskAnchor,#riskTrackAnchor,#riskWatchAnchor{scroll-margin-top:92px;}
@media (max-width:900px){.risk-quick-nav{position:sticky;top:8px;left:auto;right:auto;z-index:6;box-shadow:0 6px 14px rgba(8,52,90,.12);backdrop-filter:none;}#pingCastleRisksContainer>.content-card{padding-top:16px;}}
.risk-action-toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:6px 0 10px 0;}
.risk-action-btn{padding:8px 12px;border:1px solid #0f5f95;border-radius:9px;background:linear-gradient(145deg,#0a5f96,#0ea4d6);color:#f5fbff;font-size:12px;font-weight:800;cursor:pointer;box-shadow:0 8px 14px rgba(8,74,118,.28);letter-spacing:.02em;}
.risk-action-btn:hover{background:linear-gradient(145deg,#0f78b7,#10b5e7);transform:translateY(-1px);}
.risk-trend-card,.attack-chain-card,.mitre-panel,.remediation-tracking-card{margin-top:12px;border:1px solid #c8d9ec;border-radius:12px;background:linear-gradient(180deg,#fbfdff,#eef5fd);padding:12px;}
.risk-trend-card h3,.attack-chain-card h3,.mitre-panel h3,.remediation-tracking-card h3{margin:0 0 8px 0;color:#0f2f4f;font-size:17px;}
.risk-trend-meta,.attack-chain-note,.mitre-note,.tracking-note{margin:0 0 8px 0;color:#445b72;font-size:12px;}
.risk-trend-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;}
.risk-trend-current{display:inline-block;padding:4px 9px;border-radius:999px;border:1px solid #b9cde2;background:#f0f6fd;color:#0f2f4f;font-size:12px;font-weight:700;}
.risk-trend-svg{width:100%;height:120px;display:block;border:1px solid #cfdff0;border-radius:10px;background:linear-gradient(180deg,#ffffff,#f4f9ff);}
.risk-trend-axis{stroke:#90a9c4;stroke-width:1;}
.risk-trend-line{fill:none;stroke:#0f4d85;stroke-width:2.5;}
.risk-trend-point{fill:#0f4d85;stroke:#fff;stroke-width:1.5;}
.risk-trend-last{fill:#d83a35;}
.attack-chain-graph{border:1px solid #cfdff0;border-radius:10px;background:#fff;padding:10px;overflow:auto;}
.attack-why-list{margin:8px 0 0 18px;padding:0;color:#2f4963;font-size:12px;}
.attack-why-list li{margin:0 0 5px 0;line-height:1.35;}
.attack-scenario-card{display:block;}
.attack-scenario-empty{padding:10px 12px;border:1px dashed #cbd5e1;border-radius:8px;color:#475569;background:#f8fafc;font-size:12px;}
.mitre-heat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-top:6px;}
.mitre-cell{border:1px solid #c8d9ec;border-radius:8px;background:#fff;padding:8px;}
.mitre-cell h4{margin:0 0 4px 0;font-size:12px;color:#0f2f4f;}
.mitre-cell p{margin:0;font-size:12px;color:#3b5470;}
.mitre-cell-critical{background:#ffe3e2;border-color:#e8b2af;}
.mitre-cell-high{background:#fff0d8;border-color:#ebcd9f;}
.mitre-cell-medium{background:#fff9df;border-color:#e5d59a;}
.threat-priority-wrap{margin-top:10px;border:1px solid #c8d9ec;border-radius:10px;background:#fff;padding:8px;}
.threat-priority-note{margin:0 0 6px 0;color:#49647f;font-size:12px;}
.threat-priority-table{width:100%;border-collapse:collapse;font-size:12px;}
.threat-priority-table th,.threat-priority-table td{border:1px solid #d2e0ee;padding:6px;text-align:left;vertical-align:top;}
.threat-priority-table th{background:#eef5fd;color:#1b3d5e;}
.ca-risk-card{margin-top:12px;border:1px solid #c8d9ec;border-radius:12px;background:linear-gradient(180deg,#fbfdff,#eef5fd);padding:12px;}
.ca-risk-card h3{margin:0 0 8px 0;color:#0f2f4f;font-size:17px;}
.ca-risk-meta{margin:0 0 8px 0;color:#445b72;font-size:12px;}
.ca-risk-kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;margin:8px 0;}
.ca-risk-kpi .section-stat-card{padding:10px;}
.ca-risk-checklist{margin:8px 0 10px 18px;padding:0;color:#2f4963;font-size:12px;}
.ca-risk-checklist li{margin:0 0 4px 0;line-height:1.35;}
.ca-risk-badge{display:inline-block;padding:2px 7px;border-radius:999px;border:1px solid #b8cde3;background:#f1f7ff;color:#0f355a;font-size:11px;font-weight:800;}
.ca-risk-why{font-size:12px;color:#2f4963;line-height:1.35;}
.ca-risk-action{font-size:12px;color:#1e3f61;line-height:1.4;}
.approval-gate-card{margin-top:12px;border:1px solid #c8d9ec;border-radius:12px;background:linear-gradient(180deg,#fbfdff,#eef5fd);padding:12px;}
.approval-gate-card h4{margin:0 0 8px 0;color:#0f2f4f;font-size:16px;}
.approval-gate-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;}
.approval-gate-item{display:flex;align-items:center;gap:7px;font-size:12px;color:#24415f;}
.approval-gate-inputs{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-top:8px;}
.approval-gate-inputs input{padding:6px;border:1px solid #b7cce2;border-radius:8px;font-size:12px;}
.approval-gate-status{margin-top:8px;font-size:12px;color:#3f5872;}
.remediation-status-pill{display:inline-block;border-radius:999px;padding:3px 7px;font-size:11px;font-weight:700;}
.remediation-status-open{background:#ffe3e2;color:#7a1e1b;}
.remediation-status-fix{background:#e2f5e8;color:#155a2d;}
.remediation-status-accepted{background:#e8edf3;color:#364a5f;}
.remediation-status-exception{background:#fff2d9;color:#76520a;}
.exception-reason-chip{display:inline-block;margin-left:6px;padding:2px 6px;border-radius:999px;background:#fff2d9;color:#76520a;font-size:10px;font-weight:700;border:1px solid #e1cb91;max-width:170px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:middle;}
.risk-remediation-panel{margin-top:14px;border:1px solid #c8d9ec;border-radius:12px;background:linear-gradient(180deg,#f9fcff,#eef5fd);padding:12px;}
.risk-remediation-panel h3{margin:0 0 6px 0;color:#0f2f4f;font-size:18px;}
.risk-remediation-panel p{margin:0 0 10px 0;color:#445b72;font-size:13px;}
.risk-remediation-list{margin:0 0 10px 18px;padding:0;color:#1e3852;}
.risk-remediation-list li{margin:0 0 7px 0;line-height:1.4;}
.risk-remediation-finding-list{margin:0 0 0 18px;padding:0;color:#304962;}
.risk-remediation-finding-list li{margin:0 0 5px 0;line-height:1.35;}
.risk-remediation-muted{color:#5b7087;font-size:12px;}
.risk-sim-card,.risk-contrib-card,.risk-watch-card,.dc-heatmap-card{border:1px solid #c8d9ec;border-radius:12px;background:linear-gradient(180deg,#fbfdff,#eef5fd);padding:12px;}
.risk-sim-card h3,.risk-contrib-card h3,.risk-watch-card h3,.dc-heatmap-card h3{margin:0 0 8px 0;color:#0f2f4f;font-size:17px;}
.risk-sim-controls{display:grid;grid-template-columns:1fr;gap:8px;}
.risk-sim-control label{display:block;font-size:12px;color:#2f4963;margin-bottom:3px;}
.risk-sim-control input[type=range]{width:100%;}
.risk-sim-result{margin-top:8px;padding:8px 10px;border:1px solid #c7d8ea;border-radius:9px;background:#f2f8ff;color:#17324f;font-size:13px;}
.risk-contrib-list{display:grid;gap:8px;}
.risk-contrib-row{display:grid;gap:4px;}
.risk-contrib-head{display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#274562;}
.risk-contrib-bar{height:9px;border-radius:999px;background:#e1ebf6;overflow:hidden;}
.risk-contrib-bar span{display:block;height:100%;background:linear-gradient(90deg,#1b5f92,#0ea4d6);}
.risk-contrib-foot{margin-top:8px;font-size:12px;color:#48617b;}
.watch-btn{padding:4px 8px;border:1px solid #9bb8d6;border-radius:999px;background:#f4f9ff;color:#0f2f4f;font-size:11px;font-weight:700;cursor:pointer;}
.watch-btn.active{background:#0f2f4f;color:#fff;border-color:#0f2f4f;}
.risk-watch-item{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:8px;align-items:center;padding:6px 8px;border:1px solid #d4e1ef;border-radius:8px;background:#fff;margin-bottom:6px;}
.risk-watch-item:last-child{margin-bottom:0;}
.risk-watch-sev{font-size:11px;font-weight:800;color:#7a4100;}
.risk-watch-rule{font-size:12px;color:#0b5fb7;font-weight:700;cursor:pointer;text-decoration:underline;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.risk-watch-cat{font-size:11px;color:#506579;}
.risk-watch-empty{font-size:12px;color:#5b7087;background:#eef5fd;border:1px dashed #c6d8eb;border-radius:8px;padding:8px;}
.dc-heat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:8px;}
.dc-heat-card{border:1px solid #c8d9ec;border-radius:10px;background:#fff;padding:9px;}
.dc-heat-head{display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#17324f;margin-bottom:4px;}
.dc-heat-meta{font-size:11px;color:#4f6881;line-height:1.35;min-height:30px;}
.dc-heat-bar{height:8px;border-radius:999px;background:#e4edf8;overflow:hidden;margin-top:7px;}
.dc-heat-bar span{display:block;height:100%;background:#3fb950;}
.dc-heat-warn .dc-heat-bar span{background:#d0a000;}
.dc-heat-bad .dc-heat-bar span{background:#d83a35;}
body.dark-mode{background:#0f1822;color:#d6e1ee;}
body.dark-mode .header-frame,body.dark-mode .side-panel,body.dark-mode .content-card,body.dark-mode .site-card,body.dark-mode .risk-score-card,body.dark-mode .risk-trend-card,body.dark-mode .attack-chain-card,body.dark-mode .mitre-panel,body.dark-mode .remediation-tracking-card,body.dark-mode .risk-remediation-panel{background:#172434 !important;border-color:#2e4b68 !important;color:#d6e1ee;}
body.dark-mode .main-btn,body.dark-mode .sub-btn,body.dark-mode .risk-action-btn,body.dark-mode .panel-toggle-btn{background:#21364d !important;color:#e3edf7 !important;border-color:#3a5b7d !important;}
body.dark-mode .user-table th,body.dark-mode .risk-breakdown-table th{background:#23384f !important;color:#e7f1fb !important;}
body.dark-mode .user-table td,body.dark-mode .risk-breakdown-table td{background:#152536 !important;color:#d6e1ee !important;border-color:#35516d !important;}
body.dark-mode .risk-score-text h3,body.dark-mode .risk-model-title,body.dark-mode h2,body.dark-mode h3,body.dark-mode h4{color:#e9f2fb !important;}
body.dark-mode .risk-score-text p,body.dark-mode .risk-model-note,body.dark-mode .risk-focus-summary,body.dark-mode .risk-trend-meta,body.dark-mode .attack-chain-note,body.dark-mode .mitre-note,body.dark-mode .tracking-note{color:#b8cadc !important;}
body.dark-mode .risk-focus-summary{background:#22384f !important;}
body.dark-mode .risk-trend-svg,body.dark-mode .attack-chain-graph{background:#11202f !important;border-color:#35516d !important;}
body.dark-mode .mitre-cell{background:#122336 !important;border-color:#35516d !important;}
body.dark-mode .group-name-cell{color:#8cc4ff;}
body.dark-mode .risk-command-hero{background:radial-gradient(circle at 0% 0%,#1d2f43 0%,#162638 45%,#132233 100%) !important;border-color:#35516d !important;}
body.dark-mode .risk-command-kicker{color:#9fc4e7 !important;}
body.dark-mode .risk-command-title{color:#ecf5ff !important;}
body.dark-mode .risk-command-sub{color:#b7cade !important;}
body.dark-mode .risk-story-step{background:#142436 !important;border-color:#35516d !important;}
body.dark-mode .risk-story-step b{color:#9bb7d4 !important;}
body.dark-mode .risk-story-step span{color:#e6f1fc !important;}
.baseline-hero-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:10px 0 12px 0;}
.baseline-hero-card{border:1px solid #c8d9ec;border-radius:12px;background:linear-gradient(180deg,#f8fbff,#eef5fd);padding:12px;cursor:pointer;transition:all .18s ease;text-align:left;}
.baseline-hero-card:hover{transform:translateY(-1px);box-shadow:0 10px 16px rgba(8,44,87,0.12);}
.baseline-hero-card.active{border-color:#0f2f4f;box-shadow:0 10px 16px rgba(8,44,87,0.16);background:linear-gradient(180deg,#eef5ff,#e3eefc);}
.baseline-hero-title{font-size:11px;color:#5a6f84;font-weight:800;text-transform:uppercase;letter-spacing:.05em;}
.baseline-hero-value{font-size:30px;line-height:1.1;font-weight:900;color:#0f2f4f;margin:2px 0;}
.baseline-hero-note{font-size:12px;color:#46607a;}
.baseline-card-new .baseline-hero-value{color:#8f1c1c;}
.baseline-card-changed .baseline-hero-value{color:#8a4b00;}
.baseline-card-resolved .baseline-hero-value{color:#14532d;}
.baseline-distribution{margin:6px 0 10px 0;border:1px solid #cddded;border-radius:12px;padding:10px;background:linear-gradient(180deg,#f9fcff,#eff6ff);}
.baseline-distribution-track{display:flex;width:100%;height:16px;border-radius:999px;overflow:hidden;background:#e7eff8;border:1px solid #c9d9ea;}
.baseline-dist-seg{height:100%;transition:width .25s ease;}
.baseline-dist-new{background:#f2a7a7;}
.baseline-dist-changed{background:#ffd38a;}
.baseline-dist-resolved{background:#9fdcb3;}
.baseline-distribution-legend{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px;font-size:12px;color:#3f5872;}
.baseline-legend-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid #c8d9ec;background:#fff;border-radius:999px;padding:4px 8px;font-weight:700;}
.baseline-dot{width:10px;height:10px;border-radius:50%;display:inline-block;}
.baseline-layout{display:grid;grid-template-columns:1.5fr 1fr;gap:12px;align-items:start;margin:10px 0 8px 0;}
.baseline-panel{border:1px solid #c9daee;border-radius:12px;background:linear-gradient(180deg,#fbfdff,#f2f8ff);padding:10px;}
.baseline-panel h4{margin:0 0 8px 0;color:#0f2f4f;font-size:14px;}
.baseline-category-row{display:grid;grid-template-columns:minmax(0,1fr) 70px;gap:8px;align-items:center;padding:6px 0;border-bottom:1px dashed #dbe8f5;}
.baseline-category-row:last-child{border-bottom:none;}
.baseline-category-name{font-size:12px;color:#223f5d;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.baseline-category-meta{font-size:11px;color:#55708b;text-align:right;font-weight:700;}
.baseline-category-bar{height:8px;border-radius:999px;background:#e2ecf7;overflow:hidden;border:1px solid #d0dfef;margin-top:4px;}
.baseline-category-fill{height:100%;background:linear-gradient(90deg,#4d86bb,#0f4d85);}
.baseline-highlights{display:grid;grid-template-columns:1fr;gap:8px;}
.baseline-highlight-box{border:1px solid #d4e2f1;border-radius:10px;padding:8px;background:#fff;}
.baseline-highlight-box h5{margin:0 0 6px 0;font-size:12px;color:#2d4c68;text-transform:uppercase;letter-spacing:.04em;}
.baseline-highlight-list{margin:0;padding-left:18px;max-height:148px;overflow:auto;}
.baseline-highlight-list li{margin:0 0 5px 0;font-size:12px;color:#284560;}
.baseline-empty{font-size:12px;color:#5a6f84;}
.risk-delta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px;margin:10px 0 12px 0;}
.risk-delta-card{border:1px solid #c8d9ec;border-radius:10px;background:linear-gradient(180deg,#f7fbff,#eef5fd);padding:10px;cursor:pointer;}
.risk-delta-card:hover{filter:brightness(0.98);}
.risk-delta-title{font-size:12px;color:#4f657d;font-weight:700;text-transform:uppercase;letter-spacing:.04em;}
.risk-delta-value{font-size:24px;color:#0f2f4f;font-weight:900;line-height:1.2;margin-top:2px;}
.risk-delta-note{font-size:12px;color:#35506a;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.risk-delta-new .risk-delta-value{color:#8f1c1c;}
.risk-delta-changed .risk-delta-value{color:#8a4b00;}
.risk-delta-resolved .risk-delta-value{color:#14532d;}
.risk-model-table{width:100%;border-collapse:collapse;border:1px solid #b8cbe0;}
.risk-model-table th,.risk-model-table td{border:1px solid #b8cbe0;padding:10px;font-size:14px;vertical-align:middle;}
.risk-model-table th{background:linear-gradient(135deg,#0f2f4f,#1b4f7c);color:#fff;position:sticky;top:0;z-index:120;}
.risk-model-cell{cursor:pointer;transition:all .16s ease;font-weight:700;}
.risk-model-cell:hover{filter:brightness(0.96);}
.risk-cell-critical{background:#f8d7da;color:#721c24;}
.risk-cell-high{background:#ffd4a6;color:#7a4100;}
.risk-cell-medium{background:#fff3cd;color:#856404;}
.risk-cell-low{background:#d4edda;color:#155724;}
.risk-cell-none{background:#eef3f8;color:#71859b;font-weight:600;}
.ping-focus-row td{outline:2px solid #2563eb;outline-offset:-2px;background:#dceafe !important;}
.ping-focus-table{outline:3px solid #2563eb;outline-offset:2px;border-radius:8px;}

.export-actions{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 6px 0;}
.export-btn{padding:6px 10px;font-size:12px;border:none;border-radius:8px;background:linear-gradient(135deg,#1b4f7c,#0f2f4f);color:#fff;cursor:pointer;font-weight:700;}
.export-btn:hover{background:linear-gradient(135deg,#23679f,#134366);}


/* NEW SITE CARD STYLE - SCHEMATIC VIEW */
.site-card {
    border: 1px solid #b6cfe6;
    background: linear-gradient(145deg,#ecf6ff,#e2effc);
    padding: 20px;
    border-radius: 14px;
    margin-bottom: 25px;
    box-shadow: 0 14px 24px rgba(8,44,87,0.16);
}
.site-card h3 {
    margin-top: 0;
    color: #0f2f4f;
    border-bottom: 2px solid #aac7e3;
    padding-bottom: 8px;
    font-size: 22px;
    display: flex;
    align-items: center;
}
.site-card h3:before {
    content: '🌐'; 
    margin-right: 10px;
    font-size: 24px;
}
.site-content {
    display: flex;
    gap: 30px;
    margin-top: 15px;
}
.site-section {
    flex: 1;
    min-width: 45%; 
    background: linear-gradient(180deg,#ffffff,#f2f8ff);
    padding: 15px;
    border-radius: 8px;
    border:1px solid #c8d9ea;
    box-shadow: 0 8px 14px rgba(8,44,87,0.12);
}
.site-section h4 {
    margin-top: 0;
    color: #17a2b8;
    font-size: 16px;
    border-bottom: 1px dashed #ccc;
    padding-bottom: 5px;
    display: flex;
    align-items: center;
}
.server-list {
    list-style: none;
    padding: 0;
    margin: 10px 0 0 0;
}
.server-list li {
    padding: 8px 0;
    border-bottom: 1px dotted #eee;
    display: flex;
    align-items: center;
    font-size: 14px;
}
.server-list li:last-child {
    border-bottom: none;
}
.server-icon {
    margin-right: 8px;
    font-size: 16px;
}

/* Sneat-inspired cyber skin (default) */
body.sneat-cyber{
    font-family:'Public Sans','Bahnschrift','Segoe UI',Tahoma,Geneva,Verdana,sans-serif;
    background:
        radial-gradient(circle at 12% 8%, rgba(49,108,173,0.24) 0%, rgba(49,108,173,0) 32%),
        radial-gradient(circle at 88% 18%, rgba(34,197,94,0.14) 0%, rgba(34,197,94,0) 28%),
        linear-gradient(165deg,#171a2b 0%, #1d2034 45%, #25293f 100%);
    color:#d5deea;
}
body.sneat-cyber .header-frame{
    background:linear-gradient(135deg,rgba(58,75,117,.86),rgba(42,56,92,.78));
    border:1px solid rgba(148,168,206,.3);
    border-bottom:4px solid #ffb547;
    box-shadow:0 18px 34px rgba(6,10,24,.44);
}
body.sneat-cyber .header-frame h1{color:#eef4ff;}
body.sneat-cyber .header-frame h3{color:#c7d4ea;}
body.sneat-cyber .side-menu{
    background:rgba(255,255,255,.05);
    border:1px solid rgba(169,183,211,.2);
    box-shadow:0 18px 30px rgba(6,10,24,.4);
    backdrop-filter:blur(8px);
    scrollbar-color:#5f708d rgba(255,255,255,.05);
}
body.sneat-cyber .panel-toggle-btn{
    background:rgba(255,255,255,.08);
    border:1px solid rgba(169,183,211,.26);
    color:#d6e2f0;
}
body.sneat-cyber .panel-toggle-btn:hover{background:rgba(255,255,255,.14);border-color:rgba(188,203,230,.36);}
body.sneat-cyber .main-btn{
    background:rgba(255,255,255,.08);
    border:1px solid rgba(170,184,210,.23);
    color:#b8c6dd;
    box-shadow:none;
}
body.sneat-cyber .main-btn-icon{color:#96a9c8;}
body.sneat-cyber .main-btn:hover{
    background:rgba(255,255,255,.14);
    border-color:rgba(191,206,231,.36);
    box-shadow:0 8px 16px rgba(8,11,28,.25);
    color:#dde9ff;
}
body.sneat-cyber .main-btn.active-sidebar{
    background:linear-gradient(135deg,rgba(88,127,255,.3),rgba(61,95,208,.3));
    border-color:rgba(148,180,255,.55);
    color:#e6efff;
    box-shadow:0 10px 20px rgba(20,36,82,.45);
}
body.sneat-cyber .main-btn.active-sidebar .main-btn-icon{color:#d7e6ff;}
body.sneat-cyber .main-btn-badge{background:#3d4658;color:#f7fbff;}
body.sneat-cyber .main-btn-badge-critical{background:#c93b3b;}
body.sneat-cyber .sub-btn{
    background:rgba(198,216,238,.9);
    border:1px solid rgba(124,152,190,.55);
    color:#26415f;
    box-shadow:none;
}
body.sneat-cyber .sub-btn:hover{background:rgba(216,230,246,.95);border-color:rgba(103,134,174,.7);}
body.sneat-cyber .content-card,
body.sneat-cyber .risk-score-card,
body.sneat-cyber .risk-trend-card,
body.sneat-cyber .attack-chain-card,
body.sneat-cyber .mitre-panel,
body.sneat-cyber .remediation-tracking-card,
body.sneat-cyber .risk-remediation-panel,
body.sneat-cyber .site-card,
body.sneat-cyber .risk-exec-card,
body.sneat-cyber .risk-command-hero,
body.sneat-cyber .risk-story-step,
body.sneat-cyber .baseline-panel,
body.sneat-cyber .baseline-hero-card,
body.sneat-cyber .baseline-distribution,
body.sneat-cyber .baseline-highlight-box{
    background:rgba(255,255,255,.07) !important;
    border-color:rgba(169,183,211,.24) !important;
    color:#d5deea;
    box-shadow:0 12px 26px rgba(8,11,28,.35);
    backdrop-filter:blur(8px);
}
body.sneat-cyber .content-card h2,
body.sneat-cyber .risk-model-title,
body.sneat-cyber .risk-command-title,
body.sneat-cyber .risk-score-text h3,
body.sneat-cyber .risk-exec-value,
body.sneat-cyber .site-card h3,
body.sneat-cyber .site-section h4,
body.sneat-cyber .baseline-panel h4,
body.sneat-cyber .baseline-highlight-box h5,
body.sneat-cyber .mitre-cell h4{color:#eaf1ff !important;}
body.sneat-cyber .section-intro,
body.sneat-cyber .risk-model-note,
body.sneat-cyber .risk-exec-note,
body.sneat-cyber .risk-command-sub,
body.sneat-cyber .risk-trend-meta,
body.sneat-cyber .attack-chain-note,
body.sneat-cyber .mitre-note,
body.sneat-cyber .tracking-note,
body.sneat-cyber .baseline-hero-note,
body.sneat-cyber .baseline-empty,
body.sneat-cyber .baseline-highlight-list li,
body.sneat-cyber .baseline-category-name,
body.sneat-cyber .baseline-category-meta,
body.sneat-cyber .risk-remediation-panel p,
body.sneat-cyber .risk-remediation-list,
body.sneat-cyber .risk-remediation-finding-list,
body.sneat-cyber .risk-remediation-muted,
body.sneat-cyber .risk-focus-summary,
body.sneat-cyber .risk-mini-meta,
body.sneat-cyber .section-stat-label,
body.sneat-cyber .section-stat-note,
body.sneat-cyber .repl-link-meta,
body.sneat-cyber .repl-diagram-note,
body.sneat-cyber .risk-gauge-max{color:#aebed7 !important;}
body.sneat-cyber .section-stat-value,
body.sneat-cyber .risk-gauge-score,
body.sneat-cyber .risk-delta-value,
body.sneat-cyber .risk-exec-value{color:#f3f7ff !important;}
body.sneat-cyber .risk-command-kicker,
body.sneat-cyber .risk-story-step b,
body.sneat-cyber .risk-story-step span{color:#dce8ff !important;}
body.sneat-cyber .risk-mini-card h4,
body.sneat-cyber .risk-exec-label,
body.sneat-cyber .risk-delta-title,
body.sneat-cyber .baseline-hero-title,
body.sneat-cyber .section-stat-label,
body.sneat-cyber .repl-link-title{color:#d5e5ff !important;}
body.sneat-cyber .risk-mini-card .risk-mini-meta,
body.sneat-cyber .risk-mini-card .risk-mini-meta span,
body.sneat-cyber .risk-exec-note,
body.sneat-cyber .section-stat-note,
body.sneat-cyber .risk-delta-note,
body.sneat-cyber .risk-focus-summary{color:#c8d8ee !important;}
body.sneat-cyber .risk-action-btn{
    background:rgba(95,113,169,.2);
    border:1px solid rgba(162,180,215,.4);
    color:#dde7fa;
    border-radius:999px;
    box-shadow:none;
}
body.sneat-cyber .risk-action-btn:hover{background:rgba(119,139,198,.3);transform:translateY(-1px);}
body.sneat-cyber .risk-exec-grid{gap:12px;}
body.sneat-cyber .risk-exec-progress{margin-top:8px;height:7px;border-radius:999px;background:rgba(184,198,223,.25);overflow:hidden;}
body.sneat-cyber .risk-exec-progress-fill{display:block;height:100%;border-radius:999px;}
body.sneat-cyber .risk-exec-progress-critical{background:linear-gradient(90deg,#ff6f7d,#ff3f62);}
body.sneat-cyber .risk-exec-progress-high{background:linear-gradient(90deg,#ffb46d,#ff8c3a);}
body.sneat-cyber .risk-exec-progress-medium{background:linear-gradient(90deg,#ffe58b,#f8cb3e);}
body.sneat-cyber .risk-chip-high{background:rgba(255,97,123,.22);color:#ffc0ce;}
body.sneat-cyber .risk-chip-med{background:rgba(255,188,82,.2);color:#ffe2b6;}
body.sneat-cyber .risk-chip-poor{background:rgba(255,148,72,.22);color:#ffd6ae;}
body.sneat-cyber .risk-chip-low{background:rgba(34,197,94,.2);color:#b8efca;}
body.sneat-cyber .risk-confidence-high{background:rgba(34,197,94,.2);color:#b8efca;border-color:rgba(34,197,94,.35);}
body.sneat-cyber .risk-confidence-medium{background:rgba(255,188,82,.2);color:#ffe2b6;border-color:rgba(255,188,82,.32);}
body.sneat-cyber .risk-confidence-low{background:rgba(255,97,123,.2);color:#ffc0ce;border-color:rgba(255,97,123,.3);}
body.sneat-cyber .risk-gauge-bg{stroke:rgba(170,184,210,.32);}
body.sneat-cyber .user-table th,
body.sneat-cyber .risk-model-table th,
body.sneat-cyber .risk-breakdown-table th{background:rgba(82,102,149,.35);color:#eef4ff;}
body.sneat-cyber .user-table td,
body.sneat-cyber .risk-model-table td,
body.sneat-cyber .risk-breakdown-table td,
body.sneat-cyber .table-wrapper,
body.sneat-cyber .risk-mini-card,
body.sneat-cyber .mitre-cell,
body.sneat-cyber .repl-link-card,
body.sneat-cyber .site-section,
body.sneat-cyber .user-risk-filters,
body.sneat-cyber .user-risk-filter-summary,
body.sneat-cyber .user-risk-kpi-chip,
body.sneat-cyber .user-risk-profile-meta div,
body.sneat-cyber .user-risk-profile-timeline,
body.sneat-cyber .risk-trend-svg,
body.sneat-cyber .attack-chain-graph,
body.sneat-cyber .baseline-category-bar,
body.sneat-cyber .baseline-distribution-track,
body.sneat-cyber .repl-diagram-wrap{background:rgba(18,25,45,.45) !important;border-color:rgba(167,182,212,.2) !important;color:#d6e0ee !important;}
body.sneat-cyber .user-table tr:nth-child(even){background:rgba(255,255,255,.03);}
body.sneat-cyber .user-table tr:hover{background:rgba(132,156,211,.14);}
body.sneat-cyber .group-name-cell,
body.sneat-cyber .user-risk-user-link{color:#98b9ff;}
body.sneat-cyber .group-name-cell:hover,
body.sneat-cyber .user-risk-user-link:hover{color:#bfd2ff;}
body.sneat-cyber .risk-cell-critical{background:rgba(255,97,123,.2);color:#ffc0ce;}
body.sneat-cyber .risk-cell-high{background:rgba(255,160,64,.2);color:#ffd8ad;}
body.sneat-cyber .risk-cell-medium{background:rgba(255,210,72,.2);color:#ffe9b0;}
body.sneat-cyber .risk-cell-low{background:rgba(34,197,94,.2);color:#b8efca;}
body.sneat-cyber .risk-cell-none{background:rgba(171,186,209,.14);color:#c8d6ea;}
body.sneat-cyber .risk-focus-chip,
body.sneat-cyber .panel-toggle-btn,
body.sneat-cyber .user-risk-btn.secondary,
body.sneat-cyber .user-risk-preset-btn,
body.sneat-cyber .export-btn{background:rgba(95,113,169,.2);border-color:rgba(162,180,215,.4);color:#dde7fa;}
body.sneat-cyber .risk-focus-chip.active{background:linear-gradient(135deg,#587fff,#3d5fd0);border-color:#87a5ff;color:#f3f7ff;}
body.sneat-cyber .user-risk-btn{background:linear-gradient(135deg,#587fff,#3d5fd0);}
body.sneat-cyber .risk-model-title,
body.sneat-cyber .content-card h2,
body.sneat-cyber .site-card h3{border-bottom-color:rgba(164,181,212,.26);}
body.sneat-cyber .section-note-pill{background:rgba(255,255,255,.08);border-color:rgba(164,181,212,.26);color:#dce8ff;}

/* Contrast safety net for legacy colors and inline text */
body.sneat-cyber,
body.sneat-cyber .container,
body.sneat-cyber .content-card,
body.sneat-cyber .site-card,
body.sneat-cyber .risk-score-card,
body.sneat-cyber .baseline-panel{color:#d7e2f1;}
body.sneat-cyber p,
body.sneat-cyber li,
body.sneat-cyber td,
body.sneat-cyber th,
body.sneat-cyber label,
body.sneat-cyber small,
body.sneat-cyber .risk-score-text p,
body.sneat-cyber .section-stat-note,
body.sneat-cyber .risk-remediation-muted,
body.sneat-cyber .risk-delta-note{color:#c3d1e6 !important;}
body.sneat-cyber [style*='color:#0f2f4f'],
body.sneat-cyber [style*='color:#1f4f7a'],
body.sneat-cyber [style*='color:#223f5d'],
body.sneat-cyber [style*='color:#33485f'],
body.sneat-cyber [style*='color:#344b63'],
body.sneat-cyber [style*='color:#46607a'],
body.sneat-cyber [style*='color:#4a5f75'],
body.sneat-cyber [style*='color:#526980'],
body.sneat-cyber [style*='color:#5a6f84'],
body.sneat-cyber [style*='color:#5b7690'],
body.sneat-cyber [style*='color:#6b7280'],
body.sneat-cyber [style*='color:#6c757d']{color:#bccce4 !important;}
body.sneat-cyber [style*='color:#155724'],
body.sneat-cyber [style*='color:#14532d']{color:#9be8b2 !important;}
body.sneat-cyber [style*='color:#856404'],
body.sneat-cyber [style*='color:#8a4b00']{color:#ffd58f !important;}
body.sneat-cyber [style*='color:#721c24'],
body.sneat-cyber [style*='color:#8f1c1c']{color:#ffb6c4 !important;}
body.sneat-cyber h4,
body.sneat-cyber h5,
body.sneat-cyber h6{color:#dce8ff;}

body.sneat-cyber *::-webkit-scrollbar-track{background:rgba(255,255,255,.04);}
body.sneat-cyber *::-webkit-scrollbar-thumb{background:#5f708d;border:2px solid rgba(255,255,255,.04);}
body.sneat-cyber *::-webkit-scrollbar-thumb:hover{background:#7387a8;}

/* Dark-ink typography mode (no white text) */
body.sneat-cyber,
body.sneat-cyber p,
body.sneat-cyber li,
body.sneat-cyber td,
body.sneat-cyber th,
body.sneat-cyber label,
body.sneat-cyber span,
body.sneat-cyber small{color:#1f2f43 !important;}
body.sneat-cyber .header-frame{
    background:linear-gradient(135deg,rgba(225,234,247,.92),rgba(211,223,240,.9));
    border:1px solid rgba(125,151,185,.45);
    box-shadow:0 16px 30px rgba(10,25,45,.2);
}
body.sneat-cyber .header-frame h1,
body.sneat-cyber .header-frame h3{color:#1b314b !important;}
body.sneat-cyber .side-menu,
body.sneat-cyber .content-card,
body.sneat-cyber .risk-score-card,
body.sneat-cyber .risk-trend-card,
body.sneat-cyber .attack-chain-card,
body.sneat-cyber .mitre-panel,
body.sneat-cyber .remediation-tracking-card,
body.sneat-cyber .risk-remediation-panel,
body.sneat-cyber .site-card,
body.sneat-cyber .risk-exec-card,
body.sneat-cyber .risk-command-hero,
body.sneat-cyber .risk-story-step,
body.sneat-cyber .baseline-panel,
body.sneat-cyber .baseline-hero-card,
body.sneat-cyber .baseline-distribution,
body.sneat-cyber .baseline-highlight-box,
body.sneat-cyber .table-wrapper,
body.sneat-cyber .risk-mini-card,
body.sneat-cyber .mitre-cell,
body.sneat-cyber .repl-link-card,
body.sneat-cyber .site-section,
body.sneat-cyber .user-risk-filters,
body.sneat-cyber .user-risk-filter-summary,
body.sneat-cyber .user-risk-kpi-chip,
body.sneat-cyber .user-risk-profile-meta div,
body.sneat-cyber .user-risk-profile-timeline,
body.sneat-cyber .risk-trend-svg,
body.sneat-cyber .attack-chain-graph,
body.sneat-cyber .baseline-category-bar,
body.sneat-cyber .baseline-distribution-track,
body.sneat-cyber .repl-diagram-wrap{
    background:rgba(233,240,250,.9) !important;
    border-color:rgba(137,160,191,.42) !important;
    color:#1f2f43 !important;
    backdrop-filter:none;
}
body.sneat-cyber .content-card h2,
body.sneat-cyber .risk-model-title,
body.sneat-cyber .risk-command-title,
body.sneat-cyber .risk-score-text h3,
body.sneat-cyber .risk-exec-value,
body.sneat-cyber .site-card h3,
body.sneat-cyber .site-section h4,
body.sneat-cyber .baseline-panel h4,
body.sneat-cyber .baseline-highlight-box h5,
body.sneat-cyber .mitre-cell h4,
body.sneat-cyber .risk-mini-card h4,
body.sneat-cyber .risk-exec-label,
body.sneat-cyber h4,
body.sneat-cyber h5,
body.sneat-cyber h6{color:#16314f !important;}
body.sneat-cyber .main-btn,
body.sneat-cyber .panel-toggle-btn,
body.sneat-cyber .risk-action-btn,
body.sneat-cyber .risk-focus-chip,
body.sneat-cyber .user-risk-btn.secondary,
body.sneat-cyber .user-risk-preset-btn,
body.sneat-cyber .export-btn{
    background:rgba(214,225,241,.9) !important;
    border-color:rgba(125,151,185,.45) !important;
    color:#233a56 !important;
}
body.sneat-cyber .main-btn-icon{color:#2b4566 !important;}
body.sneat-cyber .main-btn.active-sidebar,
body.sneat-cyber .risk-focus-chip.active,
body.sneat-cyber .user-risk-btn{
    background:linear-gradient(135deg,#c8d9f2,#b8cdea) !important;
    border-color:#7d9bc1 !important;
    color:#17314f !important;
}
body.sneat-cyber .main-btn.active-sidebar .main-btn-icon{color:#17314f !important;}
body.sneat-cyber .main-btn-badge{background:#4d5f77 !important;color:#eef3f8 !important;}
body.sneat-cyber .main-btn-badge-critical{background:#a63f44 !important;color:#f7eaeb !important;}
body.sneat-cyber .risk-command-kicker,
body.sneat-cyber .risk-story-step b,
body.sneat-cyber .risk-story-step span,
body.sneat-cyber .section-intro,
body.sneat-cyber .risk-model-note,
body.sneat-cyber .risk-exec-note,
body.sneat-cyber .risk-command-sub,
body.sneat-cyber .risk-trend-meta,
body.sneat-cyber .attack-chain-note,
body.sneat-cyber .mitre-note,
body.sneat-cyber .tracking-note,
body.sneat-cyber .baseline-hero-note,
body.sneat-cyber .baseline-empty,
body.sneat-cyber .baseline-highlight-list li,
body.sneat-cyber .baseline-category-name,
body.sneat-cyber .baseline-category-meta,
body.sneat-cyber .risk-remediation-panel p,
body.sneat-cyber .risk-remediation-list,
body.sneat-cyber .risk-remediation-finding-list,
body.sneat-cyber .risk-remediation-muted,
body.sneat-cyber .risk-focus-summary,
body.sneat-cyber .risk-mini-meta,
body.sneat-cyber .section-stat-label,
body.sneat-cyber .section-stat-note,
body.sneat-cyber .repl-link-meta,
body.sneat-cyber .repl-diagram-note,
body.sneat-cyber .risk-gauge-max,
body.sneat-cyber .risk-delta-note{color:#2f4866 !important;}
body.sneat-cyber .risk-score-text p,
body.sneat-cyber .risk-confidence-note,
body.sneat-cyber .risk-breakdown-table td{color:#2a4460 !important;}
body.sneat-cyber .risk-mini-card .risk-mini-meta,
body.sneat-cyber .risk-mini-card .risk-mini-meta span{color:#334d69 !important;font-weight:700;}
body.sneat-cyber .risk-mini-card .risk-mini-meta span:last-child{color:#49698c !important;}
body.sneat-cyber .user-table th,
body.sneat-cyber .risk-model-table th,
body.sneat-cyber .risk-breakdown-table th{background:rgba(165,184,214,.92) !important;color:#17314f !important;}
body.sneat-cyber .user-table td,
body.sneat-cyber .risk-model-table td,
body.sneat-cyber .risk-breakdown-table td{background:#eaf1fb !important;color:#1f2f43 !important;border-color:#c6d4e7 !important;}
body.sneat-cyber .user-table tr:nth-child(even){background:rgba(216,227,243,.38);}
body.sneat-cyber .user-table tr:hover{background:rgba(184,203,232,.58);}
body.sneat-cyber #siteTopologyContainer > .os-section-header{
    color:#17314f !important;
    border:1px solid #c7d6e8 !important;
    border-bottom:2px solid #aac1de !important;
    background:#edf3fc !important;
    margin:0;
    padding:14px 16px 10px 16px;
    border-radius:12px 12px 0 0;
}
body.sneat-cyber #siteTopologyContainer > p{
    color:#2f4866 !important;
    background:#edf3fc !important;
    border:1px solid #c7d6e8 !important;
    border-top:none !important;
    margin:0 0 12px 0;
    padding:10px 16px 14px 16px;
    border-radius:0 0 12px 12px;
}

/* Users overview summary cards: ensure numeric KPIs are always visible */
body.sneat-cyber .section-stat-card{
    background:#f6f9ff !important;
    border:1px solid #ccd9ea !important;
    box-shadow:0 6px 12px rgba(28,54,88,.10) !important;
}
body.sneat-cyber .section-stat-value{color:#102a47 !important;}

/* Risk dashboard readability: remove washed-out look */
body.sneat-cyber .risk-score-card,
body.sneat-cyber .risk-exec-card,
body.sneat-cyber .risk-command-hero,
body.sneat-cyber .risk-story-step,
body.sneat-cyber .risk-remediation-panel,
body.sneat-cyber .mitre-panel,
body.sneat-cyber .attack-chain-card,
body.sneat-cyber .remediation-tracking-card{
    background:#edf3fc !important;
    border-color:#c7d6e8 !important;
    color:#1f2f43 !important;
    box-shadow:0 8px 16px rgba(23,45,73,.12) !important;
}
body.sneat-cyber .risk-gauge-score,
body.sneat-cyber .risk-gauge-center,
body.sneat-cyber .risk-score-text h3,
body.sneat-cyber .risk-chip,
body.sneat-cyber .risk-confidence-chip,
body.sneat-cyber .risk-breakdown-table,
body.sneat-cyber .risk-breakdown-table td,
body.sneat-cyber .risk-breakdown-table th{color:#17314f !important;}
body.sneat-cyber .risk-chip-high{background:#ffd9df !important;color:#7f1f2c !important;}
body.sneat-cyber .risk-chip-med{background:#ffe9c7 !important;color:#7a4b00 !important;}
body.sneat-cyber .risk-chip-poor{background:#ffd9b8 !important;color:#7a4100 !important;}
body.sneat-cyber .risk-chip-low{background:#d9f3e2 !important;color:#155132 !important;}
body.sneat-cyber .risk-sim-card,
body.sneat-cyber .risk-contrib-card,
body.sneat-cyber .risk-watch-card,
body.sneat-cyber .dc-heatmap-card{background:#edf3fc !important;border-color:#c7d6e8 !important;color:#1f2f43 !important;}
body.sneat-cyber .risk-sim-result,
body.sneat-cyber .risk-watch-item,
body.sneat-cyber .dc-heat-card,
body.sneat-cyber .risk-watch-empty{background:#eaf1fb !important;border-color:#c6d4e7 !important;color:#1f2f43 !important;}
body.sneat-cyber .risk-contrib-bar{background:#d4e1f0 !important;}
body.sneat-cyber .risk-contrib-bar span{background:linear-gradient(90deg,#356c9c,#2f9dc9) !important;}
body.sneat-cyber .watch-btn{background:#d9e6f6 !important;border-color:#9db4d0 !important;color:#17314f !important;}
body.sneat-cyber .watch-btn.active{background:#274a70 !important;color:#eef4fb !important;border-color:#274a70 !important;}

/* Risk model severity colors (re-enable against generic td background override) */
body.sneat-cyber .risk-model-table td.risk-cell-critical{background:#ffd4db !important;color:#7e1f2d !important;font-weight:800;}
body.sneat-cyber .risk-model-table td.risk-cell-high{background:#ffe2bf !important;color:#7a4600 !important;font-weight:800;}
body.sneat-cyber .risk-model-table td.risk-cell-medium{background:#fff1cd !important;color:#7b6000 !important;font-weight:800;}
body.sneat-cyber .risk-model-table td.risk-cell-low{background:#ddf4e5 !important;color:#175334 !important;font-weight:800;}
body.sneat-cyber .risk-model-table td.risk-cell-none{background:#e8eef8 !important;color:#5a6f87 !important;font-weight:700;}

@keyframes fadeInCard {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
}

/* Scrollbar enhancements */
*::-webkit-scrollbar { height: 10px; width: 10px; }
*::-webkit-scrollbar-track { background: #eef4fb; border-radius: 8px; }
*::-webkit-scrollbar-thumb { background: #b9cde6; border-radius: 8px; border: 2px solid #eef4fb; }
*::-webkit-scrollbar-thumb:hover { background: #9bb8dc; }

/* RESPONSIVE DESIGN */
@media (max-width: 1200px) {
    body { padding: 20px; }
    .layout { gap: 20px; }
    .side-panel { width: 200px; }
    .header-frame h1 { font-size: 30px; }
    .header-frame h3 { font-size: 16px; }
    .os-grid { grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
}

@media (max-width: 900px) {
    body { padding: 12px; }
    .layout { flex-direction: column; gap: 14px; }
    .side-panel { width: 100%; }
    .side-menu {
        display: grid;
        grid-template-columns: 1fr;
        gap: 10px;
        padding: 14px;
        max-height: none !important;
        overflow-y: visible;
    }
    .sub-buttons {
        padding: 8px 0 8px 10px;
    }
    .main-panel { gap: 14px; }
    .header-frame {
        padding: 16px;
        gap: 12px;
        align-items: flex-start;
        flex-direction: column;
    }
    .logo { height: 48px; }
    .header-frame h1 { font-size: 24px; }
    .header-frame h3 { font-size: 14px; }
    .os-grid { grid-template-columns: 1fr; gap: 14px; }
    .content-card { padding: 14px; }
    .content-card h2 { font-size: 18px; }
    .table-wrapper { max-height: 360px; }
    .user-table th, .user-table td { padding: 8px; font-size: 12px; }
    .site-content { flex-direction: column; gap: 12px; }
    .site-section { min-width: 100%; }
    .dc-info-box {
        flex-direction: column;
        align-items: stretch;
        gap: 10px;
    }
    .dc-info-item { padding: 0; }
    .dc-info-item span {
        display: inline-block;
        font-size: 16px;
    }
}
</style>
<script src='https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js'></script>
<script>
// Get Group Membership data from PowerShell
var GroupMembers = null;
var ObjectRiskDetails = null;
var PingRuleDetailsMap = $PingRuleDetailsJson;
var quickRemediationItems = $QuickRemediationJson;
var remediationBaselineStates = $RemediationStatesJson;
var priorityRiskFindings = $PriorityRiskFindingsJson;
var caRiskRows = $CARiskFindingsJson;
var mitreRows = $MitreRowsJson;
var threatPriorityRows = $ThreatPriorityRowsJson;
var attackChainNodes = $AttackChainNodesJson;
var attackChainScenarios = $AttackChainScenariosJson;
var riskTrendSeries = $RiskTrendJson;
var UserRiskActivity = $UserRiskActivityJson;
var userRiskExplorerData = [];
var UserRiskFailedByUserData = $UserRiskFailedByUserJson;
var UserRiskFailedBySourceData = $UserRiskFailedBySourceJson;
var userRiskFailedUsersData = [];
var userRiskFailedSourcesData = [];
var userRiskDefaultPresetApplied = false;
var execScore = $DomainRiskScore;
var execRating = '$RiskRating';
var execDomain = '$Domain';
var execDate = '$PingBaselineCurrentDate';
var execPreviousDate = '$PingBaselinePreviousDate';
var execPreviousScore = '$PingBaselinePreviousScore';
var execCritical = $([int]$ExecPingCriticalCount);
var execHigh = $([int]$ExecPingHighCount);
var execMedium = $([int]$ExecPingMediumCount);
var execLow = $([int]$ExecPingLowCount);
var currentContainerId = 'pingCastleRisksContainer';
var currentRiskFocusMode = 'all';
var currentTrackingFilter = 'all';
var currentBaselineChangeFilter = 'all';
var remediationTrackingStore = {};
var changeApprovalGateStore = {};
var riskWatchlistStore = {};
var currentLanguage = 'en';
var domTextOriginalMap = new WeakMap();
var domAttrOriginalMap = new WeakMap();
var domTranslationObserver = null;
var isApplyingDomTranslation = false;

var domTextExactTr = {
    'Command Center': 'Komuta Merkezi',
    'AD Risk Mission Board': 'AD Risk G\u00f6rev Panosu',
    'Fast path: read current exposure, execute actions, then track closure status. Designed for daily operational rhythm.': 'H\u0131zl\u0131 ak\u0131\u015f: mevcut maruziyeti oku, aksiyon al, sonra kapan\u0131\u015f durumunu takip et. G\u00fcnl\u00fck operasyon ritmine g\u00f6re tasarland\u0131.',
    'Step 1': 'Ad\u0131m 1',
    'Step 2': 'Ad\u0131m 2',
    'Step 3': 'Ad\u0131m 3',
    'Read Risk Now': 'Anl\u0131k Riski Oku',
    'Execute Actions': 'Aksiyonlar\u0131 Uygula',
    'Track Closure': 'Kapan\u0131\u015f\u0131 Takip Et',
    'Quick Jump': 'H\u0131zl\u0131 Ge\u00e7i\u015f',
    'Risk Now': 'Anl\u0131k Risk',
    'Risk Model': 'Risk Modeli',
    'Findings': 'Bulgular',
    'Actions': 'Aksiyonlar',
    'Tracking': 'Takip',
    'Watchlist': '\u0130zleme Listesi',
    'Executive PDF': 'Y\u00f6netici \u00d6zeti PDF',
    'Remediation Checklist PDF': '\u0130yile\u015ftirme Kontrol Listesi PDF',
    'MITRE Navigator JSON': 'MITRE Navigator JSON',
    'Tracking JSON Export': 'Takip JSON D\u0131\u015fa Aktar',
    'Recommended Sequence': '\u00d6nerilen S\u0131ra',
    'Current: -/100': 'G\u00fcncel: -/100',
    'No trend data available yet.': 'Hen\u00fcz trend verisi yok.',
    'Recommendation': '\u00d6neri',
    'Category': 'Kategori',
    'Penalty Points': 'Ceza Puan\u0131',
    'Category Risk %': 'Kategori Risk %',
    'Matched Rules': 'E\u015fle\u015fen Kurallar',
    'Score Impact Simulation': 'Skor Etki Sim\u00fclasyonu',
    'Risk Contribution Decomposition': 'Risk Katk\u0131 Da\u011f\u0131l\u0131m\u0131',
    'Model how closing Findings can lower Risk score before remediation execution.': 'Bulgular kapat\u0131ld\u0131\u011f\u0131nda, iyile\u015ftirme uygulanmadan \u00f6nce risk skorunun nas\u0131l d\u00fc\u015fece\u011fini modelle.',
    'Shows which primary categories contribute most to the Current score.': 'Birincil kategorilerin g\u00fcncel skora en fazla katk\u0131y\u0131 nas\u0131l yapt\u0131\u011f\u0131n\u0131 g\u00f6sterir.',
    'Close Critical Findings:': 'Kritik Bulgular\u0131 Kapat:',
    'Close High Findings:': 'Y\u00fcksek Bulgular\u0131 Kapat:',
    'Close Medium Findings:': 'Orta Bulgular\u0131 Kapat:',
    'Projected Score:': 'Tahmini Skor:',
    'Improvement:': '\u0130yile\u015fme:',
    'Privileged Infrastructure': 'Ayr\u0131cal\u0131kl\u0131 Altyap\u0131',
    'Certificate Authority': 'Sertifika Otoritesi',
    'Privileged Accounts': 'Ayr\u0131cal\u0131kl\u0131 Hesaplar',
    'Anomalies': 'Anomaliler',
    'Hygiene': 'Temizleme',
    'Trusts': 'G\u00fcven \u0130li\u015fkileri',
    'Stale Objects': 'Eski Nesneler',
    'Group cannot be resolved or access is denied.': 'Grup \u00e7\u00f6z\u00fcmlenemedi veya eri\u015fim engellendi.',
    'Publishing certificate data can indirectly affect authentication hygiene. Group cannot be resolved or access is denied.': 'Sertifika verisi yay\u0131nlama, kimlik do\u011frulama hijyenini dolayl\u0131 olarak etkileyebilir. Grup \u00e7\u00f6z\u00fcmlenemedi veya eri\u015fim engellendi.',
    'DNS admins can influence name resolution and potentially abuse DC plugin loading paths.': 'DNS y\u00f6neticileri ad \u00e7\u00f6z\u00fcmlemeyi etkileyebilir ve DC eklenti y\u00fckleme yollar\u0131n\u0131 k\u00f6t\u00fcye kullanabilir.',
    'Domain-wide administrative rights should be tightly limited and controlled.': 'Etki alan\u0131 geneli y\u00f6netsel haklar s\u0131k\u0131 bi\u00e7imde s\u0131n\u0131rland\u0131r\u0131lmal\u0131 ve denetlenmelidir.',
    'Forest-wide administrative rights should remain minimal and break-glass only.': 'Orman geneli y\u00f6netsel haklar minimumda kalmal\u0131 ve yaln\u0131zca acil durum i\u00e7in kullan\u0131lmal\u0131d\u0131r.',
    'Key administration rights can affect account credentials and key material.': 'Anahtar y\u00f6netim haklar\u0131 hesap kimlik bilgilerini ve anahtar materyalini etkileyebilir.',
    'GPO creation rights can enable broad policy abuse if not constrained.': 'GPO olu\u015fturma haklar\u0131 s\u0131n\u0131rland\u0131r\u0131lmazsa geni\u015f \u00f6l\u00e7ekli ilke suistimaline yol a\u00e7abilir.',
    'Name': 'Ad',
    'Enabled': 'Etkin',
    'Password Never Expires': '\u015eifre S\u00fcresi Dolmaz',
    'Last Logon': 'Son Oturum A\u00e7ma',
    'Domain Admin': 'Domain Admin',
    'Schema Admin': 'Schema Admin',
    'Enterprise Admin': 'Enterprise Admin',
    'Hostname': 'Makine Ad\u0131',
    'OS': '\u0130\u015fletim Sistemi',
    'Status': 'Durum',
    'User': 'Kullan\u0131c\u0131',
    'Source Host': 'Kaynak Sunucu',
    'Source IP': 'Kaynak IP',
    'Destination Host': 'Hedef Sunucu',
    'Destination IP': 'Hedef IP',
    'Reason': 'Gerek\u00e7e',
    'Good': '\u0130yi',
    'Acceptable': 'Kabul Edilebilir',
    'Poor': 'Zay\u0131f',
    'Critical': 'Kritik',
    'High': 'Y\u00fcksek',
    'Medium': 'Orta',
    'Low': 'D\u00fc\u015f\u00fck',
    'Yes': 'Evet',
    'No': 'Hay\u0131r',
    'Never': 'Hi\u00e7'
};

var domTextRegexTr = [
    { re: /Immediate containment needed/g, to: 'Acil kapatma gerekli' },
    { re: /Prioritize in current sprint/g, to: 'Mevcut sprintte \u00f6nceliklendir' },
    { re: /Track and reduce baseline drift/g, to: 'Baseline sapmas\u0131n\u0131 izleyip azalt' },
    { re: /Observed count:/g, to: 'G\u00f6zlenen adet:' },
    { re: /Inventory in scope/g, to: 'Kapsamdaki envanter' },
    { re: /Recent logon timestamp/g, to: 'Yak\u0131n oturum a\u00e7ma zaman\u0131' }
];

var domTextLooseRegexTr = [
    { re: /\bRecommended\b/gi, to: '\u00d6nerilen' },
    { re: /\bOverview\b/gi, to: 'Genel Bak\u0131\u015f' },
    { re: /\bDashboard\b/gi, to: 'Pano' },
    { re: /\bMission Board\b/gi, to: 'G\u00f6rev Panosu' },
    { re: /\bRisk\b/gi, to: 'Risk' },
    { re: /\bRecommendation\b/gi, to: '\u00d6neri' },
    { re: /\bCategory\b/gi, to: 'Kategori' },
    { re: /\bPenalty Points\b/gi, to: 'Ceza Puan\u0131' },
    { re: /\bMatched Rules\b/gi, to: 'E\u015fle\u015fen Kurallar' },
    { re: /\bPrivileged\b/gi, to: 'Ayr\u0131cal\u0131kl\u0131' },
    { re: /\bInfrastructure\b/gi, to: 'Altyap\u0131' },
    { re: /\bAccounts\b/gi, to: 'Hesaplar' },
    { re: /\bTrusts\b/gi, to: 'G\u00fcven \u0130li\u015fkileri' },
    { re: /\bHygiene\b/gi, to: 'Temizleme' },
    { re: /\bStale\b/gi, to: 'Eski' },
    { re: /\bFindings\b/gi, to: 'Bulgular' },
    { re: /\bModel\b/gi, to: 'Model' },
    { re: /\bAction(s)?\b/gi, to: function(_, s){ return s ? 'Aksiyonlar' : 'Aksiyon'; } },
    { re: /\bTracking\b/gi, to: 'Takip' },
    { re: /\bWatchlist\b/gi, to: '\u0130zleme Listesi' },
    { re: /\bQuick Jump\b/gi, to: 'H\u0131zl\u0131 Ge\u00e7i\u015f' },
    { re: /\bCopy\b/gi, to: 'Kopyala' },
    { re: /\bPermalink\b/gi, to: 'Kal\u0131c\u0131 Ba\u011flant\u0131' },
    { re: /\bLink\b/gi, to: 'Ba\u011flant\u0131' },
    { re: /\bExecutive\b/gi, to: 'Y\u00f6netici' },
    { re: /\bRemediation\b/gi, to: '\u0130yile\u015ftirme' },
    { re: /\bChecklist\b/gi, to: 'Kontrol Listesi' },
    { re: /\bExport\b/gi, to: 'D\u0131\u015fa Aktar' },
    { re: /\bUsers\b/gi, to: 'Kullan\u0131c\u0131lar' },
    { re: /\bUser\b/gi, to: 'Kullan\u0131c\u0131' },
    { re: /\bGroups\b/gi, to: 'Gruplar' },
    { re: /\bGroup\b/gi, to: 'Grup' },
    { re: /\bSecurity\b/gi, to: 'G\u00fcvenlik' },
    { re: /\bSites\b/gi, to: 'Siteler' },
    { re: /\bSite\b/gi, to: 'Site' },
    { re: /\bTopology\b/gi, to: 'Topoloji' },
    { re: /\bInactive\b/gi, to: 'Pasif' },
    { re: /\bObjects\b/gi, to: 'Nesneler' },
    { re: /\bObject\b/gi, to: 'Nesne' },
    { re: /\bHealth\b/gi, to: 'Sa\u011fl\u0131k' },
    { re: /\bLocked Accounts\b/gi, to: 'Kilitli Hesaplar' },
    { re: /\bPassword Expiry\b/gi, to: '\u015eifre S\u00fcresi Dolumu' },
    { re: /\bSkipped\b/gi, to: 'Atlanan' },
    { re: /\bUnreachable\b/gi, to: 'Ula\u015f\u0131lamayan' },
    { re: /\bCurrent\b/gi, to: 'G\u00fcncel' },
    { re: /\brecords listed\b/gi, to: 'kay\u0131t listelendi' },
    { re: /\bTotal\b/gi, to: 'Toplam' },
    { re: /\bEnabled\b/gi, to: 'Etkin' },
    { re: /\bDisabled\b/gi, to: 'Devre D\u0131\u015f\u0131' },
    { re: /\bNever\b/gi, to: 'Hi\u00e7' },
    { re: /\bServer\b/gi, to: 'Sunucu' },
    { re: /\bClient\b/gi, to: '\u0130stemci' },
    { re: /\bLegacy\b/gi, to: 'Eski S\u00fcr\u00fcm' },
    { re: /\bUnknown\b/gi, to: 'Bilinmeyen' },
    { re: /\bHostname\b/gi, to: 'Makine Ad\u0131' },
    { re: /\bLast Logon\b/gi, to: 'Son Oturum A\u00e7ma' },
    { re: /\bStatus\b/gi, to: 'Durum' },
    { re: /\bReason\b/gi, to: 'Gerek\u00e7e' },
    { re: /\bGroup cannot be resolved or access is denied\.?/gi, to: 'Grup \u00e7\u00f6z\u00fcmlenemedi veya eri\u015fim engellendi.' }
];

var i18nStrings = {
    en: {
        'header.title': 'Active Directory Overview',
        'nav.copyPermalink': 'Copy Permalink',
        'nav.adRiskDashboard': 'AD Risk Dashboard',
        'nav.riskBaselineDiff': 'Risk Baseline Diff',
        'nav.userRiskLevel': 'AD User Risk Level',
        'nav.windowsOverview': 'Windows OS Overview',
        'nav.adUsersOverview': 'AD Users Overview',
        'nav.groupsSecurity': 'Groups & Security',
        'nav.adSitesTopology': 'AD Sites & Topology',
        'nav.inactiveObjects': 'Inactive Objects',
        'nav.dcHealthFsmo': 'DC Health & FSMO',
        'nav.exchangeUsers': 'Exchange/O365 Users',
        'nav.lockedAccounts': 'Locked Accounts',
        'nav.passwordExpiry': 'Password Expiry',
        'nav.skippedDcs': 'Skipped / Unreachable DCs',
        'risk.copyDashboardLink': 'Copy Dashboard Link',
        'risk.caLensTitle': 'CA Risk Lens',
        'risk.caLensMeta': 'Aggregates certificate service (AD CS/CA) risks in one place and guides closure priority.',
        'risk.quickJump': 'Quick Jump',
        'risk.quickRiskNow': 'Risk Now',
        'risk.quickRiskModel': 'Risk Model',
        'risk.quickFindings': 'Findings',
        'risk.quickActions': 'Actions',
        'risk.quickCA': 'CA',
        'risk.quickTracking': 'Tracking',
        'risk.quickWatchlist': 'Watchlist',
        'alert.permalinkCopied': 'Permalink copied to clipboard.',
        'alert.permalinkFallback': 'Permalink: '
    },
    tr: {
        'header.title': 'Active Directory Genel Bakış',
        'nav.copyPermalink': 'Kalıcı Bağlantıyı Kopyala',
        'nav.adRiskDashboard': 'AD Risk Panosu',
        'nav.riskBaselineDiff': 'Risk Baseline Farkı',
        'nav.userRiskLevel': 'AD Kullanıcı Risk Seviyesi',
        'nav.windowsOverview': 'Windows OS Genel Bakış',
        'nav.adUsersOverview': 'AD Kullanıcılar Genel Bakış',
        'nav.groupsSecurity': 'Gruplar ve Güvenlik',
        'nav.adSitesTopology': 'AD Site ve Topoloji',
        'nav.inactiveObjects': 'Pasif Nesneler',
        'nav.dcHealthFsmo': 'DC Sağlığı ve FSMO',
        'nav.exchangeUsers': 'Exchange/O365 Kullanıcıları',
        'nav.lockedAccounts': 'Kilitli Hesaplar',
        'nav.passwordExpiry': 'Şifre Süresi Dolumu',
        'nav.skippedDcs': 'Atlanan / Ulaşılamayan DC\'ler',
        'risk.copyDashboardLink': 'Pano Bağlantısını Kopyala',
        'risk.caLensTitle': 'CA Risk Lens',
        'risk.caLensMeta': 'Sertifika servisi (AD CS/CA) kaynakli riskleri tek yerde toplar ve kapanis onceligi verir.',
        'risk.quickJump': 'Hızlı Geçiş',
        'risk.quickRiskNow': 'Anlık Risk',
        'risk.quickRiskModel': 'Risk Modeli',
        'risk.quickFindings': 'Bulgular',
        'risk.quickActions': 'Aksiyonlar',
        'risk.quickCA': 'CA',
        'risk.quickTracking': 'Takip',
        'risk.quickWatchlist': 'İzleme Listesi',
        'alert.permalinkCopied': 'Kalıcı bağlantı panoya kopyalandı.',
        'alert.permalinkFallback': 'Kalıcı bağlantı: '
    }
};

function textFor(key, fallback){
    var dict = i18nStrings[currentLanguage] || i18nStrings.en;
    if (dict && Object.prototype.hasOwnProperty.call(dict, key)) return dict[key];
    return fallback || key;
}

function translateTextToTurkish(input){
    var text = String(input || '');
    if (!text) return text;

    var leading = text.match(/^\s*/);
    var trailing = text.match(/\s*$/);
    var prefix = leading ? leading[0] : '';
    var suffix = trailing ? trailing[0] : '';
    var core = text.trim();
    if (!core) return text;

    if (Object.prototype.hasOwnProperty.call(domTextExactTr, core)) {
        return prefix + domTextExactTr[core] + suffix;
    }

    core = core
        .replace(/^Disable\b/i, 'Devre dışı bırak')
        .replace(/^Enable\b/i, 'Etkinleştir')
        .replace(/^Enforce\b/i, 'Zorunlu kıl')
        .replace(/^Review\b/i, 'Gözden geçir')
        .replace(/^Rotate\b/i, 'Değiştir')
        .replace(/^Set\b/i, 'Ayarla')
        .replace(/^Remove\b/i, 'Kaldır')
        .replace(/^Restrict\b/i, 'Sınırla')
        .replace(/^Use\b/i, 'Kullan')
        .replace(/^Track\b/i, 'Takip et')
        .replace(/^Separate\b/i, 'Ayrıştır')
        .replace(/^Close\b/i, 'Kapat')
        .replace(/^Clean\b/i, 'Temizle')
        .replace(/^Harden\b/i, 'Sıkılaştır')
        .replace(/^Migrate\b/i, 'Taşı')
        .replace(/^Validate\b/i, 'Doğrula')
        .replace(/^Implement\b/i, 'Uygula')
        .replace(/^Adopt\b/i, 'Benimse')
        .replace(/^Configure\b/i, 'Yapılandır');

    for (var i = 0; i < domTextRegexTr.length; i++) {
        var rule = domTextRegexTr[i];
        if (rule.re.test(core)) {
            core = core.replace(rule.re, rule.to);
        }
    }

    for (var j = 0; j < domTextLooseRegexTr.length; j++) {
        var looseRule = domTextLooseRegexTr[j];
        core = core.replace(looseRule.re, looseRule.to);
    }

    return prefix + core + suffix;
}

function applyDomAttributeTranslation(lang){
    var attrs = ['title', 'aria-label', 'placeholder'];
    var selector = '[title],[aria-label],[placeholder],button[value],input[type="button"][value],input[type="submit"][value]';
    var nodes = document.querySelectorAll(selector);

    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        var originalAttrs = domAttrOriginalMap.get(node);
        if (!originalAttrs) {
            originalAttrs = {};
            for (var a = 0; a < attrs.length; a++) {
                if (node.hasAttribute(attrs[a])) {
                    originalAttrs[attrs[a]] = node.getAttribute(attrs[a]);
                }
            }
            if (node.hasAttribute('value')) {
                originalAttrs.value = node.getAttribute('value');
            }
            domAttrOriginalMap.set(node, originalAttrs);
        }

        if (lang === 'tr') {
            for (var b = 0; b < attrs.length; b++) {
                var attr = attrs[b];
                if (Object.prototype.hasOwnProperty.call(originalAttrs, attr)) {
                    node.setAttribute(attr, translateTextToTurkish(originalAttrs[attr]));
                }
            }
            if (Object.prototype.hasOwnProperty.call(originalAttrs, 'value')) {
                node.setAttribute('value', translateTextToTurkish(originalAttrs.value));
            }
        } else {
            for (var c = 0; c < attrs.length; c++) {
                var attrName = attrs[c];
                if (Object.prototype.hasOwnProperty.call(originalAttrs, attrName)) {
                    node.setAttribute(attrName, originalAttrs[attrName]);
                }
            }
            if (Object.prototype.hasOwnProperty.call(originalAttrs, 'value')) {
                node.setAttribute('value', originalAttrs.value);
            }
        }
    }
}

function applyDomTranslation(lang){
    if (isApplyingDomTranslation) return;
    isApplyingDomTranslation = true;

    var root = document.body;
    if (!root) {
        isApplyingDomTranslation = false;
        return;
    }

    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
        acceptNode: function(node){
            if (!node || !node.parentElement) return NodeFilter.FILTER_REJECT;
            var tag = node.parentElement.tagName;
            if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT') return NodeFilter.FILTER_REJECT;
            if (!node.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
            return NodeFilter.FILTER_ACCEPT;
        }
    });

    var textNodes = [];
    var current = walker.nextNode();
    while (current) {
        textNodes.push(current);
        current = walker.nextNode();
    }

    for (var i = 0; i < textNodes.length; i++) {
        var textNode = textNodes[i];
        if (!domTextOriginalMap.has(textNode)) {
            domTextOriginalMap.set(textNode, textNode.nodeValue);
        }

        var original = domTextOriginalMap.get(textNode);
        if (lang === 'tr') {
            textNode.nodeValue = translateTextToTurkish(original);
        } else {
            textNode.nodeValue = original;
        }
    }

    applyDomAttributeTranslation(lang);
    isApplyingDomTranslation = false;
}

function startDomTranslationObserver(){
    if (domTranslationObserver || !window.MutationObserver || !document.body) return;
    domTranslationObserver = new MutationObserver(function(){
        if (currentLanguage === 'tr') {
            applyDomTranslation('tr');
        }
    });

    domTranslationObserver.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true,
        attributes: true,
        attributeFilter: ['title', 'aria-label', 'placeholder', 'value']
    });
}

function stopDomTranslationObserver(){
    if (!domTranslationObserver) return;
    domTranslationObserver.disconnect();
    domTranslationObserver = null;
}

function applyLanguage(lang){
    currentLanguage = (lang === 'tr') ? 'tr' : 'en';
    document.title = (currentLanguage === 'tr') ? 'Active Directory Genel Bakış' : 'Active Directory Overview';
    var nodes = document.querySelectorAll('[data-i18n-key]');
    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        var key = node.getAttribute('data-i18n-key');
        if (!key) continue;
        node.textContent = textFor(key, node.textContent);
    }

    var langToggle = document.getElementById('langToggleBtn');
    if (langToggle) {
        langToggle.textContent = (currentLanguage === 'tr') ? 'EN' : 'TR';
        langToggle.title = (currentLanguage === 'tr') ? 'Switch to English' : 'Türkçeye geç';
    }

    applyDomTranslation(currentLanguage);
    if (currentLanguage === 'tr') startDomTranslationObserver();
    else stopDomTranslationObserver();

    if (typeof renderCaRiskLens === 'function') renderCaRiskLens();
    if (typeof renderOUTierAdvisorShell === 'function') renderOUTierAdvisorShell();

    try { localStorage.setItem('adcheck-lang', currentLanguage); } catch (e) {}
}

function toggleLanguage(){
    applyLanguage(currentLanguage === 'tr' ? 'en' : 'tr');
    updateHashFromState();
}

var riskCategoryThresholdMap = {
    'Stale Objects': 80,
    'Privileged Accounts': 100,
    'Privileged Infrastructure': 120,
    'Certificate Authority': 80,
    'Trusts': 60,
    'Anomalies': 80,
    'Hygiene': 60
};
var riskCategoryWeightMap = {
    'Stale Objects': 20,
    'Privileged Accounts': 20,
    'Privileged Infrastructure': 20,
    'Trusts': 20,
    'Anomalies': 20
};
var riskSeverityWeightMap = { Critical: 25, High: 10, Medium: 4, Low: 1 };

function safeArray(input){
    return Array.isArray(input) ? input : (input ? [input] : []);
}

function scrollRiskStoryboard(anchorId){
    var node = document.getElementById(anchorId);
    if (!node) return;
    try {
        node.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (e) {
        node.scrollIntoView(true);
    }
}

function escapeHtml(text){
    return String(text || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function safeBase64Encode(str){
    try {
        return btoa(unescape(encodeURIComponent(String(str || ''))));
    } catch (e) {
        return '';
    }
}

function safeBase64Decode(str){
    try {
        return decodeURIComponent(escape(atob(String(str || ''))));
    } catch (e) {
        return '';
    }
}

function getGroupMembers(){
    if (!GroupMembers && window.__adcheckGroupMembers) GroupMembers = window.__adcheckGroupMembers;
    return GroupMembers;
}

function getObjectRiskDetails(){
    if (!ObjectRiskDetails && window.__adcheckObjectRiskDetails) ObjectRiskDetails = window.__adcheckObjectRiskDetails;
    return ObjectRiskDetails;
}

function loadSidecarScript(src, onDone){
    var existing = document.querySelector('script[data-sidecar-src="' + src + '"]');
    if (existing && existing.getAttribute('data-loaded') === '1') {
        if (typeof onDone === 'function') onDone();
        return;
    }

    if (existing && existing.getAttribute('data-loading') === '1') {
        existing.addEventListener('load', function(){ if (typeof onDone === 'function') onDone(); });
        return;
    }

    var script = existing || document.createElement('script');
    script.src = src;
    script.async = true;
    script.setAttribute('data-sidecar-src', src);
    script.setAttribute('data-loading', '1');
    script.onload = function(){
        script.setAttribute('data-loaded', '1');
        script.setAttribute('data-loading', '0');
        if (typeof onDone === 'function') onDone();
    };
    script.onerror = function(){
        script.setAttribute('data-loaded', '0');
        script.setAttribute('data-loading', '0');
        if (typeof onDone === 'function') onDone();
    };
    if (!existing) document.head.appendChild(script);
}

function ensureGroupMembersLoaded(onDone){
    if (getGroupMembers()) {
        if (typeof onDone === 'function') onDone();
        return;
    }
    loadSidecarScript('tools/groupMembersData.js', function(){
        if (window.__adcheckGroupMembers) GroupMembers = window.__adcheckGroupMembers;
        if (typeof onDone === 'function') onDone();
    });
}

function ensureObjectRiskDetailsLoaded(onDone){
    if (getObjectRiskDetails()) {
        if (typeof onDone === 'function') onDone();
        return;
    }
    loadSidecarScript('tools/objectRiskData.js', function(){
        if (window.__adcheckObjectRiskDetails) ObjectRiskDetails = window.__adcheckObjectRiskDetails;
        if (typeof onDone === 'function') onDone();
    });
}

function getRemediationBaselineMap(){
    if (!window.__remediationBaselineMap) {
        window.__remediationBaselineMap = {};
        safeArray(remediationBaselineStates).forEach(function(item){
            if (!item || !item.Key) return;
            window.__remediationBaselineMap[item.Key] = {
                status: String(item.Status || 'open').toLowerCase(),
                note: String(item.Note || ''),
                updatedAt: String(item.UpdatedAt || '')
            };
        });
    }
    return window.__remediationBaselineMap;
}

function normalizeRemediationStatus(status){
    var s = String(status || 'open').toLowerCase();
    if (s === 'fix' || s === 'fixed') s = 'fixing';
    if (s !== 'open' && s !== 'fixing' && s !== 'accepted' && s !== 'exception') s = 'open';
    return s;
}

function readRemediationStorageEntry(key){
    try {
        var raw = localStorage.getItem('adcheck-remediation-' + key);
        if (raw) {
            var parsed = JSON.parse(raw);
            return {
                status: normalizeRemediationStatus(parsed.status || 'open'),
                note: String(parsed.note || ''),
                updatedAt: String(parsed.updatedAt || '')
            };
        }
    } catch (e) {}
    return null;
}

function getTrackingEntry(key){
    if (!key) return { status: 'open', note: '', updatedAt: '' };
    if (remediationTrackingStore && remediationTrackingStore[key]) {
        return remediationTrackingStore[key];
    }
    var localEntry = readRemediationStorageEntry(key);
    if (localEntry) return localEntry;
    var baselineMap = getRemediationBaselineMap();
    if (baselineMap[key]) return baselineMap[key];
    return { status: 'open', note: '', updatedAt: '' };
}

function setTrackingEntry(key, entry){
    if (!key) return;
    remediationTrackingStore[key] = {
        status: normalizeRemediationStatus(entry && entry.status),
        note: String((entry && entry.note) || ''),
        updatedAt: String((entry && entry.updatedAt) || '')
    };
}

function persistTrackingEntry(key, entry){
    var normalized = {
        status: normalizeRemediationStatus(entry && entry.status),
        note: String((entry && entry.note) || ''),
        updatedAt: String((entry && entry.updatedAt) || new Date().toISOString())
    };
    setTrackingEntry(key, normalized);
    try { localStorage.setItem('adcheck-remediation-' + key, JSON.stringify(normalized)); } catch (e) {}
    try { localStorage.setItem('adcheck-remediation-tracking', JSON.stringify(remediationTrackingStore)); } catch (e) {}
    return normalized;
}

function buildTrackingControls(entry){
    var status = normalizeRemediationStatus(entry && entry.status);
    var note = String((entry && entry.note) || '');
    var updatedAt = String((entry && entry.updatedAt) || '');
    var meta = remediationStatusMeta(status);
    var updatedText = updatedAt ? ('<span class="remediation-updated-at" style="font-size:10px;color:#5b7087;">Updated: ' + escapeHtml(updatedAt) + '</span>') : '';
    return ''
        + '<div style="display:flex;flex-direction:column;gap:6px;min-width:260px;">'
        + '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
        + '<select class="risk-action-btn remediation-status-select" style="padding:4px 8px;font-size:11px;min-width:110px;" onchange="setFindingStatus(this)">'
        + '<option value="open"' + (status === 'open' ? ' selected' : '') + '>Open</option>'
        + '<option value="fixing"' + (status === 'fixing' ? ' selected' : '') + '>Fixing</option>'
        + '<option value="accepted"' + (status === 'accepted' ? ' selected' : '') + '>Accepted</option>'
        + '<option value="exception"' + (status === 'exception' ? ' selected' : '') + '>Exception</option>'
        + '</select>'
        + '<span class="' + meta.cls + ' remediation-status-pill-live" data-remediation-pill="1">' + meta.label + '</span>'
        + '</div>'
        + '<input type="text" class="remediation-note-input" style="padding:5px 8px;border:1px solid #b7cce2;border-radius:8px;font-size:11px;width:100%;box-sizing:border-box;" placeholder="Note" value="' + escapeHtml(note) + '" oninput="setFindingNote(this)">'
        + '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
        + '<button class="risk-action-btn" style="padding:5px 10px;font-size:11px;" onclick="saveRemediationRow(this)">Kaydet</button>'
        + '<span class="remediation-save-status" data-remediation-save-status="1" style="font-size:10px;color:#52708f;display:none;">Kaydedildi ✓</span>'
        + updatedText
        + '</div>'
        + '</div>';
}

function updateTrackingRowUI(row, entry){
    if (!row || !row.cells || row.cells.length < 7) return;
    var statusCell = row.cells[6];
    if (!statusCell) return;
    statusCell.innerHTML = buildTrackingControls(entry);
}

function updateHashFromState(){
    var state = {
        c: currentContainerId || 'pingCastleRisksContainer',
        rf: currentRiskFocusMode || 'all',
        tf: currentTrackingFilter || 'all',
        dm: document.body.classList.contains('dark-mode') ? 1 : 0,
        lg: currentLanguage || 'en'
    };
    var encoded = safeBase64Encode(JSON.stringify(state));
    if (encoded) window.location.hash = encoded;
}

function readHashState(){
    var h = (window.location.hash || '').replace(/^#/, '');
    if (!h) return null;
    var text = safeBase64Decode(h);
    if (!text) return null;
    try {
        return JSON.parse(text);
    } catch (e) {
        return null;
    }
}

function applyDarkMode(enabled){
    if (enabled) document.body.classList.add('dark-mode');
    else document.body.classList.remove('dark-mode');
    try { localStorage.setItem('adcheck-dark-mode', enabled ? '1' : '0'); } catch(e){}
}

function toggleDarkMode(){
    var enabled = !document.body.classList.contains('dark-mode');
    applyDarkMode(enabled);
    updateHashFromState();
}

function copyPermalinkState(){
    updateHashFromState();
    var url = window.location.href;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(function(){
            alert(textFor('alert.permalinkCopied', 'Permalink copied to clipboard.'));
        }).catch(function(){
            alert(textFor('alert.permalinkFallback', 'Permalink: ') + url);
        });
    } else {
        alert(textFor('alert.permalinkFallback', 'Permalink: ') + url);
    }
}

function drawRiskTrendSparkline(){
    var svg = document.getElementById('riskTrendSparkline');
    var currentBadge = document.getElementById('riskTrendCurrentBadge');
    if (!svg) return;
    var rows = safeArray(riskTrendSeries).slice(-24);
    if (!rows.length) {
        if (currentBadge) currentBadge.innerText = 'Current: -/100';
        svg.innerHTML = '<text x="12" y="56" fill="#5a6f84" font-size="12">No trend data available yet.</text>';
        return;
    }

    var w = 640, h = 120, padX = 18, padY = 20;
    var scores = rows.map(function(r){
        var v = parseFloat(r.DomainRiskScore);
        if (isNaN(v)) v = 0;
        return Math.max(0, Math.min(100, v));
    });

    var pathParts = [];
    for (var i = 0; i < scores.length; i++) {
        var x = padX + ((w - (padX * 2)) * (scores.length === 1 ? 0.5 : (i / (scores.length - 1))));
        var y = (h - padY) - ((h - (padY * 2)) * (scores[i] / 100));
        pathParts.push((i === 0 ? 'M' : 'L') + x.toFixed(2) + ' ' + y.toFixed(2));
    }

    var grid = '';
    [0,25,50,75,100].forEach(function(v){
        var gy = (h - padY) - ((h - (padY * 2)) * (v / 100));
        grid += '<line class="risk-trend-axis" x1="' + padX + '" y1="' + gy.toFixed(2) + '" x2="' + (w-padX) + '" y2="' + gy.toFixed(2) + '" />';
    });

    var points = '';
    scores.forEach(function(s, i){
        var x = padX + ((w - (padX * 2)) * (scores.length === 1 ? 0.5 : (i / (scores.length - 1))));
        var y = (h - padY) - ((h - (padY * 2)) * (s / 100));
        var cls = (i === scores.length - 1) ? 'risk-trend-point risk-trend-last' : 'risk-trend-point';
        points += '<circle class="' + cls + '" cx="' + x.toFixed(2) + '" cy="' + y.toFixed(2) + '" r="3.4" />';
    });

    var firstLabel = rows[0].GeneratedAt || '-';
    var lastLabel = rows[rows.length - 1].GeneratedAt || '-';
    var lastScore = scores[scores.length - 1];
    if (currentBadge) currentBadge.innerText = 'Current: ' + lastScore.toFixed(0) + '/100';

    svg.innerHTML =
        grid +
        '<path class="risk-trend-line" d="' + pathParts.join(' ') + '"></path>' +
        points +
        '<text x="' + padX + '" y="114" fill="#5a6f84" font-size="11">' + String(firstLabel).replace(/</g,'&lt;') + '</text>' +
        '<text x="' + (w - padX) + '" y="114" fill="#5a6f84" font-size="11" text-anchor="end">' + String(lastLabel).replace(/</g,'&lt;') + '</text>';
}

function buildAttackChainGraph(){
    var graphNode = document.getElementById('attackChainGraph');
    var whyList = document.getElementById('attackChainWhyList');
    if (!graphNode) return;

    var scenarios = safeArray(attackChainScenarios);
    if (!scenarios.length) {
        graphNode.innerHTML = '<div class="attack-scenario-empty">Bilinen saldiri zinciri tespit edilmedi</div>';
        if (whyList) whyList.innerHTML = '<li>No matched attack-chain scenario based on active finding combinations.</li>';
        return;
    }

    var cardsHtml = scenarios.map(function(s, idx){
        var risk = String((s && s.Risk) || '').toLowerCase();
        var border = (risk === 'critical') ? '#dc2626' : '#d97706';
        var bg = (risk === 'critical') ? 'rgba(220,38,38,.05)' : 'rgba(217,119,6,.07)';
        var steps = safeArray((s && s.Steps) || []).map(function(step){ return escapeHtml(String(step || '-')); }).join(' <span style="color:#64748b">&rarr;</span> ');
        var evidence = safeArray((s && s.Evidence) || []).map(function(ev){ return escapeHtml(String(ev || '-')); });
        var evidenceLine = evidence.length ? evidence.join(', ') : '-';
        return ''
            + '<button type="button" class="attack-scenario-card" onclick="showAttackScenarioDetail(' + idx + ')"'
            + ' style="width:100%;text-align:left;border:1px solid ' + border + ';background:' + bg + ';border-radius:10px;padding:10px 12px;margin-bottom:8px;cursor:pointer">'
            + '<div style="display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:6px">'
            + '<span style="font-weight:800;color:#183b5b">' + escapeHtml(String((s && s.ScenarioName) || 'Scenario')) + '</span>'
            + '<span style="font-size:11px;padding:2px 8px;border-radius:999px;background:' + border + ';color:#fff;font-weight:700">' + escapeHtml(String((s && s.Risk) || '-')) + '</span>'
            + '</div>'
            + '<div style="font-size:12px;color:#2f4963;line-height:1.4">' + steps + '</div>'
            + '<div style="font-size:11px;color:#465e75;margin-top:6px"><b>Evidence:</b> ' + evidenceLine + '</div>'
            + '</button>';
    }).join('');

    graphNode.innerHTML = cardsHtml;
    if (whyList) {
        whyList.innerHTML = scenarios.map(function(s){
            return '<li><b>' + escapeHtml(String((s && s.ScenarioName) || 'Scenario')) + ':</b> ' + escapeHtml(String((s && s.Description) || '')) + '</li>';
        }).join('');
    }
}

function showAttackScenarioDetail(index){
    var scenario = safeArray(attackChainScenarios)[index];
    if (!scenario) return;
    var title = 'Attack Scenario: ' + String(scenario.ScenarioName || 'Scenario');
    var steps = safeArray(scenario.Steps).join(' -> ');
    var evidence = safeArray(scenario.Evidence).join(', ');
    var body = 'Risk: ' + String(scenario.Risk || '-') + '\n\nSteps:\n' + steps + '\n\nEvidence:\n' + (evidence || '-') + '\n\n' + String(scenario.Description || '');
    if (typeof showModal === 'function') {
        try { showModal(title, body); return; } catch (e) {}
    }
    alert(title + '\n\n' + body);
}

function renderMitreHeatmap(){
    var host = document.getElementById('mitreHeatGrid');
    if (!host) return;
    var rows = safeArray(mitreRows);
    if (!rows.length) {
        host.innerHTML = '<div class="mitre-cell"><h4>No mapped finding</h4><p>Run with findings to populate ATT&CK coverage.</p></div>';
        return;
    }

    var map = {};
    rows.forEach(function(r){
        safeArray(r.Tactics).forEach(function(t){
            if (!map[t]) map[t] = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            var s = String(r.Severity || 'Low');
            if (!map[t][s]) map[t][s] = 0;
            map[t][s] += 1;
        });
    });

    var tactics = Object.keys(map).sort();
    var html = '';
    tactics.forEach(function(t){
        var m = map[t];
        var severityClass = 'mitre-cell-medium';
        if ((m.Critical || 0) > 0) severityClass = 'mitre-cell-critical';
        else if ((m.High || 0) > 0) severityClass = 'mitre-cell-high';
        html += '<div class="mitre-cell ' + severityClass + '">'
            + '<h4>' + t.replace(/</g,'&lt;') + '</h4>'
            + '<p>C:' + (m.Critical || 0) + ' | H:' + (m.High || 0) + ' | M:' + (m.Medium || 0) + ' | L:' + (m.Low || 0) + '</p>'
            + '</div>';
    });
    host.innerHTML = html;
}

function renderThreatPriorityQueue(){
    var host = document.getElementById('threatPriorityBody');
    if (!host) return;
    var rows = safeArray(threatPriorityRows);
    if (!rows.length) {
        host.innerHTML = '<div class="threat-priority-note">Tehdit oncelik verisi bulunamadi.</div>';
        return;
    }

    var topRows = rows.slice(0, 15);
    var html = '<table class="threat-priority-table"><tr><th>Oncelik</th><th>Technique</th><th>Rule</th><th>Kategori</th><th>Tactics</th></tr>';
    topRows.forEach(function(r){
        html += '<tr>'
            + '<td>' + escapeHtml(String(r.PriorityScore || 0)) + '</td>'
            + '<td>' + escapeHtml(String(r.Technique || '-')) + '</td>'
            + '<td>' + escapeHtml(String(r.Rule || '-')) + '</td>'
            + '<td>' + escapeHtml(String(r.Category || '-')) + '</td>'
            + '<td>' + escapeHtml(String(r.Tactics || '-')) + '</td>'
            + '</tr>';
    });
    html += '</table>';
    host.innerHTML = html;
}

function renderCaRiskLens(){
    var host = document.getElementById('caRiskLensBody');
    if (!host) return;
    var rows = safeArray(caRiskRows);
    function L(en, tr){ return currentLanguage === 'tr' ? tr : en; }
    if (!rows.length) {
        host.innerHTML = ''
            + '<div class="ca-risk-meta">' + escapeHtml(L('No active AD CS/CA risk detected.', 'Aktif AD CS/CA riski tespit edilmedi.')) + '</div>'
            + '<ul class="ca-risk-checklist">'
            + '<li>' + escapeHtml(L('Keep template ACL change auditing enabled.', 'Template ACL degisiklik denetimini acik tutun.')) + '</li>'
            + '<li>' + escapeHtml(L('Review published CA templates monthly.', 'Yayinda olan CA template listesini aylik gozden gecirin.')) + '</li>'
            + '<li>' + escapeHtml(L('Compare CA findings with trend in the next report run.', 'Bir sonraki raporda CA bulgularini trend ile karsilastirin.')) + '</li>'
            + '</ul>';
        return;
    }

    var critical = rows.filter(function(r){ return String(r.Severity || '').toLowerCase() === 'critical'; }).length;
    var high = rows.filter(function(r){ return String(r.Severity || '').toLowerCase() === 'high'; }).length;
    var top = rows.slice(0, 10);

    function getCaRiskGuidance(row){
        var rule = String((row && row.Rule) || '').toLowerCase();
        var recommendation = String((row && row.Recommendation) || '');

        if (rule.indexOf('esc1') >= 0 || rule.indexOf('enrollee') >= 0 || rule.indexOf('subject') >= 0) {
            return {
                why: L('User-controlled Subject/SAN fields can enable certificate-based privilege escalation.', 'Kullanici kontrollu subject/SAN alanlari, sertifika ile yetki yukselmesine yol acabilir.'),
                verify: L('Validate Enrollee supplies subject with authentication EKU combination in template settings.', 'Template ayarlarinda Enrollee supplies subject ve auth EKU kombinasyonunu dogrula.'),
                action: L('Disable subject supply for this template, narrow enrollment scope, and keep only required EKUs.', 'Bu template icin subject supply ozelligini kapat, enrollment kapsamini daralt ve sadece gerekli EKU birak.'),
                eta: L('24-48 hours', '24-48 saat')
            };
        }
        if (rule.indexOf('esc4') >= 0 || rule.indexOf('acl') >= 0 || rule.indexOf('owner') >= 0 || rule.indexOf('rights') >= 0) {
            return {
                why: L('Broad write rights can allow template manipulation for certificate-based attacks.', 'Genis yazma haklari, template manipule edilerek sertifika tabanli saldiriya imkan tanir.'),
                verify: L('Check WriteDacl/WriteOwner/GenericAll rights on template nTSecurityDescriptor.', 'Template nTSecurityDescriptor uzerinde WriteDacl/WriteOwner/GenericAll yetkilerini kontrol et.'),
                action: L('Remove write rights from broad groups such as Domain Users/Authenticated Users and delegate only to PKI admins.', 'Domain Users/Authenticated Users benzeri genis gruplarin yazma haklarini kaldir ve PKI admin grubuna delege et.'),
                eta: L('Same day', 'Ayni gun')
            };
        }
        if (rule.indexOf('ad cs') >= 0 || rule.indexOf('certificate') >= 0 || rule.indexOf('template') >= 0 || rule.indexOf('pki') >= 0) {
            return {
                why: L('Weak PKI controls can impact authentication trust chain and increase lateral movement risk.', 'PKI tarafindaki zayif kontroller kimlik dogrulama zincirini etkileyerek lateral movement riskini artirir.'),
                verify: L('Compare template publish state, enrollment permissions, and EKU set against operational need.', 'Template yayin durumu, enrollment izinleri ve EKU setini operasyonel ihtiyacla karsilastir.'),
                action: recommendation || L('Narrow high-risk templates and permissions; remove unnecessary published templates.', 'Yuksek riskli template ve izinleri daralt; gereksiz publish edilen template leri kaldir.'),
                eta: L('72 hours', '72 saat')
            };
        }
        return {
            why: L('CA-related finding is a risk signal and may indirectly impact identity security.', 'CA baglantili bulgu risk sinyalidir ve kimlik guvenligini dolayli etkileyebilir.'),
            verify: L('Validate ACL and publish settings on the related template/CA object.', 'Ilgili template/CA nesnesinin ACL ve yayin ayarlarini dogrula.'),
            action: recommendation || L('Validate with technical team and open a change plan.', 'Bulguyu teknik ekip ile dogrulayip degisiklik plani ac.'),
            eta: L('Planned window', 'Planlanan pencere')
        };
    }

    var html = '';
    html += '<div class="ca-risk-kpi">';
    html += '<div class="section-stat-card"><div class="section-stat-label">' + escapeHtml(L('Total CA Risk', 'CA Toplam Risk')) + '</div><div class="section-stat-value">' + rows.length + '</div><div class="section-stat-note">' + escapeHtml(L('AD CS/certificate related', 'AD CS/sertifika baglantili')) + '</div></div>';
    html += '<div class="section-stat-card"><div class="section-stat-label">Critical</div><div class="section-stat-value">' + critical + '</div><div class="section-stat-note">' + escapeHtml(L('Immediate closure', 'Acil kapanis')) + '</div></div>';
    html += '<div class="section-stat-card"><div class="section-stat-label">High</div><div class="section-stat-value">' + high + '</div><div class="section-stat-note">' + escapeHtml(L('Prioritize in this sprint', 'Bu sprintte ele alin')) + '</div></div>';
    html += '</div>';
    html += '<ul class="ca-risk-checklist">';
    html += '<li>' + escapeHtml(L('1) Open a change record first for Critical/High CA findings.', '1) Once Critical/High CA bulgularina degisiklik kaydi ac.')) + '</li>';
    html += '<li>' + escapeHtml(L('2) Complete validation step and attach evidence URL for each finding.', '2) Her bulgu icin dogrulama adimini tamamla ve kanit URL si ekle.')) + '</li>';
    html += '<li>' + escapeHtml(L('3) Re-run report after closure and validate downward trend.', '3) Kapatma sonrasi raporu tekrar calistirip azalis trendini dogrula.')) + '</li>';
    html += '</ul>';
    html += '<div class="table-wrapper"><table class="user-table"><tr><th>Severity</th><th>Rule</th><th>' + escapeHtml(L('Why Risk', 'Neden Risk')) + '</th><th>' + escapeHtml(L('Action Required', 'Ne Yapilmali')) + '</th><th>' + escapeHtml(L('Target Time', 'Hedef Sure')) + '</th></tr>';
    top.forEach(function(r){
        var g = getCaRiskGuidance(r);
        var sev = escapeHtml(String(r.Severity || '-'));
        html += '<tr>'
            + '<td><span class="ca-risk-badge">' + sev + '</span></td>'
            + '<td>' + escapeHtml(String(r.Rule || '-')) + '</td>'
            + '<td><div class="ca-risk-why">' + escapeHtml(g.why) + '<br><strong>' + escapeHtml(L('Validation:', 'Dogrulama:')) + '</strong> ' + escapeHtml(g.verify) + '</div></td>'
            + '<td><div class="ca-risk-action">' + escapeHtml(g.action) + '</div></td>'
            + '<td>' + escapeHtml(g.eta) + '</td>'
            + '</tr>';
    });
    html += '</table></div>';
    host.innerHTML = html;
}

function exportMitreNavigatorJson(){
    var rows = safeArray(mitreRows);
    var layer = {
        version: '4.5',
        name: 'AD Risk ATT&CK Mapping',
        domain: 'enterprise-attack',
        description: 'Generated from AD Health Check findings',
        techniques: []
    };

    rows.forEach(function(r){
        safeArray(r.Techniques).forEach(function(tid){
            var score = (String(r.Severity || '').toLowerCase() === 'critical') ? 100 :
                        (String(r.Severity || '').toLowerCase() === 'high') ? 80 :
                        (String(r.Severity || '').toLowerCase() === 'medium') ? 55 : 35;
            layer.techniques.push({ techniqueID: tid.split(' ')[0], score: score, comment: (r.Rule || '') });
        });
    });

    var blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'mitre_attack_navigator_layer.json';
    a.click();
    URL.revokeObjectURL(a.href);
}

function loadRemediationTracking(){
    try {
        var raw = localStorage.getItem('adcheck-remediation-tracking');
        remediationTrackingStore = raw ? JSON.parse(raw) : {};
    } catch (e) {
        remediationTrackingStore = {};
    }
}

function getTrackingEntry(key){
    if (!key) return { status: 'open', note: '', updatedAt: '' };
    if (remediationTrackingStore && remediationTrackingStore[key]) {
        return remediationTrackingStore[key];
    }
    var localEntry = readRemediationStorageEntry(key);
    if (localEntry) {
        remediationTrackingStore[key] = localEntry;
        return localEntry;
    }
    var baselineMap = getRemediationBaselineMap();
    if (baselineMap[key]) {
        remediationTrackingStore[key] = baselineMap[key];
        return baselineMap[key];
    }
    return { status: 'open', note: '', updatedAt: '' };
}

function setTrackingEntry(key, entry){
    remediationTrackingStore[key] = {
        status: normalizeRemediationStatus(entry && entry.status),
        note: String((entry && entry.note) || ''),
        updatedAt: String((entry && entry.updatedAt) || '')
    };
}

function saveRemediationTracking(){
    try { localStorage.setItem('adcheck-remediation-tracking', JSON.stringify(remediationTrackingStore)); } catch(e){}
}

function loadChangeApprovalGate(){
    try {
        var raw = localStorage.getItem('adcheck-change-approval');
        changeApprovalGateStore = raw ? JSON.parse(raw) : {};
    } catch (e) {
        changeApprovalGateStore = {};
    }
}

function saveChangeApprovalGate(){
    try { localStorage.setItem('adcheck-change-approval', JSON.stringify(changeApprovalGateStore || {})); } catch(e){}
}

function getChangeApprovalSnapshot(){
    return {
        ticket: String((changeApprovalGateStore && changeApprovalGateStore.ticket) || ''),
        owner: String((changeApprovalGateStore && changeApprovalGateStore.owner) || ''),
        window: String((changeApprovalGateStore && changeApprovalGateStore.window) || ''),
        rollback: String((changeApprovalGateStore && changeApprovalGateStore.rollback) || ''),
        checks: {
            impact: !!(changeApprovalGateStore && changeApprovalGateStore.impact),
            testPlan: !!(changeApprovalGateStore && changeApprovalGateStore.testPlan),
            backout: !!(changeApprovalGateStore && changeApprovalGateStore.backout),
            evidence: !!(changeApprovalGateStore && changeApprovalGateStore.evidence)
        }
    };
}

function updateApprovalGateStatus(){
    var statusNode = document.getElementById('approvalGateStatus');
    if (!statusNode) return;
    var s = getChangeApprovalSnapshot();
    var checklistOk = s.checks.impact && s.checks.testPlan && s.checks.backout && s.checks.evidence;
    var fieldsOk = !!(s.ticket && s.owner && s.window && s.rollback);
    if (checklistOk && fieldsOk) {
        statusNode.innerHTML = '<span class="remediation-status-pill remediation-status-fix">Onay Hazir</span> Degisiklik kaydi tamamlandi.';
    } else {
        statusNode.innerHTML = '<span class="remediation-status-pill remediation-status-open">Onay Bekliyor</span> Eksik alanlari tamamlayin.';
    }
}

function setApprovalGateCheck(key, checked){
    if (!changeApprovalGateStore || typeof changeApprovalGateStore !== 'object') changeApprovalGateStore = {};
    changeApprovalGateStore[key] = !!checked;
    saveChangeApprovalGate();
    updateApprovalGateStatus();
}

function setApprovalGateField(key, value){
    if (!changeApprovalGateStore || typeof changeApprovalGateStore !== 'object') changeApprovalGateStore = {};
    changeApprovalGateStore[key] = String(value || '');
    saveChangeApprovalGate();
    updateApprovalGateStatus();
}

function initChangeApprovalGate(){
    loadChangeApprovalGate();
    ['impact','testPlan','backout','evidence'].forEach(function(k){
        var cb = document.getElementById('approval_' + k);
        if (cb) cb.checked = !!changeApprovalGateStore[k];
    });
    ['ticket','owner','window','rollback'].forEach(function(k){
        var input = document.getElementById('approval_' + k);
        if (input) input.value = String(changeApprovalGateStore[k] || '');
    });
    updateApprovalGateStatus();
}

function remediationStatusMeta(status){
    var s = normalizeRemediationStatus(status);
    if (s === 'fixing') return { cls: 'remediation-status-pill remediation-status-fix', label: 'Fixing' };
    if (s === 'accepted') return { cls: 'remediation-status-pill remediation-status-accepted', label: 'Accepted' };
    if (s === 'exception') return { cls: 'remediation-status-pill remediation-status-exception', label: 'Exception' };
    return { cls: 'remediation-status-pill remediation-status-open', label: 'Open' };
}

function findingKeyFromRow(row){
    if (!row || !row.cells || row.cells.length < 3) return '';
    var category = (row.cells[0].innerText || '').trim();
    var rule = (row.cells[2].innerText || '').trim();
    return category + '||' + rule;
}

function initRemediationTracking(){
    loadRemediationTracking();
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;

    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    rows.forEach(function(row){
        if (!row.cells || row.cells.length < 8) return;
        var key = findingKeyFromRow(row);
        var statusCell = row.cells[6];
        if (!statusCell) return;

        var entry = getTrackingEntry(key);
        updateTrackingRowUI(row, entry);
    });

    filterRemediationStatus(currentTrackingFilter || 'all');
}

function setFindingStatus(selectEl){
    var row = selectEl;
    while (row && row.tagName !== 'TR') row = row.parentElement;
    if (!row) return;
    var key = findingKeyFromRow(row);
    var status = normalizeRemediationStatus(selectEl.value || 'open');
    var entry = getTrackingEntry(key);
    entry.status = status;
    setTrackingEntry(key, entry);

    var pill = row.querySelector('[data-remediation-pill="1"]');
    if (pill) {
        var meta = remediationStatusMeta(status);
        pill.className = meta.cls + ' remediation-status-pill-live';
        pill.textContent = meta.label;
    }

    filterRemediationStatus(currentTrackingFilter || 'all');
}

function setFindingNote(inputEl){
    var row = inputEl;
    while (row && row.tagName !== 'TR') row = row.parentElement;
    if (!row) return;
    var key = findingKeyFromRow(row);
    var entry = getTrackingEntry(key);
    entry.note = String(inputEl.value || '');
    setTrackingEntry(key, entry);
    filterRemediationStatus(currentTrackingFilter || 'all');
}

function saveRemediationRow(btn){
    var row = btn;
    while (row && row.tagName !== 'TR') row = row.parentElement;
    if (!row) return;
    var key = findingKeyFromRow(row);
    var selectEl = row.querySelector('.remediation-status-select');
    var noteInput = row.querySelector('.remediation-note-input');
    var entry = {
        status: normalizeRemediationStatus(selectEl ? selectEl.value : 'open'),
        note: String(noteInput ? noteInput.value : ''),
        updatedAt: new Date().toISOString()
    };
    var saved = persistTrackingEntry(key, entry);
    updateTrackingRowUI(row, saved);
    var confirmNode = row.querySelector('[data-remediation-save-status="1"]');
    if (confirmNode) {
        confirmNode.textContent = 'Kaydedildi ✓';
        confirmNode.style.display = 'inline-block';
        window.setTimeout(function(){
            confirmNode.style.display = 'none';
        }, 1500);
    }
    filterRemediationStatus(currentTrackingFilter || 'all');
}

function filterRemediationStatus(mode){
    currentTrackingFilter = String(mode || 'all').toLowerCase();
    if (currentTrackingFilter === 'fix') currentTrackingFilter = 'fixing';
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;
    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    var visible = 0;
    var counts = { open: 0, fixing: 0, accepted: 0, exception: 0 };

    rows.forEach(function(row){
        var key = findingKeyFromRow(row);
        var status = normalizeRemediationStatus(getTrackingEntry(key).status);
        if (Object.prototype.hasOwnProperty.call(counts, status)) counts[status] += 1;
        var show = (currentTrackingFilter === 'all') || (status === currentTrackingFilter);
        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    var chips = Array.from(document.querySelectorAll('.track-focus-chip'));
    chips.forEach(function(chip){
        var v = chip.getAttribute('data-track') || 'all';
        if (v === currentTrackingFilter) chip.classList.add('active');
        else chip.classList.remove('active');
    });

    var summary = document.getElementById('trackingSummary');
    if (summary) summary.innerText = counts.open + ' open, ' + counts.fixing + ' fixing, ' + counts.accepted + ' accepted, ' + counts.exception + ' exception | filter: ' + currentTrackingFilter + ' | shown: ' + visible;
    updateHashFromState();
}

function exportRemediationTrackingJson(){
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;
    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    var payload = rows.map(function(row){
        var key = findingKeyFromRow(row);
        var entry = getTrackingEntry(key);
        return {
            Category: (row.cells[0] ? row.cells[0].innerText.trim() : ''),
            Rule: (row.cells[2] ? row.cells[2].innerText.trim() : ''),
            Severity: (row.cells[1] ? row.cells[1].innerText.trim() : ''),
            Status: normalizeRemediationStatus(entry.status || 'open'),
            Note: String(entry.note || ''),
            UpdatedAt: String(entry.updatedAt || '')
        };
    });

    var blob = new Blob([JSON.stringify({
        GeneratedAt: new Date().toISOString(),
        ChangeApproval: getChangeApprovalSnapshot(),
        Findings: payload
    }, null, 2)], { type: 'application/json' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'remediation_tracking.json';
    a.click();
    URL.revokeObjectURL(a.href);
}

function exportRemediationTrackingExcel(){
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;

    function toUtf16LeBytes(str){
        var buffer = new ArrayBuffer(str.length * 2);
        var view = new DataView(buffer);
        for (var i = 0; i < str.length; i++) {
            view.setUint16(i * 2, str.charCodeAt(i), true);
        }
        return new Uint8Array(buffer);
    }

    var rows = Array.from(table.querySelectorAll('tr')).slice(1).map(function(row){
        var key = findingKeyFromRow(row);
        var entry = getTrackingEntry(key);
        return [
            row.cells[0] ? row.cells[0].innerText.trim() : '',
            row.cells[2] ? row.cells[2].innerText.trim() : '',
            row.cells[1] ? row.cells[1].innerText.trim() : '',
            normalizeRemediationStatus(entry.status || 'open'),
            String(entry.note || ''),
            String(entry.updatedAt || '')
        ];
    });

    var csv = ['"Category";"Rule";"Severity";"Status";"Note";"UpdatedAt"'];
    rows.forEach(function(cols){
        csv.push(cols.map(function(col){ return '"' + String(col).replace(/"/g, '""') + '"'; }).join(';'));
    });

    var payload = 'sep=;\r\n' + csv.join('\r\n');
    var utf16Payload = toUtf16LeBytes('\uFEFF' + payload);
    var blob = new Blob([utf16Payload], { type: 'text/csv;charset=utf-16le;' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = sanitizeFileName('remediation_tracking_states') + '.csv';
    link.click();
    URL.revokeObjectURL(link.href);
}

function openPrintHtml(title, htmlBody){
    var w = window.open('', '_blank');
    if (!w) return;
    w.document.write('<html><head><meta charset="utf-8"><title>' + title + '</title><style>body{font-family:Segoe UI,Arial,sans-serif;padding:20px;color:#1c2d3f;}h1{margin:0 0 8px 0;}h2{margin:16px 0 8px 0;}ul{margin:6px 0 12px 18px;}li{margin-bottom:6px;}table{border-collapse:collapse;width:100%;font-size:12px;}th,td{border:1px solid #a7b9cc;padding:6px;text-align:left;}th{background:#eaf1f8;} .small{font-size:12px;color:#4a5f75;}</style></head><body>');
    w.document.write(htmlBody);
    w.document.write('</body></html>');
    w.document.close();
    w.focus();
    w.print();
}

function exportExecutiveSummaryPdf(){
    var topFindings = safeArray(Object.values(PingRuleDetailsMap))
        .filter(function(f){ return Number(getPingCount(f) || 0) > 0; })
        .sort(function(a,b){
            var order = {Critical:0,High:1,Medium:2,Low:3};
            return (order[getPingSeverity(a)] || 9) - (order[getPingSeverity(b)] || 9) || (Number(getPingCount(b) || 0) - Number(getPingCount(a) || 0));
        })
        .slice(0, 5);

    var scoreColor = execScore < 40 ? '#c0392b' : execScore < 70 ? '#e67e22' : '#27ae60';
    var sevColors = {Critical:'#fde8e8',High:'#fef3e2',Medium:'#fefce8',Low:'#eafaf1'};
    var sevText = {Critical:'#7b1e1e',High:'#7a3e00',Medium:'#7a6b00',Low:'#155a2d'};

    var body = '<html><head><meta charset="utf-8">';
    body += '<style>';
    body += '@page { size: A4; margin: 18mm 20mm; }';
    body += 'body { font-family: Arial, sans-serif; font-size: 10.5pt; color: #1a2535; margin: 0; }';
    body += '@media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } .no-print { display: none !important; } }';
    body += '.header { display:flex; justify-content:space-between; align-items:flex-start; border-bottom:2px solid #0f2f4f; padding-bottom:10px; margin-bottom:14px; gap:16px; }';
    body += '.brand { display:flex; gap:10px; align-items:center; }';
    body += '.logo-box { width:42px; height:42px; border-radius:10px; background:#0f2f4f; color:#fff; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:15pt; }';
    body += '.header-left h1 { margin:0; font-size:17pt; color:#0f2f4f; }';
    body += '.header-left p { margin:3px 0 0; font-size:9pt; color:#556; }';
    body += '.score-box { text-align:center; background:' + scoreColor + '; color:#fff; border-radius:8px; padding:8px 14px; min-width:92px; }';
    body += '.score-box .num { font-size:28pt; font-weight:700; line-height:1; }';
    body += '.score-box .lbl { font-size:8pt; margin-top:2px; }';
    body += '.meta-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin-bottom:14px; }';
    body += '.meta-card { border:1px solid #d0dcea; border-radius:6px; padding:8px; text-align:center; }';
    body += '.meta-card .val { font-size:18pt; font-weight:700; line-height:1.05; }';
    body += '.meta-card .lbl { font-size:8pt; color:#666; margin-top:2px; }';
    body += '.crit { color:#c0392b; } .high { color:#e67e22; } .med { color:#f1c40f; } .low { color:#27ae60; }';
    body += 'table { width:100%; border-collapse:collapse; margin-bottom:12px; font-size:9pt; }';
    body += 'th { background:#0f2f4f; color:#fff; padding:6px 8px; text-align:left; }';
    body += 'td { padding:5px 8px; border-bottom:1px solid #e8eef5; vertical-align:top; }';
    body += 'tr:nth-child(even) td { background:#f7fafd; }';
    body += '.sev-badge { display:inline-block; padding:1px 6px; border-radius:4px; font-size:8pt; font-weight:700; }';
    body += '.summary-grid { display:grid; grid-template-columns:1.1fr .9fr; gap:12px; margin-bottom:12px; }';
    body += '.summary-card { border:1px solid #d0dcea; border-radius:8px; padding:10px; background:#f9fcff; }';
    body += '.summary-card h2 { margin:0 0 8px 0; font-size:12pt; color:#0f2f4f; }';
    body += '.summary-list { margin:0; padding-left:18px; }';
    body += '.summary-list li { margin-bottom:4px; }';
    body += '.sig-section { margin-top:16px; display:grid; grid-template-columns:1fr 1fr; gap:26px; }';
    body += '.sig-box { border-top:1px solid #888; padding-top:6px; font-size:9pt; color:#555; }';
    body += '.footer { position:fixed; bottom:0; left:0; right:0; font-size:8pt; color:#aaa; text-align:center; padding:4px; border-top:1px solid #eee; background:#fff; }';
    body += '</style></head><body>';
    body += '<div class="header">';
    body += '<div class="header-left">';
    body += '<div class="brand"><div class="logo-box">AD</div><div><h1>AD Security Risk Summary</h1><p>Domain: <b>' + execDomain + '</b> &nbsp;|&nbsp; Generated: <b>' + execDate + '</b></p></div></div>';
    body += '<p>Previous snapshot: <b>' + execPreviousDate + '</b> &nbsp;|&nbsp; Previous score: <b>' + execPreviousScore + '</b></p>';
    body += '</div>';
    body += '<div class="score-box"><div class="num">' + execScore + '</div><div class="lbl">Risk / ' + execRating + '</div></div>';
    body += '</div>';
    body += '<div class="meta-grid">';
    var counts = [
        { lbl: 'Critical', cls: 'crit', val: execCritical },
        { lbl: 'High', cls: 'high', val: execHigh },
        { lbl: 'Medium', cls: 'med', val: execMedium },
        { lbl: 'Low', cls: 'low', val: execLow }
    ];
    counts.forEach(function(c){
        body += '<div class="meta-card"><div class="val ' + c.cls + '">' + c.val + '</div><div class="lbl">' + c.lbl + '</div></div>';
    });
    body += '</div>';
    body += '<div class="summary-grid">';
    body += '<div class="summary-card"><h2>Top 5 Active Findings</h2><table><tr><th>Category</th><th>Rule</th><th>Severity</th><th>Count</th><th>Action</th></tr>';
    if (!topFindings.length) {
        body += '<tr><td colspan="5">No active Critical/High/Medium/Low finding found.</td></tr>';
    } else {
        topFindings.forEach(function(f){
            var sev = String(getPingSeverity(f) || '-');
            var bg = sevColors[sev] || '#fff';
            var tc = sevText[sev] || '#333';
            body += '<tr>';
            body += '<td>' + escapeHtml(String(getPingCategory(f) || '-')) + '</td>';
            body += '<td>' + escapeHtml(String(getPingRule(f) || '-')) + '</td>';
            body += '<td><span class="sev-badge" style="background:' + bg + ';color:' + tc + '">' + escapeHtml(sev) + '</span></td>';
            body += '<td>' + escapeHtml(String(getPingCount(f) || '0')) + '</td>';
            body += '<td>' + escapeHtml(getPingAction(f) || String(f.Recommendation || f.About || '')) + '</td>';
            body += '</tr>';
        });
    }
    body += '</table></div>';
    body += '<div class="summary-card"><h2>Recommended Sequence</h2><ol class="summary-list"><li>Contain Tier-0 and privileged account exposure.</li><li>Close delegation and ACL abuse paths.</li><li>Clean stale identities and enforce hygiene controls.</li><li>Track remediation status and exceptions with owner and note.</li><li>Re-run report and compare baseline diff.</li></ol></div>';
    body += '</div>';
    body += '<div class="sig-section"><div class="sig-box">Hazırlayan: ___________________________<br>Tarih: ___________</div><div class="sig-box">Onaylayan: ___________________________<br>Tarih: ___________</div></div>';
    body += '<div class="footer">This report was generated automatically by KusoADCheck. Confidential - Internal Use Only.</div>';
    body += '</body></html>';
    openPrintHtml('Executive_AD_Risk_Summary', body);
}

function exportRemediationChecklistPdf(){
    var items = safeArray(quickRemediationItems);
    var findings = safeArray(priorityRiskFindings);
    var body = '';
    body += '<h1>Remediation Checklist</h1>';
    body += '<p class="small">Generated: ' + new Date().toLocaleString() + '</p>';
    body += '<h2>Category Actions</h2><ul>';
    if (!items.length) {
        body += '<li>No category action item available.</li>';
    } else {
        items.forEach(function(i){
            body += '<li>[ ] <b>' + String(i.Category || '-') + ' (' + String(i.RiskPct || 0) + '%)</b> - ' + String(i.Action || '').replace(/</g,'&lt;') + '</li>';
        });
    }
    body += '</ul><h2>Critical/High Findings</h2><ul>';
    if (!findings.length) {
        body += '<li>No active Critical/High finding.</li>';
    } else {
        findings.forEach(function(f){
            body += '<li>[ ] <b>[' + String(f.Severity || '-') + ']</b> ' + String(f.Rule || '-') + ' - ' + String(f.Recommendation || '').replace(/</g,'&lt;') + '</li>';
        });
    }
    body += '</ul><h2>Closure</h2><ul><li>[ ] Evidence attached</li><li>[ ] Owner assigned</li><li>[ ] Re-test scheduled</li></ul>';
    openPrintHtml('Remediation_Checklist', body);
}

function showMembers(groupName, samAccountName) {
    var membersMap = getGroupMembers();
    var members = membersMap ? membersMap[samAccountName] : null;
    if (members && Array.isArray(members) && members.length > 0) {
        var memberArray = members;
        var memberList = memberArray.join('\n');
        
        var message = 'Group Name: ' + groupName + '\n' +
                      'SAM Account: ' + samAccountName + '\n' +
                      'Member Count: ' + memberArray.length + '\n\n' +
                      'Members:\n' + memberList;
        
        alert(message);
    } else {
        ensureGroupMembersLoaded(function(){
            var loadedMembersMap = getGroupMembers() || {};
            var loadedMembers = loadedMembersMap[samAccountName];
            if (loadedMembers && Array.isArray(loadedMembers) && loadedMembers.length > 0) {
                showMembers(groupName, samAccountName);
                return;
            }
            alert(groupName + ' group has no member data or member count is 0.');
        });
    }
}

function showObjectRiskDetails(detailKey, title) {
    var riskMap = getObjectRiskDetails();
    var detailsRaw = riskMap ? riskMap[detailKey] : null;
    var details = Array.isArray(detailsRaw) ? detailsRaw : (detailsRaw ? [String(detailsRaw)] : []);
    if (details.length > 0) {
        alert(title + '\n\n' + details.join('\n'));
    } else {
        ensureObjectRiskDetailsLoaded(function(){
            var loadedRiskMap = getObjectRiskDetails() || {};
            var loadedDetailsRaw = loadedRiskMap[detailKey];
            var loadedDetails = Array.isArray(loadedDetailsRaw) ? loadedDetailsRaw : (loadedDetailsRaw ? [String(loadedDetailsRaw)] : []);
            if (loadedDetails.length > 0) {
                showObjectRiskDetails(detailKey, title);
                return;
            }
            alert(title + '\n\nNo detail data available.');
        });
    }
}

function getPingAbout(ruleData){
    return (ruleData && (ruleData.a || ruleData.About)) || 'AD security finding';
}

function getPingSource(ruleData){
    return (ruleData && (ruleData.o || ruleData.Source)) || 'Directory attributes and related checks';
}

function getPingAction(ruleData){
    return (ruleData && (ruleData.u || ruleData.Action)) || (ruleData && (ruleData.p || ruleData.Recommendation)) || 'Apply remediation steps based on the specific rule context.';
}

function getPingCategory(ruleData){ return (ruleData && (ruleData.c || ruleData.Category)) || ''; }
function getPingRule(ruleData){ return (ruleData && (ruleData.r || ruleData.Rule)) || ''; }
function getPingSeverity(ruleData){ return (ruleData && (ruleData.s || ruleData.Severity)) || ''; }
function getPingCount(ruleData){ return (ruleData && (ruleData.n || ruleData.Count)) || 0; }
function getPingSample(ruleData){ return (ruleData && (ruleData.m || ruleData.Sample)) || ''; }
function getPingRecommendation(ruleData){ return (ruleData && (ruleData.p || ruleData.Recommendation)) || ''; }
function getPingReference(ruleData){ return (ruleData && (ruleData.f || ruleData.Reference)) || ''; }
function getPingDetails(ruleData){ return (ruleData && (ruleData.d || ruleData.Details)) || []; }

function showReplicationHealth(dcName, detail) {
    var text = detail;
    if (!text || String(text).trim() === '') {
        text = 'No replication detail available.';
    }
    alert('DC: ' + dcName + '\n\nReplication Detail:\n' + text);
}

function showPingFindingDetails(category, rule) {
    var key = category + '||' + rule;
    var data = PingRuleDetailsMap[key];
    if (!data) {
        alert('No detail data available for this finding.');
        return;
    }

    var lines = [];
    lines.push('Category: ' + (getPingCategory(data) || category));
    lines.push('Rule: ' + (getPingRule(data) || rule));
    lines.push('Severity: ' + (getPingSeverity(data) || '-'));
    lines.push('Count: ' + (getPingCount(data) || 0));
    lines.push('');
    lines.push('About: ' + getPingAbout(data));
    lines.push('Source: ' + getPingSource(data));
    lines.push('Reference: ' + (getPingReference(data) || '-'));
    lines.push('Action: ' + getPingAction(data));
    lines.push('Sample: ' + (getPingSample(data) || '-'));

    var details = Array.isArray(getPingDetails(data)) ? getPingDetails(data).slice() : [];

    // Enrich privileged review rules with exact member lists from ObjectRiskDetails map.
    if (rule.indexOf('Privileged Review: ') === 0) {
        var objectName = rule.replace('Privileged Review: ', '').trim();
        var detailKey = objectName.replace(/[^a-zA-Z0-9_-]/g, '_');
        var objectRiskMap = getObjectRiskDetails();
        var usersRaw = objectRiskMap[detailKey + '|users'];
        var compsRaw = objectRiskMap[detailKey + '|computers'];
        var indirectRaw = objectRiskMap[detailKey + '|indirect'];
        var unresolvedRaw = objectRiskMap[detailKey + '|unresolved'];

        var users = Array.isArray(usersRaw) ? usersRaw : (usersRaw ? [String(usersRaw)] : []);
        var comps = Array.isArray(compsRaw) ? compsRaw : (compsRaw ? [String(compsRaw)] : []);
        var indirect = Array.isArray(indirectRaw) ? indirectRaw : (indirectRaw ? [String(indirectRaw)] : []);
        var unresolved = Array.isArray(unresolvedRaw) ? unresolvedRaw : (unresolvedRaw ? [String(unresolvedRaw)] : []);

        details.push('Users -> ' + (users.length ? users.join(', ') : 'No data'));
        details.push('Computers -> ' + (comps.length ? comps.join(', ') : 'No data'));
        details.push('Indirect Groups -> ' + (indirect.length ? indirect.join(', ') : 'No data'));
        details.push('Unresolved -> ' + (unresolved.length ? unresolved.join(', ') : 'No data'));
    }

    lines.push('');
    lines.push('Triggered By / Detail:');
    if (details.length > 0) {
        for (var i = 0; i < details.length; i++) {
            lines.push('- ' + details[i]);
        }
    } else {
        lines.push('- No detailed object/user list available for this rule.');
    }

    alert(lines.join('\n'));
}

function parseTrDate(input) {
    // Parses dd/MM/yyyy or dd/MM/yyyy HH:mm formats deterministically.
    var m = input.match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2}))?$/);
    if (!m) return NaN;

    var day = parseInt(m[1], 10);
    var month = parseInt(m[2], 10) - 1;
    var year = parseInt(m[3], 10);
    var hour = m[4] ? parseInt(m[4], 10) : 0;
    var minute = m[5] ? parseInt(m[5], 10) : 0;
    return new Date(year, month, day, hour, minute, 0, 0).getTime();
}


function sortTable(tableId, columnIndex){
    var table = document.getElementById(tableId);
    var rows = Array.from(table.rows).slice(1);
    if(table.sortedColumn === columnIndex){
        table.asc = !table.asc;
    } else {
        table.asc = true;
    }
    table.sortedColumn = columnIndex;

    rows.sort(function(a,b){
        var x = a.cells[columnIndex].innerText.trim();
        var y = b.cells[columnIndex].innerText.trim();
        var dateX = parseTrDate(x);
        var dateY = parseTrDate(y);

        if (isNaN(dateX)) dateX = Date.parse(x);
        if (isNaN(dateY)) dateY = Date.parse(y);

        if(!isNaN(dateX) && !isNaN(dateY)){ x=dateX; y=dateY; }
        // Extra check: "Expired" value
        else if(x.startsWith("Expired") || y.startsWith("Expired")){
             var isXExpired = x.startsWith("Expired");
             var isYExpired = y.startsWith("Expired");
             
             if (isXExpired && !isYExpired) return table.asc ? -1 : 1; 
             if (!isXExpired && isYExpired) return table.asc ? 1 : -1; 
        }
        // Yes/No comparison
        else if((x.toLowerCase() == "yes" || x.toLowerCase() == "no") && (y.toLowerCase() == "yes" || y.toLowerCase() == "no")){
             x = (x.toLowerCase() == "yes") ? 1 : 0;
             y = (y.toLowerCase() == "yes") ? 1 : 0;
        }
        // Number comparison
        else if(!isNaN(parseFloat(x)) && !isNaN(parseFloat(y))){ x=parseFloat(x); y=parseFloat(y); }
        // Text comparison
        else { x=x.toLowerCase(); y=y.toLowerCase(); }

        if(x < y) return table.asc ? -1 : 1;
        if(x > y) return table.asc ? 1 : -1;
        return 0;
    });

    for(var i=0;i<rows.length;i++){ table.appendChild(rows[i]); }
}

function ipToNumber(ipText){
    var m = (ipText || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if(!m) return NaN;
    var a = parseInt(m[1],10), b = parseInt(m[2],10), c = parseInt(m[3],10), d = parseInt(m[4],10);
    return (((a * 256) + b) * 256 + c) * 256 + d;
}

function sortNetworkTableByIP(tableId, columnIndex){
    var table = document.getElementById(tableId);
    if(!table) return;
    var rows = Array.from(table.rows).slice(1);

    if(table.networkSortedColumn === columnIndex){
        table.networkAsc = !table.networkAsc;
    } else {
        table.networkAsc = true;
    }
    table.networkSortedColumn = columnIndex;

    rows.sort(function(a,b){
        var x = ipToNumber(a.cells[columnIndex].innerText);
        var y = ipToNumber(b.cells[columnIndex].innerText);

        if (isNaN(x) && isNaN(y)) return 0;
        if (isNaN(x)) return table.networkAsc ? 1 : -1;
        if (isNaN(y)) return table.networkAsc ? -1 : 1;
        if (x < y) return table.networkAsc ? -1 : 1;
        if (x > y) return table.networkAsc ? 1 : -1;
        return 0;
    });

    rows.forEach(function(row){ table.appendChild(row); });
}

function applyDefaultNetworkOrdering(){
    var table = document.getElementById('networkDiscoveryTable');
    if(!table) return;

    var rows = Array.from(table.rows).slice(1);
    rows.sort(function(a, b){
        var statusA = (a.cells[0] ? a.cells[0].innerText : '').trim().toLowerCase();
        var statusB = (b.cells[0] ? b.cells[0].innerText : '').trim().toLowerCase();

        var rankA = (statusA === 'up') ? 0 : 1;
        var rankB = (statusB === 'up') ? 0 : 1;
        if (rankA !== rankB) return rankA - rankB;

        var ipA = ipToNumber(a.cells[1] ? a.cells[1].innerText : '');
        var ipB = ipToNumber(b.cells[1] ? b.cells[1].innerText : '');

        if (isNaN(ipA) && isNaN(ipB)) return 0;
        if (isNaN(ipA)) return 1;
        if (isNaN(ipB)) return -1;
        return ipA - ipB;
    });

    rows.forEach(function(row){ table.appendChild(row); });
}

function sanitizeFileName(name){
    return name.replace(/[^a-z0-9\-_]+/gi, '_');
}

function exportTableToExcel(tableId, fileName){
    var table = document.getElementById(tableId);
    if(!table) return;

    function toUtf16LeBytes(str){
        var buffer = new ArrayBuffer(str.length * 2);
        var view = new DataView(buffer);
        for (var i = 0; i < str.length; i++) {
            view.setUint16(i * 2, str.charCodeAt(i), true);
        }
        return new Uint8Array(buffer);
    }

    var csv = [];
    var rows = table.querySelectorAll('tr');
    rows.forEach(function(row){
        var cols = row.querySelectorAll('th,td');
        var vals = [];
        cols.forEach(function(col){
            var text = (col.innerText || '').replace(/\r?\n|\r/g, ' ');
            vals.push('"' + text.replace(/"/g, '""') + '"');
        });
        csv.push(vals.join(';'));
    });

    // Use UTF-16LE + BOM + separator hint for reliable Turkish characters in Excel.
    var csvContent = 'sep=;\r\n' + csv.join('\r\n');
    var utf16Payload = toUtf16LeBytes('\uFEFF' + csvContent);
    var blob = new Blob([utf16Payload], { type: 'text/csv;charset=utf-16le;' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = sanitizeFileName(fileName) + '.csv';
    link.click();
    URL.revokeObjectURL(link.href);
}

function exportTableToWord(tableId, fileName){
    var table = document.getElementById(tableId);
    if(!table) return;

    var html = '<html><head><meta charset="utf-8"></head><body>' + table.outerHTML + '</body></html>';
    var blob = new Blob(['\ufeff', html], { type: 'application/msword' });
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = sanitizeFileName(fileName) + '.doc';
    link.click();
    URL.revokeObjectURL(link.href);
}

function exportTableToPdf(tableId, title){
    var table = document.getElementById(tableId);
    if(!table) return;

    var w = window.open('', '_blank');
    w.document.write('<html><head><title>' + title + '</title><style>body{font-family:Segoe UI,Arial,sans-serif;padding:16px;} table{border-collapse:collapse;width:100%;font-size:12px;} th,td{border:1px solid #999;padding:6px;text-align:left;} th{background:#eee;}</style></head><body>');
    w.document.write('<h2>' + title + '</h2>');
    w.document.write(table.outerHTML);
    w.document.write('</body></html>');
    w.document.close();
    w.focus();
    w.print();
}

function addExportButtonsToTables(){
    var tables = document.querySelectorAll('.container table.user-table');
    tables.forEach(function(table){
        if (!table.id) return;

        // Export buttons for PingCastle category tables are added server-side.
        if (table.id.indexOf('pingCastleCategory') === 0) return;

        var previous = table.previousElementSibling;
        if (previous && previous.classList && previous.classList.contains('export-actions')) return;

        var actions = document.createElement('div');
        actions.className = 'export-actions';

        var btnExcel = document.createElement('button');
        btnExcel.className = 'export-btn';
        btnExcel.innerText = 'Excel';
        btnExcel.onclick = function(){ exportTableToExcel(table.id, table.id); };

        var btnWord = document.createElement('button');
        btnWord.className = 'export-btn';
        btnWord.innerText = 'Word';
        btnWord.onclick = function(){ exportTableToWord(table.id, table.id); };

        var btnPdf = document.createElement('button');
        btnPdf.className = 'export-btn';
        btnPdf.innerText = 'PDF';
        btnPdf.onclick = function(){ exportTableToPdf(table.id, table.id); };

        actions.appendChild(btnExcel);
        actions.appendChild(btnWord);
        actions.appendChild(btnPdf);

        table.parentNode.insertBefore(actions, table);
    });
}

function focusPingCategory(tableId){
    showLoadingAndContent('pingCastleRisksContainer');
    setTimeout(function(){
        var table = document.getElementById(tableId);
        if(!table) return;
        table.scrollIntoView({ behavior: 'smooth', block: 'start' });
        table.classList.add('ping-focus-table');
        setTimeout(function(){ table.classList.remove('ping-focus-table'); }, 2200);
    }, 480);
}

function focusPingRule(ruleName){
    showLoadingAndContent('pingCastleRisksContainer');
    setTimeout(function(){
        var table = document.getElementById('pingCastleRiskTable');
        if(!table) return;

        var rows = Array.from(table.querySelectorAll('tr')).slice(1);
        var targetRow = null;
        rows.forEach(function(row){ row.classList.remove('ping-focus-row'); });

        for (var i = 0; i < rows.length; i++) {
            var ruleCell = rows[i].cells[2];
            if (ruleCell && ruleCell.innerText.trim() === ruleName) {
                targetRow = rows[i];
                break;
            }
        }

        if (targetRow) {
            targetRow.classList.add('ping-focus-row');
            targetRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
            setTimeout(function(){ targetRow.classList.remove('ping-focus-row'); }, 2500);
        }
    }, 480);
}

function applyBaselineDiffFilter(changeType){
    currentBaselineChangeFilter = changeType || 'all';
    var table = document.getElementById('pingBaselineDiffTable');
    if (!table) return;

    var searchEl = document.getElementById('baselineDiffSearch');
    var fieldEl = document.getElementById('baselineDiffField');
    var searchTerm = searchEl ? String(searchEl.value || '').toLowerCase().trim() : '';
    var fieldMode = fieldEl ? String(fieldEl.value || 'all') : 'all';

    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    var visible = 0;
    var newCount = 0;
    var changedCount = 0;
    var resolvedCount = 0;

    rows.forEach(function(row){
        var cells = row.cells;
        if (!cells || cells.length < 1) {
            row.style.display = '';
            return;
        }

        var isInfoRow = (cells.length === 1) && ((cells[0].colSpan || 1) > 1);
        if (isInfoRow) {
            row.style.display = (currentBaselineChangeFilter === 'all' && !searchTerm) ? '' : 'none';
            return;
        }

        var typeText = (cells[0].innerText || '').trim().toLowerCase();
        var typeMatch = (currentBaselineChangeFilter === 'all') || (typeText === currentBaselineChangeFilter);

        var haystack = '';
        if (fieldMode === 'rule') haystack = (cells[2] && cells[2].innerText) ? cells[2].innerText : '';
        else if (fieldMode === 'category') haystack = (cells[1] && cells[1].innerText) ? cells[1].innerText : '';
        else if (fieldMode === 'delta') haystack = (cells[7] && cells[7].innerText) ? cells[7].innerText : '';
        else if (fieldMode === 'action') haystack = (cells[8] && cells[8].innerText) ? cells[8].innerText : '';
        else haystack = row.innerText || '';

        var searchMatch = (!searchTerm) || (String(haystack).toLowerCase().indexOf(searchTerm) !== -1);
        var show = typeMatch && searchMatch;
        row.style.display = show ? '' : 'none';
        if (show) {
            visible++;
            if (typeText === 'new') newCount++;
            else if (typeText === 'changed') changedCount++;
            else if (typeText === 'resolved') resolvedCount++;
        }
    });

    var chips = Array.from(document.querySelectorAll('.baseline-focus-chip'));
    chips.forEach(function(chip){
        var mode = chip.getAttribute('data-mode') || 'all';
        if (mode === currentBaselineChangeFilter) chip.classList.add('active');
        else chip.classList.remove('active');
    });

    var cards = Array.from(document.querySelectorAll('.baseline-hero-card'));
    cards.forEach(function(card){
        var mode = card.getAttribute('data-mode') || 'all';
        if (mode === currentBaselineChangeFilter) card.classList.add('active');
        else card.classList.remove('active');
    });

    var totalCount = (currentBaselineChangeFilter === 'all') ? visible : (newCount + changedCount + resolvedCount);

    var newEl = document.getElementById('baselineCountNew');
    var changedEl = document.getElementById('baselineCountChanged');
    var resolvedEl = document.getElementById('baselineCountResolved');
    var totalEl = document.getElementById('baselineCountTotal');
    if (newEl) newEl.innerText = newCount;
    if (changedEl) changedEl.innerText = changedCount;
    if (resolvedEl) resolvedEl.innerText = resolvedCount;
    if (totalEl) totalEl.innerText = totalCount;

    var newPct = totalCount > 0 ? ((newCount * 100) / totalCount) : 0;
    var changedPct = totalCount > 0 ? ((changedCount * 100) / totalCount) : 0;
    var resolvedPct = totalCount > 0 ? ((resolvedCount * 100) / totalCount) : 0;

    var barNew = document.getElementById('baselineBarNew');
    var barChanged = document.getElementById('baselineBarChanged');
    var barResolved = document.getElementById('baselineBarResolved');
    if (barNew) barNew.style.width = newPct.toFixed(1) + '%';
    if (barChanged) barChanged.style.width = changedPct.toFixed(1) + '%';
    if (barResolved) barResolved.style.width = resolvedPct.toFixed(1) + '%';

    var pctNewEl = document.getElementById('baselinePctNew');
    var pctChangedEl = document.getElementById('baselinePctChanged');
    var pctResolvedEl = document.getElementById('baselinePctResolved');
    if (pctNewEl) pctNewEl.innerText = newPct.toFixed(1);
    if (pctChangedEl) pctChangedEl.innerText = changedPct.toFixed(1);
    if (pctResolvedEl) pctResolvedEl.innerText = resolvedPct.toFixed(1);

    var summary = document.getElementById('pingBaselineFilterSummary');
    if (summary) {
        var searchInfo = searchTerm ? (' | Search: ' + searchTerm) : '';
        summary.innerText = visible + ' rows listed | New ' + newCount + ' | Changed ' + changedCount + ' | Resolved ' + resolvedCount + searchInfo;
    }
}

function openRiskBaselineWithFilter(changeType){
    showLoadingAndContent('pingBaselineDiffContainer');
    setTimeout(function(){ applyBaselineDiffFilter(changeType || 'all'); }, 480);
}

function openUserRiskContainer(sectionKey){
    showLoadingAndContent('adUserRiskLevelContainer');
    setTimeout(function(){ showUserRiskSection(sectionKey || 'lockouts'); }, 480);
}

function showUserRiskSection(sectionKey){
    var sectionMap = {
        lockouts: 'userRiskSectionLockouts',
        failedUsers: 'userRiskSectionFailedUsers',
        failedSources: 'userRiskSectionFailedSources',
        spray: 'userRiskSectionSpray',
        privileged: 'userRiskSectionPrivileged',
        correlation: 'userRiskSectionCorrelation',
        userDevice: 'userRiskSectionUserDevice'
    };

    var cardMap = {
        lockouts: 'userRiskCardLockouts',
        failedUsers: 'userRiskCardFailedUsers',
        failedSources: 'userRiskCardFailedSources',
        spray: 'userRiskCardSpray',
        privileged: 'userRiskCardPrivileged',
        correlation: 'userRiskCardCorrelation',
        userDevice: 'userRiskCardUserDevice'
    };

    Object.keys(sectionMap).forEach(function(key){
        var sec = document.getElementById(sectionMap[key]);
        if (sec) { sec.style.display = (key === sectionKey ? 'block' : 'none'); }
    });

    Object.keys(cardMap).forEach(function(key){
        var card = document.getElementById(cardMap[key]);
        if (card) {
            if (key === sectionKey) { card.classList.add('active'); }
            else { card.classList.remove('active'); }
        }
    });

    if (sectionKey === 'lockouts') {
        if (!userRiskExplorerData || !userRiskExplorerData.length) {
            initUserRiskExplorer();
        }
        applyUserRiskFilters();
    } else if (sectionKey === 'failedUsers') {
        showAllFailedUsers();
    } else if (sectionKey === 'failedSources') {
        showAllFailedSources();
    } else if (sectionKey === 'spray') {
        showAllPasswordSprayCandidates();
    } else if (sectionKey === 'privileged') {
        showAllPrivilegedWatchlist();
    } else if (sectionKey === 'correlation') {
        showAllLockoutCorrelations();
    }
}

function applyPingRiskFocus(mode){
    currentRiskFocusMode = mode || 'all';
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;

    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    var visible = 0;

    rows.forEach(function(row){
        var cells = row.cells;
        if (!cells || cells.length < 2) {
            row.style.display = '';
            return;
        }

        var category = (cells[0].innerText || '').toLowerCase();
        var severity = (cells[1].innerText || '').toLowerCase();
        var show = true;

        if (mode === 'critical') {
            show = (severity === 'critical');
        } else if (mode === 'criticalhigh') {
            show = (severity === 'critical' || severity === 'high');
        } else if (mode === 'privileged') {
            show = (category.indexOf('privileged') !== -1 || category.indexOf('infrastructure') !== -1);
        } else if (mode === 'anomalies') {
            show = (category.indexOf('anomalies') !== -1);
        } else if (mode === 'hygiene') {
            show = (category.indexOf('hygiene') !== -1 || category.indexOf('stale') !== -1);
        }

        row.style.display = show ? '' : 'none';
        if (show) visible++;
    });

    var chips = Array.from(document.querySelectorAll('#pingRiskFocusBar .risk-focus-chip'));
    chips.forEach(function(chip){
        var chipMode = chip.getAttribute('data-mode') || 'all';
        if (chipMode === currentRiskFocusMode) chip.classList.add('active');
        else chip.classList.remove('active');
    });

    var summary = document.getElementById('pingRiskFocusSummary');
    if (summary) {
        var total = rows.length;
        summary.innerText = visible + ' of ' + total + ' findings listed';
    }
    updateHashFromState();
}

function parseRiskCountValue(text){
    var t = String(text || '').trim();
    var n = parseFloat(t.replace(/[^0-9.-]/g, ''));
    if (isNaN(n)) return 0;
    return n;
}

function getRiskTableRowsData(){
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return [];
    return Array.from(table.querySelectorAll('tr')).slice(1).map(function(row){
        var cells = row.cells || [];
        return {
            row: row,
            category: (cells[0] ? cells[0].innerText : '').trim(),
            severity: (cells[1] ? cells[1].innerText : '').trim(),
            rule: (cells[2] ? cells[2].innerText : '').trim(),
            count: parseRiskCountValue(cells[3] ? cells[3].innerText : '0')
        };
    });
}

function getCategoryPenaltyMapFromBreakdown(){
    var map = {};
    var rows = Array.from(document.querySelectorAll('.risk-breakdown-table tr')).slice(1);
    rows.forEach(function(r){
        var cells = r.cells || [];
        if (cells.length < 2) return;
        var category = (cells[0].innerText || '').trim();
        var penalty = parseRiskCountValue(cells[1].innerText || '0');
        if (category) map[category] = penalty;
    });
    return map;
}

function computeWeightedRiskScore(penaltyByCategory){
    var weightedSum = 0;
    var totalWeight = 0;
    Object.keys(riskCategoryWeightMap).forEach(function(category){
        var weight = riskCategoryWeightMap[category] || 0;
        var threshold = riskCategoryThresholdMap[category] || 100;
        var penalty = parseFloat(penaltyByCategory[category] || 0);
        var riskPct = Math.min(100, Math.max(0, (penalty / threshold) * 100));
        weightedSum += riskPct * weight;
        totalWeight += weight;
    });
    if (totalWeight <= 0) return 0;
    return Math.max(0, Math.min(100, Math.round(weightedSum / totalWeight)));
}

function riskRatingFromScore(score){
    if (score >= 80) return 'Critical';
    if (score >= 60) return 'Poor';
    if (score >= 40) return 'Acceptable';
    return 'Good';
}

function getCurrentRiskScoreFromGauge(){
    var node = document.querySelector('.risk-gauge-score');
    if (!node) return 0;
    var n = parseInt((node.innerText || '0').replace(/[^0-9-]/g, ''), 10);
    return isNaN(n) ? 0 : n;
}

function renderRiskImpactSimulator(){
    var host = document.getElementById('riskImpactSimulatorBody');
    if (!host) return;

    var rows = getRiskTableRowsData().filter(function(r){
        return r.count > 0 && (r.severity === 'Critical' || r.severity === 'High' || r.severity === 'Medium');
    });
    if (!rows.length) {
        host.innerHTML = '<p class="risk-model-note">No active Critical/High/Medium findings available for simulation.</p>';
        return;
    }

    var severityCounts = { Critical: 0, High: 0, Medium: 0 };
    rows.forEach(function(r){ if (severityCounts[r.severity] !== undefined) severityCounts[r.severity] += 1; });

    host.innerHTML = ''
        + '<div class="risk-sim-controls">'
        + '  <div class="risk-sim-control"><label>Close Critical Findings: <b id="simCriticalVal">0</b> / ' + severityCounts.Critical + '</label><input id="simCritical" type="range" min="0" max="' + severityCounts.Critical + '" value="0" oninput="updateRiskImpactSimulation()"></div>'
        + '  <div class="risk-sim-control"><label>Close High Findings: <b id="simHighVal">0</b> / ' + severityCounts.High + '</label><input id="simHigh" type="range" min="0" max="' + severityCounts.High + '" value="0" oninput="updateRiskImpactSimulation()"></div>'
        + '  <div class="risk-sim-control"><label>Close Medium Findings: <b id="simMediumVal">0</b> / ' + severityCounts.Medium + '</label><input id="simMedium" type="range" min="0" max="' + severityCounts.Medium + '" value="0" oninput="updateRiskImpactSimulation()"></div>'
        + '</div>'
        + '<div class="risk-sim-result" id="riskImpactResult">Simulation ready</div>';

    updateRiskImpactSimulation();
}

function updateRiskImpactSimulation(){
    var currentScore = getCurrentRiskScoreFromGauge();
    var rows = getRiskTableRowsData().filter(function(r){
        return r.count > 0 && (r.severity === 'Critical' || r.severity === 'High' || r.severity === 'Medium');
    });
    var penaltyByCategory = getCategoryPenaltyMapFromBreakdown();

    var closeCritical = parseInt((document.getElementById('simCritical') || {}).value || '0', 10) || 0;
    var closeHigh = parseInt((document.getElementById('simHigh') || {}).value || '0', 10) || 0;
    var closeMedium = parseInt((document.getElementById('simMedium') || {}).value || '0', 10) || 0;

    var vCritical = document.getElementById('simCriticalVal');
    var vHigh = document.getElementById('simHighVal');
    var vMedium = document.getElementById('simMediumVal');
    if (vCritical) vCritical.innerText = closeCritical;
    if (vHigh) vHigh.innerText = closeHigh;
    if (vMedium) vMedium.innerText = closeMedium;

    function applyCloseForSeverity(severity, closeCount){
        if (closeCount <= 0) return;
        var candidates = rows.filter(function(r){ return r.severity === severity; }).sort(function(a,b){
            var ca = parseRiskCountValue(penaltyByCategory[a.category] || 0);
            var cb = parseRiskCountValue(penaltyByCategory[b.category] || 0);
            return cb - ca;
        });
        var used = 0;
        for (var i = 0; i < candidates.length && used < closeCount; i++) {
            var c = candidates[i];
            if (penaltyByCategory[c.category] === undefined) penaltyByCategory[c.category] = 0;
            penaltyByCategory[c.category] = Math.max(0, parseFloat(penaltyByCategory[c.category]) - (riskSeverityWeightMap[severity] || 0));
            used += 1;
        }
    }

    applyCloseForSeverity('Critical', closeCritical);
    applyCloseForSeverity('High', closeHigh);
    applyCloseForSeverity('Medium', closeMedium);

    var projected = computeWeightedRiskScore(penaltyByCategory);
    var delta = currentScore - projected;
    var rating = riskRatingFromScore(projected);
    var result = document.getElementById('riskImpactResult');
    if (result) {
        result.innerHTML = 'Projected Score: <b>' + projected + '/100</b> (' + rating + ') | Improvement: <b>' + (delta >= 0 ? '-' + delta : '+' + Math.abs(delta)) + '</b>';
    }
}

function renderRiskContributionBreakdown(){
    var host = document.getElementById('riskContributionBody');
    if (!host) return;

    var penaltyByCategory = getCategoryPenaltyMapFromBreakdown();
    var scoreRawByCategory = {};
    var total = 0;

    Object.keys(riskCategoryWeightMap).forEach(function(category){
        var weight = riskCategoryWeightMap[category] || 0;
        var threshold = riskCategoryThresholdMap[category] || 100;
        var penalty = parseFloat(penaltyByCategory[category] || 0);
        var riskPct = Math.min(100, Math.max(0, (penalty / threshold) * 100));
        var contribution = (riskPct * weight) / 100;
        scoreRawByCategory[category] = contribution;
        total += contribution;
    });

    var html = '<div class="risk-contrib-list">';
    Object.keys(scoreRawByCategory)
        .sort(function(a,b){ return scoreRawByCategory[b] - scoreRawByCategory[a]; })
        .forEach(function(category){
            var value = scoreRawByCategory[category];
            var pct = total > 0 ? (value * 100 / total) : 0;
            html += '<div class="risk-contrib-row">'
                + '<div class="risk-contrib-head"><span>' + escapeHtml(category) + '</span><b>' + pct.toFixed(1) + '%</b></div>'
                + '<div class="risk-contrib-bar"><span style="width:' + pct.toFixed(1) + '%"></span></div>'
                + '</div>';
        });
    html += '</div>';

    var confLabel = (document.querySelector('.risk-confidence-chip') || {}).innerText || 'Confidence: -';
    var confNote = (document.querySelector('.risk-confidence-note') || {}).innerText || '';
    html += '<div class="risk-contrib-foot">' + escapeHtml(confLabel + ' | ' + confNote) + '</div>';
    host.innerHTML = html;
}

function loadRiskWatchlist(){
    try {
        var raw = localStorage.getItem('adcheck-risk-watchlist');
        riskWatchlistStore = raw ? JSON.parse(raw) : {};
    } catch (e) {
        riskWatchlistStore = {};
    }
}

function saveRiskWatchlist(){
    try { localStorage.setItem('adcheck-risk-watchlist', JSON.stringify(riskWatchlistStore)); } catch (e) {}
}

function buildWatchButtonHtml(active){
    var cls = active ? 'watch-btn active' : 'watch-btn';
    var txt = active ? 'Watching' : 'Watch';
    return '<button class="' + cls + '" onclick="toggleRiskWatch(this)">' + txt + '</button>';
}

function initRiskWatchlist(){
    loadRiskWatchlist();
    var table = document.getElementById('pingCastleRiskTable');
    if (!table) return;
    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    rows.forEach(function(row){
        if (!row.cells || row.cells.length < 9) return;
        var key = findingKeyFromRow(row);
        var watchCell = row.cells[8];
        watchCell.innerHTML = buildWatchButtonHtml(!!riskWatchlistStore[key]);
    });
    renderRiskWatchlistPanel();
}

function toggleRiskWatch(button){
    var row = button;
    while (row && row.tagName !== 'TR') row = row.parentElement;
    if (!row) return;

    var key = findingKeyFromRow(row);
    if (!key) return;
    if (riskWatchlistStore[key]) delete riskWatchlistStore[key];
    else riskWatchlistStore[key] = 1;

    saveRiskWatchlist();
    var watchCell = row.cells[8];
    if (watchCell) watchCell.innerHTML = buildWatchButtonHtml(!!riskWatchlistStore[key]);
    renderRiskWatchlistPanel();
}

function renderRiskWatchlistPanel(){
    var host = document.getElementById('riskWatchlistBody');
    var countNode = document.getElementById('riskWatchlistCount');
    if (!host) return;

    var rows = getRiskTableRowsData();
    var watched = rows.filter(function(r){ return riskWatchlistStore[r.category + '||' + r.rule]; });
    if (countNode) countNode.innerText = watched.length;

    if (!watched.length) {
        host.innerHTML = '<div class="risk-watch-empty">No watchlisted rule yet.</div>';
        return;
    }

    var html = '';
    watched.slice(0, 20).forEach(function(w){
        var safeRuleJs = String(w.rule || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
        html += '<div class="risk-watch-item">'
            + '<span class="risk-watch-sev">[' + escapeHtml(w.severity) + ']</span> '
            + '<span class="risk-watch-rule" onclick="focusPingRule(\'' + safeRuleJs + '\')">' + escapeHtml(w.rule) + '</span>'
            + '<span class="risk-watch-cat">' + escapeHtml(w.category) + '</span>'
            + '</div>';
    });
    host.innerHTML = html;
}

function renderDcHealthHeatmap(){
    var host = document.getElementById('dcHealthHeatmapBody');
    if (!host) return;
    var table = document.getElementById('dcHealthTable');
    if (!table) return;

    var rows = Array.from(table.querySelectorAll('tr')).slice(1);
    if (!rows.length) {
        host.innerHTML = '<div class="risk-watch-empty">No DC health row available.</div>';
        return;
    }

    function scoreRow(row){
        var dns = ((row.cells[8] ? row.cells[8].innerText : '') || '').toLowerCase();
        var repl = ((row.cells[9] ? row.cells[9].innerText : '') || '').toLowerCase();
        var sysvol = ((row.cells[3] ? row.cells[3].innerText : '') || '').toLowerCase();
        var score = 100;

        if (dns.indexOf('access error') >= 0) score -= 45;
        else if (dns.indexOf('error') >= 0) score -= 40;
        else if (dns.indexOf('ok') === -1) score -= 20;

        if (repl.indexOf('error') >= 0 || repl.indexOf('access error') >= 0) score -= 45;
        else if (repl.indexOf('warn') >= 0) score -= 20;

        if (sysvol.indexOf('frs') >= 0) score -= 20;
        return Math.max(0, Math.min(100, score));
    }

    function clsByScore(s){
        if (s >= 85) return 'dc-heat-good';
        if (s >= 65) return 'dc-heat-warn';
        return 'dc-heat-bad';
    }

    var html = '<div class="dc-heat-grid">';
    rows.forEach(function(row){
        var dcName = (row.cells[0] ? row.cells[0].innerText : '-').trim();
        var dns = (row.cells[8] ? row.cells[8].innerText : '-').trim();
        var repl = (row.cells[9] ? row.cells[9].innerText : '-').trim();
        var score = scoreRow(row);
        html += '<div class="dc-heat-card ' + clsByScore(score) + '">'
            + '<div class="dc-heat-head"><b>' + escapeHtml(dcName) + '</b><span>' + score + '/100</span></div>'
            + '<div class="dc-heat-meta">DNS: ' + escapeHtml(dns) + ' | Repl: ' + escapeHtml(repl) + '</div>'
            + '<div class="dc-heat-bar"><span style="width:' + score + '%"></span></div>'
            + '</div>';
    });
    html += '</div>';
    host.innerHTML = html;
}

function userRiskSafeText(value){
    return (value === null || value === undefined || value === '') ? '-' : String(value);
}

function userRiskNormalize(value){
    return userRiskSafeText(value).toLowerCase();
}

function userRiskQuery(value){
    if (value === null || value === undefined) return '';
    return String(value).trim().toLowerCase();
}

function userRiskEsc(text){
    return userRiskSafeText(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function userRiskStatusClass(status){
    var normalized = userRiskNormalize(status);
    if (normalized === 'failed') return 'user-risk-status user-risk-status-failed';
    if (normalized === 'success') return 'user-risk-status user-risk-status-success';
    return 'user-risk-status user-risk-status-locked';
}

function userRiskSetDatalist(listId, values){
    var node = document.getElementById(listId);
    if (!node) return;
    var html = '';
    var seen = {};
    (values || []).forEach(function(val){
        var text = userRiskSafeText(val);
        if (text === '-' || seen[text]) return;
        seen[text] = true;
        html += '<option value="' + text.replace(/"/g, '&quot;') + '"></option>';
    });
    node.innerHTML = html;
}

function initUserRiskExplorer(){
    var sourceRows = Array.isArray(UserRiskActivity) ? UserRiskActivity : (UserRiskActivity ? [UserRiskActivity] : []);
    userRiskExplorerData = sourceRows.map(function(row){
        return {
            TimeIso: userRiskSafeText(row.TimeIso),
            TimeDisplay: userRiskSafeText(row.TimeDisplay),
            Status: userRiskSafeText(row.Status),
            User: userRiskSafeText(row.User),
            SourceHost: userRiskSafeText(row.SourceHost),
            SourceIP: userRiskSafeText(row.SourceIP),
            DestinationHost: userRiskSafeText(row.DestinationHost),
            DestinationIP: userRiskSafeText(row.DestinationIP),
            LogonType: userRiskSafeText(row.LogonType),
            Reason: userRiskSafeText(row.Reason)
        };
    });

    userRiskSetDatalist('userRiskUsersList', userRiskExplorerData.map(function(r){ return r.User; }));
    userRiskSetDatalist('userRiskSourcesList', userRiskExplorerData.map(function(r){ return (r.SourceHost !== '-' ? r.SourceHost : r.SourceIP); }));
    userRiskSetDatalist('userRiskDestinationsList', userRiskExplorerData.map(function(r){ return (r.DestinationHost !== '-' ? r.DestinationHost : r.DestinationIP); }));
    renderUserRisk24hSummary();

    if (!userRiskDefaultPresetApplied) {
        userRiskDefaultPresetApplied = true;
        setUserRiskQuickPreset('failed24');
        return;
    }

    applyUserRiskFilters();
}

function renderUserRisk24hSummary(){
    var node = document.getElementById('userRisk24hSummary');
    if (!node) return;

    var nowMs = Date.now();
    var cutoff = nowMs - (24 * 3600000);
    var rows = userRiskExplorerData.filter(function(r){
        var t = Date.parse(r.TimeIso);
        return (!isNaN(t) && t >= cutoff);
    });

    var failed = 0, locked = 0, success = 0;
    var users = {};
    rows.forEach(function(r){
        var s = userRiskNormalize(r.Status);
        if (s === 'failed') failed += 1;
        else if (s === 'locked') locked += 1;
        else if (s === 'success') success += 1;
        users[userRiskSafeText(r.User)] = true;
    });

    var html = '';
    html += '<span class="user-risk-kpi-chip">24h Events <b>' + rows.length + '</b></span>';
    html += '<span class="user-risk-kpi-chip">Failed <b>' + failed + '</b></span>';
    html += '<span class="user-risk-kpi-chip">Locked <b>' + locked + '</b></span>';
    html += '<span class="user-risk-kpi-chip">Success <b>' + success + '</b></span>';
    html += '<span class="user-risk-kpi-chip">Distinct Users <b>' + Object.keys(users).length + '</b></span>';
    node.innerHTML = html;
}

function initUserRiskFailedDatasets(){
    var users = Array.isArray(UserRiskFailedByUserData) ? UserRiskFailedByUserData : (UserRiskFailedByUserData ? [UserRiskFailedByUserData] : []);
    userRiskFailedUsersData = users.map(function(row){
        return {
            TargetUser: userRiskSafeText(row.TargetUser),
            FailedCount: parseInt(row.FailedCount, 10) || 0,
            LastSeenIso: userRiskSafeText(row.LastSeenIso),
            LastSeenDisplay: userRiskSafeText(row.LastSeenDisplay),
            TopSources: userRiskSafeText(row.TopSources)
        };
    });

    var sources = Array.isArray(UserRiskFailedBySourceData) ? UserRiskFailedBySourceData : (UserRiskFailedBySourceData ? [UserRiskFailedBySourceData] : []);
    userRiskFailedSourcesData = sources.map(function(row){
        return {
            Source: userRiskSafeText(row.Source),
            FailedCount: parseInt(row.FailedCount, 10) || 0,
            LastSeenIso: userRiskSafeText(row.LastSeenIso),
            LastSeenDisplay: userRiskSafeText(row.LastSeenDisplay),
            TopUsers: userRiskSafeText(row.TopUsers)
        };
    });
}

function renderFailedUsersRows(rows){
    var tbody = document.getElementById('userRiskFailedByUserTbody');
    if (!tbody) return;

    if (!rows || !rows.length) {
        tbody.innerHTML = '<tr><td colspan="4">No failed logon event found for selected filters.</td></tr>';
        return;
    }

    var sorted = rows.slice().sort(function(a,b){
        var c = (parseInt(b.FailedCount, 10) || 0) - (parseInt(a.FailedCount, 10) || 0);
        if (c !== 0) return c;
        return Date.parse(b.LastSeenIso || '') - Date.parse(a.LastSeenIso || '');
    });

    var html = '';
    sorted.forEach(function(r){
        html += '<tr>' +
            '<td>' + userRiskEsc(r.TargetUser) + '</td>' +
            '<td>' + r.FailedCount + '</td>' +
            '<td>' + userRiskEsc(r.LastSeenDisplay) + '</td>' +
            '<td>' + userRiskEsc(r.TopSources) + '</td>' +
            '</tr>';
    });
    tbody.innerHTML = html;
}

function clearFailedUsersFilterInputs(){
    var ids = ['userRiskFailedUsersFilterUser', 'userRiskFailedUsersFilterSource', 'userRiskFailedUsersFilterMinCount', 'userRiskFailedUsersFilterHours'];
    ids.forEach(function(id){
        var node = document.getElementById(id);
        if (node) node.value = '';
    });
}

function showAllFailedUsers(){
    var summary = document.getElementById('userRiskFailedUsersFilterSummary');
    if (!userRiskFailedUsersData || !userRiskFailedUsersData.length) {
        initUserRiskFailedDatasets();
    }
    clearFailedUsersFilterInputs();
    renderFailedUsersRows(userRiskFailedUsersData);
    if (summary) summary.innerText = userRiskFailedUsersData.length + ' records listed';
}

function renderFailedSourcesRows(rows){
    var tbody = document.getElementById('userRiskFailedBySourceTbody');
    if (!tbody) return;

    if (!rows || !rows.length) {
        tbody.innerHTML = '<tr><td colspan="4">No failed source found for selected filters.</td></tr>';
        return;
    }

    var sorted = rows.slice().sort(function(a,b){
        var c = (parseInt(b.FailedCount, 10) || 0) - (parseInt(a.FailedCount, 10) || 0);
        if (c !== 0) return c;
        return Date.parse(b.LastSeenIso || '') - Date.parse(a.LastSeenIso || '');
    });

    var html = '';
    sorted.forEach(function(r){
        html += '<tr>' +
            '<td>' + userRiskEsc(r.Source) + '</td>' +
            '<td>' + r.FailedCount + '</td>' +
            '<td>' + userRiskEsc(r.LastSeenDisplay) + '</td>' +
            '<td>' + userRiskEsc(r.TopUsers) + '</td>' +
            '</tr>';
    });
    tbody.innerHTML = html;
}

function clearFailedSourcesFilterInputs(){
    var ids = ['userRiskFailedSourcesFilterSource', 'userRiskFailedSourcesFilterUser', 'userRiskFailedSourcesFilterMinCount', 'userRiskFailedSourcesFilterHours'];
    ids.forEach(function(id){
        var node = document.getElementById(id);
        if (node) node.value = '';
    });
}

function showAllFailedSources(){
    var summary = document.getElementById('userRiskFailedSourcesFilterSummary');
    if (!userRiskFailedSourcesData || !userRiskFailedSourcesData.length) {
        initUserRiskFailedDatasets();
    }
    clearFailedSourcesFilterInputs();
    renderFailedSourcesRows(userRiskFailedSourcesData);
    if (summary) summary.innerText = userRiskFailedSourcesData.length + ' records listed';
}

function showAllPasswordSprayCandidates(){
    return;
}

function showAllPrivilegedWatchlist(){
    return;
}

function showAllLockoutCorrelations(){
    return;
}

function applyUserRiskFilters(){
    var status = userRiskNormalize((document.getElementById('userRiskFilterStatus') || {}).value || 'all');
    var userQ = userRiskQuery((document.getElementById('userRiskFilterUser') || {}).value || '');
    var srcQ = userRiskQuery((document.getElementById('userRiskFilterSource') || {}).value || '');
    var dstQ = userRiskQuery((document.getElementById('userRiskFilterDestination') || {}).value || '');
    var hoursRaw = ((document.getElementById('userRiskFilterHours') || {}).value || '').trim();
    var nowMs = Date.now();
    var maxAgeMs = 0;

    if (hoursRaw !== '') {
        var hours = parseFloat(hoursRaw);
        if (!isNaN(hours) && hours > 0) {
            maxAgeMs = hours * 3600000;
        }
    }

    var filtered = userRiskExplorerData.filter(function(row){
        if (status !== 'all' && userRiskNormalize(row.Status) !== status) return false;
        if (userQ && userRiskNormalize(row.User).indexOf(userQ) === -1) return false;

        var srcCombined = userRiskNormalize(row.SourceHost + ' ' + row.SourceIP);
        if (srcQ && srcCombined.indexOf(srcQ) === -1) return false;

        var dstCombined = userRiskNormalize(row.DestinationHost + ' ' + row.DestinationIP);
        if (dstQ && dstCombined.indexOf(dstQ) === -1) return false;

        if (maxAgeMs > 0) {
            var eventMs = Date.parse(row.TimeIso);
            if (!isNaN(eventMs) && (nowMs - eventMs) > maxAgeMs) return false;
        }

        return true;
    });

    renderUserRiskExplorer(filtered);
    renderCompoundIncidents(filtered);
}

function renderUserRiskExplorer(rows){
    var tbody = document.getElementById('userRiskActivityTbody');
    var summary = document.getElementById('userRiskFilterSummary');
    if (!tbody) return;

    if (!rows || !rows.length) {
        tbody.innerHTML = '<tr><td colspan="10">No activity found for selected filters.</td></tr>';
        if (summary) { summary.innerText = '0 records listed'; }
        return;
    }

    var html = '';
    rows.forEach(function(row){
        var userSafe = userRiskEsc(row.User);
        html += '<tr>' +
            '<td>' + userRiskEsc(row.TimeDisplay) + '</td>' +
            '<td><span class="' + userRiskStatusClass(row.Status) + '">' + userRiskEsc(row.Status) + '</span></td>' +
            '<td><span class="user-risk-user-link" onclick="openUserRiskProfile(\'' + userSafe + '\')">' + userSafe + '</span></td>' +
            '<td>' + userRiskEsc(row.SourceHost) + '</td>' +
            '<td>' + userRiskEsc(row.SourceIP) + '</td>' +
            '<td>' + userRiskEsc(row.DestinationHost) + '</td>' +
            '<td>' + userRiskEsc(row.DestinationIP) + '</td>' +
            '<td>' + userRiskEsc(row.LogonType) + '</td>' +
            '<td>' + userRiskEsc(row.Reason) + '</td>' +
            '<td>' + userRiskEsc(row.SourceHost) + ' -> ' + userRiskEsc(row.DestinationHost) + '</td>' +
            '</tr>';
    });

    tbody.innerHTML = html;
    if (summary) {
        summary.innerText = rows.length + ' records listed';
    }
}

function setUserRiskQuickPreset(mode){
    resetUserRiskFilters();

    var statusEl = document.getElementById('userRiskFilterStatus');
    var hoursEl = document.getElementById('userRiskFilterHours');
    var sourceEl = document.getElementById('userRiskFilterSource');

    if (mode === 'lockout24') {
        if (statusEl) statusEl.value = 'locked';
        if (hoursEl) hoursEl.value = '24';
    } else if (mode === 'failed24') {
        if (statusEl) statusEl.value = 'failed';
        if (hoursEl) hoursEl.value = '24';
    } else if (mode === 'bruteforce') {
        if (statusEl) statusEl.value = 'failed';
        if (hoursEl) hoursEl.value = '6';
    } else if (mode === 'dcfocus') {
        if (statusEl) statusEl.value = 'all';
        if (hoursEl) hoursEl.value = '24';
        if (sourceEl) sourceEl.value = 'kbdc';
    }

    applyUserRiskFilters();
}

function renderCompoundIncidents(rows){
    var tbody = document.getElementById('userRiskIncidentTbody');
    var summary = document.getElementById('userRiskIncidentSummary');
    if (!tbody || !Array.isArray(rows)) return;

    var grouped = {};
    rows.forEach(function(r){
        var user = userRiskSafeText(r.User);
        if (!grouped[user]) {
            grouped[user] = { User: user, Failed: 0, Locked: 0, Success: 0, Sources: {}, LastTime: '-' };
        }
        var g = grouped[user];
        var s = userRiskNormalize(r.Status);
        if (s === 'failed') g.Failed += 1;
        else if (s === 'locked') g.Locked += 1;
        else if (s === 'success') g.Success += 1;

        var src = userRiskSafeText(r.SourceHost);
        if (src !== '-') g.Sources[src] = true;
        if (g.LastTime === '-' || Date.parse(r.TimeIso) > Date.parse(g.LastTimeIso || '1970-01-01')) {
            g.LastTime = userRiskSafeText(r.TimeDisplay);
            g.LastTimeIso = userRiskSafeText(r.TimeIso);
        }
    });

    var incidents = Object.keys(grouped).map(function(k){
        var g = grouped[k];
        var sourceCount = Object.keys(g.Sources).length;
        var score = (g.Failed * 2) + (g.Locked * 5) + (sourceCount >= 3 ? 3 : 0);
        return {
            User: g.User,
            Failed: g.Failed,
            Locked: g.Locked,
            Success: g.Success,
            DistinctSources: sourceCount,
            LastTime: g.LastTime,
            Score: score
        };
    }).filter(function(x){ return x.Failed > 0 || x.Locked > 0; })
      .sort(function(a,b){ return b.Score - a.Score; })
      .slice(0, 12);

    if (!incidents.length) {
        tbody.innerHTML = '<tr><td colspan="7">No compound incident candidate for selected filters.</td></tr>';
        if (summary) summary.innerText = '0 incident candidate';
        return;
    }

    var html = '';
    incidents.forEach(function(i){
        var userSafe = userRiskEsc(i.User);
        html += '<tr>' +
            '<td><span class="user-risk-user-link" onclick="openUserRiskProfile(\'' + userSafe + '\')">' + userSafe + '</span></td>' +
            '<td>' + i.Failed + '</td>' +
            '<td>' + i.Locked + '</td>' +
            '<td>' + i.Success + '</td>' +
            '<td>' + i.DistinctSources + '</td>' +
            '<td>' + userRiskEsc(i.LastTime) + '</td>' +
            '<td>' + i.Score + '</td>' +
            '</tr>';
    });

    tbody.innerHTML = html;
    if (summary) summary.innerText = incidents.length + ' incident candidate';
}

function openUserRiskProfile(userName){
    var panel = document.getElementById('userRiskProfilePanel');
    var title = document.getElementById('userRiskProfileTitle');
    var meta = document.getElementById('userRiskProfileMeta');
    var timeline = document.getElementById('userRiskProfileTimeline');
    if (!panel || !title || !meta || !timeline) return;

    var normalized = userRiskNormalize(userName);
    var rows = userRiskExplorerData.filter(function(r){ return userRiskNormalize(r.User) === normalized; });

    if (!rows.length) {
        panel.style.display = 'none';
        return;
    }

    var failed = 0, locked = 0, success = 0;
    var srcMap = {}, dstMap = {};
    var lastSeen = '-';
    var lastIso = '1970-01-01T00:00:00Z';

    rows.forEach(function(r){
        var s = userRiskNormalize(r.Status);
        if (s === 'failed') failed += 1;
        else if (s === 'locked') locked += 1;
        else if (s === 'success') success += 1;

        if (r.SourceHost && r.SourceHost !== '-') srcMap[r.SourceHost] = (srcMap[r.SourceHost] || 0) + 1;
        if (r.DestinationHost && r.DestinationHost !== '-') dstMap[r.DestinationHost] = (dstMap[r.DestinationHost] || 0) + 1;

        if (Date.parse(r.TimeIso) > Date.parse(lastIso)) {
            lastIso = r.TimeIso;
            lastSeen = r.TimeDisplay;
        }
    });

    function topKey(obj){
        var keys = Object.keys(obj);
        if (!keys.length) return '-';
        keys.sort(function(a,b){ return obj[b] - obj[a]; });
        return keys[0] + ' (' + obj[keys[0]] + ')';
    }

    title.innerText = 'User Profile: ' + userRiskSafeText(userName);
    meta.innerHTML =
        '<div><b>Failed</b><br>' + failed + '</div>' +
        '<div><b>Locked</b><br>' + locked + '</div>' +
        '<div><b>Success</b><br>' + success + '</div>' +
        '<div><b>Last Seen</b><br>' + userRiskEsc(lastSeen) + '</div>' +
        '<div><b>Top Source</b><br>' + userRiskEsc(topKey(srcMap)) + '</div>' +
        '<div><b>Top Destination</b><br>' + userRiskEsc(topKey(dstMap)) + '</div>';

    var recentRows = rows
        .slice()
        .sort(function(a,b){ return Date.parse(b.TimeIso) - Date.parse(a.TimeIso); })
        .slice(0, 20);

    if (!recentRows.length) {
        timeline.innerHTML = '<div class="user-risk-timeline-row"><div class="user-risk-timeline-time">-</div><div>-</div><div class="user-risk-timeline-path">No timeline entry</div></div>';
    } else {
        var timelineHtml = '';
        recentRows.forEach(function(r){
            timelineHtml += '<div class="user-risk-timeline-row">' +
                '<div class="user-risk-timeline-time">' + userRiskEsc(r.TimeDisplay) + '</div>' +
                '<div><span class="' + userRiskStatusClass(r.Status) + '">' + userRiskEsc(r.Status) + '</span></div>' +
                '<div class="user-risk-timeline-path">' + userRiskEsc(r.SourceHost) + ' (' + userRiskEsc(r.SourceIP) + ') -> ' + userRiskEsc(r.DestinationHost) + ' (' + userRiskEsc(r.DestinationIP) + ')</div>' +
                '</div>';
        });
        timeline.innerHTML = timelineHtml;
    }

    panel.style.display = 'block';
}

function resetUserRiskFilters(){
    var fields = ['userRiskFilterStatus', 'userRiskFilterUser', 'userRiskFilterSource', 'userRiskFilterDestination', 'userRiskFilterHours'];
    fields.forEach(function(id){
        var node = document.getElementById(id);
        if (!node) return;
        node.value = (id === 'userRiskFilterStatus') ? 'all' : '';
    });
    applyUserRiskFilters();
}

function userRiskParseDisplayDate(text){
    var value = userRiskSafeText(text).trim();
    if (value === '-' || value === '') return NaN;

    var m = value.match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?$/);
    if (!m) return Date.parse(value);

    var day = parseInt(m[1], 10);
    var month = parseInt(m[2], 10) - 1;
    var year = parseInt(m[3], 10);
    var hour = m[4] ? parseInt(m[4], 10) : 0;
    var minute = m[5] ? parseInt(m[5], 10) : 0;
    var second = m[6] ? parseInt(m[6], 10) : 0;
    return new Date(year, month, day, hour, minute, second, 0).getTime();
}

function applyFailedUsersFilters(){
    var summary = document.getElementById('userRiskFailedUsersFilterSummary');
    if (!userRiskFailedUsersData || !userRiskFailedUsersData.length) {
        initUserRiskFailedDatasets();
    }

    var userQ = userRiskQuery((document.getElementById('userRiskFailedUsersFilterUser') || {}).value || '');
    var sourceQ = userRiskQuery((document.getElementById('userRiskFailedUsersFilterSource') || {}).value || '');
    var minCountRaw = ((document.getElementById('userRiskFailedUsersFilterMinCount') || {}).value || '').trim();
    var hoursRaw = ((document.getElementById('userRiskFailedUsersFilterHours') || {}).value || '').trim();

    var minCount = parseInt(minCountRaw, 10);
    if (isNaN(minCount) || minCount < 1) minCount = 0;

    var maxAgeMs = 0;
    if (hoursRaw !== '') {
        var h = parseFloat(hoursRaw);
        if (!isNaN(h) && h > 0) maxAgeMs = h * 3600000;
    }

    var nowMs = Date.now();
    var filtered = userRiskFailedUsersData.filter(function(item){
        var user = userRiskNormalize(item.TargetUser);
        var sources = userRiskNormalize(item.TopSources);
        var count = parseInt(item.FailedCount, 10);
        var lastSeenMs = Date.parse(item.LastSeenIso);
        if (isNaN(lastSeenMs)) lastSeenMs = userRiskParseDisplayDate(item.LastSeenDisplay);

        if (userQ && user.indexOf(userQ) === -1) return false;
        if (sourceQ && sources.indexOf(sourceQ) === -1) return false;
        if (minCount > 0 && (isNaN(count) || count < minCount)) return false;
        if (maxAgeMs > 0 && !isNaN(lastSeenMs) && ((nowMs - lastSeenMs) > maxAgeMs)) return false;
        return true;
    });

    renderFailedUsersRows(filtered);

    if (summary) summary.innerText = filtered.length + ' records listed';
}

function resetFailedUsersFilters(){
    showAllFailedUsers();
}

function applyFailedSourcesFilters(){
    var summary = document.getElementById('userRiskFailedSourcesFilterSummary');
    if (!userRiskFailedSourcesData || !userRiskFailedSourcesData.length) {
        initUserRiskFailedDatasets();
    }

    var sourceQ = userRiskQuery((document.getElementById('userRiskFailedSourcesFilterSource') || {}).value || '');
    var userQ = userRiskQuery((document.getElementById('userRiskFailedSourcesFilterUser') || {}).value || '');
    var minCountRaw = ((document.getElementById('userRiskFailedSourcesFilterMinCount') || {}).value || '').trim();
    var hoursRaw = ((document.getElementById('userRiskFailedSourcesFilterHours') || {}).value || '').trim();

    var minCount = parseInt(minCountRaw, 10);
    if (isNaN(minCount) || minCount < 1) minCount = 0;

    var maxAgeMs = 0;
    if (hoursRaw !== '') {
        var h = parseFloat(hoursRaw);
        if (!isNaN(h) && h > 0) maxAgeMs = h * 3600000;
    }

    var nowMs = Date.now();
    var filtered = userRiskFailedSourcesData.filter(function(item){
        var source = userRiskNormalize(item.Source);
        var users = userRiskNormalize(item.TopUsers);
        var count = parseInt(item.FailedCount, 10);
        var lastSeenMs = Date.parse(item.LastSeenIso);
        if (isNaN(lastSeenMs)) lastSeenMs = userRiskParseDisplayDate(item.LastSeenDisplay);

        if (sourceQ && source.indexOf(sourceQ) === -1) return false;
        if (userQ && users.indexOf(userQ) === -1) return false;
        if (minCount > 0 && (isNaN(count) || count < minCount)) return false;
        if (maxAgeMs > 0 && !isNaN(lastSeenMs) && ((nowMs - lastSeenMs) > maxAgeMs)) return false;
        return true;
    });

    renderFailedSourcesRows(filtered);

    if (summary) summary.innerText = filtered.length + ' records listed';
}

function resetFailedSourcesFilters(){
    showAllFailedSources();
}

function hideAllContainers(){
    var containers=document.getElementsByClassName('container');
    for(var i=0;i<containers.length;i++){
        containers[i].style.display='none';
    }
} 
// LOADING OVERLAY FUNCTION
function showLoadingAndContent(id){
    try {
        var overlay = document.getElementById('loadingOverlay');
        var target = document.getElementById(id);
        if (!target) return;

        if (!overlay) {
            hideAllContainers();
            target.style.display = 'flex';
            currentContainerId = id;
            if (id === 'ouTreeContainer') { setTimeout(initOUTree, 80); }
            updateHashFromState();
            return;
        }

        overlay.style.display = 'flex';
        setTimeout(function(){
            try { overlay.classList.add('visible'); } catch (e) {}
        }, 10);

        hideAllContainers();

        setTimeout(function(){
            var newContainer = document.getElementById(id);
            if (newContainer) {
                newContainer.style.display = 'flex';
                currentContainerId = id;
            }
            if (id === 'ouTreeContainer') { setTimeout(initOUTree, 100); }

            try { overlay.classList.remove('visible'); } catch (e) {}
            setTimeout(function(){
                try { overlay.style.display = 'none'; } catch (e) {}
            }, 300);

            updateHashFromState();
        }, 400);
    } catch (e) {
        hideAllContainers();
        var fallback = document.getElementById(id) || document.getElementById('pingCastleRisksContainer');
        if (fallback) {
            fallback.style.display = 'flex';
            currentContainerId = fallback.id;
        }
    }
}

function toggleSubMenu(menuId, targetId){
    var menu = document.getElementById(menuId);
    if (menu.style.display === 'flex') {
        menu.style.display = 'none';
    } else {
        // Hide all submenus
        var subMenus = document.getElementsByClassName('sub-buttons');
        for (var i = 0; i < subMenus.length; i++) {
            if (subMenus[i].id !== menuId) {
                subMenus[i].style.display = 'none';
            }
        }
        menu.style.display = 'flex';
        // Load default sub-container when submenu opens
        if (targetId) {
            showLoadingAndContent(targetId); 
        }
    }
}

document.addEventListener('DOMContentLoaded', function(){
    var mainButtons = document.querySelectorAll('.side-menu .main-btn');
    for (var i = 0; i < mainButtons.length; i++) {
        mainButtons[i].addEventListener('click', function(){
            for (var j = 0; j < mainButtons.length; j++) {
                mainButtons[j].classList.remove('active-sidebar');
            }
            this.classList.add('active-sidebar');
        });
    }
    var anyVisible = document.querySelector('.container[style*="display: flex"], .container[style*="display:flex"]');
    if (!anyVisible) {
        var fallbackContainer = document.getElementById('pingCastleRisksContainer');
        if (fallbackContainer) {
            fallbackContainer.style.display = 'flex';
            currentContainerId = 'pingCastleRisksContainer';
        }
    }
});

function resolveLogoPath(){
    var logoCandidates = ['tools/kuso_logo.png', 'kuso_logo.png', '../tools/kuso_logo.png'];
    var headerLogo = document.getElementById('headerLogo');
    var loadingLogo = document.querySelector('.loading-logo');

    function tryNext(index){
        if (index >= logoCandidates.length) {
            if (headerLogo) headerLogo.style.display = 'none';
            if (loadingLogo) loadingLogo.style.display = 'none';
            return;
        }

        var probe = new Image();
        probe.onload = function(){
            var selected = logoCandidates[index];
            if (headerLogo) headerLogo.src = selected;
            if (loadingLogo) loadingLogo.style.backgroundImage = "url('" + selected + "')";
        };
        probe.onerror = function(){
            tryNext(index + 1);
        };
        probe.src = logoCandidates[index];
    }

    tryNext(0);
}

function fitSidebarToViewport(){
    var sideMenu = document.querySelector('.side-menu');
    if (!sideMenu) return;

    if (window.innerWidth <= 900) {
        sideMenu.style.maxHeight = 'none';
        return;
    }

    var rect = sideMenu.getBoundingClientRect();
    var marginBottom = 12;
    var available = Math.floor(window.innerHeight - rect.top - marginBottom);
    if (available < 260) available = 260;
    sideMenu.style.maxHeight = available + 'px';
}
// Show first tab at startup
window.onload = function() {
    document.body.classList.add('sneat-cyber');
    document.body.classList.add('compact-mode');

    // Fail-safe: always show a default container first.
    try {
        var landing = document.getElementById('pingCastleRisksContainer');
        if (landing) {
            landing.style.display = 'flex';
            currentContainerId = 'pingCastleRisksContainer';
        }
    } catch (e) {
        console.error('Landing container init error:', e);
    }

    function safeInit(fn){
        try { fn(); } catch (e) { console.error('Init step failed:', e); }
    }

    if (window.mermaid) {
        mermaid.initialize({ startOnLoad: true, securityLevel: 'loose' });
    }

    safeInit(resolveLogoPath);
    safeInit(fitSidebarToViewport);
    safeInit(addExportButtonsToTables);
    safeInit(applyDefaultNetworkOrdering);
    safeInit(initUserRiskExplorer);
    safeInit(buildAttackChainGraph);
    safeInit(renderMitreHeatmap);
    safeInit(renderThreatPriorityQueue);
    safeInit(renderCaRiskLens);
    safeInit(initRemediationTracking);
    safeInit(initChangeApprovalGate);
    safeInit(function(){ applyPingRiskFocus('all'); });
    safeInit(renderRiskImpactSimulator);
    safeInit(renderRiskContributionBreakdown);
    safeInit(initRiskWatchlist);
    safeInit(renderDcHealthHeatmap);

    var state = readHashState();
    var storedLang = 'en';
    try { storedLang = localStorage.getItem('adcheck-lang') || 'en'; } catch (e) {}

window.addEventListener('resize', fitSidebarToViewport);
    if (state) {
        if (state.c && document.getElementById(state.c)) {
            hideAllContainers();
            document.getElementById(state.c).style.display = 'flex';
            currentContainerId = state.c;
        }
        if (state.rf) applyPingRiskFocus(state.rf);
        if (state.tf) filterRemediationStatus(state.tf);
        if (state.lg) storedLang = state.lg;
    }
    applyLanguage(storedLang);
    updateHashFromState();
};
</script>
</head>
<body>
<div id="loadingOverlay">
    <div class="loading-logo"></div>
</div>
<div class='header-frame'>
    <img id='headerLogo' src='tools/kuso_logo.png' class='logo' alt='Kuso Logo'>
    <div>
        <h1 data-i18n-key='header.title'>Active Directory Overview</h1>
        <h3>Domain: $Domain</h3>
    </div>
</div>

<div class='layout'>
<div class='side-panel side-menu'>
<div class='side-panel-controls'>
<button class='panel-toggle-btn' id='langToggleBtn' onclick='toggleLanguage()' title='Türkçeye geç'>TR</button>
<button class='panel-toggle-btn' onclick='copyPermalinkState()' data-i18n-key='nav.copyPermalink'>Copy Permalink</button>
</div>
<button class='main-btn active-sidebar' onclick='showLoadingAndContent("pingCastleRisksContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-chart-line'></i><span class='main-btn-label' data-i18n-key='nav.adRiskDashboard'>AD Risk Dashboard</span></span><span class='main-btn-badge'>$($PingCastleFindings.Count)</span></button>
<button class='main-btn' onclick='showLoadingAndContent("pingBaselineDiffContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-code-compare'></i><span class='main-btn-label' data-i18n-key='nav.riskBaselineDiff'>Risk Baseline Diff</span></span><span class='main-btn-badge'>$($PingBaselineSummary.TotalDifferences)</span></button>
<button class='main-btn' onclick='openUserRiskContainer("lockouts")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-user-shield'></i><span class='main-btn-label' data-i18n-key='nav.userRiskLevel'>AD User Risk Level</span></span><span class='main-btn-badge'>$UserRiskAlertCount</span></button>
<button class='main-btn' onclick='toggleSubMenu("osSubMenu", "serverOsContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-brands fa-windows'></i><span class='main-btn-label' data-i18n-key='nav.windowsOverview'>Windows OS Overview</span></span><span class='main-btn-badge'>$($TotalServer + $TotalClient)</span></button>
<div class='sub-buttons' id='osSubMenu'>
    <button class='sub-btn' onclick='showLoadingAndContent("serverOsContainer")'>Windows Server OS ($TotalServer)</button>
    <button class='sub-btn' onclick='showLoadingAndContent("clientOsContainer")'>Windows Client OS ($TotalClient)</button>
</div>
<button class='main-btn' onclick='toggleSubMenu("userSubMenu", "allUserContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-users'></i><span class='main-btn-label' data-i18n-key='nav.adUsersOverview'>AD Users Overview</span></span><span class='main-btn-badge'>$($Users.Count)</span></button>
<div class='sub-buttons' id='userSubMenu'>
    <button class='sub-btn' onclick='showLoadingAndContent("allUserContainer")'>All Users ($($UserFilters.AllUsers.Count))</button>
    <button class='sub-btn' onclick='showLoadingAndContent("neverExpiresContainer")'>Password Never Expires ($($UserFilters.NeverExpiresUsers.Count))</button>
    <button class='sub-btn' onclick='showLoadingAndContent("domainAdminContainer")'>Domain Admins ($($UserFilters.DomainAdminsUsers.Count))</button>
    <button class='sub-btn' onclick='showLoadingAndContent("schemaAdminContainer")'>Schema Admins ($($UserFilters.SchemaAdminsUsers.Count))</button>
    <button class='sub-btn' onclick='showLoadingAndContent("enterpriseAdminContainer")'>Enterprise Admins ($($UserFilters.EnterpriseAdminsUsers.Count))</button>
    <button class='sub-btn' onclick='showLoadingAndContent("disabledUserContainer")'>Disabled Users ($($UserFilters.DisabledUsers.Count))</button>
</div>
<button class='main-btn' onclick='toggleSubMenu("groupsSubMenu", "securityGroupsContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-shield-halved'></i><span class='main-btn-label' data-i18n-key='nav.groupsSecurity'>Groups & Security</span></span><span class='main-btn-badge'>$($AllGroups.Count)</span></button>
<div class='sub-buttons' id='groupsSubMenu'>
    <button class='sub-btn' onclick='showLoadingAndContent("securityGroupsContainer")'>Security Groups ($($SecurityGroups.Count))</button>
    <button class='sub-btn' onclick='showLoadingAndContent("distributionGroupsContainer")'>Distribution Groups ($($DistributionGroups.Count))</button>
</div>
<button class='main-btn' onclick='showLoadingAndContent("siteTopologyContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-network-wired'></i><span class='main-btn-label' data-i18n-key='nav.adSitesTopology'>AD Sites & Topology</span></span><span class='main-btn-badge'>$(@($SiteData.Keys).Count)</span></button>
<button class='main-btn' onclick='showLoadingAndContent("ouTreeContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-sitemap'></i><span class='main-btn-label'>AD Structure & Tier Advisor</span></span><span class='main-btn-badge'>$($OUTreeData.Count)</span></button>
<button class='main-btn' onclick='toggleSubMenu("inactiveSubMenu", "inactiveUsersContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-trash-can'></i><span class='main-btn-label' data-i18n-key='nav.inactiveObjects'>Inactive Objects</span></span><span class='main-btn-badge'>$($InactiveUsers.Count + $InactiveComputers.Count)</span></button>
<div class='sub-buttons' id='inactiveSubMenu'>
    <button class='sub-btn' onclick='showLoadingAndContent("inactiveUsersContainer")'>Inactive Users ($($InactiveUsers.Count))</button>
    <button class='sub-btn' onclick='showLoadingAndContent("inactiveComputersContainer")'>Inactive Computers ($($InactiveComputers.Count))</button>
</div>

<button class='main-btn' onclick='showLoadingAndContent("dcHealthContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-server'></i><span class='main-btn-label' data-i18n-key='nav.dcHealthFsmo'>DC Health & FSMO</span></span><span class='main-btn-badge'>$($DCHealth.Count)</span></button>

<button class='main-btn' onclick='showLoadingAndContent("exchangeContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-cloud'></i><span class='main-btn-label' data-i18n-key='nav.exchangeUsers'>Exchange/O365 Users</span></span><span class='main-btn-badge'>$(@($ExchangeUsers).Count)</span></button>
<button class='main-btn' onclick='showLoadingAndContent("lockedAccountsContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-lock'></i><span class='main-btn-label' data-i18n-key='nav.lockedAccounts'>Locked Accounts</span></span><span class='main-btn-badge'>-</span></button>
<button class='main-btn' onclick='showLoadingAndContent("pwdExpiryContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-key'></i><span class='main-btn-label' data-i18n-key='nav.passwordExpiry'>Password Expiry</span></span><span class='main-btn-badge'>-</span></button>
<button class='main-btn' onclick='showLoadingAndContent("skippedDcsContainer")'><span class='main-btn-content'><i class='main-btn-icon fa-solid fa-database'></i><span class='main-btn-label' data-i18n-key='nav.skippedDcs'>Skipped / Unreachable DCs</span></span><span class='main-btn-badge main-btn-badge-critical'>$(@($SkippedDCs).Count)</span></button>
</div>
<div class='main-panel'>
"@

# ---------------------
# Windows Server Container (Shortened)
# ---------------------
$ServerNodes = @()
foreach ($k in $ServerCategories.Keys) {
    if ($ServerCategories[$k]) { $ServerNodes += @($ServerCategories[$k]) }
}
$ServerTotalNodes = @($ServerNodes).Count
$ServerActive30Count = @($ServerNodes | Where-Object { $_.LastLogonTimestamp -and $_.LastLogonTimestamp -ge (Get-Date).AddDays(-30).ToFileTimeUtc() }).Count
$ServerLegacyCount = @($ServerNodes | Where-Object { [string]$_.OperatingSystem -match '2008|2012|2016' }).Count

$Html += "<div class='container' id='serverOsContainer'><div class='content-card'>"
$Html += "<h2>Windows Server OS Overview</h2>"
$Html += "<p class='section-intro'>Server fleet breakdown with activity and legacy footprint indicators.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Total Servers</div><div class='section-stat-value'>$ServerTotalNodes</div><div class='section-stat-note'>Inventory in scope</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Active in 30 Days</div><div class='section-stat-value'>$ServerActive30Count</div><div class='section-stat-note'>Recent logon timestamp</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Legacy OS</div><div class='section-stat-value'>$ServerLegacyCount</div><div class='section-stat-note'>Server 2016 and older</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Unknown Class</div><div class='section-stat-value'>$TotalUnknownCount</div><div class='section-stat-note'>Undetermined server/client</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Review legacy and unknown nodes for modernization and hardening.</span></div><div class='os-grid'>" 
$serverKeys = $ServerCategories.Keys | Sort-Object -Descending { 
    if ($_ -match 'Server (\d{4})') { [int]$matches[1] } 
    else { 1 }
}
foreach ($key in $serverKeys) {
    $cat = @{Key=$key; Value=$ServerCategories[$key]}
    if ($cat.Value.Count -eq 0) { continue }
    
    $Html += "<div class='content-card'><h2>$($cat.Key) ($($cat.Value.Count))</h2><div class='table-wrapper'>"
    
    $Html += "<table class='user-table' id='osTable$($cat.Key -replace '\s','_')'><tr><th onclick='sortTable(`"osTable$($cat.Key -replace '\s','_')`",0)'>Hostname</th><th onclick='sortTable(`"osTable$($cat.Key -replace '\s','_')`",1)'>Last Logon</th></tr>"
    foreach ($pc in $cat.Value | Sort Name) {
        $LastLogon = Convert-ADTimestamp $pc.LastLogonTimestamp
        $Html += "<tr><td>$($pc.Name)</td><td>$LastLogon</td></tr>"
    }
    $Html += "</table></div></div>"
}
$Html += "</div>" # os-grid closed

# Unknown entries (UnknownTotal) are shown in this section
if ($TotalUnknownCount -gt 0) {
    $Html += "<h2 class='os-section-header'>Completely Unknown (Server/Client Undetermined)</h2><div class='os-grid'>" 
    
    $Html += "<div class='content-card'><h2>Unknown ($TotalUnknownCount)</h2><div class='table-wrapper'>"
    
    $Html += "<table class='user-table' id='osTableUnknownTotal'><tr><th onclick='sortTable(`"osTableUnknownTotal`",0)'>Hostname</th><th onclick='sortTable(`"osTableUnknownTotal`",1)'>Last Logon</th></tr>"
    foreach ($pc in $UnknownTotal | Sort Name) {
        $LastLogon = Convert-ADTimestamp $pc.LastLogonTimestamp
        $Html += "<tr><td>$($pc.Name)</td><td>$LastLogon</td></tr>"
    }
    $Html += "</table></div></div>"
    
    $Html += "</div>"
}

$Html += "</div>" # serverOsContainer closed



# ---------------------
# Windows Client Container (Shortened)
# ---------------------
$ClientNodes = @()
foreach ($k in $ClientCategories.Keys) {
    if ($ClientCategories[$k]) { $ClientNodes += @($ClientCategories[$k]) }
}
$ClientTotalNodes = @($ClientNodes).Count
$ClientActive30Count = @($ClientNodes | Where-Object { $_.LastLogonTimestamp -and $_.LastLogonTimestamp -ge (Get-Date).AddDays(-30).ToFileTimeUtc() }).Count
$ClientStale90Count = @($ClientNodes | Where-Object { -not $_.LastLogonTimestamp -or $_.LastLogonTimestamp -lt (Get-Date).AddDays(-90).ToFileTimeUtc() }).Count

$Html += "<div class='container' id='clientOsContainer' style='display:none;'><div class='content-card'>"
$Html += "<h2>Windows Client OS Overview</h2>"
$Html += "<p class='section-intro'>Endpoint estate snapshot for supportability and stale device tracking.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Total Clients</div><div class='section-stat-value'>$ClientTotalNodes</div><div class='section-stat-note'>Inventory in scope</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Active in 30 Days</div><div class='section-stat-value'>$ClientActive30Count</div><div class='section-stat-note'>Recent endpoint activity</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Stale 90d+</div><div class='section-stat-value'>$ClientStale90Count</div><div class='section-stat-note'>Cleanup candidates</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Windows 11</div><div class='section-stat-value'>$(@($ClientCategories['Windows 11']).Count)</div><div class='section-stat-note'>Modern endpoint baseline</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Track stale endpoints before they become unmanaged risks.</span></div><div class='os-grid'>" 
$clientKeys = $ClientCategories.Keys | Sort-Object -Descending { 
    if ($_ -match 'Windows (\d+)') { [int]$matches[1] } 
    elseif ($_ -match 'Unknown') { 0 }
    else { 1 }
}

foreach ($key in $clientKeys) {
    $cat = @{Key=$key; Value=$ClientCategories[$key]}
    if ($cat.Value.Count -eq 0) { continue }
    
    $Html += "<div class='content-card'><h2>$($cat.Key) ($($cat.Value.Count))</h2><div class='table-wrapper'>"
    
    $Html += "<table class='user-table' id='osTable$($cat.Key -replace '\s','_')'><tr><th onclick='sortTable(`"osTable$($cat.Key -replace '\s','_')`",0)'>Hostname</th><th onclick='sortTable(`"osTable$($cat.Key -replace '\s','_')`",1)'>Last Logon</th></tr>"
    foreach ($pc in $cat.Value | Sort Name) {
        $LastLogon = Convert-ADTimestamp $pc.LastLogonTimestamp
        $Html += "<tr><td>$($pc.Name)</td><td>$LastLogon</td></tr>"
    }
    $Html += "</table></div></div>"
}
$Html += "</div></div>" # clientOsContainer closed

# ---------------------
# USER FILTER CONTAINER GENERATION FUNCTION (Shortened)
# ---------------------
function GenerateUserContainer($Title, $ContainerId, $UserList, $DomainAdmins, $SchemaAdmins, $EnterpriseAdmins) {
    $TotalUsers = @($UserList).Count
    $EnabledUsers = @($UserList | Where-Object { $_.Enabled -eq $true }).Count
    $DisabledUsers = $TotalUsers - $EnabledUsers
    $PwdNeverExpiresUsers = @($UserList | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
    $PrivilegedUsers = @($UserList | Where-Object {
        ($DomainAdmins -contains $_.SamAccountName) -or
        ($SchemaAdmins -contains $_.SamAccountName) -or
        ($EnterpriseAdmins -contains $_.SamAccountName)
    }).Count

    $UserContainerHtml = "<div class='container' id='$ContainerId' style='display:none;'><div class='content-card'>" 
    $UserContainerHtml += "<h2>$Title ($TotalUsers)</h2>"
    $UserContainerHtml += "<p class='section-intro'>Operational view for account hygiene and privilege exposure.</p>"
    $UserContainerHtml += "<div class='section-stat-grid'>"
    $UserContainerHtml += "<div class='section-stat-card'><div class='section-stat-label'>Total Accounts</div><div class='section-stat-value'>$TotalUsers</div><div class='section-stat-note'>Scoped list size</div></div>"
    $UserContainerHtml += "<div class='section-stat-card'><div class='section-stat-label'>Enabled</div><div class='section-stat-value'>$EnabledUsers</div><div class='section-stat-note'>Active sign-in capable</div></div>"
    $UserContainerHtml += "<div class='section-stat-card'><div class='section-stat-label'>Disabled</div><div class='section-stat-value'>$DisabledUsers</div><div class='section-stat-note'>Review for cleanup</div></div>"
    $UserContainerHtml += "<div class='section-stat-card'><div class='section-stat-label'>Privileged</div><div class='section-stat-value'>$PrivilegedUsers</div><div class='section-stat-note'>DA/SA/EA overlap</div></div>"
    $UserContainerHtml += "</div>"
    $UserContainerHtml += "<span class='section-note-pill'>Password Never Expires: $PwdNeverExpiresUsers</span><div class='table-wrapper'>" 
    $UserContainerHtml += "<table class='user-table' id='$ContainerId" + "Table'><tr>
    <th onclick='sortTable(`"$ContainerId" + "Table`",0)'>Name</th>
    <th onclick='sortTable(`"$ContainerId" + "Table`",1)'>Enabled</th>
    <th onclick='sortTable(`"$ContainerId" + "Table`",2)'>Password Never Expires</th>
    <th onclick='sortTable(`"$ContainerId" + "Table`",3)'>Last Logon</th>
    <th onclick='sortTable(`"$ContainerId" + "Table`",4)'>Domain Admin</th>
    <th onclick='sortTable(`"$ContainerId" + "Table`",5)'>Schema Admin</th>
    <th onclick='sortTable(`"$ContainerId" + "Table`",6)'>Enterprise Admin</th>
    </tr>"
    foreach ($u in $UserList | Sort Name) {
        $LastLogon = Convert-ADTimestamp $u.LastLogonTimestamp
        $Enabled = if($u.Enabled){"Yes"} else {"No"}
        $PwdNE = if($u.PasswordNeverExpires){"Yes"} else {"No"}
        $DA = if($DomainAdmins -contains $u.SamAccountName){"Yes"} else {"No"}
        $SA = if($SchemaAdmins -contains $u.SamAccountName){"Yes"} else {"No"}
        $EA = if($EnterpriseAdmins -contains $u.SamAccountName){"Yes"} else {"No"}
        $UserContainerHtml += "<tr><td>$($u.Name)</td><td>$Enabled</td><td>$PwdNE</td><td>$LastLogon</td><td>$DA</td><td>$SA</td><td>$EA</td></tr>"
    }
    $UserContainerHtml += "</table></div></div></div>"
    return $UserContainerHtml
}

# ---------------------
# AD Users Containers (Shortened)
# ---------------------
# 1. All
$Html += GenerateUserContainer "All AD Users" "allUserContainer" $UserFilters.AllUsers $DomainAdmins $SchemaAdmins $EnterpriseAdmins
# 2. Never Expires
$Html += GenerateUserContainer "Password Never Expires Users" "neverExpiresContainer" $UserFilters.NeverExpiresUsers $DomainAdmins $SchemaAdmins $EnterpriseAdmins
# 3. Domain Admins
$Html += GenerateUserContainer "Domain Administrators" "domainAdminContainer" $UserFilters.DomainAdminsUsers $DomainAdmins $SchemaAdmins $EnterpriseAdmins
# 4. Schema Admins
$Html += GenerateUserContainer "Schema Administrators" "schemaAdminContainer" $UserFilters.SchemaAdminsUsers $DomainAdmins $SchemaAdmins $EnterpriseAdmins
# 5. Enterprise Admins
$Html += GenerateUserContainer "Enterprise Administrators" "enterpriseAdminContainer" $UserFilters.EnterpriseAdminsUsers $DomainAdmins $SchemaAdmins $EnterpriseAdmins
# 6. Disabled Users
$Html += GenerateUserContainer "Disabled Users" "disabledUserContainer" $UserFilters.DisabledUsers $DomainAdmins $SchemaAdmins $EnterpriseAdmins

# ---------------------
# AD User Risk Level Container
# ---------------------
$Html += "<div class='container' id='adUserRiskLevelContainer' style='display:none;'><div class='content-card'>"
$Html += "<h2>AD User Risk Level ($UserRiskLookbackLabel)</h2>"
if ($SkipHeavyTelemetry) {
    $Html += "<p class='section-intro' style='border:1px solid #e5b4b4;background:#fff1f1;color:#8f1c1c;padding:8px 10px;border-radius:8px;'>This report was generated with SkipHeavyTelemetry. AD User Risk events (4625/4740/4624) were not collected, so values may appear as 0.</p>"
}
$Html += "<div class='risk-mini-grid'>"
$Html += "<div id='userRiskCardLockouts' class='risk-mini-card user-risk-card active' onclick='showUserRiskSection(""lockouts"")'><h4><span class='user-risk-icon'>&#128269;</span>Activity Explorer</h4><div class='risk-mini-meta'><span>$(@($UserRiskActivityForJs).Count)</span><span>Click to open</span></div></div>"
$Html += "<div id='userRiskCardFailedUsers' class='risk-mini-card user-risk-card' onclick='showUserRiskSection(""failedUsers"")'><h4><span class='user-risk-icon'>&#128100;</span>Failed Logon Users</h4><div class='risk-mini-meta'><span>$(@($UserRiskFailedByUserForJs).Count)</span><span>Click to open</span></div></div>"
$Html += "<div id='userRiskCardFailedSources' class='risk-mini-card user-risk-card' onclick='showUserRiskSection(""failedSources"")'><h4><span class='user-risk-icon'>&#128421;</span>Failed Logon Sources</h4><div class='risk-mini-meta'><span>$(@($UserRiskFailedBySourceForJs).Count)</span><span>Click to open</span></div></div>"
$Html += "<div id='userRiskCardSpray' class='risk-mini-card user-risk-card' onclick='showUserRiskSection(""spray"")'><h4><span class='user-risk-icon'>&#128165;</span>Password Spray</h4><div class='risk-mini-meta'><span>$(@($PasswordSprayRows).Count)</span><span>Click to open</span></div></div>"
$Html += "<div id='userRiskCardPrivileged' class='risk-mini-card user-risk-card' onclick='showUserRiskSection(""privileged"")'><h4><span class='user-risk-icon'>&#128081;</span>Privileged Watchlist</h4><div class='risk-mini-meta'><span>$(@($PrivilegedWatchlistRows | Where-Object { $_.RiskScore -gt 0 }).Count)</span><span>Click to open</span></div></div>"
$Html += "<div id='userRiskCardCorrelation' class='risk-mini-card user-risk-card' onclick='showUserRiskSection(""correlation"")'><h4><span class='user-risk-icon'>&#128279;</span>Lockout Correlation</h4><div class='risk-mini-meta'><span>$(@($LockoutCorrelationRows).Count)</span><span>Click to open</span></div></div>"
$Html += "<div id='userRiskCardUserDevice' class='risk-mini-card user-risk-card' onclick='showUserRiskSection(""userDevice"")'><h4><span class='user-risk-icon'>&#128187;</span>User-Device Links</h4><div class='risk-mini-meta'><span>$(@($UserRiskUserDeviceMap).Count)</span><span>Click to open</span></div></div>"
$Html += "</div>"
$Html += "<div id='userRisk24hSummary' class='user-risk-kpi-row'><span class='user-risk-kpi-chip'>24h Summary loading...</span></div>"

$Html += "<div id='userRiskSectionLockouts' class='user-risk-section' style='display:block;'>"
$Html += "<h3 style='margin-top:16px;'>AD User Activity Explorer (Success / Failed / Locked)</h3>"
$Html += "<div class='user-risk-explorer'>"
$Html += "<div class='user-risk-main'><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskActivityTable'><tr>
<th onclick='sortTable(""userRiskActivityTable"",0)'>Time</th>
<th>Status</th>
<th>User</th>
<th>Source Host</th>
<th>Source IP</th>
<th>Destination Host</th>
<th>Destination IP</th>
<th>Logon Type</th>
<th>Reason</th>
<th>Path</th>
</tr><tbody id='userRiskActivityTbody'><tr><td colspan='10'>Loading activity data...</td></tr></tbody></table>"
$Html += "</div></div>"
$Html += "<div class='user-risk-filters'>"
$Html += "<h4>Investigation Filters</h4>"
$Html += "<div class='user-risk-filter-group'><label>Status</label><select id='userRiskFilterStatus' onchange='applyUserRiskFilters()'><option value='all'>All</option><option value='failed'>Failed</option><option value='success'>Success</option><option value='locked'>Locked</option></select></div>"
$Html += "<div class='user-risk-filter-group'><label>User</label><input type='text' id='userRiskFilterUser' list='userRiskUsersList' placeholder='samAccountName / user' oninput='applyUserRiskFilters()'/><datalist id='userRiskUsersList'></datalist></div>"
$Html += "<div class='user-risk-filter-group'><label>Source Host or IP</label><input type='text' id='userRiskFilterSource' list='userRiskSourcesList' placeholder='source machine or ip' oninput='applyUserRiskFilters()'/><datalist id='userRiskSourcesList'></datalist></div>"
$Html += "<div class='user-risk-filter-group'><label>Destination Host or IP</label><input type='text' id='userRiskFilterDestination' list='userRiskDestinationsList' placeholder='target dc or ip' oninput='applyUserRiskFilters()'/><datalist id='userRiskDestinationsList'></datalist></div>"
$Html += "<div class='user-risk-filter-group'><label>Last N Hours</label><input type='number' id='userRiskFilterHours' min='1' step='1' placeholder='e.g. 24' oninput='applyUserRiskFilters()'/></div>"
$Html += "<div class='user-risk-filter-group'><label>Quick Queries</label><div class='user-risk-preset-grid'>"
$Html += "<button class='user-risk-preset-btn' onclick='setUserRiskQuickPreset(""lockout24"")'>Last 24h Lockouts</button>"
$Html += "<button class='user-risk-preset-btn' onclick='setUserRiskQuickPreset(""failed24"")'>Last 24h Failed</button>"
$Html += "<button class='user-risk-preset-btn' onclick='setUserRiskQuickPreset(""bruteforce"")'>Brute Force (6h)</button>"
$Html += "<button class='user-risk-preset-btn' onclick='setUserRiskQuickPreset(""dcfocus"")'>DC Focus (24h)</button>"
$Html += "</div></div>"
$Html += "<div class='user-risk-filter-actions'><button class='user-risk-btn' onclick='applyUserRiskFilters()'>Apply</button><button class='user-risk-btn secondary' onclick='resetUserRiskFilters()'>Reset</button></div>"
$Html += "<div id='userRiskFilterSummary' class='user-risk-filter-summary'>-</div>"
$Html += "</div>"
$Html += "</div>"
$Html += "<div class='user-risk-insights'>"
$Html += "<div class='content-card-lite'><h4>Compound Incident Candidates</h4><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskIncidentTable'><tr><th>User</th><th>Failed</th><th>Locked</th><th>Success</th><th>Distinct Sources</th><th>Last Seen</th><th>Score</th></tr><tbody id='userRiskIncidentTbody'><tr><td colspan='7'>Loading incidents...</td></tr></tbody></table>"
$Html += "</div><div id='userRiskIncidentSummary' class='user-risk-filter-summary' style='margin-top:8px;'>-</div></div>"
$Html += "<div id='userRiskProfilePanel' class='content-card-lite' style='display:none;'><h4 id='userRiskProfileTitle'>User Profile</h4><div id='userRiskProfileMeta' class='user-risk-profile-meta'></div><h4 style='margin-top:10px;'>Recent Timeline (20)</h4><div id='userRiskProfileTimeline' class='user-risk-profile-timeline'></div></div>"
$Html += "</div>"
$Html += "<h3 style='margin-top:12px;'>7d Current vs Previous Trend</h3><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskTrendTable'><tr><th onclick='sortTable(""userRiskTrendTable"",0)'>Metric</th><th onclick='sortTable(""userRiskTrendTable"",1)'>Last 7d</th><th onclick='sortTable(""userRiskTrendTable"",2)'>Previous 7d</th><th onclick='sortTable(""userRiskTrendTable"",3)'>Current Avg/Day</th><th onclick='sortTable(""userRiskTrendTable"",4)'>Previous Avg/Day</th><th onclick='sortTable(""userRiskTrendTable"",5)'>Delta %</th></tr>"
foreach ($tr in $UserRiskTrendRows) {
    $deltaClass = if ($tr.DeltaPct -ge 25) { 'status-hata' } elseif ($tr.DeltaPct -ge 5) { 'status-uyari' } elseif ($tr.DeltaPct -le -10) { 'status-ok' } else { '' }
    $deltaText = if ($tr.DeltaPct -gt 0) { "+$($tr.DeltaPct)%" } else { "$($tr.DeltaPct)%" }
    $Html += "<tr><td>$($tr.Metric)</td><td>$($tr.Count7)</td><td>$($tr.Count14)</td><td>$($tr.Rate7Text)</td><td>$($tr.Rate14Text)</td><td class='$deltaClass'>$deltaText</td></tr>"
}
$Html += "</table></div>"
$Html += "<h3 style='margin-top:12px;'>DC Authentication Heatmap (Last 24h)</h3><div class='table-wrapper'>"
$Html += "<table class='user-table heatmap-table' id='userRiskDcHeatmapTable'><tr><th>DC</th>"
foreach ($h in 0..23) { $Html += "<th>$('{0:D2}' -f $h)</th>" }
$Html += "<th>Total</th></tr>"
foreach ($hr in $UserRiskDcHeatmapRows) {
    $Html += "<tr><td>$($hr.DC)</td>"
    foreach ($h in 0..23) {
        $count = [int]$hr.HourCounts[$h]
        $riskCount = [int]$hr.RiskCounts[$h]
        $cls = Get-HeatCellClass -Count $count -Max $UserRiskDcHeatmapMax
        $Html += "<td class='$cls' title='Failed+Locked: $riskCount'>$count</td>"
    }
    $Html += "<td><b>$([int]$hr.Total)</b></td></tr>"
}
$Html += "</table></div></div>"

$Html += "<div id='userRiskSectionFailedUsers' class='user-risk-section'>"
$Html += "<h3 style='margin-top:16px;'>Top Failed Logons by User</h3>"
$Html += "<div class='user-risk-explorer'>"
$Html += "<div class='user-risk-main'><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskFailedByUserTable'><tr>
<th onclick='sortTable(""userRiskFailedByUserTable"",0)'>User</th>
<th onclick='sortTable(""userRiskFailedByUserTable"",1)'>Failed Count</th>
<th onclick='sortTable(""userRiskFailedByUserTable"",2)'>Last Seen</th>
<th onclick='sortTable(""userRiskFailedByUserTable"",3)'>Top Sources</th>
</tr><tbody id='userRiskFailedByUserTbody'>"
if (@($UserRiskFailedByUser).Count -eq 0) {
    $Html += "<tr><td colspan='4'>No failed logon event found for the selected lookback period.</td></tr>"
} else {
    foreach ($item in $UserRiskFailedByUser) {
        $lastSeen = if ($item.LastSeen) { $item.LastSeen.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
        $userText = Convert-ToHtmlText $item.TargetUser
        $userJs = Convert-ToJsDoubleQuoted $item.TargetUser
        $topSourcesText = Convert-ToHtmlText $item.TopSources
        $Html += "<tr><td><span class='user-risk-user-link' onclick='openUserRiskProfile(""$userJs"")'>$userText</span></td><td>$($item.FailedCount)</td><td>$lastSeen</td><td>$topSourcesText</td></tr>"
    }
}
$Html += "</tbody></table></div></div>"
$Html += "<div class='user-risk-filters'>"
$Html += "<h4>Failed User Filters</h4>"
$Html += "<div class='user-risk-filter-group'><label>User</label><input type='text' id='userRiskFailedUsersFilterUser' placeholder='user contains' oninput='applyFailedUsersFilters()'/></div>"
$Html += "<div class='user-risk-filter-group'><label>Top Sources</label><input type='text' id='userRiskFailedUsersFilterSource' placeholder='source contains' oninput='applyFailedUsersFilters()'/></div>"
$Html += "<div class='user-risk-filter-group'><label>Minimum Failed Count</label><input type='number' id='userRiskFailedUsersFilterMinCount' min='1' step='1' placeholder='e.g. 5' oninput='applyFailedUsersFilters()'/></div>"
$Html += "<div class='user-risk-filter-group'><label>Last N Hours</label><input type='number' id='userRiskFailedUsersFilterHours' min='1' step='1' placeholder='e.g. 24' oninput='applyFailedUsersFilters()'/></div>"
$Html += "<div class='user-risk-filter-actions'><button class='user-risk-btn' onclick='applyFailedUsersFilters()'>Apply</button><button class='user-risk-btn secondary' onclick='resetFailedUsersFilters()'>Reset</button></div>"
$Html += "<div id='userRiskFailedUsersFilterSummary' class='user-risk-filter-summary'>-</div>"
$Html += "</div></div></div>"

$Html += "<div id='userRiskSectionFailedSources' class='user-risk-section'>"
$Html += "<h3 style='margin-top:16px;'>Top Failed Logon Sources</h3>"
$Html += "<div class='user-risk-explorer'>"
$Html += "<div class='user-risk-main'><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskFailedBySourceTable'><tr>
<th onclick='sortTable(""userRiskFailedBySourceTable"",0)'>Source</th>
<th onclick='sortTable(""userRiskFailedBySourceTable"",1)'>Failed Count</th>
<th onclick='sortTable(""userRiskFailedBySourceTable"",2)'>Last Seen</th>
<th onclick='sortTable(""userRiskFailedBySourceTable"",3)'>Top Users</th>
</tr><tbody id='userRiskFailedBySourceTbody'>"
if (@($UserRiskFailedBySource).Count -eq 0) {
    $Html += "<tr><td colspan='4'>No failed source found for the selected lookback period.</td></tr>"
} else {
    foreach ($item in $UserRiskFailedBySource) {
        $lastSeen = if ($item.LastSeen) { $item.LastSeen.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
        $sourceText = Convert-ToHtmlText $item.Source
        $topUsersText = Convert-ToHtmlText $item.TopUsers
        $Html += "<tr><td>$sourceText</td><td>$($item.FailedCount)</td><td>$lastSeen</td><td>$topUsersText</td></tr>"
    }
}
$Html += "</tbody></table></div></div>"
$Html += "<div class='user-risk-filters'>"
$Html += "<h4>Failed Source Filters</h4>"
$Html += "<div class='user-risk-filter-group'><label>Source</label><input type='text' id='userRiskFailedSourcesFilterSource' placeholder='source contains' oninput='applyFailedSourcesFilters()'/></div>"
$Html += "<div class='user-risk-filter-group'><label>Top Users</label><input type='text' id='userRiskFailedSourcesFilterUser' placeholder='user contains' oninput='applyFailedSourcesFilters()'/></div>"
$Html += "<div class='user-risk-filter-group'><label>Minimum Failed Count</label><input type='number' id='userRiskFailedSourcesFilterMinCount' min='1' step='1' placeholder='e.g. 5' oninput='applyFailedSourcesFilters()'/></div>"
$Html += "<div class='user-risk-filter-group'><label>Last N Hours</label><input type='number' id='userRiskFailedSourcesFilterHours' min='1' step='1' placeholder='e.g. 24' oninput='applyFailedSourcesFilters()'/></div>"
$Html += "<div class='user-risk-filter-actions'><button class='user-risk-btn' onclick='applyFailedSourcesFilters()'>Apply</button><button class='user-risk-btn secondary' onclick='resetFailedSourcesFilters()'>Reset</button></div>"
$Html += "<div id='userRiskFailedSourcesFilterSummary' class='user-risk-filter-summary'>-</div>"
$Html += "</div></div></div>"

$Html += "<div id='userRiskSectionSpray' class='user-risk-section'>"
$Html += "<h3 style='margin-top:16px;'>Password Spray Candidates</h3>"
$Html += "<p class='section-intro'>Sources that generated many failed logons across many distinct users in the selected window.</p><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskSprayTable'><tr><th>Source</th><th>Failed</th><th>Distinct Users</th><th>Window (min)</th><th>First Seen</th><th>Last Seen</th><th>Top Users</th></tr>"
if (@($PasswordSprayRows).Count -eq 0) {
    $Html += "<tr><td colspan='7'>No password spray candidate detected in the selected lookback period.</td></tr>"
} else {
    foreach ($item in $PasswordSprayRows) {
        $firstSeen = if ($item.FirstSeen) { $item.FirstSeen.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
        $lastSeen = if ($item.LastSeen) { $item.LastSeen.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
        $Html += "<tr><td>$(Convert-ToHtmlText $item.Source)</td><td>$($item.FailedCount)</td><td>$($item.DistinctUsers)</td><td>$($item.WindowMinutes)</td><td>$firstSeen</td><td>$lastSeen</td><td>$(Convert-ToHtmlText $item.TopUsers)</td></tr>"
    }
}
$Html += "</table></div></div>"

$Html += "<div id='userRiskSectionPrivileged' class='user-risk-section'>"
$Html += "<h3 style='margin-top:16px;'>Privileged Account Watchlist</h3>"
$Html += "<p class='section-intro'>Domain Admin, Schema Admin and Enterprise Admin accounts with recent failed logons or lockouts.</p><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskPrivilegedTable'><tr><th>User</th><th>Groups</th><th>Failed</th><th>Lockouts</th><th>Recent Events</th><th>Last Seen</th><th>Top Sources</th><th>Risk Score</th></tr>"
if (@($PrivilegedWatchlistRows | Where-Object { $_.RiskScore -gt 0 }).Count -eq 0) {
    $Html += "<tr><td colspan='8'>No recent privileged account anomaly detected in the selected lookback period.</td></tr>"
} else {
    foreach ($item in $PrivilegedWatchlistRows) {
        if ($item.RiskScore -le 0) { continue }
        $lastSeen = if ($item.LastSeen) { $item.LastSeen.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
        $userJs = Convert-ToJsDoubleQuoted $item.TargetUser
        $Html += "<tr><td><span class='user-risk-user-link' onclick='openUserRiskProfile(""$userJs"")'>$(Convert-ToHtmlText $item.TargetUser)</span></td><td>$(Convert-ToHtmlText $item.Groups)</td><td>$($item.FailedCount)</td><td>$($item.LockoutCount)</td><td>$($item.EventCount)</td><td>$lastSeen</td><td>$(Convert-ToHtmlText $item.TopSources)</td><td>$($item.RiskScore)</td></tr>"
    }
}
$Html += "</table></div></div>"

$Html += "<div id='userRiskSectionCorrelation' class='user-risk-section'>"
$Html += "<h3 style='margin-top:16px;'>Account Lockout Correlation</h3>"
$Html += "<p class='section-intro'>Matches each lockout to failed logons by the same user in the prior 30 minutes.</p><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskCorrelationTable'><tr><th>User</th><th>Lockout Time</th><th>Failed Before</th><th>Minutes to Lockout</th><th>Likely Sources</th><th>First Failed</th></tr>"
if (@($LockoutCorrelationRows).Count -eq 0) {
    $Html += "<tr><td colspan='6'>No lockout correlation found in the selected lookback period.</td></tr>"
} else {
    foreach ($item in $LockoutCorrelationRows) {
        $lockoutTime = if ($item.LockoutTime) { $item.LockoutTime.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
        $firstFailed = if ($item.FirstFailed) { $item.FirstFailed.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
        $userJs = Convert-ToJsDoubleQuoted $item.TargetUser
        $Html += "<tr><td><span class='user-risk-user-link' onclick='openUserRiskProfile(""$userJs"")'>$(Convert-ToHtmlText $item.TargetUser)</span></td><td>$lockoutTime</td><td>$($item.FailedBefore)</td><td>$($item.MinutesToLockout)</td><td>$(Convert-ToHtmlText $item.LikelySources)</td><td>$firstFailed</td></tr>"
    }
}
$Html += "</table></div></div>"

$Html += "<div id='userRiskSectionUserDevice' class='user-risk-section'>"
$Html += "<h3 style='margin-top:16px;'>User-Device Activity Map</h3><div class='table-wrapper'>"
$Html += "<table class='user-table' id='userRiskUserDeviceTable'><tr>
<th onclick='sortTable(""userRiskUserDeviceTable"",0)'>User</th>
<th onclick='sortTable(""userRiskUserDeviceTable"",1)'>Source Device/IP</th>
<th onclick='sortTable(""userRiskUserDeviceTable"",2)'>Logon Type</th>
<th onclick='sortTable(""userRiskUserDeviceTable"",3)'>Seen Count</th>
<th onclick='sortTable(""userRiskUserDeviceTable"",4)'>Last Seen</th>
</tr>"
if (@($UserRiskUserDeviceMap).Count -eq 0) {
    $Html += "<tr><td colspan='5'>No user-device activity found for the selected lookback period.</td></tr>"
} else {
    foreach ($item in $UserRiskUserDeviceMap) {
        $lastSeen = if ($item.LastSeen) { $item.LastSeen.ToString("dd/MM/yyyy HH:mm:ss") } else { "-" }
        $Html += "<tr><td>$($item.TargetUser)</td><td>$($item.Source)</td><td>$($item.LogonType)</td><td>$($item.SeenCount)</td><td>$lastSeen</td></tr>"
    }
}
$Html += "</table></div></div>"
$Html += "</div></div>"

# ---------------------
# GROUPS & SITES & INACTIVE OBJECTS (Shortened)
# ---------------------
# Security Groups
$SecurityGlobalCount = @($SecurityGroups | Where-Object { $_.GroupScope -eq 'Global' }).Count
$SecurityUniversalCount = @($SecurityGroups | Where-Object { $_.GroupScope -eq 'Universal' }).Count
$SecurityDomainLocalCount = @($SecurityGroups | Where-Object { $_.GroupScope -eq 'DomainLocal' }).Count
$SecurityTopGroup = @($SecurityGroups | Sort-Object {[int]$_.MemberCount} -Descending | Select-Object -First 1)
$SecurityTopGroupText = if ($SecurityTopGroup) { "$($SecurityTopGroup.Name) ($($SecurityTopGroup.MemberCount))" } else { '-' }

$Html += "<div class='container' id='securityGroupsContainer' style='display:none;'><div class='content-card'>" 
$Html += "<h2>Security Groups ($($SecurityGroups.Count))</h2>"
$Html += "<p class='section-intro'>Membership and scope distribution for security boundaries.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Global</div><div class='section-stat-value'>$SecurityGlobalCount</div><div class='section-stat-note'>Cross-domain membership</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Universal</div><div class='section-stat-value'>$SecurityUniversalCount</div><div class='section-stat-note'>Forest-wide replication</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Domain Local</div><div class='section-stat-value'>$SecurityDomainLocalCount</div><div class='section-stat-note'>Resource permissions</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Largest Group</div><div class='section-stat-value' style='font-size:14px;'>$SecurityTopGroupText</div><div class='section-stat-note'>By direct member count</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Tip: Click group name to inspect direct members.</span><div class='table-wrapper'>"
$Html += "<table class='user-table' id='securityGroupsTable'><tr>
<th onclick='sortTable(""securityGroupsTable"",0)'>Group Name (Click)</th>
<th onclick='sortTable(""securityGroupsTable"",1)'>Scope</th>
<th onclick='sortTable(""securityGroupsTable"",2)'>Member Count (Direct)</th>
<th onclick='sortTable(""securityGroupsTable"",3)'>Managed By</th>
</tr>"
foreach ($g in $SecurityGroups) {
    $GroupNameEscaped = $g.Name -replace "'", "\'" # Escape quote characters in group name
    $SamAccountName = $g.SamAccountName
    $Html += "<tr><td class='group-name-cell' onclick=""showMembers('$GroupNameEscaped', '$SamAccountName')"">$($g.Name)</td><td>$($g.GroupScope)</td><td>$($g.MemberCount)</td><td>$($g.ManagedBy)</td></tr>"
}
$Html += "</table></div></div></div>"

# ---------------------
# Risk Baseline Diff Container
# ---------------------
$Html += "<div class='container' id='pingBaselineDiffContainer' style='display:none;'><div class='content-card'>"
$Html += "<h2>Risk Baseline Diff</h2>"
$Html += "<p style='color:#6b7280; font-style:italic;'>Current run is compared with the previous baseline snapshot file: pingcastle_baseline_snapshot.json</p>"
$Html += "<div class='dc-info-box'>"
$Html += "<div class='dc-info-item'><h4>Previous Snapshot</h4><span>$($PingBaselineSummary.PreviousSnapshot)</span></div>"
$Html += "<div class='dc-info-item'><h4>Current Snapshot</h4><span>$($PingBaselineSummary.CurrentSnapshot)</span></div>"
$Html += "</div>"

$Html += "<h3 style='margin:8px 0 6px 0;color:#0f2f4f;'>Snapshot Timeline (Last 12 Runs)</h3>"
$Html += "<div class='table-wrapper' style='max-height:260px;'><table class='user-table' id='baselineTimelineTable'><tr>"
$Html += "<th>Run Time</th><th>Total Diff</th><th>New</th><th>Changed</th><th>Resolved</th><th>Risk Score</th><th>Risk Rating</th>"
$Html += "</tr>"
if (@($PingBaselineTimelineRecentRows).Count -eq 0) {
    $Html += "<tr><td colspan='7'>No timeline rows yet.</td></tr>"
} else {
    foreach ($row in $PingBaselineTimelineRecentRows) {
        $ts = Convert-ToHtmlText $row.GeneratedAt
        $riskRating = Convert-ToHtmlText $row.RiskRating
        $Html += "<tr><td>$ts</td><td>$($row.TotalDifferences)</td><td>$($row.NewFindings)</td><td>$($row.ChangedFindings)</td><td>$($row.ResolvedFindings)</td><td>$($row.DomainRiskScore)/100</td><td>$riskRating</td></tr>"
    }
}
$Html += "</table></div>"

$Html += "<div class='baseline-hero-grid'>"
$Html += "<button class='baseline-hero-card baseline-card-total active' data-mode='all' onclick='applyBaselineDiffFilter(""all"")'><div class='baseline-hero-title'>Total Differences</div><div class='baseline-hero-value' id='baselineCountTotal'>$($PingBaselineSummary.TotalDifferences)</div><div class='baseline-hero-note'>Visible against selected filter</div></button>"
$Html += "<button class='baseline-hero-card baseline-card-new' data-mode='new' onclick='applyBaselineDiffFilter(""new"")'><div class='baseline-hero-title'>New Findings</div><div class='baseline-hero-value' id='baselineCountNew'>$($PingBaselineSummary.NewFindings)</div><div class='baseline-hero-note'>Top Rule: $(Convert-ToHtmlText $PingTopNewRule)</div></button>"
$Html += "<button class='baseline-hero-card baseline-card-changed' data-mode='changed' onclick='applyBaselineDiffFilter(""changed"")'><div class='baseline-hero-title'>Changed Findings</div><div class='baseline-hero-value' id='baselineCountChanged'>$($PingBaselineSummary.ChangedFindings)</div><div class='baseline-hero-note'>Top Rule: $(Convert-ToHtmlText $PingTopChangedRule)</div></button>"
$Html += "<button class='baseline-hero-card baseline-card-resolved' data-mode='resolved' onclick='applyBaselineDiffFilter(""resolved"")'><div class='baseline-hero-title'>Resolved Findings</div><div class='baseline-hero-value' id='baselineCountResolved'>$($PingBaselineSummary.ResolvedFindings)</div><div class='baseline-hero-note'>Top Rule: $(Convert-ToHtmlText $PingTopResolvedRule)</div></button>"
$Html += "</div>"

$Html += "<div class='baseline-distribution'>"
$Html += "<div class='baseline-distribution-track'><span class='baseline-dist-seg baseline-dist-new' id='baselineBarNew' style='width:$($PingDiffNewPct)%;'></span><span class='baseline-dist-seg baseline-dist-changed' id='baselineBarChanged' style='width:$($PingDiffChangedPct)%;'></span><span class='baseline-dist-seg baseline-dist-resolved' id='baselineBarResolved' style='width:$($PingDiffResolvedPct)%;'></span></div>"
$Html += "<div class='baseline-distribution-legend'><span class='baseline-legend-chip'><span class='baseline-dot baseline-dist-new'></span>New <b id='baselinePctNew'>$($PingDiffNewPct)</b>%</span><span class='baseline-legend-chip'><span class='baseline-dot baseline-dist-changed'></span>Changed <b id='baselinePctChanged'>$($PingDiffChangedPct)</b>%</span><span class='baseline-legend-chip'><span class='baseline-dot baseline-dist-resolved'></span>Resolved <b id='baselinePctResolved'>$($PingDiffResolvedPct)</b>%</span></div>"
$Html += "</div>"

$Html += "<div class='baseline-layout'>"
$Html += "<div class='baseline-panel'><h4>Category Concentration</h4>"
if (@($PingBaselineTopCategories).Count -eq 0) {
    $Html += "<div class='baseline-empty'>No category data available.</div>"
} else {
    foreach ($cat in $PingBaselineTopCategories) {
        $catName = Convert-ToHtmlText $cat.Category
        $catPct = [string]$cat.Percent
        $Html += "<div class='baseline-category-row'><div><div class='baseline-category-name'>$catName</div><div class='baseline-category-bar'><div class='baseline-category-fill' style='width:$catPct%;'></div></div></div><div class='baseline-category-meta'>$($cat.Count) | $catPct%</div></div>"
    }
}
$Html += "</div>"

$Html += "<div class='baseline-panel'><h4>Rule Highlights</h4><div class='baseline-highlights'>"
$Html += "<div class='baseline-highlight-box'><h5>New</h5><ul class='baseline-highlight-list'>"
if (@($PingTopNewRows).Count -eq 0) {
    $Html += "<li class='baseline-empty'>No new rules.</li>"
} else {
    foreach ($it in $PingTopNewRows) {
        $ruleText = Convert-ToHtmlText $it.Rule
        $catText = Convert-ToHtmlText $it.Category
        $Html += "<li><b>$ruleText</b> <span style='color:#5b7690;'>($catText)</span></li>"
    }
}
$Html += "</ul></div>"

$Html += "<div class='baseline-highlight-box'><h5>Changed</h5><ul class='baseline-highlight-list'>"
if (@($PingTopChangedRows).Count -eq 0) {
    $Html += "<li class='baseline-empty'>No changed rules.</li>"
} else {
    foreach ($it in $PingTopChangedRows) {
        $ruleText = Convert-ToHtmlText $it.Rule
        $catText = Convert-ToHtmlText $it.Category
        $Html += "<li><b>$ruleText</b> <span style='color:#5b7690;'>($catText)</span></li>"
    }
}
$Html += "</ul></div>"

$Html += "<div class='baseline-highlight-box'><h5>Resolved</h5><ul class='baseline-highlight-list'>"
if (@($PingTopResolvedRows).Count -eq 0) {
    $Html += "<li class='baseline-empty'>No resolved rules.</li>"
} else {
    foreach ($it in $PingTopResolvedRows) {
        $ruleText = Convert-ToHtmlText $it.Rule
        $catText = Convert-ToHtmlText $it.Category
        $Html += "<li><b>$ruleText</b> <span style='color:#5b7690;'>($catText)</span></li>"
    }
}
$Html += "</ul></div>"
$Html += "</div></div></div>"

$Html += "<div class='risk-focus-bar' style='margin-top:8px;'>"
$Html += "<button class='risk-focus-chip baseline-focus-chip active' data-mode='all' onclick='applyBaselineDiffFilter(""all"")'>All</button>"
$Html += "<button class='risk-focus-chip baseline-focus-chip' data-mode='new' onclick='applyBaselineDiffFilter(""new"")'>New</button>"
$Html += "<button class='risk-focus-chip baseline-focus-chip' data-mode='changed' onclick='applyBaselineDiffFilter(""changed"")'>Changed</button>"
$Html += "<button class='risk-focus-chip baseline-focus-chip' data-mode='resolved' onclick='applyBaselineDiffFilter(""resolved"")'>Resolved</button>"
$Html += "<span class='risk-focus-summary' id='pingBaselineFilterSummary'>All rows listed</span>"
$Html += "</div>"

$Html += "<div class='network-controls' style='margin-top:8px;'>"
$Html += "<input id='baselineDiffSearch' type='text' placeholder='Search exact changes...' oninput='applyBaselineDiffFilter(currentBaselineChangeFilter)' />"
$Html += "<select id='baselineDiffField' onchange='applyBaselineDiffFilter(currentBaselineChangeFilter)'>"
$Html += "<option value='all'>All Fields</option>"
$Html += "<option value='rule'>Rule</option>"
$Html += "<option value='category'>Category</option>"
$Html += "<option value='delta'>Exact Delta</option>"
$Html += "<option value='action'>Action Recommendation</option>"
$Html += "</select>"
$Html += "</div>"

$Html += "<h2 style='margin-top:20px;'>Diff Details</h2><div class='table-wrapper'>"
$Html += "<table class='user-table' id='pingBaselineDiffTable'><tr>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",0)'>Change Type</th>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",1)'>Category</th>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",2)'>Rule</th>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",3)'>Previous Severity</th>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",4)'>Current Severity</th>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",5)'>Previous Count</th>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",6)'>Current Count</th>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",7)'>Exact Delta</th>"
$Html += "<th onclick='sortTable(""pingBaselineDiffTable"",8)'>Action (Current)</th>"
$Html += "</tr>"

if ($PingDiffRows.Count -eq 0) {
    $Html += "<tr><td colspan='9'>No baseline difference. Current findings match the previous snapshot.</td></tr>"
} else {
    foreach ($row in $PingDiffRows) {
        $ChangeClass = switch ($row.ChangeType) {
            "New" { "status-hata" }
            "Changed" { "status-uyari" }
            "Resolved" { "status-ok" }
            default { "" }
        }

        $categoryText = Convert-ToHtmlText $row.Category
        $ruleText = Convert-ToHtmlText $row.Rule
        $prevSeverityText = Convert-ToHtmlText $row.PreviousSeverity
        $currSeverityText = Convert-ToHtmlText $row.CurrentSeverity
        $prevCountText = Convert-ToHtmlText $row.PreviousCount
        $currCountText = Convert-ToHtmlText $row.CurrentCount
        $notesText = Convert-ToHtmlText $row.Notes
        $actionText = Convert-ToHtmlText $row.CurrentRecommendation

        $Html += "<tr>"
        $Html += "<td class='$ChangeClass'>$($row.ChangeType)</td>"
        $Html += "<td>$categoryText</td>"
        $Html += "<td>$ruleText</td>"
        $Html += "<td>$prevSeverityText</td>"
        $Html += "<td>$currSeverityText</td>"
        $Html += "<td>$prevCountText</td>"
        $Html += "<td>$currCountText</td>"
        $Html += "<td>$notesText</td>"
        $Html += "<td>$actionText</td>"
        $Html += "</tr>"
    }
}

$Html += "</table></div></div></div>"

# Distribution Groups
$DistributionGlobalCount = @($DistributionGroups | Where-Object { $_.GroupScope -eq 'Global' }).Count
$DistributionUniversalCount = @($DistributionGroups | Where-Object { $_.GroupScope -eq 'Universal' }).Count
$DistributionDomainLocalCount = @($DistributionGroups | Where-Object { $_.GroupScope -eq 'DomainLocal' }).Count
$DistributionTopGroup = @($DistributionGroups | Sort-Object {[int]$_.MemberCount} -Descending | Select-Object -First 1)
$DistributionTopGroupText = if ($DistributionTopGroup) { "$($DistributionTopGroup.Name) ($($DistributionTopGroup.MemberCount))" } else { '-' }

$Html += "<div class='container' id='distributionGroupsContainer' style='display:none;'><div class='content-card'>" 
$Html += "<h2>Distribution Groups ($($DistributionGroups.Count))</h2>"
$Html += "<p class='section-intro'>Mail-distribution group governance and sprawl overview.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Global</div><div class='section-stat-value'>$DistributionGlobalCount</div><div class='section-stat-note'>Common scoped groups</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Universal</div><div class='section-stat-value'>$DistributionUniversalCount</div><div class='section-stat-note'>Replicated across forest</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Domain Local</div><div class='section-stat-value'>$DistributionDomainLocalCount</div><div class='section-stat-note'>Domain-specific delivery</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Largest Group</div><div class='section-stat-value' style='font-size:14px;'>$DistributionTopGroupText</div><div class='section-stat-note'>By direct member count</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Tip: Review oversized groups for stale mail routing.</span><div class='table-wrapper'>"
$Html += "<table class='user-table' id='distributionGroupsTable'><tr>
<th onclick='sortTable(""distributionGroupsTable"",0)'>Group Name (Click)</th>
<th onclick='sortTable(""distributionGroupsTable"",1)'>Scope</th>
<th onclick='sortTable(""distributionGroupsTable"",2)'>Member Count (Direct)</th>
<th onclick='sortTable(""distributionGroupsTable"",3)'>Managed By</th>
</tr>"
foreach ($g in $DistributionGroups) {
    $GroupNameEscaped = $g.Name -replace "'", "\'" # Escape quote characters in group name
    $SamAccountName = $g.SamAccountName
    $Html += "<tr><td class='group-name-cell' onclick=""showMembers('$GroupNameEscaped', '$SamAccountName')"">$($g.Name)</td><td>$($g.GroupScope)</td><td>$($g.MemberCount)</td><td>$($g.ManagedBy)</td></tr>"
}
$Html += "</table></div></div></div>"

# AD SITES & TOPOLOGY CONTAINER
$SiteTotalCount = @($SiteData.Keys).Count
$SiteDcTotalCount = 0
$SiteMemberServerTotalCount = 0
$SiteNoDcCount = 0
foreach ($siteKey in $SiteData.Keys) {
    $dcCountForSite = @($SiteData[$siteKey].DCs).Count
    $srvCountForSite = @($SiteData[$siteKey].Servers).Count
    $SiteDcTotalCount += $dcCountForSite
    $SiteMemberServerTotalCount += $srvCountForSite
    if ($dcCountForSite -eq 0) { $SiteNoDcCount++ }
}

$Html += "<div class='container' id='siteTopologyContainer' style='display:none;'>"
$Html += "<h2 class='os-section-header'>Active Directory Sites & Topology Overview</h2>"
$Html += "<p class='section-intro' style='font-style:italic;'>The schematic view below lists each site in Active Directory Sites and Services (ADSS), including Domain Controllers and member servers.</p>"
$Html += "<div class='content-card'>"
$Html += "<h2>Topology Summary</h2>"
$Html += "<p class='section-intro'>Inter-site visibility for DC placement and branch server density.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Total Sites</div><div class='section-stat-value'>$SiteTotalCount</div><div class='section-stat-note'>ADSS site objects</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Total DCs</div><div class='section-stat-value'>$SiteDcTotalCount</div><div class='section-stat-note'>Domain controller footprint</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Member Servers</div><div class='section-stat-value'>$SiteMemberServerTotalCount</div><div class='section-stat-note'>Non-DC server spread</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Sites Without DC</div><div class='section-stat-value'>$SiteNoDcCount</div><div class='section-stat-note'>Potential resilience gap</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Review sites without DC for authentication latency and failover risk.</span></div>"
foreach ($SiteName in $SiteData.Keys | Sort-Object) {
    $SiteInfo = $SiteData[$SiteName]
    $DCCount = $SiteInfo.DCs.Count
    $ServerCount = $SiteInfo.Servers.Count
    $Html += "<div class='site-card'>"
    $Html += "<h3>$SiteName</h3>"
    $Html += "<div class='site-content'>"
    $Html += "<div class='site-section'>"
    $Html += "<h4>💻 Domain Controllers ($DCCount)</h4>"
    $Html += "<ul class='server-list'>"
    if ($DCCount -eq 0) { $Html += "<li><span class='server-icon'>❌</span> No DC found in this site.</li>" }
    foreach ($dc in $SiteInfo.DCs | Sort Name) {
        $DC_OS = $dc.OperatingSystem -replace 'Windows Server',''
        $Html += "<li><span class='server-icon'>👑</span> <strong>$($dc.Name)</strong> ($DC_OS)</li>"
    }
    $Html += "</ul></div>"
    $Html += "<div class='site-section'>"
    $Html += "<h4>💾 Member Servers ($ServerCount)</h4>"
    $Html += "<ul class='server-list'>"
    if ($ServerCount -eq 0) { $Html += "<li><span class='server-icon'>&ndash;</span> No member server found in this site.</li>" }
    foreach ($server in $SiteInfo.Servers | Sort Name) {
        $Server_OS = $server.OperatingSystem -replace 'Windows Server',''
        $Html += "<li><span class='server-icon'>🗄️</span> $($server.Name) ($Server_OS)</li>"
    }
    $Html += "</ul></div>"
    $Html += "</div>"
    $Html += "</div>"
}
$Html += "</div>"

$Html += @"
<div class='container' id='ouTreeContainer'>
<div class='content-card'>
<h2>AD Structure &amp; Tier Advisor</h2>
<p class='section-intro'>Live OU tree from your Active Directory. Click any OU to see its inferred tier and hardening guidance.</p>
<div style='display:flex;align-items:center;gap:12px;margin-bottom:14px'>
    <button id='demoToggleBtn' onclick='toggleDemoMode()' style='padding:6px 16px;border-radius:20px;border:1px solid var(--color-border-secondary);background:var(--color-background-primary);color:var(--color-text-primary);font-size:13px;cursor:pointer;font-weight:500'>
        ▷ Demo Modunu Aç
    </button>
    <div id='demoBanner' style='display:none;font-size:12px;background:#fef3c7;color:#92400e;padding:5px 12px;border-radius:20px;border:1px solid #fcd34d'>
        ⚠ Demo Mode aktif — hiçbir değişiklik Active Directory'e yazılmıyor
    </div>
</div>
<div style='display:flex;gap:16px;align-items:flex-start'>

<div style='flex:0 0 60%;background:var(--color-background-secondary);border:1px solid var(--color-border-tertiary);border-radius:12px;padding:16px;max-height:75vh;overflow-y:auto'>
    <div id='demoTreeActions' style='display:none;margin-bottom:10px;padding:10px;border:1px solid var(--color-border-tertiary);border-radius:10px;background:var(--color-background-primary)'>
        <div style='display:flex;gap:8px;flex-wrap:wrap;align-items:center'>
            <button class='panel-toggle-btn' onclick='runDemoQuickAction("create")'>📁 New Child OU</button>
            <button class='panel-toggle-btn' onclick='runDemoQuickAction("rename")'>✏️ Rename</button>
            <button class='panel-toggle-btn' onclick='runDemoQuickAction("editGpo")'>🧩 Edit GPO Links</button>
            <button class='panel-toggle-btn' onclick='runDemoQuickAction("delete")'>🗑 Delete</button>
            <span id='demoTreeActionHint' style='font-size:11px;color:var(--color-text-secondary)'>Select an OU, then choose an action.</span>
        </div>
        <div style='font-size:11px;color:var(--color-text-secondary);margin-top:8px'>Drag &amp; drop an OU to move it under another OU. Double-click an OU name to rename quickly.</div>
    </div>
    <div style='font-size:12px;margin-bottom:10px;display:flex;gap:8px'>
        <span style='background:#dc2626;color:#fff;padding:1px 8px;border-radius:10px;font-size:11px'>T0 — Control Plane</span>
        <span style='background:#d97706;color:#fff;padding:1px 8px;border-radius:10px;font-size:11px'>T1 — Server</span>
        <span style='background:#2563eb;color:#fff;padding:1px 8px;border-radius:10px;font-size:11px'>T2 — User/WS</span>
        <span style='background:#6b7280;color:#fff;padding:1px 8px;border-radius:10px;font-size:11px'>? Unknown</span>
    </div>
    <div id='ouTreeNodes'></div>
</div>

<div style='flex:0 0 38%;position:sticky;top:16px'>
    <div id='tierAdvisorSelected' style='margin-bottom:14px'></div>
    <div id='tierAdvisorReference'></div>
        <div id='demoChangeLog' style='display:none;margin-top:14px'>
            <div style='font-size:11px;font-weight:500;color:var(--color-text-secondary);margin-bottom:8px;letter-spacing:.05em'>DEMO DEĞİŞİKLİK LOGU</div>
            <div id='demoChangeLogItems' style='background:var(--color-background-secondary);border:1px solid var(--color-border-tertiary);border-radius:8px;max-height:220px;overflow-y:auto;font-size:12px'>
                <div style='padding:10px 12px;color:var(--color-text-secondary)'>Henüz değişiklik yapılmadı.</div>
            </div>
            <button onclick='clearDemoLog()' style='margin-top:6px;font-size:11px;color:var(--color-text-secondary);background:none;border:none;cursor:pointer;padding:0'>Logu temizle</button>
        </div>
</div>

<div id='ouContextMenu' style='display:none;position:fixed;z-index:9999;background:var(--color-background-primary);border:1px solid var(--color-border-secondary);border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,0.15);padding:4px 0;min-width:180px;font-size:13px'>
    <div style='padding:4px 8px;font-size:11px;color:var(--color-text-secondary);font-weight:500;border-bottom:1px solid var(--color-border-tertiary);margin-bottom:2px' id='ctxOUName'></div>
    <div class='ctx-item' onclick='ctxAction("create")'>📁 New Child OU</div>
    <div class='ctx-item' onclick='ctxAction("rename")'>✏️ Rename</div>
    <div class='ctx-item' onclick='ctxAction("editGpo")'>🧩 Edit GPO Links</div>
    <div class='ctx-item' onclick='ctxAction("delete")' style='color:#dc2626'>🗑 Delete</div>
</div>

</div>
</div>
</div>

<script>
const ouTreeData = $OUTreeJson;
const ouDomainRootName = $OUTreeDomainNameJson;
const ouDomainRootDn = $OUTreeDomainDnJson;
var ouTreeWorkingData = [];
var ouAdvisorState = { selected: null, draft: null, selectedGpo: null };
let demoModeActive = false;
let demoLog = [];
let ctxTargetDN = null;
let ctxTargetName = null;
let dragSourceDN = null;
let demoOUData = [];

if (!document.getElementById('ouDemoModeStyles')) {
        var ouDemoStyle = document.createElement('style');
        ouDemoStyle.id = 'ouDemoModeStyles';
    ouDemoStyle.textContent = '.ctx-item { padding:7px 14px; cursor:pointer; color:var(--color-text-primary); } .ctx-item:hover { background:var(--color-background-tertiary); } #ouTreeContainer .content-card{padding:14px 14px 12px;border-radius:14px;} #ouTreeContainer .section-intro{margin-bottom:10px;font-size:12px;} #demoToggleBtn{padding:5px 14px;font-size:12px;border-radius:999px;} #demoBanner{font-size:11px;padding:4px 10px;border-radius:999px;} #demoTreeActions{padding:8px 10px;margin-bottom:8px;} #demoTreeActions .panel-toggle-btn{padding:6px 10px;font-size:12px;border-radius:10px;} #ouTreeNodes{font-size:12px;} .ou-row.ou-selected{outline:2px solid #3b82f6;outline-offset:0;box-shadow:0 0 0 2px rgba(59,130,246,.14) inset;}';
        document.head.appendChild(ouDemoStyle);
}

try {
    ouTreeWorkingData = JSON.parse(JSON.stringify(ouTreeData || []));
} catch (e) {
    ouTreeWorkingData = Array.isArray(ouTreeData) ? ouTreeData.slice() : [];
}

function ouAdvisorText(en, tr) {
    return currentLanguage === 'tr' ? tr : en;
}

function ouAdvisorNumber(value) {
    var parsed = parseInt(value, 10);
    return isNaN(parsed) ? 0 : parsed;
}

function ouNormalizeGpoNames(text) {
    if (!text) return [];
    var raw = String(text).split(/[;,\n]/);
    var seen = {};
    var names = [];
    raw.forEach(function(item) {
        var clean = String(item || '').trim();
        if (!clean) return;
        var key = clean.toLowerCase();
        if (seen[key]) return;
        seen[key] = true;
        names.push(clean);
    });
    return names;
}

function ouNormalizeGpoDetails(value) {
    if (!value) return [];
    if (Array.isArray(value)) {
        return value.map(function(item) { return String(item || '').trim(); }).filter(function(item) { return !!item; });
    }
    return String(value).split('||').map(function(item) { return String(item || '').trim(); }).filter(function(item) { return !!item; });
}

function ouParseGpoDetailLine(line) {
    var info = { name: 'GPO', status: 'Unknown', link: 'Unknown', enforced: 'Unknown', also: 'Unknown' };
    var parts = String(line || '').split('|').map(function(part) { return String(part || '').trim(); }).filter(function(part) { return !!part; });
    if (parts.length === 0) return info;
    info.name = parts[0] || info.name;
    for (var i = 1; i < parts.length; i++) {
        var kv = parts[i].split(':');
        if (kv.length < 2) continue;
        var key = String(kv[0] || '').trim().toLowerCase();
        var value = String(parts[i].slice(parts[i].indexOf(':') + 1) || '').trim();
        if (key === 'status') info.status = value || info.status;
        if (key === 'link') info.link = value || info.link;
        if (key === 'enforced') info.enforced = value || info.enforced;
        if (key === 'also linked') info.also = value || info.also;
    }
    return info;
}

function ouCloneWorkingData() {
    try {
        return JSON.parse(JSON.stringify(ouTreeData || []));
    } catch (e) {
        return Array.isArray(ouTreeData) ? ouTreeData.slice() : [];
    }
}

function buildOUTreeFrom(data) {
    var map = {};
    var roots = [];
    (data || []).forEach(function(item) {
        map[item.DN] = { DN: item.DN, Name: item.Name, Description: item.Description || '', GPLinks: item.GPLinks || 0, GPONames: item.GPONames || '', GPODetails: item.GPODetails || [], ManagedBy: item.ManagedBy || '', children: [], IsDomainRoot: false };
    });
    (data || []).forEach(function(item) {
        var parentDn = ouParentDn(item.DN);
        if (map[parentDn]) map[parentDn].children.push(map[item.DN]); else roots.push(map[item.DN]);
    });
    function sortNode(node) {
        node.children.sort(function(a, b) { return String(a.Name || '').localeCompare(String(b.Name || '')); });
        node.children.forEach(sortNode);
    }
    roots.sort(function(a, b) { return String(a.Name || '').localeCompare(String(b.Name || '')); });
    roots.forEach(sortNode);

    if (ouDomainRootName) {
        return [{
            DN: ouDomainRootDn || '',
            Name: ouDomainRootName,
            Description: 'Domain root',
            GPLinks: 0,
            GPONames: '',
            GPODetails: [],
            ManagedBy: '',
            children: roots,
            IsDomainRoot: true
        }];
    }
    return roots;
}

function findOuByDn(data, dn) {
    var rows = data || [];
    for (var i = 0; i < rows.length; i++) {
        if (rows[i].DN === dn) return rows[i];
    }
    return null;
}

function selectGpoDetail(payloadEncoded, event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    try {
        var payload = JSON.parse(decodeURIComponent(payloadEncoded));
        var sourceData = demoModeActive ? demoOUData : ouTreeData;
        var ownerOu = findOuByDn(sourceData, String(payload.ouDn || ''));
        if (ownerOu) {
            ouAdvisorState.selected = {
                name: String(ownerOu.Name || ''),
                dn: String(ownerOu.DN || ''),
                desc: String(ownerOu.Description || ''),
                gp: ouAdvisorNumber(ownerOu.GPLinks),
                gpNames: String(ownerOu.GPONames || ''),
                gpDetails: ouNormalizeGpoDetails(ownerOu.GPODetails),
                mb: String(ownerOu.ManagedBy || ''),
                tier: inferOUTier(String(ownerOu.Name || ''))
            };
        }
        ouAdvisorState.selectedGpo = {
            name: String(payload.name || ''),
            status: String(payload.status || 'Unknown'),
            link: String(payload.link || 'Unknown'),
            enforced: String(payload.enforced || 'Unknown'),
            also: String(payload.also || 'Unknown')
        };
        renderOUTierAdvisorShell();
    } catch (e) {}
}

function reRenderTree() {
    var el = document.getElementById('ouTreeNodes');
    if (!el) return;
    var data = demoModeActive ? demoOUData : ouTreeData;
    if (!data || data.length === 0) {
        el.innerHTML = '<div style="color:var(--color-text-secondary);font-size:13px;padding:12px">OU verisi bulunamadı.</div>';
        return;
    }
    var roots = buildOUTreeFrom(data);
    el.innerHTML = roots.map(function(root) { return renderNode(root, 0, demoModeActive); }).join('');
}

function toggleDemoMode() {
    demoModeActive = !demoModeActive;
    var btn = document.getElementById('demoToggleBtn');
    var banner = document.getElementById('demoBanner');
    var log = document.getElementById('demoChangeLog');
    var quickActions = document.getElementById('demoTreeActions');
    var quickHint = document.getElementById('demoTreeActionHint');
    if (demoModeActive) {
        if (btn) {
            btn.textContent = '⏹ Demo Modunu Kapat';
            btn.style.background = '#fef3c7';
            btn.style.borderColor = '#fcd34d';
        }
        if (banner) banner.style.display = 'block';
        if (log) log.style.display = 'block';
        if (quickActions) quickActions.style.display = 'block';
        if (quickHint) quickHint.textContent = 'Select an OU, then choose an action.';
        demoOUData = ouCloneWorkingData();
        reRenderTree();
    } else {
        if (btn) {
            btn.textContent = '▷ Demo Modunu Aç';
            btn.style.background = 'var(--color-background-primary)';
            btn.style.borderColor = 'var(--color-border-secondary)';
        }
        if (banner) banner.style.display = 'none';
        if (log) log.style.display = 'none';
        if (quickActions) quickActions.style.display = 'none';
        if (quickHint) quickHint.textContent = 'Select an OU, then choose an action.';
        demoOUData = [];
        initOUTree();
    }
}

function runDemoQuickAction(action) {
    if (!demoModeActive) return;
    if (!ouAdvisorState.selected || !ouAdvisorState.selected.dn) {
        alert('Please select an OU first.');
        return;
    }
    ctxTargetDN = ouAdvisorState.selected.dn;
    ctxTargetName = ouAdvisorState.selected.name;
    ctxAction(action);
}

function demoRenameInline(dn, name, event) {
    if (!demoModeActive) return;
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    ctxTargetDN = dn;
    ctxTargetName = name;
    ctxAction('rename');
}

function demoDragStart(dn, event) {
    dragSourceDN = dn;
    if (event && event.dataTransfer) event.dataTransfer.effectAllowed = 'move';
}

function demoDragOver(event) {
    if (!demoModeActive) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = 'move';
}

function demoDrop(targetDN, event) {
    if (!demoModeActive) return;
    event.preventDefault();
    if (!dragSourceDN || dragSourceDN === targetDN) return;
    var sourceItem = demoOUData.find(function(item) { return item.DN === dragSourceDN; });
    var targetItem = demoOUData.find(function(item) { return item.DN === targetDN; });
    if (!sourceItem || !targetItem) return;
    var oldDN = sourceItem.DN;
    var newParentDN = targetItem.DN;
    var oldParentDN = ouParentDn(oldDN);
    var newDN = 'OU=' + sourceItem.Name + ',' + newParentDN;
    demoOUData.forEach(function(item) {
        if (item.DN === oldDN || item.DN.indexOf(',' + oldDN) === item.DN.length - (',' + oldDN).length || item.DN.indexOf(oldDN + ',') > -1 || item.DN.indexOf(',' + oldDN + ',') !== -1 || item.DN.endsWith(',' + oldDN)) {
            item.DN = item.DN.replace(oldDN, newDN);
        }
    });
    addDemoLog('move', sourceItem.Name, oldParentDN, newParentDN);
    dragSourceDN = null;
    reRenderTree();
}

function demoContextMenu(dn, name, event) {
    if (!demoModeActive) return;
    event.preventDefault();
    ctxTargetDN = dn;
    ctxTargetName = name;
    var menu = document.getElementById('ouContextMenu');
    var label = document.getElementById('ctxOUName');
    if (label) label.textContent = name;
    if (!menu) return;
    menu.style.display = 'block';
    menu.style.left = event.clientX + 'px';
    menu.style.top = event.clientY + 'px';
}

document.addEventListener('click', function() {
    var menu = document.getElementById('ouContextMenu');
    if (menu) menu.style.display = 'none';
});

function ctxAction(action) {
    var menu = document.getElementById('ouContextMenu');
    if (menu) menu.style.display = 'none';
    if (!ctxTargetDN || !demoModeActive) return;

    if (action === 'create') {
        var newName = prompt('Yeni OU adı:');
        if (!newName || !newName.trim()) return;
        var cleanName = ouUniqueName(ctxTargetDN, newName.trim());
        demoOUData.push({ DN: 'OU=' + cleanName + ',' + ctxTargetDN, Name: cleanName, Description: '', GPLinks: 0, GPONames: '', GPODetails: [], ManagedBy: '' });
        addDemoLog('create', cleanName, 'OU=' + cleanName + ',' + ctxTargetDN, ctxTargetDN);
        reRenderTree();
    } else if (action === 'rename') {
        var renameTo = prompt('Yeni isim:', ctxTargetName);
        if (!renameTo || !renameTo.trim()) return;
        var ou = demoOUData.find(function(item) { return item.DN === ctxTargetDN; });
        if (!ou) return;
        var oldName = ou.Name;
        var parentDn = ouParentDn(ou.DN);
        var newName2 = ouUniqueName(parentDn, renameTo.trim());
        var oldRootDN = ou.DN;
        var newRootDN = 'OU=' + newName2 + (parentDn ? ',' + parentDn : '');
        demoOUData.forEach(function(item) {
            if (item.DN === oldRootDN || item.DN.endsWith(',' + oldRootDN)) {
                item.DN = item.DN.replace(oldRootDN, newRootDN);
                if (item.DN === newRootDN) item.Name = newName2;
            }
        });
        addDemoLog('rename', oldName, oldRootDN, newName2);
        ctxTargetDN = newRootDN;
        ctxTargetName = newName2;
        reRenderTree();
    } else if (action === 'delete') {
        if (!confirm('Demo: "' + ctxTargetName + '" OU\'su ve tüm alt OU\'ları silinecek. Onaylıyor musun?')) return;
        demoOUData = demoOUData.filter(function(item) {
            return !(item.DN === ctxTargetDN || item.DN.endsWith(',' + ctxTargetDN));
        });
        addDemoLog('delete', ctxTargetName, ctxTargetDN, null);
        ctxTargetDN = null;
        ctxTargetName = null;
        reRenderTree();
    } else if (action === 'editGpo') {
        var itemForGpo = demoOUData.find(function(item) { return item.DN === ctxTargetDN; });
        if (!itemForGpo) return;
        var existingGpos = String(itemForGpo.GPONames || '');
        var updatedGpos = prompt('GPO links (comma/semicolon separated):', existingGpos);
        if (updatedGpos === null) return;
        var gpoList = ouNormalizeGpoNames(updatedGpos);
        itemForGpo.GPONames = gpoList.join('; ');
        itemForGpo.GPLinks = gpoList.length;
        itemForGpo.GPODetails = gpoList.map(function(name) {
            return name + ' | Status: Demo custom | Link: Enabled | Enforced: No | Also linked: Unknown (demo)';
        });
        if (ouAdvisorState.selected && ouAdvisorState.selected.dn === itemForGpo.DN) {
            ouAdvisorState.selected.gp = itemForGpo.GPLinks;
            ouAdvisorState.selected.gpNames = itemForGpo.GPONames;
            ouAdvisorState.selected.gpDetails = itemForGpo.GPODetails;
        }
        addDemoLog('editGpo', itemForGpo.Name, itemForGpo.DN, gpoList.length + ' links');
        reRenderTree();
    }
}

function addDemoLog(action, name, dn, extra) {
    var icons = { create: '📁', rename: '✏️', delete: '🗑', move: '📦', editGpo: '🧩' };
    var labels = { create: 'Created', rename: 'Renamed', delete: 'Deleted', move: 'Moved', editGpo: 'GPO links updated' };
    var time = new Date().toLocaleTimeString();
    demoLog.unshift({ action: action, name: name, dn: dn, extra: extra, time: time });
    var container = document.getElementById('demoChangeLogItems');
    if (!container) return;
    if (demoLog.length === 0) {
        container.innerHTML = '<div style="padding:10px 12px;color:var(--color-text-secondary)">Henüz değişiklik yapılmadı.</div>';
        return;
    }
    container.innerHTML = demoLog.map(function(entry) {
        var icon = icons[entry.action] || '•';
        var label = labels[entry.action] || entry.action;
        var detail = '';
        if (entry.action === 'rename' && entry.extra) detail = ' → ' + entry.extra;
        if (entry.action === 'move' && entry.extra) detail = ' → ' + entry.extra;
        if (entry.action === 'create' && entry.extra) detail = ' under ' + entry.extra;
        if (entry.action === 'editGpo' && entry.extra) detail = ' (' + entry.extra + ')';
        return "<div style='padding:7px 12px;border-bottom:1px solid var(--color-border-tertiary);display:flex;gap:8px;align-items:flex-start'>" +
            "<span style='flex-shrink:0'>" + icon + "</span>" +
            "<div style='flex:1'>" +
            "<span style='font-weight:500;color:var(--color-text-primary)'>" + escapeHtml(String(entry.name || '')) + "</span>" +
            "<span style='color:var(--color-text-secondary)'> " + label + escapeHtml(String(detail)) + "</span>" +
            "<div style='font-size:10px;color:var(--color-text-secondary);margin-top:1px'>" + escapeHtml(String(entry.time || '')) + "</div>" +
            "</div></div>";
    }).join('');
}

function clearDemoLog() {
    demoLog = [];
    var container = document.getElementById('demoChangeLogItems');
    if (container) container.innerHTML = '<div style="padding:10px 12px;color:var(--color-text-secondary)">Henüz değişiklik yapılmadı.</div>';
}

function ouParentDn(dn) {
    var parts = String(dn || '').split(',');
    if (parts.length <= 1) return '';
    return parts.slice(1).join(',');
}

function ouFindNode(nodes, dn) {
    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        if (node.DN === dn) return node;
        if (node.children && node.children.length) {
            var childMatch = ouFindNode(node.children, dn);
            if (childMatch) return childMatch;
        }
    }
    return null;
}

function ouTraverse(nodes, callback) {
    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        callback(node);
        if (node.children && node.children.length) {
            ouTraverse(node.children, callback);
        }
    }
}

function ouRemoveNode(nodes, dn) {
    for (var i = 0; i < nodes.length; i++) {
        if (nodes[i].DN === dn) {
            nodes.splice(i, 1);
            return true;
        }
        if (nodes[i].children && nodes[i].children.length && ouRemoveNode(nodes[i].children, dn)) {
            return true;
        }
    }
    return false;
}

function ouUniqueName(parentDn, baseName) {
    var name = String(baseName || '').trim() || 'New OU';
    var existing = {};
    ouTraverse(ouTreeWorkingData, function(node) {
        if (ouParentDn(node.DN) === parentDn) {
            existing[node.Name.toLowerCase()] = true;
        }
    });
    if (!existing[name.toLowerCase()]) return name;
    var index = 2;
    while (existing[(name + ' ' + index).toLowerCase()]) index++;
    return name + ' ' + index;
}

function ouCreateChildNode(parentDn, childName) {
    var cleanName = ouUniqueName(parentDn, childName);
    return {
        DN: 'OU=' + cleanName + (parentDn ? ',' + parentDn : ''),
        Name: cleanName,
        Description: '',
        GPLinks: 0,
        ManagedBy: '',
        children: []
    };
}

function ouRefreshWorkingTree() {
    try {
        var selectedDn = ouAdvisorState.selected ? ouAdvisorState.selected.dn : '';
        var rebuilt = buildOUTree();
        ouTreeWorkingData = [];
        function flatten(nodes) {
            nodes.forEach(function(node) {
                ouTreeWorkingData.push({ DN: node.DN, Name: node.Name, Description: node.Description || '', GPLinks: node.GPLinks || 0, GPONames: node.GPONames || '', GPODetails: node.GPODetails || [], ManagedBy: node.ManagedBy || '' });
                if (node.children && node.children.length) flatten(node.children);
            });
        }
        flatten(rebuilt);
        if (selectedDn) {
            var selectedNode = ouFindNode(rebuilt, selectedDn);
            if (selectedNode) {
                ouAdvisorState.selected = {
                    name: selectedNode.Name,
                    dn: selectedNode.DN,
                    desc: selectedNode.Description || '',
                    gp: selectedNode.GPLinks || 0,
                    gpNames: selectedNode.GPONames || '',
                    gpDetails: selectedNode.GPODetails || [],
                    mb: selectedNode.ManagedBy || '',
                    tier: inferOUTier(selectedNode.Name)
                };
                ouAdvisorState.draft = {
                    name: ouAdvisorState.selected.name,
                    desc: ouAdvisorState.selected.desc,
                    gp: ouAdvisorState.selected.gp,
                    mb: ouAdvisorState.selected.mb
                };
            }
        }
    } catch (e) {}
}

function ouResetDemoTree() {
    ouTreeWorkingData = ouCloneWorkingData();
    ouAdvisorState.selected = null;
    ouAdvisorState.draft = null;
    initOUTree();
}

function ouAddChildToSelected() {
    if (!ouAdvisorState.selected) return;
    var parentDn = ouAdvisorState.selected.dn;
    var childNameInput = document.getElementById('ouDraftChildName');
    var childName = childNameInput ? String(childNameInput.value || '').trim() : '';
    var newChild = ouCreateChildNode(parentDn, childName || (ouAdvisorState.selected.name + ' Child'));
    ouTreeWorkingData.push({ DN: newChild.DN, Name: newChild.Name, Description: newChild.Description, GPLinks: newChild.GPLinks, GPONames: newChild.GPONames || '', GPODetails: newChild.GPODetails || [], ManagedBy: newChild.ManagedBy });
    ouAdvisorState.selected = {
        name: newChild.Name,
        dn: newChild.DN,
        desc: '',
        gp: 0,
        mb: '',
        tier: inferOUTier(newChild.Name)
    };
    ouAdvisorState.draft = { name: newChild.Name, desc: '', gp: 0, mb: '' };
    initOUTree();
}

function ouRenameSelected() {
    if (!ouAdvisorState.selected) return;
    var oldDn = ouAdvisorState.selected.dn;
    var newNameInput = document.getElementById('ouDraftName');
    var newDescInput = document.getElementById('ouDraftDesc');
    var newGpInput = document.getElementById('ouDraftGp');
    var newMbInput = document.getElementById('ouDraftMb');
    var newName = newNameInput ? String(newNameInput.value || '').trim() : ouAdvisorState.selected.name;
    var newDesc = newDescInput ? String(newDescInput.value || '').trim() : ouAdvisorState.selected.desc;
    var newGp = newGpInput ? ouAdvisorNumber(newGpInput.value) : ouAdvisorState.selected.gp;
    var newMb = newMbInput ? String(newMbInput.value || '').trim() : ouAdvisorState.selected.mb;
    var newDn = 'OU=' + (newName || ouAdvisorState.selected.name) + (ouParentDn(oldDn) ? ',' + ouParentDn(oldDn) : '');

    ouTreeWorkingData = ouTreeWorkingData.map(function(item) {
        var clone = {
            DN: item.DN,
            Name: item.Name,
            Description: item.Description || '',
            GPLinks: item.GPLinks || 0,
            GPONames: item.GPONames || '',
            GPODetails: item.GPODetails || [],
            ManagedBy: item.ManagedBy || ''
        };

        if (clone.DN === oldDn || clone.DN.endsWith(',' + oldDn)) {
            clone.DN = clone.DN.replace(oldDn, newDn);
        }

        if (item.DN === oldDn) {
            clone.Name = newName || item.Name;
            clone.Description = newDesc;
            clone.GPLinks = newGp;
            clone.ManagedBy = newMb;
        }

        return clone;
    });

    ouAdvisorState.selected = {
        name: newName || ouAdvisorState.selected.name,
        dn: newDn,
        desc: newDesc,
        gp: newGp,
        mb: newMb,
        tier: inferOUTier(newName || ouAdvisorState.selected.name)
    };
    ouAdvisorState.draft = { name: ouAdvisorState.selected.name, desc: newDesc, gp: newGp, mb: newMb };
    initOUTree();
}

function ouDeleteSelected() {
    if (!ouAdvisorState.selected) return;
    var dn = ouAdvisorState.selected.dn;
    ouTreeWorkingData = ouTreeWorkingData.filter(function(item) {
        return !(item.DN === dn || item.DN.endsWith(',' + dn));
    });
    ouAdvisorState.selected = null;
    ouAdvisorState.draft = null;
    initOUTree();
}

function toggleOuReference(sectionId) {
    var body = document.getElementById(sectionId);
    if (!body) return;
    body.style.display = (body.style.display === 'none') ? 'block' : 'none';
}

function inferOUTier(name) {
        const n = name.toLowerCase();
        if (['domain controller','domain controllers','dc','paw','privileged','tier0','tier 0','service account','service accounts','laps','schema','krbtgt'].some(k=>n.includes(k)))
                return {tier:0, color:'#dc2626', label:'T0', reason:'Tier 0 keyword match (DC / PAW / privileged)'};
        if (['server','servers','application','app','file','database','db','sql','web','exchange','tier1','tier 1','member server'].some(k=>n.includes(k)))
                return {tier:1, color:'#d97706', label:'T1', reason:'Tier 1 keyword match (server / application)'};
        if (['workstation','workstations','laptop','desktop','user','users','client','helpdesk','help desk','tier2','tier 2','computer','computers','standard'].some(k=>n.includes(k)))
                return {tier:2, color:'#2563eb', label:'T2', reason:'Tier 2 keyword match (workstation / user)'};
        return {tier:-1, color:'#6b7280', label:'?', reason:'Tier belirlenemedi — manuel inceleme gerekli'};
}

function buildOUTree() {
        const map = {};
    ouTreeWorkingData.forEach(o => { map[o.DN] = {...o, children:[]}; });
        const roots = [];
    ouTreeWorkingData.forEach(o => {
                const parentDN = o.DN.split(',').slice(1).join(',');
                if (map[parentDN]) map[parentDN].children.push(map[o.DN]);
                else roots.push(map[o.DN]);
        });
        function sort(n) { n.children.sort((a,b)=>a.Name.localeCompare(b.Name)); n.children.forEach(sort); }
        roots.forEach(sort);
        return roots;
}

function renderNode(node, depth, interactive) {
        const tier = inferOUTier(node.Name);
        const hasKids = node.children && node.children.length > 0;
        const detailLines = ouNormalizeGpoDetails(node.GPODetails);
        const gpoItems = (detailLines.length > 0)
            ? detailLines.map(function(line) { return ouParseGpoDetailLine(line); })
            : ouNormalizeGpoNames(node.GPONames).map(function(name) {
                return { name: name, status: 'Unknown', link: 'Unknown', enforced: 'Unknown', also: 'Unknown' };
            });
        const hasChildContent = hasKids || gpoItems.length > 0;
        const id = 'ou' + Math.random().toString(36).substr(2,9);
        const rowBorder = node.IsDomainRoot ? '#0ea5a3' : 'var(--color-border-tertiary)';
        const rowBg = node.IsDomainRoot ? 'rgba(14,165,163,.10)' : 'var(--color-background-primary)';
        const rowWeight = node.IsDomainRoot ? '700' : '600';
        const rowCursor = interactive ? 'grab' : 'pointer';
    const data = encodeURIComponent(JSON.stringify({ name: node.Name, dn: node.DN, desc: node.Description || '', gp: node.GPLinks || 0, gpNames: node.GPONames || '', gpDetails: node.GPODetails || [], mb: node.ManagedBy || '', tier: tier }));
    const dragAttrs = interactive ? "draggable='true' ondragstart='demoDragStart(" + "\"" + String(node.DN).replace(/'/g, "\\'") + "\"" + ",event)' ondragover='demoDragOver(event)' ondrop='demoDrop(" + "\"" + String(node.DN).replace(/'/g, "\\'") + "\"" + ",event)'" : '';
    const contextAttr = interactive ? "oncontextmenu='demoContextMenu(" + "\"" + String(node.DN).replace(/'/g, "\\'") + "\"" + "," + "\"" + String(node.Name || '').replace(/'/g, "\\'") + "\"" + ",event)'" : '';
    const dblClickAttr = interactive ? "ondblclick='demoRenameInline(" + "\"" + String(node.DN).replace(/'/g, "\\'") + "\"" + "," + "\"" + String(node.Name || '').replace(/'/g, "\\'") + "\"" + ",event)'" : '';
    let html = '';
    html += "<div class='ou-row' data-root='" + (node.IsDomainRoot ? '1' : '0') + "' id='" + id + "-row' " + dragAttrs + " " + contextAttr + " " + dblClickAttr + " style='padding-left:" + (depth * 18 + 10) + "px;display:flex;align-items:center;gap:6px;padding-top:7px;padding-bottom:7px;padding-right:8px;margin:3px 0;border:1px solid " + rowBorder + ";background:" + rowBg + ";cursor:" + rowCursor + ";border-radius:10px;font-weight:" + rowWeight + "' onclick='ouClick(\"" + id + "\",\"" + data + "\",event)'>";
    html += "<span id='" + id + "-tog' style='width:14px;font-size:10px;color:var(--color-text-secondary);flex-shrink:0'>" + (hasChildContent ? '▶' : '') + "</span>";
    html += "<i id='" + id + "-ico' class='fa-solid " + (node.IsDomainRoot ? 'fa-globe' : (hasChildContent ? 'fa-folder' : 'fa-folder-open')) + "' style='color:" + (node.IsDomainRoot ? '#0f766e' : '#f59e0b') + ";font-size:13px;flex-shrink:0'></i>";
    html += "<span style='flex:1;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>" + escapeHtml(String(node.Name || '')) + "</span>";
    if (node.GPLinks > 0) html += "<span style='font-size:10px;background:#dbeafe;color:#1e40af;padding:1px 6px;border-radius:10px;flex-shrink:0'>" + escapeHtml(String(node.GPLinks)) + " GPO</span>";
    html += "<span style='font-size:10px;color:#fff;padding:1px 6px;border-radius:10px;background:" + tier.color + ";flex-shrink:0'>" + tier.label + "</span>";
    html += "</div>";
    if (hasChildContent) {
        html += "<div id='" + id + "-ch' style='display:none'>";
        gpoItems.forEach(function(gpo) {
            var linkEnabled = String(gpo.link || '').toLowerCase() === 'enabled';
            var enforcedYes = String(gpo.enforced || '').toLowerCase() === 'yes';
            var linkTone = linkEnabled ? '#1d4ed8' : '#9ca3af';
            var rowBg = linkEnabled ? 'rgba(37,99,235,.06)' : 'rgba(107,114,128,.10)';
            var rowBorder = linkEnabled ? 'rgba(37,99,235,.22)' : 'rgba(107,114,128,.25)';
            var lockIcon = enforcedYes ? 'fa-lock' : 'fa-unlock';
            var lockTone = enforcedYes ? '#b91c1c' : '#6b7280';
            var alsoLinked = String(gpo.also || 'Unknown');
            var compactMeta = 'Status: ' + String(gpo.status || 'Unknown') + ' | Also linked: ' + alsoLinked;
            var gpoPayload = encodeURIComponent(JSON.stringify({ ouDn: node.DN, name: gpo.name, status: gpo.status, link: gpo.link, enforced: gpo.enforced, also: gpo.also }));
            html += "<div title='" + escapeHtml(compactMeta) + "' style='padding-left:" + (depth * 18 + 30) + "px;display:flex;align-items:center;gap:6px;padding:3px 6px 3px " + (depth * 18 + 30) + "px;margin:2px 0;border:1px solid " + rowBorder + ";border-radius:8px;background:" + rowBg + "'>" +
                "<i class='fa-solid fa-link' style='color:" + linkTone + ";font-size:11px;flex-shrink:0'></i>" +
                "<span onclick='selectGpoDetail(\"" + gpoPayload + "\",event)' style='font-size:11px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer;text-decoration:" + (linkEnabled ? 'none' : 'line-through') + ";opacity:" + (linkEnabled ? '1' : '.78') + "'>" + escapeHtml(String(gpo.name || 'GPO')) + "</span>" +
                "<span style='font-size:10px;color:" + linkTone + ";font-weight:700;flex-shrink:0'>" + (linkEnabled ? 'Linked' : 'Disabled') + "</span>" +
                (enforcedYes ? "<span style='font-size:9px;background:#dc2626;color:#fff;padding:1px 5px;border-radius:8px;flex-shrink:0'>ENF</span>" : '') +
                "<i class='fa-solid " + lockIcon + "' style='color:" + lockTone + ";font-size:10px;flex-shrink:0' title='Enforced: " + escapeHtml(String(gpo.enforced || 'Unknown')) + "'></i>" +
                "</div>" +
                "<div style='padding-left:" + (depth * 18 + 48) + "px;padding-bottom:2px;font-size:10px;color:var(--color-text-secondary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis'>" +
                escapeHtml('Status: ' + String(gpo.status || 'Unknown') + ' | Also linked: ' + alsoLinked) +
                "</div>";
        });
        node.children.forEach(function(c) { html += renderNode(c, depth + 1, interactive); });
        html += "</div>";
    }
    return html;
}

function ouClick(id, encoded, event) {
        const ch  = document.getElementById(id + '-ch');
        const tog = document.getElementById(id + '-tog');
        const ico = document.getElementById(id + '-ico');
        const row = document.getElementById(id + '-row');
        if (ch) {
                const open = ch.style.display !== 'none';
                ch.style.display = open ? 'none' : 'block';
                if (tog) tog.textContent = open ? '▶' : '▼';
        if (ico && row && row.getAttribute('data-root') !== '1') { ico.className = 'fa-solid ' + (open ? 'fa-folder' : 'fa-folder-open'); ico.style.color = '#f59e0b'; }
        }
    document.querySelectorAll('.ou-row').forEach(function(r) { r.classList.remove('ou-selected'); });
    if (row) row.classList.add('ou-selected');
        try { updateAdvisor(JSON.parse(decodeURIComponent(encoded))); } catch(e) {}
}

function updateAdvisor(d) {
        const el = document.getElementById('tierAdvisorSelected');
        if (!el) return;
    ouAdvisorState.selected = {
    name: String(d.name || ''),
    dn: String(d.dn || ''),
    desc: String(d.desc || ''),
    gp: ouAdvisorNumber(d.gp),
    gpNames: String(d.gpNames || ''),
    gpDetails: ouNormalizeGpoDetails(d.gpDetails),
    mb: String(d.mb || ''),
    tier: d.tier
    };
    ouAdvisorState.draft = {
    name: ouAdvisorState.selected.name,
    desc: ouAdvisorState.selected.desc,
    gp: ouAdvisorState.selected.gp,
    mb: ouAdvisorState.selected.mb
    };
    if (demoModeActive) {
        var quickHint = document.getElementById('demoTreeActionHint');
        if (quickHint) quickHint.textContent = 'Selected: ' + ouAdvisorState.selected.name;
    }
    ouAdvisorState.selectedGpo = null;
    renderOUTierAdvisorShell();
}

function applyAdvisorDraft(){
    if (!ouAdvisorState.selected) return;
    var nameEl = document.getElementById('ouDraftName');
    var descEl = document.getElementById('ouDraftDesc');
    var gpEl = document.getElementById('ouDraftGp');
    var mbEl = document.getElementById('ouDraftMb');
    var name = nameEl ? String(nameEl.value || '').trim() : ouAdvisorState.selected.name;
    var desc = descEl ? String(descEl.value || '').trim() : ouAdvisorState.selected.desc;
    var gp = gpEl ? ouAdvisorNumber(gpEl.value) : ouAdvisorState.selected.gp;
    var mb = mbEl ? String(mbEl.value || '').trim() : ouAdvisorState.selected.mb;
    var tier = inferOUTier(name || ouAdvisorState.selected.name);
    ouAdvisorState.selected = {
        name: name || ouAdvisorState.selected.name,
        dn: ouAdvisorState.selected.dn,
        desc: desc,
        gp: gp,
        mb: mb,
        tier: tier
    };
    ouAdvisorState.draft = {
        name: ouAdvisorState.selected.name,
        desc: ouAdvisorState.selected.desc,
        gp: ouAdvisorState.selected.gp,
        mb: ouAdvisorState.selected.mb
    };
    renderOUTierAdvisorShell();
}

function resetAdvisorDraft(){
    if (!ouAdvisorState.selected) return;
    ouAdvisorState.draft = {
        name: ouAdvisorState.selected.name,
        desc: ouAdvisorState.selected.desc,
        gp: ouAdvisorState.selected.gp,
        mb: ouAdvisorState.selected.mb
    };
    renderOUTierAdvisorShell();
}

function renderOUTierAdvisorShell(){
    var selectedEl = document.getElementById('tierAdvisorSelected');
    var referenceEl = document.getElementById('tierAdvisorReference');
    if (!selectedEl || !referenceEl) return;

    if (!ouAdvisorState.selected) {
        selectedEl.innerHTML = "<div style='color:var(--color-text-secondary);font-size:13px;padding:12px;border:1px dashed var(--color-border-secondary);border-radius:8px;text-align:center'>" +
            ouAdvisorText('Click an OU in the tree to see tier analysis', 'Ağaçta bir OU seçince tier analizi burada görünür') +
            "</div>";
    } else {
        var current = ouAdvisorState.selected;
        var draft = ouAdvisorState.draft || current;
        var gpoDetailItems = ouNormalizeGpoDetails(current.gpDetails);
        selectedEl.innerHTML = "<div style='border-left:4px solid " + current.tier.color + ";padding:10px 14px;border-radius:0 8px 8px 0;background:var(--color-background-secondary);margin-bottom:14px'>" +
            "<div style='font-size:11px;color:var(--color-text-secondary)'>" + ouAdvisorText('Selected OU', 'Seçili OU') + "</div>" +
            "<div style='font-weight:500;font-size:15px;margin:2px 0'>" + escapeHtml(String(current.name || '')) + "</div>" +
            (current.desc ? "<div style='font-size:12px;color:var(--color-text-secondary);margin-top:2px'>" + escapeHtml(String(current.desc)) + "</div>" : '') +
            "<div style='margin-top:8px;display:flex;gap:6px;flex-wrap:wrap'>" +
            "<span style='background:" + current.tier.color + ";color:#fff;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:500'>" + ouAdvisorText('Tier', 'Tier') + " " + (current.tier.tier < 0 ? '?' : current.tier.tier) + "</span>" +
            (current.gp > 0 ? "<span style='background:var(--color-background-tertiary);padding:2px 10px;border-radius:20px;font-size:12px'>" + escapeHtml(String(current.gp)) + " GPO linked</span>" : '') +
            (current.mb ? "<span style='background:var(--color-background-tertiary);padding:2px 10px;border-radius:20px;font-size:12px'>" + escapeHtml(String(current.mb)) + "</span>" : '') +
            "</div>" +
            (current.gpNames ? "<div style='font-size:11px;color:var(--color-text-secondary);margin-top:6px'><b>Linked GPOs:</b> " + escapeHtml(String(current.gpNames)) + "</div>" : '') +
            (gpoDetailItems.length ? "<div style='margin-top:8px;padding:8px;border:1px solid var(--color-border-tertiary);border-radius:8px;background:var(--color-background-primary)'><div style='font-size:11px;font-weight:600;margin-bottom:4px'>GPO Settings & Link Scope</div><ul style='margin:0;padding-left:18px;font-size:11px;color:var(--color-text-secondary);line-height:1.5'>" + gpoDetailItems.map(function(line){ return "<li>" + escapeHtml(String(line)) + "</li>"; }).join('') + "</ul></div>" : '') +
            "<div style='font-size:11px;color:var(--color-text-secondary);margin-top:6px'>" + escapeHtml(String(current.tier.reason || '')) + "</div>" +
            "</div>";

        if (ouAdvisorState.selectedGpo) {
            var g = ouAdvisorState.selectedGpo;
            selectedEl.innerHTML += "<div style='margin-bottom:12px;padding:10px 12px;border:1px solid var(--color-border-tertiary);border-radius:10px;background:var(--color-background-primary)'>" +
                "<div style='font-size:11px;font-weight:700;color:var(--color-text-secondary);letter-spacing:.04em;margin-bottom:6px'>FOCUSED GPO</div>" +
                "<div style='font-size:13px;font-weight:600;margin-bottom:6px'>" + escapeHtml(String(g.name || 'GPO')) + "</div>" +
                "<div style='font-size:11px;color:var(--color-text-secondary);line-height:1.6'>Status: " + escapeHtml(String(g.status || 'Unknown')) + "<br>Link: " + escapeHtml(String(g.link || 'Unknown')) + "<br>Enforced: " + escapeHtml(String(g.enforced || 'Unknown')) + "<br>Also linked: " + escapeHtml(String(g.also || 'Unknown')) + "</div>" +
                "</div>";
        }

    }

    referenceEl.innerHTML = "<div style='font-size:11px;font-weight:500;color:var(--color-text-secondary);margin-bottom:8px;letter-spacing:.05em'>" + ouAdvisorText('TIER REFERENCE', 'TIER REFERENCE') + "</div>" +
        "<div style='border:1px solid var(--color-border-tertiary);border-radius:8px;margin-bottom:8px;overflow:hidden'>" +
        "<div style='padding:10px 14px;cursor:pointer;font-weight:500;font-size:13px;border-left:4px solid #dc2626;display:flex;justify-content:space-between' onclick='toggleOuReference(\"ouTier0Ref\")'>" +
        "<span>Tier 0 — Control Plane</span><span>▾</span></div>" +
        "<div id='ouTier0Ref' style='padding:12px 14px;font-size:12px;color:var(--color-text-secondary);line-height:1.6;border-top:1px solid var(--color-border-tertiary)'>" +
        "<b>Who belongs:</b> DCs, PAW, privileged service accounts, PKI/CA<br><br>" +
        "<b>Required controls:</b><br>" +
        "• No interactive logon from lower tiers<br>" +
        "• Protected Users membership required<br>" +
        "• LAPS with short expiry enforced<br>" +
        "• Dedicated GPO, no logon rights for lower-tier accounts<br>" +
        "• Maximum audit policy" +
        "</div></div>" +
        "<div style='border:1px solid var(--color-border-tertiary);border-radius:8px;margin-bottom:8px;overflow:hidden'>" +
        "<div style='padding:10px 14px;cursor:pointer;font-weight:500;font-size:13px;border-left:4px solid #d97706;display:flex;justify-content:space-between' onclick='toggleOuReference(\"ouTier1Ref\")'>" +
        "<span>Tier 1 — Server Tier</span><span>▾</span></div>" +
        "<div id='ouTier1Ref' style='padding:12px 14px;font-size:12px;color:var(--color-text-secondary);line-height:1.6;border-top:1px solid var(--color-border-tertiary);display:none'>" +
        "<b>Who belongs:</b> Member servers, app/DB/file servers<br><br>" +
        "<b>Required controls:</b><br>" +
        "• Separate Tier 1 admin account (do not use DA)<br>" +
        "• Server hardening GPO (SMB signing, LSASS)<br>" +
        "• LAPS required on all member servers<br>" +
        "• Restricted Admin mode for RDP" +
        "</div></div>" +
        "<div style='border:1px solid var(--color-border-tertiary);border-radius:8px;margin-bottom:8px;overflow:hidden'>" +
        "<div style='padding:10px 14px;cursor:pointer;font-weight:500;font-size:13px;border-left:4px solid #2563eb;display:flex;justify-content:space-between' onclick='toggleOuReference(\"ouTier2Ref\")'>" +
        "<span>Tier 2 — User &amp; Workstation</span><span>▾</span></div>" +
        "<div id='ouTier2Ref' style='padding:12px 14px;font-size:12px;color:var(--color-text-secondary);line-height:1.6;border-top:1px solid var(--color-border-tertiary);display:none'>" +
        "<b>Who belongs:</b> Workstations, standard users, helpdesk<br><br>" +
        "<b>Required controls:</b><br>" +
        "• AppLocker / WDAC policy<br>" +
        "• Credential Guard enabled<br>" +
        "• No local admin for standard users<br>" +
        "• LAPS on all workstations<br>" +
        "• ASR rules enabled" +
        "</div></div>";
        if (currentLanguage === 'tr') {
            applyDomTranslation('tr');
        }
}

function initOUTree() {
    if (demoModeActive) {
        reRenderTree();
        return;
    }
        const el = document.getElementById('ouTreeNodes');
        if (!el || ouTreeData.length === 0) {
                if (el) el.innerHTML = '<div style="color:var(--color-text-secondary);font-size:13px;padding:12px">OU verisi bulunamadı.</div>';
                return;
        }
        const roots = buildOUTreeFrom(ouTreeData);
        el.innerHTML = roots.map(function(r) { return renderNode(r, 0, false); }).join('');
    renderOUTierAdvisorShell();
}

document.addEventListener('DOMContentLoaded', function() {
    var menu = document.getElementById('ouContextMenu');
    if (menu) menu.style.display = 'none';
});
</script>
"@

# INACTIVE USERS CONTAINER
$Html += "<div class='container' id='inactiveUsersContainer' style='display:none;'><div class='content-card'>" 
$Html += "<h2>Inactive Users (Last Logon > 90 Days)</h2>"
$Html += "<p class='section-intro'>Dormant user accounts increase attack surface and credential exposure risk.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Inactive Users</div><div class='section-stat-value'>$(@($InactiveUsers).Count)</div><div class='section-stat-note'>Current 90-day threshold</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Never Logged On</div><div class='section-stat-value'>$InactiveUsersNeverLogonCount</div><div class='section-stat-note'>Potential stale identities</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Very Stale 180d+</div><div class='section-stat-value'>$InactiveUsersVeryStaleCount</div><div class='section-stat-note'>Strong cleanup candidates</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Prioritize disable/delete after business validation.</span><div class='table-wrapper'>"
$Html += "<table class='user-table' id='inactiveUsersTable'><tr>
<th onclick='sortTable(""inactiveUsersTable"",0)'>User Name</th>
<th onclick='sortTable(""inactiveUsersTable"",1)'>Last Logon</th>
</tr>"
foreach ($u in $InactiveUsers | Sort Name) {
    $Html += "<tr><td>$($u.Name)</td><td>$($u.LastLogon)</td></tr>"
}
$Html += "</table></div></div></div>"

# INACTIVE COMPUTERS CONTAINER
$Html += "<div class='container' id='inactiveComputersContainer' style='display:none;'><div class='content-card'>" 
$Html += "<h2>Inactive Computers (Last Logon > 90 Days)</h2>"
$Html += "<p class='section-intro'>Dormant machine accounts can retain old trust paths and unmanaged access.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Inactive Computers</div><div class='section-stat-value'>$(@($InactiveComputers).Count)</div><div class='section-stat-note'>Current 90-day threshold</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Never Logged On</div><div class='section-stat-value'>$InactiveComputersNeverLogonCount</div><div class='section-stat-note'>Provisioning residue</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Very Stale 180d+</div><div class='section-stat-value'>$InactiveComputersVeryStaleCount</div><div class='section-stat-note'>Cleanup priority</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Confirm decommission status before account removal.</span><div class='table-wrapper'>"
$Html += "<table class='user-table' id='inactiveComputersTable'><tr>
<th onclick='sortTable(""inactiveComputersTable"",0)'>Hostname</th>
<th onclick='sortTable(""inactiveComputersTable"",1)'>Last Logon</th>
<th onclick='sortTable(""inactiveComputersTable"",2)'>OS</th>
</tr>"
foreach ($c in $InactiveComputers | Sort Name) {
    $Html += "<tr><td>$($c.Name)</td><td>$($c.LastLogon)</td><td>$($c.OperatingSystem)</td></tr>"
}
$Html += "</table></div></div></div>"

# ---------------------
# AD Risk Dashboard Container
# ---------------------
$Html += "<div class='container' id='pingCastleRisksContainer' style='display:flex;'><div class='content-card'>"
$Html += "<div class='risk-command-hero'>"
$Html += "<div class='risk-command-kicker'>Command Center</div>"
$Html += "<h2 class='risk-command-title'>AD Risk Mission Board</h2>"
$Html += "<p class='risk-command-sub'>Fast path: read current exposure, execute actions, then track closure status. Designed for daily operational rhythm.</p>"
$Html += "<div class='risk-story-strip'>"
$Html += "<button class='risk-story-step' onclick='scrollRiskStoryboard(""riskNowAnchor"")'><b>Step 1</b><span>Read Risk Now</span></button>"
$Html += "<button class='risk-story-step' onclick='scrollRiskStoryboard(""riskActionAnchor"")'><b>Step 2</b><span>Execute Actions</span></button>"
$Html += "<button class='risk-story-step' onclick='scrollRiskStoryboard(""riskTrackAnchor"")'><b>Step 3</b><span>Track Closure</span></button>"
$Html += "</div>"
$Html += "</div>"
$Html += "<div class='risk-quick-nav'>"
$Html += "<span class='risk-quick-nav-label' data-i18n-key='risk.quickJump'>Quick Jump</span>"
$Html += "<button class='risk-quick-jump' onclick='scrollRiskStoryboard(""riskNowAnchor"")' data-i18n-key='risk.quickRiskNow'>Risk Now</button>"
$Html += "<button class='risk-quick-jump' onclick='scrollRiskStoryboard(""riskModelAnchor"")' data-i18n-key='risk.quickRiskModel'>Risk Model</button>"
$Html += "<button class='risk-quick-jump' onclick='scrollRiskStoryboard(""riskFindingsAnchor"")' data-i18n-key='risk.quickFindings'>Findings</button>"
$Html += "<button class='risk-quick-jump' onclick='scrollRiskStoryboard(""riskActionAnchor"")' data-i18n-key='risk.quickActions'>Actions</button>"
$Html += "<button class='risk-quick-jump' onclick='scrollRiskStoryboard(""caRiskAnchor"")' data-i18n-key='risk.quickCA'>CA</button>"
$Html += "<button class='risk-quick-jump' onclick='scrollRiskStoryboard(""riskTrackAnchor"")' data-i18n-key='risk.quickTracking'>Tracking</button>"
$Html += "<button class='risk-quick-jump' onclick='scrollRiskStoryboard(""riskWatchAnchor"")' data-i18n-key='risk.quickWatchlist'>Watchlist</button>"
$Html += "</div>"
$Html += "<div class='risk-action-toolbar'>"
$Html += "<button class='risk-action-btn' onclick='exportExecutiveSummaryPdf()'>Executive PDF</button>"
$Html += "<button class='risk-action-btn' onclick='exportRemediationChecklistPdf()'>Remediation Checklist PDF</button>"
$Html += "<button class='risk-action-btn' onclick='copyPermalinkState()' data-i18n-key='risk.copyDashboardLink'>Copy Dashboard Link</button>"
$Html += "<button class='risk-action-btn' onclick='exportMitreNavigatorJson()'>MITRE Navigator JSON</button>"
$Html += "<button class='risk-action-btn' onclick='exportRemediationTrackingJson()'>Tracking JSON Export</button>"
$Html += "</div>"
$PingCriticalCount = @($PingCastleFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
$PingHighCount = @($PingCastleFindings | Where-Object { $_.Severity -eq 'High' }).Count
$PingMediumCount = @($PingCastleFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
$PingSeverityTotal = [Math]::Max(1, ($PingCriticalCount + $PingHighCount + $PingMediumCount))
$PingCriticalPct = [int][math]::Round(($PingCriticalCount * 100.0) / $PingSeverityTotal, 0)
$PingHighPct = [int][math]::Round(($PingHighCount * 100.0) / $PingSeverityTotal, 0)
$PingMediumPct = [int][math]::Round(($PingMediumCount * 100.0) / $PingSeverityTotal, 0)
$PingActionableCount = $PingCriticalCount + $PingHighCount
$TopRuleFinding = @($PingCastleFindings | Sort-Object @{Expression={ Get-PingSeverityRank $_.Severity }; Descending=$true}, @{Expression={ $safeCount = 0; [void][int]::TryParse([string]$_.Count, [ref]$safeCount); $safeCount }; Descending=$true}) | Select-Object -First 1
$TopRuleName = if ($TopRuleFinding) { $TopRuleFinding.Rule } else { '-' }
$TopRuleCount = if ($TopRuleFinding) { [int]$TopRuleFinding.Count } else { 0 }
$Html += "<div class='risk-exec-grid'>"
$Html += "<div class='risk-exec-card'><div class='risk-exec-label'>Critical Findings</div><div class='risk-exec-value'>$PingCriticalCount</div><div class='risk-exec-note'>Immediate containment needed</div><div class='risk-exec-progress'><span class='risk-exec-progress-fill risk-exec-progress-critical' style='width:$($PingCriticalPct)%'></span></div></div>"
$Html += "<div class='risk-exec-card'><div class='risk-exec-label'>High Findings</div><div class='risk-exec-value'>$PingHighCount</div><div class='risk-exec-note'>Prioritize in current sprint</div><div class='risk-exec-progress'><span class='risk-exec-progress-fill risk-exec-progress-high' style='width:$($PingHighPct)%'></span></div></div>"
$Html += "<div class='risk-exec-card'><div class='risk-exec-label'>Medium Findings</div><div class='risk-exec-value'>$PingMediumCount</div><div class='risk-exec-note'>Track and reduce baseline drift</div><div class='risk-exec-progress'><span class='risk-exec-progress-fill risk-exec-progress-medium' style='width:$($PingMediumPct)%'></span></div></div>"
$Html += "<div class='risk-exec-card'><div class='risk-exec-label'>Top Risk Rule</div><div class='risk-exec-value' style='font-size:15px;'>$TopRuleName</div><div class='risk-exec-note'>Observed count: $TopRuleCount | Critical+High: $PingActionableCount</div></div>"
$Html += "</div>"
$GlobalChipClass = switch ($RiskRating) {
    "Good" { "risk-chip risk-chip-low" }
    "Acceptable" { "risk-chip risk-chip-med" }
    "Poor" { "risk-chip risk-chip-poor" }
    default { "risk-chip risk-chip-high" }
}
$GlobalLevelText = $RiskRating
$GaugeRadius = 62
$GaugeCircumference = [math]::Round((2 * [math]::PI * $GaugeRadius), 2)
$GaugeOffset = [math]::Round($GaugeCircumference * (1 - ($DomainRiskScore / 100.0)), 2)
$GaugeClass = switch ($RiskRating) {
    "Good" { "risk-gauge-good" }
    "Acceptable" { "risk-gauge-acceptable" }
    "Poor" { "risk-gauge-poor" }
    default { "risk-gauge-critical" }
}
$RiskConfidenceChipClass = switch ($RiskConfidenceLevel) {
    "High" { "risk-confidence-chip risk-confidence-high" }
    "Medium" { "risk-confidence-chip risk-confidence-medium" }
    default { "risk-confidence-chip risk-confidence-low" }
}

$Html += "<div id='riskNowAnchor' class='risk-score-card'>"
$Html += "<div class='risk-score-main'>"
$Html += "<div class='risk-gauge-wrap'>"
$Html += "<svg class='risk-gauge-svg' viewBox='0 0 170 170' aria-label='Domain risk score gauge'>"
$Html += "<circle class='risk-gauge-bg' cx='85' cy='85' r='$GaugeRadius'></circle>"
$Html += "<circle class='$GaugeClass' cx='85' cy='85' r='$GaugeRadius' style='stroke-dasharray:$GaugeCircumference;stroke-dashoffset:$GaugeOffset;'></circle>"
$Html += "</svg>"
$Html += "<div class='risk-gauge-center'><div class='risk-gauge-score'>$DomainRiskScore</div><div class='risk-gauge-max'>/100</div></div>"
$Html += "</div>"
$Html += "<div class='risk-score-text'>"
$Html += "<h3>Domain Risk Level: $DomainRiskScore / 100</h3>"
$Html += "<p>Score increases with risk. Each category is normalized by its threshold and combined with equal category weights.</p>"
$Html += "<p>Raw penalty points: $RawPenalty (Critical=25, High=10, Medium=4, Low=1)</p>"
$Html += "<p style='margin-top:8px;'><span class='$GlobalChipClass'>$GlobalLevelText</span><span class='$RiskConfidenceChipClass'>Confidence: $RiskConfidenceLevel</span></p>"
$Html += "<p class='risk-confidence-note'>$([System.Net.WebUtility]::HtmlEncode([string]$RiskConfidenceNote))</p>"
$Html += "</div></div>"

$Html += "<div class='table-wrapper'>"
$Html += "<table class='risk-breakdown-table'><tr><th>Category</th><th>Penalty Points</th><th>Category Risk %</th><th>Matched Rules</th></tr>"
foreach ($row in $CategoryPenaltyRows) {
    $Html += "<tr><td>$($row.Category)</td><td>$($row.Penalty)</td><td>$($row.RiskPct)%</td><td>$($row.Matched)</td></tr>"
}
$Html += "</table></div>"

$Html += "<div class='risk-overview-grid'>"
$Html += "<div class='risk-sim-card'><h3>Score Impact Simulation</h3><p class='risk-model-note'>Model how closing findings can lower risk score before remediation execution.</p><div id='riskImpactSimulatorBody'></div></div>"
$Html += "<div class='risk-contrib-card'><h3>Risk Contribution Decomposition</h3><p class='risk-model-note'>Shows which primary categories contribute most to the current score.</p><div id='riskContributionBody'></div></div>"
$Html += "</div>"

$Html += "<div class='risk-mini-grid'>"
foreach ($cat in $PingScoreCategoriesPrimary) {
    $catScore = [int]$CategoryPenaltyMap[$cat]
    $catMatchedCount = [int]$PingCategoryMatchedCountMap[$cat]
    $safeCat = $cat -replace '[^a-zA-Z0-9]',''
    $Html += "<div class='risk-mini-card' onclick='focusPingCategory(""pingCastleCategory$safeCat"")'>"
    $Html += "<h4>${cat}: $catScore point</h4>"
    $Html += "<div class='risk-mini-meta'><span>Matched rules: $catMatchedCount</span><span>Click to open</span></div>"
    $Html += "</div>"
}
$Html += "</div></div>"

$Html += "<h3 id='riskModelAnchor' class='risk-model-title'>Risk Model</h3>"
$Html += "<p class='risk-model-note'>Click any risk cell to jump directly to that finding.</p>"
$Html += "<div class='table-wrapper'>"
$Html += "<table class='risk-model-table'><tr>"
foreach ($cat in $PingScoreCategoriesPrimary) {
    $Html += "<th>$cat</th>"
}
$Html += "</tr>"

for ($i = 0; $i -lt $PingModelMaxRows; $i++) {
    $Html += "<tr>"
    foreach ($cat in $PingScoreCategoriesPrimary) {
        $catRules = @($PingCategoryFindingsSortedMap[$cat])
        if ($i -ge $catRules.Count) {
            $Html += "<td class='risk-cell-none'>-</td>"
            continue
        }

        $rf = $catRules[$i]
        $isMatched = Test-PingFindingMatched $rf
        if (-not $isMatched) {
            $riskCellClass = "risk-model-cell risk-cell-none"
        } else {
            $riskCellClass = switch ($rf.Severity) {
                "Critical" { "risk-model-cell risk-cell-critical" }
                "High" { "risk-model-cell risk-cell-high" }
                "Medium" { "risk-model-cell risk-cell-medium" }
                default { "risk-model-cell risk-cell-low" }
            }
        }

        $ruleSafe = ($rf.Rule -replace "'", "\\'")
        $cellTitle = ("Severity: {0} | Count: {1}" -f $rf.Severity, $rf.Count) -replace "'", "&#39;"
        $Html += "<td class='$riskCellClass' title='$cellTitle' onclick='focusPingRule(""$ruleSafe"")'>$($rf.Rule)</td>"
    }
    $Html += "</tr>"
}
$Html += "</table></div>"

$Html += "<div class='risk-focus-bar' id='pingRiskFocusBar'>"
$Html += "<button class='risk-focus-chip active' data-mode='all' onclick='applyPingRiskFocus(""all"")'>All</button>"
$Html += "<button class='risk-focus-chip' data-mode='criticalhigh' onclick='applyPingRiskFocus(""criticalhigh"")'>Critical + High</button>"
$Html += "<button class='risk-focus-chip' data-mode='critical' onclick='applyPingRiskFocus(""critical"")'>Critical Only</button>"
$Html += "<button class='risk-focus-chip' data-mode='privileged' onclick='applyPingRiskFocus(""privileged"")'>Privileged Focus</button>"
$Html += "<button class='risk-focus-chip' data-mode='anomalies' onclick='applyPingRiskFocus(""anomalies"")'>Anomalies</button>"
$Html += "<button class='risk-focus-chip' data-mode='hygiene' onclick='applyPingRiskFocus(""hygiene"")'>Hygiene + Stale</button>"
$Html += "<span class='risk-focus-summary' id='pingRiskFocusSummary'>All findings listed</span>"
$Html += "</div>"

$Html += "<div class='attack-chain-card'>"
$Html += "<h3>Attack Path Visualization</h3>"
$Html += "<p class='attack-chain-note'>Matched attack scenarios are derived from real finding combinations and show likely escalation chains.</p>"
$Html += "<div class='attack-chain-graph'><div id='attackChainGraph'><div class='attack-scenario-empty'>Collecting attack scenarios...</div></div></div>"
$Html += "<ul class='attack-why-list' id='attackChainWhyList'><li>Collecting rationale...</li></ul>"
$Html += "</div>"

$Html += "<div class='mitre-panel'>"
$Html += "<h3>MITRE ATT&CK Heatmap</h3>"
$Html += "<p class='mitre-note'>Category findings are mapped to ATT&CK tactics for prioritization and SOC alignment.</p>"
$Html += "<div class='mitre-heat-grid' id='mitreHeatGrid'></div>"
$Html += "<div class='threat-priority-wrap'><p class='threat-priority-note'>Tehdit odakli oncelik kuyrugu (Madde 9): en kritik teknikleri ve bagli kurallari one cikarir.</p><div id='threatPriorityBody'></div></div>"
$Html += "</div>"

$Html += "<div id='caRiskAnchor' class='ca-risk-card'>"
$Html += "<h3 data-i18n-key='risk.caLensTitle'>CA Risk Lens</h3>"
$Html += "<p class='ca-risk-meta' data-i18n-key='risk.caLensMeta'>Aggregates certificate service (AD CS/CA) risks in one place and guides closure priority.</p>"
$Html += "<div id='caRiskLensBody'></div>"
$Html += "</div>"

$Html += "<div id='riskFindingsAnchor' class='table-wrapper'>"
$Html += "<table class='user-table' id='pingCastleRiskTable'><tr>
<th onclick='sortTable(""pingCastleRiskTable"",0)'>Category</th>
<th onclick='sortTable(""pingCastleRiskTable"",1)'>Severity</th>
<th onclick='sortTable(""pingCastleRiskTable"",2)'>Rule</th>
<th onclick='sortTable(""pingCastleRiskTable"",3)'>Count</th>
<th onclick='sortTable(""pingCastleRiskTable"",4)'>Affected Sample</th>
<th onclick='sortTable(""pingCastleRiskTable"",5)'>Recommendation</th>
<th>Status</th>
<th>Detail</th>
<th>Watch</th>
</tr>"
foreach ($f in $PingCastleFindings) {
    $SeverityClass = switch ($f.Severity) {
        "Critical" { "status-hata" }
        "High" { "status-hata" }
        "Medium" { "status-uyari" }
        default { "status-ok" }
    }
    $RuleInfo = Get-PingRuleInfo $f.Rule
    $RuleReference = Get-PingRuleReference $f.Rule
    $HoverText = ("About: {0}&#10;Source: {1}&#10;Reference: {2}&#10;Action: {3}" -f $RuleInfo.About, $RuleInfo.Source, $RuleReference, $RuleInfo.Action) -replace "'", "&#39;"
    $CatJs = ($f.Category -replace "'", "\\'")
    $RuleJs = ($f.Rule -replace "'", "\\'")

    $Html += "<tr>
    <td>$($f.Category)</td>
    <td class='$SeverityClass'>$($f.Severity)</td>
    <td title='$HoverText'><span class='group-name-cell' onclick=""showPingFindingDetails('$CatJs','$RuleJs')"">$($f.Rule)</span></td>
    <td><span class='group-name-cell' onclick=""showPingFindingDetails('$CatJs','$RuleJs')"">$($f.Count)</span></td>
    <td><span class='group-name-cell' onclick=""showPingFindingDetails('$CatJs','$RuleJs')"">$($f.Sample)</span></td>
    <td>$($f.Recommendation)</td>
    <td><span class='remediation-status-pill remediation-status-open'>Open</span></td>
    <td><span class='group-name-cell' onclick=""showPingFindingDetails('$CatJs','$RuleJs')"">Open</span></td>
    <td><button class='watch-btn' onclick='toggleRiskWatch(this)'>Watch</button></td>
    </tr>"
}
$Html += "</table></div>"

$Html += "<div id='riskWatchAnchor' class='risk-watch-card'>"
$Html += "<h3>Watchlist <span id='riskWatchlistCount'>0</span></h3>"
$Html += "<p class='tracking-note'>Pin high-priority rules to keep daily focus and quickly jump to details.</p>"
$Html += "<div id='riskWatchlistBody' class='risk-watch-body'></div>"
$Html += "</div>"

$Html += "<div id='riskTrackAnchor' class='remediation-tracking-card'>"
$Html += "<h3>Remediation Tracking</h3>"
$Html += "<p class='tracking-note'>Assign each finding as Fixed / Accepted / Exception. Export tracking JSON for governance evidence.</p>"
$Html += "<div class='risk-focus-bar'>"
$Html += "<button class='risk-focus-chip track-focus-chip active' data-track='all' onclick='filterRemediationStatus(""all"")'>All</button>"
$Html += "<button class='risk-focus-chip track-focus-chip' data-track='open' onclick='filterRemediationStatus(""open"")'>Open</button>"
$Html += "<button class='risk-focus-chip track-focus-chip' data-track='fixing' onclick='filterRemediationStatus(""fixing"")'>Fixing</button>"
$Html += "<button class='risk-focus-chip track-focus-chip' data-track='accepted' onclick='filterRemediationStatus(""accepted"")'>Accepted</button>"
$Html += "<button class='risk-focus-chip track-focus-chip' data-track='exception' onclick='filterRemediationStatus(""exception"")'>Exception</button>"
$Html += "<button class='risk-focus-chip track-focus-chip' onclick='exportRemediationTrackingExcel()'>Excel Export</button>"
$Html += "<span class='risk-focus-summary' id='trackingSummary'>Tracking ready</span>"
$Html += "</div>"
$Html += "<div class='approval-gate-card'>"
$Html += "<h4>Change Approval Gate (Madde 11)</h4>"
$Html += "<p class='tracking-note'>Risk kapatma degisiklikleri icin onay kontrolu: kayit no, sorumlu, pencere ve geri donus kaniti.</p>"
$Html += "<div class='approval-gate-grid'>"
$Html += "<label class='approval-gate-item'><input type='checkbox' id='approval_impact' onchange='setApprovalGateCheck(""impact"", this.checked)'/> Etki analizi tamamlandi</label>"
$Html += "<label class='approval-gate-item'><input type='checkbox' id='approval_testPlan' onchange='setApprovalGateCheck(""testPlan"", this.checked)'/> Test plani hazir</label>"
$Html += "<label class='approval-gate-item'><input type='checkbox' id='approval_backout' onchange='setApprovalGateCheck(""backout"", this.checked)'/> Backout plani onaylandi</label>"
$Html += "<label class='approval-gate-item'><input type='checkbox' id='approval_evidence' onchange='setApprovalGateCheck(""evidence"", this.checked)'/> Kanit baglantisi eklendi</label>"
$Html += "</div>"
$Html += "<div class='approval-gate-inputs'>"
$Html += "<input id='approval_ticket' placeholder='Change Ticket (CHG-...)' oninput='setApprovalGateField(""ticket"", this.value)' />"
$Html += "<input id='approval_owner' placeholder='Onaylayan / Owner' oninput='setApprovalGateField(""owner"", this.value)' />"
$Html += "<input id='approval_window' placeholder='Change Window (dd/MM HH:mm)' oninput='setApprovalGateField(""window"", this.value)' />"
$Html += "<input id='approval_rollback' placeholder='Rollback Ref / Prosedur' oninput='setApprovalGateField(""rollback"", this.value)' />"
$Html += "</div>"
$Html += "<div id='approvalGateStatus' class='approval-gate-status'>Kontrol bekleniyor...</div>"
$Html += "</div>"
$Html += "</div>"

$TopRiskCategorySummaryEscaped = [System.Net.WebUtility]::HtmlEncode([string]$TopRiskCategorySummary)
$Html += "<div id='riskActionAnchor' class='risk-remediation-panel'>"
$Html += "<h3>Quick Remediation Plan</h3>"
$Html += "<p>Highest pressure areas: $TopRiskCategorySummaryEscaped. Follow the steps below to reduce risk in order.</p>"
$Html += "<ol class='risk-remediation-list'>"
if (@($QuickRemediationItems).Count -gt 0) {
    foreach ($item in $QuickRemediationItems) {
        $itemCategory = [System.Net.WebUtility]::HtmlEncode([string]$item.Category)
        $itemAction = [System.Net.WebUtility]::HtmlEncode([string]$item.Action)
        $itemRisk = [string]$item.RiskPct
        $Html += "<li><strong>$itemCategory ($itemRisk%)</strong>: $itemAction</li>"
    }
} else {
    $Html += "<li>No immediate high-pressure category detected. Keep current baseline controls and continue periodic review.</li>"
}
$Html += "<li><strong>Validate and close</strong>: re-run this report after remediation and confirm Critical/High findings trend downward.</li>"
$Html += "</ol>"

$Html += "<p class='risk-remediation-muted'><strong>Immediate focus (Critical/High):</strong></p>"
$Html += "<ul class='risk-remediation-finding-list'>"
if (@($PriorityRiskFindings).Count -gt 0) {
    foreach ($finding in $PriorityRiskFindings) {
        $ruleText = [System.Net.WebUtility]::HtmlEncode([string]$finding.Rule)
        $recText = [string]$finding.Recommendation
        if ($recText.Length -gt 180) { $recText = $recText.Substring(0, 177) + "..." }
        $recText = [System.Net.WebUtility]::HtmlEncode($recText)
        $sevText = [System.Net.WebUtility]::HtmlEncode([string]$finding.Severity)
        $Html += "<li><strong>[$sevText]</strong> $ruleText - $recText</li>"
    }
} else {
    $Html += "<li>No active Critical/High finding detected.</li>"
}
$Html += "</ul>"
$Html += "</div>"

$CategoryOrder = @("Privileged Accounts","Privileged Infrastructure","Trusts","Anomalies","Stale Objects","Hygiene")
foreach ($cat in $CategoryOrder) {
    $CategoryFindings = @($PingCastleFindings | Where-Object { $_.Category -eq $cat })
    if ($CategoryFindings.Count -eq 0) { continue }

    $SafeCat = $cat -replace '[^a-zA-Z0-9]',''
    $Html += "<h2 style='margin-top:20px;'>$cat ($($CategoryFindings.Count))</h2><div class='table-wrapper'>"
    $Html += "<div class='export-actions'>"
    $Html += "<button class='export-btn' onclick='exportTableToExcel(""pingCastleCategory$SafeCat"",""Risk_$SafeCat"")'>Excel</button>"
    $Html += "<button class='export-btn' onclick='exportTableToWord(""pingCastleCategory$SafeCat"",""Risk_$SafeCat"")'>Word</button>"
    $Html += "<button class='export-btn' onclick='exportTableToPdf(""pingCastleCategory$SafeCat"",""Risk $cat"")'>PDF</button>"
    $Html += "</div>"
    $Html += "<table class='user-table' id='pingCastleCategory$SafeCat'><tr>
<th onclick='sortTable(""pingCastleCategory$SafeCat"",0)'>Severity</th>
<th onclick='sortTable(""pingCastleCategory$SafeCat"",1)'>Rule</th>
<th onclick='sortTable(""pingCastleCategory$SafeCat"",2)'>Count</th>
<th onclick='sortTable(""pingCastleCategory$SafeCat"",3)'>Affected Sample</th>
<th onclick='sortTable(""pingCastleCategory$SafeCat"",4)'>Recommendation</th>
    <th>Detail</th>
</tr>"

    foreach ($cf in $CategoryFindings) {
        $CategorySeverityClass = switch ($cf.Severity) {
            "Critical" { "status-hata" }
            "High" { "status-hata" }
            "Medium" { "status-uyari" }
            default { "status-ok" }
        }
        $CategoryRuleInfo = Get-PingRuleInfo $cf.Rule
        $CategoryRuleReference = Get-PingRuleReference $cf.Rule
        $CategoryHoverText = ("About: {0}&#10;Source: {1}&#10;Reference: {2}&#10;Action: {3}" -f $CategoryRuleInfo.About, $CategoryRuleInfo.Source, $CategoryRuleReference, $CategoryRuleInfo.Action) -replace "'", "&#39;"
        $CatJs = ($cf.Category -replace "'", "\\'")
        $RuleJs = ($cf.Rule -replace "'", "\\'")
        $Html += "<tr>
        <td class='$CategorySeverityClass'>$($cf.Severity)</td>
        <td title='$CategoryHoverText'><span class='group-name-cell' onclick=""showPingFindingDetails('$CatJs','$RuleJs')"">$($cf.Rule)</span></td>
        <td><span class='group-name-cell' onclick=""showPingFindingDetails('$CatJs','$RuleJs')"">$($cf.Count)</span></td>
        <td><span class='group-name-cell' onclick=""showPingFindingDetails('$CatJs','$RuleJs')"">$($cf.Sample)</span></td>
        <td>$($cf.Recommendation)</td>
        <td><span class='group-name-cell' onclick=""showPingFindingDetails('$CatJs','$RuleJs')"">Open</span></td>
        </tr>"
    }

    $Html += "</table></div>"
}

$Html += "<h2 style='margin-top:20px;'>Privileged Groups & Critical Infrastructure</h2>"
$Html += "<p style='color:#6b7280; font-style:italic;'>Included in AD risk scoring. Click any Details or Analysis link for object-level zoom.</p>"

$Html += "<h3 style='margin-top:12px;'>Privileged Groups</h3><div class='table-wrapper'>"
$Html += "<table class='user-table' id='privilegedGroupsReviewTable'><tr>
<th onclick='sortTable(""privilegedGroupsReviewTable"",0)'>Group or User Account</th>
<th onclick='sortTable(""privilegedGroupsReviewTable"",1)'>Priority</th>
<th onclick='sortTable(""privilegedGroupsReviewTable"",2)'>Users Member</th>
<th onclick='sortTable(""privilegedGroupsReviewTable"",3)'>Computer Member of the Group</th>
<th onclick='sortTable(""privilegedGroupsReviewTable"",4)'>Indirect Control</th>
<th onclick='sortTable(""privilegedGroupsReviewTable"",5)'>Unresolved Members</th>
<th onclick='sortTable(""privilegedGroupsReviewTable"",6)'>Links</th>
<th onclick='sortTable(""privilegedGroupsReviewTable"",7)'>Detail</th>
</tr>"
foreach ($row in $PrivilegedGroupReviewRows) {
    $priorityClass = switch ($row.Priority) {
        "Critical" { "status-hata" }
        "High" { "status-hata" }
        "Medium" { "status-uyari" }
        default { "status-ok" }
    }
    $usersCell = if ($row.UsersMember -is [int] -and $row.UsersMember -gt 0) { "<span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|users','$($row.ObjectName) - Users Member')"">$($row.UsersMember) (Details)</span>" } else { "$($row.UsersMember)" }
    $computerCell = if ($row.ComputersMember -is [int] -and $row.ComputersMember -gt 0) { "<span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|computers','$($row.ObjectName) - Computer Member')"">$($row.ComputersMember) (Details)</span>" } else { "$($row.ComputersMember)" }
    $indirectCell = if ($row.IndirectControl -is [int] -and $row.IndirectControl -gt 0) { "<span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|indirect','$($row.ObjectName) - Indirect Control')"">$($row.IndirectControl) (Details)</span>" } else { "$($row.IndirectControl)" }
    $unresolvedCell = if ($row.UnresolvedMembers -is [int] -and $row.UnresolvedMembers -gt 0) { "<span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|unresolved','$($row.ObjectName) - Unresolved Members')"">$($row.UnresolvedMembers) (Details)</span>" } else { "$($row.UnresolvedMembers)" }
    $Html += "<tr><td>$($row.ObjectName)</td><td class='$priorityClass'>$($row.Priority)</td><td>$usersCell</td><td>$computerCell</td><td>$indirectCell</td><td>$unresolvedCell</td><td>$($row.Links)</td><td><span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|analysis','$($row.ObjectName) - Analysis')"">Analysis</span></td></tr>"
}
$Html += "</table></div>"

$Html += "<h3 style='margin-top:12px;'>Critical Infrastructure</h3><div class='table-wrapper'>"
$Html += "<table class='user-table' id='criticalInfrastructureReviewTable'><tr>
<th onclick='sortTable(""criticalInfrastructureReviewTable"",0)'>Group or User Account</th>
<th onclick='sortTable(""criticalInfrastructureReviewTable"",1)'>Priority</th>
<th onclick='sortTable(""criticalInfrastructureReviewTable"",2)'>Users Member</th>
<th onclick='sortTable(""criticalInfrastructureReviewTable"",3)'>Computer Member of the Group</th>
<th onclick='sortTable(""criticalInfrastructureReviewTable"",4)'>Indirect Control</th>
<th onclick='sortTable(""criticalInfrastructureReviewTable"",5)'>Unresolved Members</th>
<th onclick='sortTable(""criticalInfrastructureReviewTable"",6)'>Links</th>
<th onclick='sortTable(""criticalInfrastructureReviewTable"",7)'>Detail</th>
</tr>"
foreach ($row in $CriticalInfrastructureRows) {
    $priorityClass = switch ($row.Priority) {
        "Critical" { "status-hata" }
        "High" { "status-hata" }
        "Medium" { "status-uyari" }
        default { "status-ok" }
    }
    $usersCell = if ($row.UsersMember -is [int] -and $row.UsersMember -gt 0) { "<span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|users','$($row.ObjectName) - Users Member')"">$($row.UsersMember) (Details)</span>" } else { "$($row.UsersMember)" }
    $computerCell = if ($row.ComputersMember -is [int] -and $row.ComputersMember -gt 0) { "<span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|computers','$($row.ObjectName) - Computer Member')"">$($row.ComputersMember) (Details)</span>" } else { "$($row.ComputersMember)" }
    $indirectCell = if ($row.IndirectControl -is [int] -and $row.IndirectControl -gt 0) { "<span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|indirect','$($row.ObjectName) - Indirect Control')"">$($row.IndirectControl) (Details)</span>" } else { "$($row.IndirectControl)" }
    $unresolvedCell = if ($row.UnresolvedMembers -is [int] -and $row.UnresolvedMembers -gt 0) { "<span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|unresolved','$($row.ObjectName) - Unresolved Members')"">$($row.UnresolvedMembers) (Details)</span>" } else { "$($row.UnresolvedMembers)" }
    $Html += "<tr><td>$($row.ObjectName)</td><td class='$priorityClass'>$($row.Priority)</td><td>$usersCell</td><td>$computerCell</td><td>$indirectCell</td><td>$unresolvedCell</td><td>$($row.Links)</td><td><span class='group-name-cell' onclick=""showObjectRiskDetails('$($row.DetailKey)|analysis','$($row.ObjectName) - Analysis')"">Analysis</span></td></tr>"
}
$Html += "</table></div>"

$Html += "<h2 style='margin-top:20px;'>Finding Details</h2><div class='table-wrapper'>"
$Html += "<table class='user-table' id='pingCastleDetailTable'><tr>
<th onclick='sortTable(""pingCastleDetailTable"",0)'>Category</th>
<th onclick='sortTable(""pingCastleDetailTable"",1)'>Rule</th>
<th onclick='sortTable(""pingCastleDetailTable"",2)'>Target</th>
<th onclick='sortTable(""pingCastleDetailTable"",3)'>Detail</th>
<th onclick='sortTable(""pingCastleDetailTable"",4)'>Severity</th>
</tr>"

if ($PingCastleDetails.Count -eq 0) {
    $Html += "<tr><td colspan='5'>No detailed finding detected.</td></tr>"
} else {
    foreach ($d in $PingCastleDetails | Sort-Object Category, Rule, Target) {
        $DetailSeverityClass = switch ($d.Severity) {
            "Critical" { "status-hata" }
            "High" { "status-hata" }
            "Medium" { "status-uyari" }
            default { "status-ok" }
        }

        $Html += "<tr>
        <td>$($d.Category)</td>
        <td>$($d.Rule)</td>
        <td>$($d.Target)</td>
        <td>$($d.Detail)</td>
        <td class='$DetailSeverityClass'>$($d.Severity)</td>
        </tr>"
    }
}

$Html += "</table></div></div></div>"


# ---------------------
# DC HEALTH & INFO CONTAINER (Shortened)
# ---------------------
$DcDnsOkCount = @($DCHealth | Where-Object { $_.DNS_Health -eq 'OK' }).Count
$DcDnsAccessErrorCount = @($DCHealth | Where-Object { $_.DNS_Health -eq 'Access Error' }).Count
$DcDnsErrorCount = @($DCHealth | Where-Object { $_.DNS_Health -match 'ERROR|Access Error' }).Count
$DcGcCount = @($DCHealth | Where-Object { [string]$_.IsGC -match 'True|Yes' }).Count
$DcReplicationOkCount = @($DCHealth | Where-Object { [string]$_.Replication_6h -match '^OK' }).Count
$DcReplicationWarnCount = @($DCHealth | Where-Object { [string]$_.Replication_6h -match '^WARN' }).Count
$DcReplication6hErrorCount = @($DCHealth | Where-Object { [string]$_.Replication_6h -match '^ERROR|Access Error' }).Count

$Html += "<div class='container' id='dcHealthContainer' style='display:none;'><div class='content-card'>" 
$Html += "<h2>DC Health & FSMO Roles</h2>"
$Html += "<p class='section-intro'>Domain controller service health, DNS posture, and role placement overview.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Total DC</div><div class='section-stat-value'>$(@($DCHealth).Count)</div><div class='section-stat-note'>Controllers discovered</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>DNS OK</div><div class='section-stat-value'>$DcDnsOkCount</div><div class='section-stat-note'>Healthy resolver config</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>DNS Access Error</div><div class='section-stat-value'>$DcDnsAccessErrorCount</div><div class='section-stat-note'>Remote read/permission issue</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>DNS Error</div><div class='section-stat-value'>$DcDnsErrorCount</div><div class='section-stat-note'>Immediate remediation</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Replication Error (6h)</div><div class='section-stat-value'>$DcReplication6hErrorCount</div><div class='section-stat-note'>Recent AD sync failures</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Global Catalog enabled on $DcGcCount / $(@($DCHealth).Count) DCs.</span>"
$Html += "<div class='dc-info-box'>"
$Html += "<div class='dc-info-item'><h4>Domain Functional Level (DFL)</h4><span>$DFL</span></div>"
$Html += "<div class='dc-info-item'><h4>Forest Functional Level (FFL)</h4><span>$FFL</span></div>"
$Html += "</div>"
$Html += "<div class='dc-heatmap-card'><h3>DC Health Heatmap</h3><p class='tracking-note'>Fast severity map across controllers based on DNS, replication, and SYSVOL indicators.</p><div id='dcHealthHeatmapBody'></div></div>"
$Html += "<div class='table-wrapper'>"
$Html += "<table class='user-table' id='dcHealthTable'><tr>
<th onclick='sortTable(""dcHealthTable"",0)'>DC Name</th>
<th onclick='sortTable(""dcHealthTable"",1)'>OS</th>
<th onclick='sortTable(""dcHealthTable"",2)'>Uptime</th>
<th onclick='sortTable(""dcHealthTable"",3)'>Sysvol Status</th>
<th onclick='sortTable(""dcHealthTable"",4)'>FSMO Rolleri</th>
<th onclick='sortTable(""dcHealthTable"",5)'>Global Catalog</th>
<th onclick='sortTable(""dcHealthTable"",6)'>IP Address</th>
<th onclick='sortTable(""dcHealthTable"",7)'>DNS Servers (Network Setting)</th>
<th onclick='sortTable(""dcHealthTable"",8)'>DNS Health Status</th>
<th onclick='sortTable(""dcHealthTable"",9)'>Replication Status (Last 6h)</th>
</tr>"
foreach ($d in $DCHealth | Sort Name) {
    $DNSClass = switch ($d.DNS_Health) {
        "OK" { "status-ok" }
        "ERROR (Secondary Not DC/Loopback)" { "status-hata" }
        "Access Error" { "status-hata" }
        default { "" }
    }
    $ReplicationClass = if ([string]$d.Replication_6h -match '^OK') {
        "status-ok"
    } elseif ([string]$d.Replication_6h -match '^WARN') {
        "status-uyari"
    } else {
        "status-hata"
    }
    $ReplicationTitle = [System.Net.WebUtility]::HtmlEncode([string]$d.Replication_6h_Detail)
    $ReplicationDetailJs = ([string]$d.Replication_6h_Detail -replace "'", "\\'" -replace "`r", " " -replace "`n", " ")
    $ReplicationDcJs = ([string]$d.Name -replace "'", "\\'")
    $Html += "<tr>
    <td>$($d.Name)</td>
    <td>$($d.OperatingSystem)</td>
    <td>$($d.Uptime)</td>
    <td>$($d.Sysvol)</td>
    <td>$($d.FSMORoles)</td>
    <td>$($d.IsGC)</td>
    <td>$($d.IPv4Address)</td>
    <td>$($d.DNS_Servers)</td>
    <td class='$DNSClass'>$($d.DNS_Health)</td>
    <td class='$ReplicationClass' title='$ReplicationTitle'><span class='group-name-cell' onclick=""showReplicationHealth('$ReplicationDcJs','$ReplicationDetailJs')"">$($d.Replication_6h)</span></td>
    </tr>"
}
$Html += "</table></div>"

$totalDcHealth = [math]::Max(@($DCHealth).Count, 1)
$Html += "<div class='adrep-wrap'>"
$Html += "<style>"
$Html += ".adrep-wrap{margin-top:14px;background:#f7fbff;border:1px solid #c9daee;border-radius:12px;padding:14px;color:#16324f;}"
$Html += ".adrep-title{font-size:12px;font-weight:700;margin:0 0 8px 0;color:#12395f;letter-spacing:.2px;}"
$Html += ".adrep-tl{background:#ffffff;border:1px solid #c9daee;border-radius:10px;padding:12px 12px 18px 12px;}"
$Html += ".adrep-tl-ticks{display:flex;justify-content:space-between;color:#5b7289;font-size:10px;font-family:'JetBrains Mono',Consolas,monospace;margin:0 0 8px 170px;}"
$Html += ".adrep-tl-row{display:flex;align-items:center;gap:12px;margin:0 0 28px 0;} .adrep-tl-row:last-child{margin-bottom:0;}"
$Html += ".adrep-tl-label{width:160px;color:#3f5d79;font-size:11px;font-family:'JetBrains Mono',Consolas,monospace;}"
$Html += ".adrep-tl-bar{position:relative;height:10px;background:#eaf2fb;border-radius:999px;flex:1;overflow:visible;}"
$Html += ".adrep-evt{position:absolute;top:50%;transform:translateX(-50%);display:flex;flex-direction:column;align-items:center;cursor:pointer;}"
$Html += ".adrep-evt-dot{width:10px;height:10px;border-radius:50%;transform:translateY(-50%);}"
$Html += ".adrep-evt-dot.ok{background:#3fb950;box-shadow:0 0 8px #3fb950;} .adrep-evt-dot.err{background:#f85149;box-shadow:0 0 8px #f85149;} .adrep-evt-dot.warn{background:#e3b341;box-shadow:0 0 8px #e3b341;}"
$Html += ".adrep-evt-txt{margin-top:8px;font-size:11px;line-height:1.25;text-align:center;font-family:'JetBrains Mono',Consolas,monospace;white-space:normal;min-width:58px;max-width:130px;padding:2px 6px;border-radius:6px;background:rgba(255,255,255,.9);border:1px solid #c9daee;}"
$Html += ".adrep-evt-txt.ok{color:#2f4f6f;} .adrep-evt-txt.err{color:#d83a35;} .adrep-evt-txt.warn{color:#a66d00;}"
$Html += ".adrep-tooltip{position:fixed;z-index:9999;display:none;background:#ffffff;color:#16324f;border:1px solid #c9daee;border-radius:8px;padding:9px 10px;font-size:11px;box-shadow:0 8px 20px rgba(7,38,66,.22);min-width:180px;}"
$Html += ".adrep-tooltip b{color:#58a6ff;}"
$Html += "</style>"

$nowRef = Get-Date
$timelineStart = $nowRef.AddHours(-6)
$timelineWindowSec = 21600.0
$recent3hThreshold = $nowRef.AddHours(-3)

$UniqueLinks = @{}
foreach ($ln in ($ReplicationTopologyLinks | Sort-Object SourceDC, PartnerDC, LastAttempt -Descending)) {
    $lnKey = "$($ln.SourceDC)|$($ln.PartnerDC)"
    if (-not $UniqueLinks.ContainsKey($lnKey)) {
        $UniqueLinks[$lnKey] = $ln
    }
}
$ReplicationLinkRows = @($UniqueLinks.Values | Sort-Object SourceDC, PartnerDC)

$ReplicationLinkStatusRows = @()
$TimelineRows = @()

foreach ($ln in $ReplicationLinkRows) {
    $lnKey = "$($ln.SourceDC)|$($ln.PartnerDC)"
    $linkFailures = @($ReplicationFailureEvents | Where-Object { "$($_.Source)|$($_.Partner)" -eq $lnKey } | Sort-Object Time -Descending)
    $lastFailure = if ($linkFailures.Count -gt 0) { $linkFailures[0] } else { $null }

    $isCurrentError = $false
    if ($ln.LastResult -ne $null -and [int]$ln.LastResult -ne 0) { $isCurrentError = $true }
    if ([int]$ln.ConsecutiveFailures -gt 0) { $isCurrentError = $true }

    $hasRecentFailure3h = $false
    if ($lastFailure -and $lastFailure.Time -ge $recent3hThreshold) {
        $hasRecentFailure3h = $true
    }

    if ($isCurrentError) {
        $badgeText = 'ERROR NOW'
        $stateClass = 'err'
    } elseif ($hasRecentFailure3h) {
        $badgeText = 'HEALTHY (Recovered <= 3H)'
        $stateClass = 'ok'
    } else {
        $badgeText = 'HEALTHY'
        $stateClass = 'ok'
    }

    $lastSuccessText = if ($ln.LastSuccess) { ([datetime]$ln.LastSuccess).ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
    $lastAttemptText = if ($ln.LastAttempt) { ([datetime]$ln.LastAttempt).ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }
    $lastFailureText = if ($lastFailure) { ([datetime]$lastFailure.Time).ToString('yyyy-MM-dd HH:mm') } else { 'No failure record' }
    $lastErrorText = if ($lastFailure) { [System.Net.WebUtility]::HtmlEncode([string]$lastFailure.LastError) } else { '-' }

    $ReplicationLinkStatusRows += [PSCustomObject]@{
        SourceDC = $ln.SourceDC
        PartnerDC = $ln.PartnerDC
        StateClass = $stateClass
        BadgeText = $badgeText
        LastSuccessText = $lastSuccessText
        LastAttemptText = $lastAttemptText
        LastFailureText = $lastFailureText
        LastErrorText = $lastErrorText
        LastFailureTime = if ($lastFailure) { [datetime]$lastFailure.Time } else { $null }
    }

    $events = @()
    if ($lastFailure -and [datetime]$lastFailure.Time -ge $timelineStart) {
        $posFail = [math]::Round(((New-TimeSpan -Start $timelineStart -End ([datetime]$lastFailure.Time)).TotalSeconds / $timelineWindowSec) * 100, 1)
        if ($posFail -lt 0) { $posFail = 0 }
        if ($posFail -gt 100) { $posFail = 100 }
        $events += [PSCustomObject]@{
            Pos = $posFail
            Class = if ($stateClass -eq 'err') { 'err' } else { 'warn' }
            TimeText = ([datetime]$lastFailure.Time).ToString('HH:mm')
            SubText = [string]$lastFailure.LastError
            Tooltip = "zaman=$(([datetime]$lastFailure.Time).ToString('yyyy-MM-dd HH:mm'));durum=FAIL;gecikme=-;hata=$([string]$lastFailure.LastError)"
        }
    }

    if ($ln.LastAttempt) {
        $attemptDt = [datetime]$ln.LastAttempt
        if ($attemptDt -ge $timelineStart) {
            $posAttempt = [math]::Round(((New-TimeSpan -Start $timelineStart -End $attemptDt).TotalSeconds / $timelineWindowSec) * 100, 1)
            if ($posAttempt -lt 0) { $posAttempt = 0 }
            if ($posAttempt -gt 100) { $posAttempt = 100 }
            $events += [PSCustomObject]@{
                Pos = $posAttempt
                Class = if ($isCurrentError) { 'err' } else { 'ok' }
                TimeText = $attemptDt.ToString('HH:mm')
                SubText = if ($isCurrentError) { 'Replication error' } elseif ($hasRecentFailure3h) { 'Recovered' } else { '' }
                Tooltip = "zaman=$($attemptDt.ToString('yyyy-MM-dd HH:mm'));durum=$badgeText;gecikme=-;hata=$lastErrorText"
            }
        }
    }

    $TimelineRows += [PSCustomObject]@{
        Label = "$($ln.SourceDC) -> $($ln.PartnerDC)"
        Events = $events
    }
}
$TimelineHtml = ""
$TimelineHtml += "<div class='adrep-tl'><div class='adrep-title'>Replikasyon Zaman Cizelgesi (Son 6 Saat)</div>"
$TimelineHtml += "<div class='adrep-tl-ticks'><span>-6s</span><span>-5s</span><span>-4s</span><span>-3s</span><span>-2s</span><span>-1s</span><span>Simdi</span></div>"
foreach ($tr in $TimelineRows) {
    $labelSafe = [System.Net.WebUtility]::HtmlEncode([string]$tr.Label)
    $TimelineHtml += "<div class='adrep-tl-row'><div class='adrep-tl-label'>$labelSafe</div><div class='adrep-tl-bar'>"
    $sortedEvents = @($tr.Events | Sort-Object Pos)
    $previousPos = -999
    $lane = 0
    foreach ($ev in $sortedEvents) {
        $evClass = [string]$ev.Class
        $timeSafe = [System.Net.WebUtility]::HtmlEncode([string]$ev.TimeText)
        $subSafe = [System.Net.WebUtility]::HtmlEncode([string]$ev.SubText)
        $tipSafe = [System.Net.WebUtility]::HtmlEncode([string]$ev.Tooltip)
        if (($ev.Pos - $previousPos) -lt 10) {
            $lane = 1 - $lane
        } else {
            $lane = 0
        }
        $previousPos = [double]$ev.Pos
        $labelMarginTop = if ($lane -eq 1) { 22 } else { 8 }
        $eventText = if ([string]::IsNullOrWhiteSpace($subSafe)) { $timeSafe } else { "$timeSafe<br/><span style='font-size:9px'>$subSafe</span>" }
        $TimelineHtml += "<div class='adrep-evt' style='left:$($ev.Pos)%' data-tip='$tipSafe'><span class='adrep-evt-dot $evClass'></span><span class='adrep-evt-txt $evClass' style='margin-top:${labelMarginTop}px;'>$eventText</span></div>"
    }
    $TimelineHtml += "</div></div>"
}
$TimelineHtml += "</div><div id='adrepTooltip' class='adrep-tooltip'></div>"
$TimelineHtml += "<script>(function(){var tip=document.getElementById('adrepTooltip');if(!tip)return;document.querySelectorAll('.adrep-evt').forEach(function(el){el.addEventListener('mouseenter',function(e){tip.innerHTML='<b>Detay</b><br>'+String(el.getAttribute('data-tip')||'').replace(/;/g,'<br>');tip.style.display='block';tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY-12)+'px';});el.addEventListener('mousemove',function(e){tip.style.left=(e.clientX+14)+'px';tip.style.top=(e.clientY-12)+'px';});el.addEventListener('mouseleave',function(){tip.style.display='none';});});})();</script>"

$ProblemDcRows = @($DCHealth | Where-Object { [string]$_.Replication_6h -notmatch '^OK' } | Sort-Object Name)
if ($ProblemDcRows.Count -gt 0) {
    $Html += "<div class='table-wrapper' style='margin-top:10px;'><table class='user-table' id='replicationFaultTable'><tr><th>Problem DC</th><th>Status</th><th>Detail</th></tr>"
    foreach ($p in $ProblemDcRows) {
        $faultClass = if ([string]$p.Replication_6h -match '^WARN') { 'status-uyari' } else { 'status-hata' }
        $faultDetail = [System.Net.WebUtility]::HtmlEncode([string]$p.Replication_6h_Detail)
        $Html += "<tr><td>$($p.Name)</td><td class='$faultClass'>$($p.Replication_6h)</td><td>$faultDetail</td></tr>"
    }
    $Html += "</table></div>"
} else {
    $Html += "<p style='margin:8px 0 0 0;font-size:12px;color:#155724;font-weight:700;'>No DC replication issue detected in the last 6 hours.</p>"
}

$Html += "<p style='margin:8px 0 0 0;font-size:12px;color:#526980;'>Link view shows active replication state and recent failure timestamps per DC partner path.</p>"
$Html += $TimelineHtml
$Html += "</div>"

$Html += "</div></div>"

# ---------------------
# Exchange Users Container (Shortened)
# ---------------------
$ExchangeTotalCount = @($ExchangeUsers).Count
$ExchangeCloudCount = @($ExchangeUsers | Where-Object { $_.Type -match 'O365|Cloud' }).Count
$ExchangeOnPremCount = @($ExchangeUsers | Where-Object { $_.Type -notmatch 'O365|Cloud' }).Count
$ExchangeMissingMailCount = @($ExchangeUsers | Where-Object { [string]::IsNullOrWhiteSpace($_.EmailAddress) }).Count

$Html += "<div class='container' id='exchangeContainer' style='display:none;'><div class='content-card'>" 
$Html += "<h2>Exchange/O365 Users</h2>"
$Html += "<p class='section-intro'>Mailbox identity coverage across cloud and on-prem profiles.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Total Mail Users</div><div class='section-stat-value'>$ExchangeTotalCount</div><div class='section-stat-note'>Directory matched entries</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>O365 / Cloud</div><div class='section-stat-value'>$ExchangeCloudCount</div><div class='section-stat-note'>Remote mailbox profile</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>On-Prem / Hybrid</div><div class='section-stat-value'>$ExchangeOnPremCount</div><div class='section-stat-note'>Local or hybrid profile</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Missing Email</div><div class='section-stat-value'>$ExchangeMissingMailCount</div><div class='section-stat-note'>Attribute quality check</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Tip: missing email attributes often indicate provisioning drift.</span><div class='table-wrapper'>"
$Html += "<table class='user-table' id='exchangeUserTable'><tr>
<th onclick='sortTable(""exchangeUserTable"",0)'>Name</th>
<th onclick='sortTable(""exchangeUserTable"",1)'>Email</th>
<th onclick='sortTable(""exchangeUserTable"",2)'>Type</th>
</tr>"
foreach ($e in $ExchangeUsers | Sort Name) {
    $Html += "<tr><td>$($e.Name)</td><td>$($e.EmailAddress)</td><td>$($e.Type)</td></tr>"
}
$Html += "</table></div></div></div>"

# ---------------------
# Locked Accounts Container (Shortened)
# ---------------------
$LockedTotalCount = @($LockedAccounts).Count
$LockedHighBadPwdCount = @($LockedAccounts | Where-Object { $v = 0; [void][int]::TryParse([string]$_.BadPwdCount, [ref]$v); $v -ge 5 }).Count
$LockedTopBadPwd = @($LockedAccounts | Sort-Object {[int](if ([string]::IsNullOrWhiteSpace([string]$_.BadPwdCount)) { 0 } else { [string]$_.BadPwdCount })} -Descending | Select-Object -First 1)
$LockedTopBadPwdText = if ($LockedTopBadPwd) { "$($LockedTopBadPwd.Name) ($($LockedTopBadPwd.BadPwdCount))" } else { '-' }

$Html += "<div class='container' id='lockedAccountsContainer' style='display:none;'><div class='content-card'>" 
$Html += "<h2>Locked Accounts</h2>"
$Html += "<p class='section-intro'>Lockout concentration helps identify brute-force and misconfigured services.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Locked Users</div><div class='section-stat-value'>$LockedTotalCount</div><div class='section-stat-note'>Current lockout state</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>BadPwd >= 5</div><div class='section-stat-value'>$LockedHighBadPwdCount</div><div class='section-stat-note'>Likely attack or loop</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Top BadPwd User</div><div class='section-stat-value' style='font-size:14px;'>$LockedTopBadPwdText</div><div class='section-stat-note'>Highest password failures</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Investigate repeated lockouts for service account misuse.</span><div class='table-wrapper'>"
$Html += "<table class='user-table' id='lockedAccountsTable'><tr>
<th onclick='sortTable(""lockedAccountsTable"",0)'>User Name</th>
<th onclick='sortTable(""lockedAccountsTable"",1)'>Lockout Time</th>
<th onclick='sortTable(""lockedAccountsTable"",2)'>Bad Password Count</th>
</tr>"
foreach ($l in $LockedAccounts | Sort Name) {
    $LockTime = if($l.LockoutTime) {$l.LockoutTime.ToString("dd/MM/yyyy HH:mm")} else {"Never"}
    $Html += "<tr><td>$($l.Name)</td><td>$LockTime</td><td>$($l.BadPwdCount)</td></tr>"
}
$Html += "</table></div></div></div>"

# ---------------------
# Password Expiry Container (Shortened)
# ---------------------
$PwdExpiredCount = @($PwdExpiry | Where-Object { $_.PasswordExpiryDate -like 'Expired*' }).Count
$PwdNoExpiryCount = @($Users | Where-Object { $_.PasswordNeverExpires -eq $true }).Count
$PwdDueSoonCount = @(
    $PwdExpiry | Where-Object {
        $dateRaw = [string]$_.PasswordExpiryDate
        if ([string]::IsNullOrWhiteSpace($dateRaw)) { return $false }
        if ($dateRaw -eq 'N/A' -or $dateRaw -like 'Expired*') { return $false }
        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($dateRaw, 'dd/MM/yyyy', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { return $false }
        return ($parsed -ge (Get-Date).Date -and $parsed -le (Get-Date).Date.AddDays(7))
    }
).Count

$Html += "<div class='container' id='pwdExpiryContainer' style='display:none;'><div class='content-card'>" 
$Html += "<h2>Password Expiry</h2>"
$Html += "<p class='section-intro'>Password lifecycle view for outage prevention and policy hygiene.</p>"
$Html += "<div class='section-stat-grid'>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Expired</div><div class='section-stat-value'>$PwdExpiredCount</div><div class='section-stat-note'>Action required</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Due in 7 Days</div><div class='section-stat-value'>$PwdDueSoonCount</div><div class='section-stat-note'>Notify before lockout</div></div>"
$Html += "<div class='section-stat-card'><div class='section-stat-label'>Never Expires</div><div class='section-stat-value'>$PwdNoExpiryCount</div><div class='section-stat-note'>Policy exception count</div></div>"
$Html += "</div>"
$Html += "<span class='section-note-pill'>Focus first on expired users with business-critical roles.</span><div class='table-wrapper'>"
$Html += "<table class='user-table' id='pwdExpiryTable'><tr>
<th onclick='sortTable(""pwdExpiryTable"",0)'>User Name</th>
<th onclick='sortTable(""pwdExpiryTable"",1)'>Password Last Set</th>
<th onclick='sortTable(""pwdExpiryTable"",2)'>Password Expiry Date</th>
</tr>"
foreach ($p in $PwdExpiry | Sort Name) {
    $RowClass = if ($p.PasswordExpiryDate -like "Expired*") { "class='expired-row'" } else { "" }
    
    $Html += "<tr $RowClass><td>$($p.Name)</td><td>$($p.PasswordLastSet)</td><td>$($p.PasswordExpiryDate)</td></tr>"
}
$Html += "</table></div></div></div>"

# ---------------------
# Skipped / Unreachable DC Summary
# ---------------------
$SkippedRows = @($SkippedDCs)
$Html += "<div class='container' id='skippedDcsContainer' style='display:none;'><div class='content-card'>"
$Html += "<h2>Skipped / Unreachable DCs</h2>"
if ($SkippedRows.Count -gt 0) {
    $Html += "<div style='margin:8px 0 12px 0;padding:10px 12px;border:1px solid #ffe082;border-radius:8px;background:#fff8e1;color:#7a5d00;font-weight:700;'>Warning: $($SkippedRows.Count) control(s) could not be fully evaluated due to unreachable/failed remote checks.</div>"
} else {
    $Html += "<p class='section-intro'>No skipped or unreachable DC/CA control execution detected.</p>"
}
$Html += "<div class='table-wrapper'><table class='user-table' id='skippedDcsTable'><tr><th onclick='sortTable(""skippedDcsTable"",0)'>Host</th><th onclick='sortTable(""skippedDcsTable"",1)'>Section</th><th onclick='sortTable(""skippedDcsTable"",2)'>Reason</th></tr>"
if ($SkippedRows.Count -eq 0) {
    $Html += "<tr><td colspan='3'>No skipped host record.</td></tr>"
} else {
    foreach ($s in $SkippedRows | Select-Object -First 500) {
        $reasonSafe = [System.Net.WebUtility]::HtmlEncode([string]$s.Reason)
        $Html += "<tr><td>$([string]$s.DC)</td><td>$([string]$s.Section)</td><td>$reasonSafe</td></tr>"
    }
}
$Html += "</table></div></div></div>"

# ---------------------
# HTML Closing and Auto-Open
# ---------------------
$Html += "</div></div></body></html>"

# Safety normalization: force the replication timeline block to use light styling
# in case an older dark snippet is still injected during generation.
$Html = $Html.Replace(".adrep-wrap{margin-top:14px;background:#0d1117;border:1px solid #30363d;border-radius:12px;padding:14px;color:#e6edf3;}", ".adrep-wrap{margin-top:14px;background:#f7fbff;border:1px solid #c9daee;border-radius:12px;padding:14px;color:#16324f;}")
$Html = $Html.Replace(".adrep-title{font-size:12px;font-weight:700;margin:0 0 8px 0;color:#e6edf3;letter-spacing:.2px;}", ".adrep-title{font-size:12px;font-weight:700;margin:0 0 8px 0;color:#12395f;letter-spacing:.2px;}")
$Html = $Html.Replace(".adrep-tl{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px 12px 18px 12px;}", ".adrep-tl{background:#ffffff;border:1px solid #c9daee;border-radius:10px;padding:12px 12px 18px 12px;}")
$Html = $Html.Replace(".adrep-tl-ticks{display:flex;justify-content:space-between;color:#8d96a0;font-size:10px;font-family:'JetBrains Mono',Consolas,monospace;margin:0 0 8px 170px;}", ".adrep-tl-ticks{display:flex;justify-content:space-between;color:#5b7289;font-size:10px;font-family:'JetBrains Mono',Consolas,monospace;margin:0 0 8px 170px;}")
$Html = $Html.Replace(".adrep-tl-label{width:160px;color:#8d96a0;font-size:11px;font-family:'JetBrains Mono',Consolas,monospace;}", ".adrep-tl-label{width:160px;color:#3f5d79;font-size:11px;font-family:'JetBrains Mono',Consolas,monospace;}")
$Html = $Html.Replace(".adrep-tl-bar{position:relative;height:10px;background:#1c2128;border-radius:999px;flex:1;overflow:visible;}", ".adrep-tl-bar{position:relative;height:10px;background:#eaf2fb;border-radius:999px;flex:1;overflow:visible;}")
$Html = $Html.Replace(".adrep-evt-txt{margin-top:8px;font-size:11px;line-height:1.25;text-align:center;font-family:'JetBrains Mono',Consolas,monospace;white-space:normal;min-width:58px;max-width:130px;padding:2px 6px;border-radius:6px;background:rgba(13,17,23,.75);border:1px solid #30363d;}", ".adrep-evt-txt{margin-top:8px;font-size:11px;line-height:1.25;text-align:center;font-family:'JetBrains Mono',Consolas,monospace;white-space:normal;min-width:58px;max-width:130px;padding:2px 6px;border-radius:6px;background:rgba(255,255,255,.9);border:1px solid #c9daee;}")
$Html = $Html.Replace(".adrep-evt-txt.ok{color:#c9d1d9;} .adrep-evt-txt.err{color:#f85149;} .adrep-evt-txt.warn{color:#e3b341;}", ".adrep-evt-txt.ok{color:#2f4f6f;} .adrep-evt-txt.err{color:#d83a35;} .adrep-evt-txt.warn{color:#a66d00;}")
$Html = $Html.Replace(".adrep-tooltip{position:fixed;z-index:9999;display:none;background:#1c2128;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:9px 10px;font-size:11px;box-shadow:0 8px 20px rgba(0,0,0,.45);min-width:180px;}", ".adrep-tooltip{position:fixed;z-index:9999;display:none;background:#ffffff;color:#16324f;border:1px solid #c9daee;border-radius:8px;padding:9px 10px;font-size:11px;box-shadow:0 8px 20px rgba(7,38,66,.22);min-width:180px;}")
$Html = $Html.Replace(".adrep-tooltip b{color:#58a6ff;}", ".adrep-tooltip b{color:#2f6fa8;}")

function ConvertTo-MinifiedCssBlock {
    param([string]$Css)

    if ([string]::IsNullOrWhiteSpace($Css)) { return $Css }
    $min = [regex]::Replace($Css, '(?s)/\*.*?\*/', '')
    $min = [regex]::Replace($min, '\s+', ' ')
    $min = [regex]::Replace($min, '\s*([{}:;,>+])\s*', '$1')
    $min = $min.Replace(";}", "}")
    return $min.Trim()
}

function Compress-Styles {
    param([string]$InputHtml)

    $pattern = '(?is)<style>(.*?)</style>'
    $styleBlocks = [regex]::Matches($InputHtml, $pattern)
    if ($styleBlocks.Count -eq 0) { return $InputHtml }

    $builder = New-Object System.Text.StringBuilder
    $lastIndex = 0
    foreach ($match in $styleBlocks) {
        [void]$builder.Append($InputHtml.Substring($lastIndex, $match.Index - $lastIndex))
        [void]$builder.Append('<style>')
        [void]$builder.Append((ConvertTo-MinifiedCssBlock $match.Groups[1].Value))
        [void]$builder.Append('</style>')
        $lastIndex = $match.Index + $match.Length
    }
    [void]$builder.Append($InputHtml.Substring($lastIndex))
    return $builder.ToString()
}

$Html = Compress-Styles $Html

$File = "AD_Full_Overview_$Domain.html"
$LatestFile = "latest.html"
$Html | Out-File $File -Encoding UTF8
$Html | Out-File $LatestFile -Encoding UTF8
Write-Host "Report generated: $File"
Write-Host "Latest report generated: $LatestFile"

# ---------------------
# COMMAND: Opens report automatically
# ---------------------
Invoke-Item $File



