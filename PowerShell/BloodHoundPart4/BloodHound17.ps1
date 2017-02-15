function Invoke-BloodHound {
<#
    .SYNOPSIS

        This function automates the collection of the data needed for BloodHound.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        This function collects the information needed to populate the BloodHound graph
        database. It offers a varity of targeting and collection options.
        By default, it will map all domain trusts, enumerate all groups and associated memberships,
        enumerate all computers on the domain and execute session/loggedon/local admin enumeration
        queries against each. Targeting options are modifiable with -CollectionMethod. The
        -SearchForest searches all domains in the forest instead of just the current domain.
        By default, the data is output to CSVs in the current folder location (old Export-BloodHoundCSV functionality).
        To modify this, use -CSVFolder. To export to a neo4j RESTful API interface, specify a
        -URI X and -UserPass "...".

    .PARAMETER ComputerName

        Array of one or more computers to enumerate.

    .PARAMETER ComputerADSpath

        The LDAP source to search through for computers, e.g. "LDAP://OU=secret,DC=testlab,DC=local".

    .PARAMETER UserADSpath

        The LDAP source to search through for users/groups, e.g. "LDAP://OU=secret,DC=testlab,DC=local".

    .PARAMETER Domain

        Domain to query for machines, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to bind to for queries.

    .PARAMETER CollectionMethod

        The method to collect data. 'Group', 'ComputerOnly', 'LocalGroup', 'GPOLocalGroup', 'Session', 'LoggedOn', 'Trusts, 'Stealth', or 'Default'.
        'Stealth' uses 'Group' collection, stealth user hunting ('Session' on certain servers), 'GPOLocalGroup' enumeration, and trust enumeration.
        'Default' uses 'Group' collection, regular user hunting with 'Session'/'LoggedOn', 'LocalGroup' enumeration, and 'Trusts' enumeration.
        'ComputerOnly' only enumerates computers, not groups/trusts, and executes local admin/session/loggedon on each.

    .PARAMETER SearchForest

        Switch. Search all domains in the forest for target users instead of just
        a single domain.

    .PARAMETER CSVFolder

        The CSV folder to use for output, defaults to the current folder location.

    .PARAMETER CSVPrefix

        A prefix for all CSV files.

    .PARAMETER URI

        The BloodHound neo4j URL location (http://host:port/).

    .PARAMETER UserPass

        The "user:password" for the BloodHound neo4j instance

   .PARAMETER GlobalCatalog

        The global catalog location to resolve user memberships from, form of GC://global.catalog.

    .PARAMETER SkipGCDeconfliction

        Switch. Skip global catalog enumeration for session deconfliction.

    .PARAMETER Threads

        The maximum concurrent threads to execute, default of 20.

    .PARAMETER Throttle

        The number of cypher queries to queue up for neo4j RESTful API ingestion.

    .EXAMPLE

        PS C:\> Invoke-BloodHound

        Executes default collection methods and exports the data to a CSVs in the current directory.

    .EXAMPLE

        PS C:\> Invoke-BloodHound -URI http://SERVER:7474/ -UserPass "user:pass"

        Executes default collection options and exports the data to a BloodHound neo4j RESTful API endpoint.

    .EXAMPLE

        PS C:\> Invoke-BloodHound -CollectionMethod stealth

        Executes stealth collection and exports the data to a CSVs in the current directory.
        This includes 'stealth' user hunting and GPO object correlation for local admin membership.
        This is significantly faster but the information is not as complete as the default options.

    .LINK

        http://neo4j.com/docs/stable/rest-api-batch-ops.html
        http://stackoverflow.com/questions/19839469/optimizing-high-volume-batch-inserts-into-neo4j-using-rest
#>

    [CmdletBinding(DefaultParameterSetName = 'CSVExport')]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName,

        [String]
        $ComputerADSpath,

        [String]
        $UserADSpath,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        [ValidateSet('Group', 'ComputerOnly', 'LocalGroup', 'GPOLocalGroup', 'Session', 'LoggedOn', 'Stealth', 'Trusts', 'Default')]
        $CollectionMethod = 'Default',

        [Switch]
        $SearchForest,

        [Parameter(ParameterSetName = 'CSVExport')]
        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $CSVFolder = $(Get-Location),

        [Parameter(ParameterSetName = 'CSVExport')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CSVPrefix,

        [Parameter(ParameterSetName = 'RESTAPI', Mandatory = $True)]
        [URI]
        $URI,

        [Parameter(ParameterSetName = 'RESTAPI', Mandatory = $True)]
        [String]
        [ValidatePattern('.*:.*')]
        $UserPass,

        [ValidatePattern('^GC://')]
        [String]
        $GlobalCatalog,

        [Switch]
        $SkipGCDeconfliction,

        [ValidateRange(1,50)]
        [Int]
        $Threads = 20,

        [ValidateRange(1,5000)]
        [Int]
        $Throttle = 1000
    )

    BEGIN {

        Switch ($CollectionMethod) {
            'Group'         { $UseGroup = $True; $SkipComputerEnumeration = $True; $SkipGCDeconfliction2 = $True }
            'ComputerOnly'  { $UseGroup = $False; $UseLocalGroup = $True; $UseSession = $True; $UseLoggedOn = $True; $SkipGCDeconfliction2 = $False }
            'LocalGroup'    { $UseLocalGroup = $True; $SkipGCDeconfliction2 = $True }
            'GPOLocalGroup' { $UseGPOGroup = $True; $SkipComputerEnumeration = $True; $SkipGCDeconfliction2 = $True }
            'Session'       { $UseSession = $True; $SkipGCDeconfliction2 = $False }
            'LoggedOn'      { $UseLoggedOn = $True; $SkipGCDeconfliction2 = $True }
            'Trusts'        { $UseDomainTrusts = $True; $SkipComputerEnumeration = $True; $SkipGCDeconfliction2 = $True }
            'Stealth'       {
                $UseGroup = $True
                $UseGPOGroup = $True
                $UseSession = $True
                $UseDomainTrusts = $True
                $SkipGCDeconfliction2 = $False
            }
            'Default'       {
                $UseGroup = $True
                $UseLocalGroup = $True
                $UseSession = $True
                $UseLoggedOn = $False
                $UseDomainTrusts = $True
                $SkipGCDeconfliction2 = $False
            }
        }

        if($SkipGCDeconfliction) {
            $SkipGCDeconfliction2 = $True
        }

        if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
            try {
                $OutputFolder = $CSVFolder | Resolve-Path -ErrorAction Stop | Select-Object -ExpandProperty Path
            }
            catch {
                throw "Error: $_"
            }

            if($CSVPrefix) {
                $CSVExportPrefix = "$($CSVPrefix)_"
            }
            else {
                $CSVExportPrefix = ''
            }

            Write-Output "Writing output to CSVs in: $OutputFolder\$CSVExportPrefix"

            if($UseSession -or $UseLoggedon) {
                $SessionPath = "$OutputFolder\$($CSVExportPrefix)user_sessions.csv"
                $Exists = [System.IO.File]::Exists($SessionPath)
                $SessionFileStream = New-Object IO.FileStream($SessionPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $SessionWriter = New-Object System.IO.StreamWriter($SessionFileStream)
                $SessionWriter.AutoFlush = $True
                if (-not $Exists) {
                    # add the header if the file doesn't already exist
                    $SessionWriter.WriteLine('"ComputerName","UserName","Weight"')
                }
            }

            if($UseGroup) {
                $GroupPath = "$OutputFolder\$($CSVExportPrefix)group_memberships.csv"
                $Exists = [System.IO.File]::Exists($GroupPath)
                $GroupFileStream = New-Object IO.FileStream($GroupPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $GroupWriter = New-Object System.IO.StreamWriter($GroupFileStream)
                $GroupWriter.AutoFlush = $True
                if (-not $Exists) {
                    # add the header if the file doesn't already exist
                    $GroupWriter.WriteLine('"GroupName","AccountName","AccountType"')
                }
            }

            if($UseLocalGroup -or $UseGPOGroup) {
                $LocalAdminPath = "$OutputFolder\$($CSVExportPrefix)local_admins.csv"
                $Exists = [System.IO.File]::Exists($LocalAdminPath)
                $LocalAdminFileStream = New-Object IO.FileStream($LocalAdminPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $LocalAdminWriter = New-Object System.IO.StreamWriter($LocalAdminFileStream)
                $LocalAdminWriter.AutoFlush = $True
                if (-not $Exists) {
                    # add the header if the file doesn't already exist
                    $LocalAdminWriter.WriteLine('"ComputerName","AccountName","AccountType"')
                }
            }

            if($UseDomainTrusts) {
                $TrustsPath = "$OutputFolder\$($CSVExportPrefix)trusts.csv"
                $Exists = [System.IO.File]::Exists($TrustsPath)
                $TrustsFileStream = New-Object IO.FileStream($TrustsPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $TrustWriter = New-Object System.IO.StreamWriter($TrustsFileStream)
                $TrustWriter.AutoFlush = $True
                if (-not $Exists) {
                    # add the header if the file doesn't already exist
                    $TrustWriter.WriteLine('"SourceDomain","TargetDomain","TrustDirection","TrustType","Transitive"')
                }
            }
        }

        else {
            # otherwise we're doing ingestion straight to the neo4j RESTful API interface
            $WebClient = New-Object System.Net.WebClient

            $Base64UserPass = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($UserPass))

            # add the auth headers
            $WebClient.Headers.Add('Accept','application/json; charset=UTF-8')
            $WebClient.Headers.Add('Authorization',"Basic $Base64UserPass")

            # check auth to the BloodHound neo4j server
            try {
                $Null = $WebClient.DownloadString($URI.AbsoluteUri + 'user/neo4j')
                Write-Verbose "Connection established with neo4j ingestion interface at $($URI.AbsoluteUri)"
                $Authorized = $True
            }
            catch {
                $Authorized = $False
                throw "Error connecting to Neo4j rest REST server at '$($URI.AbsoluteUri)'"
            }

            Write-Output "Sending output to neo4j RESTful API interface at: $($URI.AbsoluteUri)"

            $Null = [Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")

            # from http://stackoverflow.com/questions/28077854/powershell-2-0-convertfrom-json-and-convertto-json-implementation
            function ConvertTo-Json20([object] $Item){
                $ps_js = New-Object System.Web.Script.Serialization.javascriptSerializer
                return $ps_js.Serialize($item)
            }

            $Authorized = $True
            $Statements = New-Object System.Collections.ArrayList

            # add in the necessary constraints on nodes
            $Null = $Statements.Add( @{ "statement"="CREATE CONSTRAINT ON (c:User) ASSERT c.UserName IS UNIQUE" } )
            $Null = $Statements.Add( @{ "statement"="CREATE CONSTRAINT ON (c:Computer) ASSERT c.ComputerName IS UNIQUE"} )
            $Null = $Statements.Add( @{ "statement"="CREATE CONSTRAINT ON (c:Group) ASSERT c.GroupName IS UNIQUE" } )
            $Json = @{ "statements"=[System.Collections.Hashtable[]]$Statements }
            $JsonRequest = ConvertTo-Json20 $Json
            $Null = $WebClient.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $JsonRequest)
            $Statements.Clear()
        }

        $UserDomainMappings = @{}
        if(-not $SkipGCDeconfliction2) {
            # if we're doing session enumeration, create a {user : @(domain,..)} from a global catalog
            #   in order to do user domain deconfliction for sessions
            if($PSBoundParameters['GlobalCatalog']) {
                $UserDomainMappings = Get-GlobalCatalogUserMapping -GlobalCatalog $GlobalCatalog
            }
            else {
                $UserDomainMappings = Get-GlobalCatalogUserMapping
            }
        }
        $DomainShortnameMappings = @{}

        if($Domain) {
            $TargetDomains = @($Domain)
        }
        elseif($SearchForest) {
            # get ALL the domains in the forest to search
            $TargetDomains = Get-NetForestDomain | Select-Object -ExpandProperty Name
        }
        else {
            # use the local domain
            $TargetDomains = @( (Get-NetDomain).Name )
        }

        if($UseGroup -and $TargetDomains) {
            $Title = (Get-Culture).TextInfo
            ForEach ($TargetDomain in $TargetDomains) {
                # enumerate all groups and all members of each group
                Write-Verbose "Enumerating group memberships for domain $TargetDomain"

                # in-line updated hashtable with group DN->SamAccountName mappings
                $GroupDNMappings = @{}
                $PrimaryGroups = @{}
                $DomainSID = Get-DomainSID -Domain $TargetDomain -DomainController $DomainController

                $ObjectSearcher = Get-DomainSearcher -Domain $TargetDomain -DomainController $DomainController -ADSPath $UserADSpath
                # only return results that have 'memberof' set
                $ObjectSearcher.Filter = '(memberof=*)'
                # only return specific properties in the results
                $Null = $ObjectSearcher.PropertiesToLoad.AddRange(('samaccountname', 'distinguishedname', 'cn', 'dnshostname', 'samaccounttype', 'primarygroupid', 'memberof'))
                $Counter = 0
                $ObjectSearcher.FindAll() | ForEach-Object {
                    if($Counter % 1000 -eq 0) {
                        Write-Verbose "Group object counter: $Counter"
                        if($GroupWriter) {
                            $GroupWriter.Flush()
                        }
                        [GC]::Collect()
                    }
                    $Properties = $_.Properties

                    $MemberDN = $Null
                    $MemberDomain = $Null
                    try {
                        $MemberDN = $Properties['distinguishedname'][0]

                        if (($MemberDN -match 'ForeignSecurityPrincipals') -and ($MemberDN -match 'S-1-5-21')) {
                            try {
                                if(-not $MemberSID) {
                                    $MemberSID = $Properties.cn[0]
                                }
                                $MemberSimpleName = Convert-SidToName -SID $MemberSID | Convert-ADName -InputType 'NT4' -OutputType 'Canonical'
                                if($MemberSimpleName) {
                                    $MemberDomain = $MemberSimpleName.Split('/')[0]
                                }
                                else {
                                    Write-Verbose "Error converting $MemberDN"
                                }
                            }
                            catch {
                                Write-Verbose "Error converting $MemberDN"
                            }
                        }
                        else {
                            # extract the FQDN from the Distinguished Name
                            $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {}

                    if (@('268435456','268435457','536870912','536870913') -contains $Properties['samaccounttype']) {
                        $ObjectType = 'group'
                        if($Properties['samaccountname']) {
                            $MemberName = $Properties['samaccountname'][0]
                        }
                        else {
                            # external trust users have a SID, so convert it
                            try {
                                $MemberName = Convert-SidToName $Properties['cn'][0]
                            }
                            catch {
                                # if there's a problem contacting the domain to resolve the SID
                                $MemberName = $Properties['cn'][0]
                            }
                        }
                        if ($MemberName -Match "\\") {
                            # if the membername itself contains a backslash, get the trailing section
                            #   TODO: later preserve this once BloodHound can properly display these characters
                            $AccountName = $MemberName.split('\')[1] + '@' + $MemberDomain
                        }
                        else {
                            $AccountName = "$MemberName@$MemberDomain"
                        }
                    }
                    elseif (@('805306369') -contains $Properties['samaccounttype']) {
                        $ObjectType = 'computer'
                        $AccountName = $Properties['dnshostname'][0]
                    }
                    elseif (@('805306368') -contains $Properties['samaccounttype']) {
                        $ObjectType = 'user'
                        if($Properties['samaccountname']) {
                            $MemberName = $Properties['samaccountname'][0]
                        }
                        else {
                            # external trust users have a SID, so convert it
                            try {
                                $MemberName = Convert-SidToName $Properties['cn'][0]
                            }
                            catch {
                                # if there's a problem contacting the domain to resolve the SID
                                $MemberName = $Properties['cn'][0]
                            }
                        }
                        if ($MemberName -Match "\\") {
                            # if the membername itself contains a backslash, get the trailing section
                            #   TODO: later preserve this once BloodHound can properly display these characters
                            $AccountName = $MemberName.split('\')[1] + '@' + $MemberDomain
                        }
                        else {
                            $AccountName = "$MemberName@$MemberDomain"
                        }
                    }
                    else {
                        Write-Verbose "Unknown account type for object $($Properties['distinguishedname']) : $($Properties['samaccounttype'])"
                    }

                    if($AccountName -and (-not $AccountName.StartsWith('@'))) {

                        # Write-Verbose "AccountName: $AccountName"
                        $MemberPrimaryGroupName = $Null
                        try {
                            if($AccountName -match $TargetDomain) {
                                # also retrieve the primary group name for this object, if it exists
                                if($Properties['primarygroupid'] -and $Properties['primarygroupid'][0] -and ($Properties['primarygroupid'][0] -ne '')) {
                                    $PrimaryGroupSID = "$DomainSID-$($Properties['primarygroupid'][0])"
                                    # Write-Verbose "PrimaryGroupSID: $PrimaryGroupSID"
                                    if($PrimaryGroups[$PrimaryGroupSID]) {
                                        $PrimaryGroupName = $PrimaryGroups[$PrimaryGroupSID]
                                    }
                                    else {
                                        $RawName = Convert-SidToName -SID $PrimaryGroupSID
                                        if ($RawName -notmatch '^S-1-.*') {
                                            $PrimaryGroupName = $RawName.split('\')[-1]
                                            $PrimaryGroups[$PrimaryGroupSID] = $PrimaryGroupName
                                        }
                                    }
                                    if ($PrimaryGroupName) {
                                        $MemberPrimaryGroupName = "$PrimaryGroupName@$TargetDomain"
                                    }
                                }
                                else { }
                            }
                        }
                        catch { }

                        if($MemberPrimaryGroupName) {
                            # Write-Verbose "MemberPrimaryGroupName: $MemberPrimaryGroupName"
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $GroupWriter.WriteLine("`"$MemberPrimaryGroupName`",`"$AccountName`",`"$ObjectType`"")
                            }
                            else {
                                $ObjectTypeCap = $Title.ToTitleCase($ObjectType)
                                $Null = $Statements.Add( @{ "statement"="MERGE ($($ObjectType)1:$ObjectTypeCap { name: UPPER('$AccountName') }) MERGE (group2:Group { name: UPPER('$MemberPrimaryGroupName') }) MERGE ($($ObjectType)1)-[:MemberOf]->(group2)" } )
                            }
                        }

                        # iterate through each membership for this object
                        ForEach($GroupDN in $_.properties['memberof']) {
                            $GroupDomain = $GroupDN.subString($GroupDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

                            if($GroupDNMappings[$GroupDN]) {
                                $GroupName = $GroupDNMappings[$GroupDN]
                            }
                            else {
                                $GroupName = Convert-ADName -ObjectName $GroupDN
                                if($GroupName) {
                                    $GroupName = $GroupName.Split('\')[-1]
                                }
                                else {
                                    $GroupName = $GroupDN.SubString(0, $GroupDN.IndexOf(',')).Split('=')[-1]
                                }
                                $GroupDNMappings[$GroupDN] = $GroupName
                            }

                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $GroupWriter.WriteLine("`"$GroupName@$GroupDomain`",`"$AccountName`",`"$ObjectType`"")
                            }
                            else {
                                # otherwise we're exporting to the neo4j RESTful API
                                $ObjectTypeCap = $Title.ToTitleCase($ObjectType)

                                $Null = $Statements.Add( @{ "statement"="MERGE ($($ObjectType)1:$ObjectTypeCap { name: UPPER('$AccountName') }) MERGE (group2:Group { name: UPPER('$GroupName@$GroupDomain') }) MERGE ($($ObjectType)1)-[:MemberOf]->(group2)" } )

                                if ($Statements.Count -ge $Throttle) {
                                    $Json = @{ "statements"=[System.Collections.Hashtable[]]$Statements }
                                    $JsonRequest = ConvertTo-Json20 $Json
                                    $Null = $WebClient.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $JsonRequest)
                                    $Statements.Clear()
                                }
                            }
                        }
                        $Counter += 1
                    }
                }
                $ObjectSearcher.Dispose()

                if ($PSCmdlet.ParameterSetName -eq 'RESTAPI') {
                    $Json = @{ "statements"=[System.Collections.Hashtable[]]$Statements }
                    $JsonRequest = ConvertTo-Json20 $Json
                    $Null = $WebClient.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $JsonRequest)
                    $Statements.Clear()
                }
                Write-Verbose "Done with group enumeration for domain $TargetDomain"
            }
            [GC]::Collect()
        }

        if($UseDomainTrusts -and $TargetDomains) {
            Write-Verbose "Mapping domain trusts"
            Invoke-MapDomainTrust | ForEach-Object {
                if($_.SourceDomain) {
                    $SourceDomain = $_.SourceDomain
                }
                else {
                    $SourceDomain = $_.SourceName
                }
                if($_.TargetDomain) {
                    $TargetDomain = $_.TargetDomain
                }
                else {
                    $TargetDomain = $_.TargetName
                }

                if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                    $TrustWriter.WriteLine("`"$SourceDomain`",`"$TargetDomain`",`"$($_.TrustDirection)`",`"$($_.TrustType)`",`"$True`"")
                }
                else {
                    $Null = $Statements.Add( @{ "statement"="MERGE (SourceDomain:Domain { name: UPPER('$SourceDomain') }) MERGE (TargetDomain:Domain { name: UPPER('$TargetDomain') })" } )

                    $TrustType = $_.TrustType
                    $Transitive = $True

                    Switch ($_.TrustDirection) {
                        'Inbound' {
                             $Null = $Statements.Add( @{ "statement"="MERGE (SourceDomain)-[:TrustedBy{ TrustType: UPPER('$TrustType'), Transitive: UPPER('$Transitive')}]->(TargetDomain)" } )
                        }
                        'Outbound' {
                             $Null = $Statements.Add( @{ "statement"="MERGE (TargetDomain)-[:TrustedBy{ TrustType: UPPER('$TrustType'), Transitive: UPPER('$Transitive')}]->(SourceDomain)" } )
                        }
                        'Bidirectional' {
                             $Null = $Statements.Add( @{ "statement"="MERGE (TargetDomain)-[:TrustedBy{ TrustType: UPPER('$TrustType'), Transitive: UPPER('$Transitive')}]->(SourceDomain) MERGE (SourceDomain)-[:TrustedBy{ TrustType: UPPER('$TrustType'), Transitive: UPPER('$Transitive')}]->(TargetDomain)" } )
                        }
                    }

                }
            }
            if ($PSCmdlet.ParameterSetName -eq 'RESTAPI') {
                $Json = @{ "statements"=[System.Collections.Hashtable[]]$Statements }
                $JsonRequest = ConvertTo-Json20 $Json
                $Null = $WebClient.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $JsonRequest)
                $Statements.Clear()
            }
            Write-Verbose "Done mapping domain trusts"
        }

        if($UseGPOGroup -and $TargetDomains) {
            ForEach ($TargetDomain in $TargetDomains) {

                Write-Verbose "Enumerating GPO local group memberships for domain $TargetDomain"
                Find-GPOLocation -Domain $TargetDomain -DomainController $DomainController | ForEach-Object {
                    $AccountName = "$($_.ObjectName)@$($_.ObjectDomain)"
                    ForEach($Computer in $_.ComputerName) {
                        if($_.IsGroup) {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $LocalAdminWriter.WriteLine("`"$Computer`",`"$AccountName`",`"group`"")
                            }
                            else {
                                $Null = $Statements.Add( @{"statement"="MERGE (group:Group { name: UPPER('$AccountName') }) MERGE (computer:Computer { name: UPPER('$Computer') }) MERGE (group)-[:AdminTo]->(computer)" } )
                            }
                        }
                        else {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $LocalAdminWriter.WriteLine("`"$Computer`",`"$AccountName`",`"user`"")
                            }
                            else {
                                $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER('$AccountName') }) MERGE (computer:Computer { name: UPPER('$Computer') }) MERGE (user)-[:AdminTo]->(computer)" } )
                            }
                        }
                    }
                }
                Write-Verbose "Done enumerating GPO local group memberships for domain $TargetDomain"
            }
            Write-Verbose "Done enumerating GPO local group"
            # TODO: cypher query to add 'domain admins' to every found machine
        }

        # get the current user so we can ignore it in the results
        $CurrentUser = ([Environment]::UserName).toLower()

        # script block that enumerates a server
        $HostEnumBlock = {
            Param($ComputerName, $CurrentUser2, $UseLocalGroup2, $UseSession2, $UseLoggedon2, $DomainSID2)

            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if($Up) {
                    if($UseLocalGroup2) {
                        # grab the users for the local admins on this server
                        $Results = Get-NetLocalGroup -ComputerName $TargetComputer -API -IsDomain -DomainSID $DomainSID2
                        if($Results) {
                            $Results
                        }
                        else {
                            Get-NetLocalGroup -ComputerName $TargetComputer -IsDomain -DomainSID $DomainSID2
                        }
                    }

                    $IPAddress = @(Get-IPAddress -ComputerName $TargetComputer)[0].IPAddress

                    if($UseSession2) {
                        ForEach ($Session in $(Get-NetSession -ComputerName $TargetComputer)) {
                            $UserName = $Session.sesi10_username
                            $CName = $Session.sesi10_cname

                            if($CName -and $CName.StartsWith("\\")) {
                                $CName = $CName.TrimStart("\")
                            }

                            # make sure we have a result
                            if (($UserName) -and ($UserName.trim() -ne '') -and ($UserName -notmatch '\$') -and ($UserName -notmatch $CurrentUser2)) {
                                # Try to resolve the DNS hostname of $Cname
                                try {
                                    $CNameDNSName = [System.Net.Dns]::GetHostEntry($CName) | Select-Object -ExpandProperty HostName
                                }
                                catch {
                                    $CNameDNSName = $CName
                                }
                                @{
                                    'UserDomain' = $Null
                                    'UserName' = $UserName
                                    'ComputerName' = $TargetComputer
                                    'IPAddress' = $IPAddress
                                    'SessionFrom' = $CName
                                    'SessionFromName' = $CNameDNSName
                                    'LocalAdmin' = $Null
                                    'Type' = 'UserSession'
                                }
                            }
                        }
                    }

                    if($UseLoggedon2) {
                        ForEach ($User in $(Get-NetLoggedon -ComputerName $TargetComputer)) {
                            $UserName = $User.wkui1_username
                            $UserDomain = $User.wkui1_logon_domain

                            # ignore local account logons
                            if($TargetComputer -notmatch "^$UserDomain") {
                                if (($UserName) -and ($UserName.trim() -ne '') -and ($UserName -notmatch '\$')) {
                                    @{
                                        'UserDomain' = $UserDomain
                                        'UserName' = $UserName
                                        'ComputerName' = $TargetComputer
                                        'IPAddress' = $IPAddress
                                        'SessionFrom' = $Null
                                        'SessionFromName' = $Null
                                        'LocalAdmin' = $Null
                                        'Type' = 'UserSession'
                                    }
                                }
                            }
                        }

                        ForEach ($User in $(Get-LoggedOnLocal -ComputerName $TargetComputer)) {
                            $UserName = $User.UserName
                            $UserDomain = $User.UserDomain

                            # ignore local account logons ?
                            if($TargetComputer -notmatch "^$UserDomain") {
                                @{
                                    'UserDomain' = $UserDomain
                                    'UserName' = $UserName
                                    'ComputerName' = $TargetComputer
                                    'IPAddress' = $IPAddress
                                    'SessionFrom' = $Null
                                    'SessionFromName' = $Null
                                    'LocalAdmin' = $Null
                                    'Type' = 'UserSession'
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    PROCESS {
        if ($TargetDomains -and (-not $SkipComputerEnumeration)) {

            if($Statements) {
                $Statements.Clear()
            }
            [Array]$TargetComputers = @()

            ForEach ($TargetDomain in $TargetDomains) {

                $DomainSID = Get-DomainSid -Domain $TargetDomain

                $ScriptParameters = @{
                    'CurrentUser2' = $CurrentUser
                    'UseLocalGroup2' = $UseLocalGroup
                    'UseSession2' = $UseSession
                    'UseLoggedon2' = $UseLoggedon
                    'DomainSID2' = $DomainSID
                }

                if($CollectionMethod -eq 'Stealth') {
                    Write-Verbose "Executing stealth computer enumeration of domain $TargetDomain"

                    Write-Verbose "Querying domain $TargetDomain for File Servers"
                    $TargetComputers += Get-NetFileServer -Domain $TargetDomain -DomainController $DomainController

                    Write-Verbose "Querying domain $TargetDomain for DFS Servers"
                    $TargetComputers += ForEach($DFSServer in $(Get-DFSshare -Domain $TargetDomain -DomainController $DomainController)) {
                        $DFSServer.RemoteServerName
                    }

                    Write-Verbose "Querying domain $TargetDomain for Domain Controllers"
                    $TargetComputers += ForEach($DomainController in $(Get-NetDomainController -LDAP -DomainController $DomainController -Domain $TargetDomain)) {
                        $DomainController.dnshostname
                    }

                    $TargetComputers = $TargetComputers | Where-Object {$_ -and ($_.Trim() -ne '')} | Sort-Object -Unique
                }
                else {
                    if($ComputerName) {
                        Write-Verbose "Using specified -ComputerName target set"
                        if($ComputerName -isnot [System.Array]) {$ComputerName = @($ComputerName)}
                        $TargetComputers = $ComputerName
                    }
                    else {
                        Write-Verbose "Enumerating all machines in domain $TargetDomain"
                        $ComputerSearcher = Get-DomainSearcher -Domain $TargetDomain -DomainController $DomainController -ADSPath $ComputerADSpath
                        $ComputerSearcher.filter = '(sAMAccountType=805306369)'
                        $Null = $ComputerSearcher.PropertiesToLoad.Add('dnshostname')
                        $TargetComputers = $ComputerSearcher.FindAll() | ForEach-Object {$_.Properties.dnshostname}
                        $ComputerSearcher.Dispose()
                    }
                }
                $TargetComputers = $TargetComputers | Where-Object { $_ }

                New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParameters -Threads $Threads | ForEach-Object {
                    if($_['Type'] -eq 'UserSession') {
                        if($_['SessionFromName']) {
                            try {
                                $SessionFromName = $_['SessionFromName']
                                $UserName = $_['UserName'].ToUpper()
                                $ComputerDomain = $_['SessionFromName'].SubString($_['SessionFromName'].IndexOf('.')+1).ToUpper()

                                if($UserDomainMappings) {
                                    $UserDomain = $Null
                                    if($UserDomainMappings[$UserName]) {
                                        if($UserDomainMappings[$UserName].Count -eq 1) {
                                            $UserDomain = $UserDomainMappings[$UserName]
                                            $LoggedOnUser = "$UserName@$UserDomain"
                                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                                $SessionWriter.WriteLine("`"$SessionFromName`",`"$LoggedOnUser`",`"1`"")
                                            }
                                            else {
                                                $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER('$LoggedOnUser') }) MERGE (computer:Computer { name: UPPER('$SessionFromName') }) MERGE (computer)-[:HasSession {Weight: '1'}]->(user)" } )
                                            }
                                        }
                                        else {
                                            $ComputerDomain = $_['SessionFromName'].SubString($_['SessionFromName'].IndexOf('.')+1).ToUpper()

                                            $UserDomainMappings[$UserName] | ForEach-Object {
                                                # for multiple GC results, set a weight of 1 for the same domain as the target computer
                                                if($_ -eq $ComputerDomain) {
                                                    $UserDomain = $_
                                                    $LoggedOnUser = "$UserName@$UserDomain"
                                                    if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                                        $SessionWriter.WriteLine("`"$SessionFromName`",`"$LoggedOnUser`",`"1`"")
                                                    }
                                                    else {
                                                        $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER('$LoggedOnUser') }) MERGE (computer:Computer { name: UPPER('$SessionFromName') }) MERGE (computer)-[:HasSession {Weight: '1'}]->(user)" } )
                                                    }
                                                }
                                                # and set a weight of 2 for all other users in additional domains
                                                else {
                                                    $UserDomain = $_
                                                    $LoggedOnUser = "$UserName@$UserDomain"
                                                    if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                                        $SessionWriter.WriteLine("`"$SessionFromName`",`"$LoggedOnUser`",`"2`"")
                                                    }
                                                    else {
                                                        $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER('$LoggedOnUser') }) MERGE (computer:Computer { name: UPPER('$SessionFromName') }) MERGE (computer)-[:HasSession {Weight: '2'}]->(user)" } )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    else {
                                        # no user object in the GC with this username, so set the domain to "UNKNOWN"
                                        $LoggedOnUser = "$UserName@UNKNOWN"
                                        if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                            $SessionWriter.WriteLine("`"$SessionFromName`",`"$LoggedOnUser`",`"2`"")
                                        }
                                        else {
                                            $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER('$LoggedOnUser') }) MERGE (computer:Computer { name: UPPER('$SessionFromName') }) MERGE (computer)-[:HasSession {Weight: '2'}]->(user)" } )
                                        }
                                    }
                                }
                                else {
                                    # if not using GC mappings, set the weight to 2
                                    $LoggedOnUser = "$UserName@$ComputerDomain"
                                    if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                        $SessionWriter.WriteLine("`"$SessionFromName`",`"$LoggedOnUser`",`"2`"")
                                    }
                                    else {
                                        $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER('$LoggedOnUser') }) MERGE (computer:Computer { name: UPPER('$SessionFromName') }) MERGE (computer)-[:HasSession {Weight: '2'}]->(user)"} )
                                    }
                                }
                            }
                            catch {
                                Write-Warning "Error extracting domain from $SessionFromName"
                            }
                        }
                        elseif($_['SessionFrom']) {
                            $SessionFromName = $_['SessionFrom']
                            $LoggedOnUser = "$($_['UserName'])@UNKNOWN"
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $SessionWriter.WriteLine("`"$SessionFromName`",`"$LoggedOnUser`",`"2`"")
                            }
                            else {
                                $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER(`"$LoggedOnUser`") }) MERGE (computer:Computer { name: UPPER(`"$SessionFromName`") }) MERGE (computer)-[:HasSession {Weight: '2'}]->(user)"} )
                            }
                        }
                        else {
                            # assume Get-NetLoggedOn result
                            $UserDomain = $_['UserDomain']
                            $UserName = $_['UserName']
                            try {
                                if($DomainShortnameMappings[$UserDomain]) {
                                    # in case the short name mapping is 'cached'
                                    $AccountName = "$UserName@$($DomainShortnameMappings[$UserDomain])"
                                }
                                else {
                                    $MemberSimpleName = "$UserDomain\$UserName" | Convert-ADName -InputType 'NT4' -OutputType 'Canonical'

                                    if($MemberSimpleName) {
                                        $MemberDomain = $MemberSimpleName.Split('/')[0]
                                        $AccountName = "$UserName@$MemberDomain"
                                        $DomainShortnameMappings[$UserDomain] = $MemberDomain
                                    }
                                    else {
                                        $AccountName = "$UserName@UNKNOWN"
                                    }
                                }

                                $SessionFromName = $_['ComputerName']

                                if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                    $SessionWriter.WriteLine("`"$SessionFromName`",`"$AccountName`",`"1`"")
                                }
                                else {
                                    $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER('$AccountName') }) MERGE (computer:Computer { name: UPPER('$SessionFromName') }) MERGE (computer)-[:HasSession {Weight: '1'}]->(user)" } )
                                }
                            }
                            catch {
                                Write-Verbose "Error converting $UserDomain\$UserName : $_"
                            }
                        }
                    }
                    elseif($_['Type'] -eq 'LocalUser') {
                        $Parts = $_['AccountName'].split('\')
                        $UserDomain = $Parts[0]
                        $UserName = $Parts[-1]

                        if($DomainShortnameMappings[$UserDomain]) {
                            # in case the short name mapping is 'cached'
                            $AccountName = "$UserName@$($DomainShortnameMappings[$UserDomain])"
                        }
                        else {
                            $MemberSimpleName = "$UserDomain\$UserName" | Convert-ADName -InputType 'NT4' -OutputType 'Canonical'

                            if($MemberSimpleName) {
                                $MemberDomain = $MemberSimpleName.Split('/')[0]
                                $AccountName = "$UserName@$MemberDomain"
                                $DomainShortnameMappings[$UserDomain] = $MemberDomain
                            }
                            else {
                                $AccountName = "$UserName@UNKNOWN"
                            }
                        }

                        $ComputerName = $_['ComputerName']
                        if($_['IsGroup']) {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $LocalAdminWriter.WriteLine("`"$ComputerName`",`"$AccountName`",`"group`"")
                            }
                            else {
                                $Null = $Statements.Add( @{ "statement"="MERGE (group:Group { name: UPPER('$AccountName') }) MERGE (computer:Computer { name: UPPER('$ComputerName') }) MERGE (group)-[:AdminTo]->(computer)" } )
                            }
                        }
                        else {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $LocalAdminWriter.WriteLine("`"$ComputerName`",`"$AccountName`",`"user`"")
                            }
                            else {
                                $Null = $Statements.Add( @{"statement"="MERGE (user:User { name: UPPER('$AccountName') }) MERGE (computer:Computer { name: UPPER('$ComputerName') }) MERGE (user)-[:AdminTo]->(computer)" } )
                            }
                        }
                    }

                    if (($PSCmdlet.ParameterSetName -eq 'RESTAPI') -and ($Statements.Count -ge $Throttle)) {
                        $Json = @{ "statements"=[System.Collections.Hashtable[]]$Statements }
                        $JsonRequest = ConvertTo-Json20 $Json
                        $Null = $WebClient.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $JsonRequest)
                        $Statements.Clear()
                        [GC]::Collect()
                    }
                }
            }
        }
    }

    END {

        if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
            if($SessionWriter) {
                $SessionWriter.Dispose()
                $SessionFileStream.Dispose()
            }
            if($GroupWriter) {
                $GroupWriter.Dispose()
                $GroupFileStream.Dispose()
            }
            if($LocalAdminWriter) {
                $LocalAdminWriter.Dispose()
                $LocalAdminFileStream.Dispose()
            }
            if($TrustWriter) {
                $TrustWriter.Dispose()
                $TrustsFileStream.Dispose()
            }

            Write-Output "Done writing output to CSVs in: $OutputFolder\$CSVExportPrefix"
        }
        else {
           $Json = @{ "statements"=[System.Collections.Hashtable[]]$Statements }
           $JsonRequest = ConvertTo-Json20 $Json
           $Null = $WebClient.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $JsonRequest)
           $Statements.Clear()
           Write-Output "Done sending output to neo4j RESTful API interface at: $($URI.AbsoluteUri)"
        }

        [GC]::Collect()
    }
}