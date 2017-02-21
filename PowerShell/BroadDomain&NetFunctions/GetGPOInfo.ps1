
########################################################
#
# GPO related functions.
#
########################################################

function Get-GptTmpl {
<#
    .SYNOPSIS

        Helper to parse a GptTmpl.inf policy file path into a custom object.

    .PARAMETER GptTmplPath

        The GptTmpl.inf file path name to parse.

    .PARAMETER UsePSDrive

        Switch. Mount the target GptTmpl folder path as a temporary PSDrive.

    .EXAMPLE

        PS C:\> Get-GptTmpl -GptTmplPath "\\dev.testlab.local\sysvol\dev.testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

        Parse the default domain policy .inf for dev.testlab.local
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GptTmplPath,

        [Switch]
        $UsePSDrive
    )

    begin {
        if($UsePSDrive) {
            # if we're PSDrives, create a temporary mount point
            $Parts = $GptTmplPath.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''

            Write-Verbose "Mounting path $GptTmplPath using a temp PSDrive at $RandDrive"

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Verbose "Error mounting path $GptTmplPath : $_"
                return $Null
            }

            # so we can cd/dir the new drive
            $TargetGptTmplPath = $RandDrive + ":\" + $FilePath
        }
        else {
            $TargetGptTmplPath = $GptTmplPath
        }
    }

    process {
        try {
            Write-Verbose "Attempting to parse GptTmpl: $TargetGptTmplPath"
            $TargetGptTmplPath | Get-IniContent -ErrorAction SilentlyContinue
        }
        catch {
            # Write-Verbose "Error parsing $TargetGptTmplPath : $_"
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose "Removing temp PSDrive $RandDrive"
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive -Force
        }
    }
}


function Get-GroupsXML {
<#
    .SYNOPSIS

        Helper to parse a groups.xml file path into a custom object.

    .PARAMETER GroupsXMLpath

        The groups.xml file path name to parse.

    .PARAMETER UsePSDrive

        Switch. Mount the target groups.xml folder path as a temporary PSDrive.
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $GroupsXMLPath,

        [Switch]
        $UsePSDrive
    )

    begin {
        if($UsePSDrive) {
            # if we're PSDrives, create a temporary mount point
            $Parts = $GroupsXMLPath.split('\')
            $FolderPath = $Parts[0..($Parts.length-2)] -join '\'
            $FilePath = $Parts[-1]
            $RandDrive = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''

            Write-Verbose "Mounting path $GroupsXMLPath using a temp PSDrive at $RandDrive"

            try {
                $Null = New-PSDrive -Name $RandDrive -PSProvider FileSystem -Root $FolderPath  -ErrorAction Stop
            }
            catch {
                Write-Verbose "Error mounting path $GroupsXMLPath : $_"
                return $Null
            }

            # so we can cd/dir the new drive
            $TargetGroupsXMLPath = $RandDrive + ":\" + $FilePath
        }
        else {
            $TargetGroupsXMLPath = $GroupsXMLPath
        }
    }

    process {

        try {
            Write-Verbose "Attempting to parse Groups.xml: $TargetGroupsXMLPath"
            [XML]$GroupsXMLcontent = Get-Content $TargetGroupsXMLPath -ErrorAction Stop

            # process all group properties in the XML
            $GroupsXMLcontent | Select-Xml "//Groups" | Select-Object -ExpandProperty node | ForEach-Object {

                $Groupname = $_.Group.Properties.groupName

                # extract the localgroup sid for memberof
                $GroupSID = $_.Group.Properties.GroupSid
                if(-not $LocalSid) {
                    if($Groupname -match 'Administrators') {
                        $GroupSID = 'S-1-5-32-544'
                    }
                    elseif($Groupname -match 'Remote Desktop') {
                        $GroupSID = 'S-1-5-32-555'
                    }
                    elseif($Groupname -match 'Guests') {
                        $GroupSID = 'S-1-5-32-546'
                    }
                    else {
                        $GroupSID = Convert-NameToSid -ObjectName $Groupname | Select-Object -ExpandProperty SID
                    }
                }

                # extract out members added to this group
                $Members = $_.Group.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {
                    if($_.sid) { $_.sid }
                    else { $_.name }
                }

                if ($Members) {

                    # extract out any/all filters...I hate you GPP
                    if($_.Group.filters) {
                        $Filters = $_.Group.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        $Filters = $Null
                    }

                    if($Members -isnot [System.Array]) { $Members = @($Members) }

                    $GPOGroup = New-Object PSObject
                    $GPOGroup | Add-Member Noteproperty 'GPOPath' $TargetGroupsXMLPath
                    $GPOGroup | Add-Member Noteproperty 'Filters' $Filters
                    $GPOGroup | Add-Member Noteproperty 'GroupName' $GroupName
                    $GPOGroup | Add-Member Noteproperty 'GroupSID' $GroupSID
                    $GPOGroup | Add-Member Noteproperty 'GroupMemberOf' $Null
                    $GPOGroup | Add-Member Noteproperty 'GroupMembers' $Members
                    $GPOGroup
                }
            }
        }
        catch {
            # Write-Verbose "Error parsing $TargetGroupsXMLPath : $_"
        }
    }

    end {
        if($UsePSDrive -and $RandDrive) {
            Write-Verbose "Removing temp PSDrive $RandDrive"
            Get-PSDrive -Name $RandDrive -ErrorAction SilentlyContinue | Remove-PSDrive -Force
        }
    }
}


function Get-NetGPOGroup {
<#
    .SYNOPSIS

        Returns all GPOs in a domain that set "Restricted Groups" or use groups.xml on on target machines.

        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: Get-NetGPO, Get-GptTmpl, Get-GroupsXML, Convert-NameToSid, Convert-SidToName
        Optional Dependencies: None

    .DESCRIPTION

        First enumerates all GPOs in the current/target domain using Get-NetGPO with passed
        arguments, and for each GPO checks if 'Restricted Groups' are set with GptTmpl.inf or
        group membership is set through Group Policy Preferences groups.xml files. For any
        GptTmpl.inf files found, the file is parsed with Get-GptTmpl and any 'Group Membership'
        section data is processed if present. Any found Groups.xml files are parsed with
        Get-GroupsXML and those memberships are returned as well.

    .PARAMETER GPOname

        The GPO name to query for, wildcards accepted.

    .PARAMETER DisplayName

        The GPO display name to query for, wildcards accepted.

    .PARAMETER Domain

        The domain to query for GPOs, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through for GPOs.
        e.g. "LDAP://cn={8FF59D28-15D7-422A-BCB7-2AE45724125A},cn=policies,cn=system,DC=dev,DC=testlab,DC=local"

    .PARAMETER ResolveMemberSIDs

        Switch. Try to resolve the SIDs of all found group members.

    .PARAMETER UsePSDrive

        Switch. Mount any found policy files with temporary PSDrives.

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Get-NetGPOGroup

        Returns all local groups set by GPO along with their members and memberof.

    .LINK

        https://morgansimonsenblog.azurewebsites.net/tag/groups/
#>

    [CmdletBinding()]
    Param (
        [String]
        $GPOname = '*',

        [String]
        $DisplayName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $ResolveMemberSIDs,

        [Switch]
        $UsePSDrive,

        [ValidateRange(1,10000)]
        [Int]
        $PageSize = 200
    )

    $Option = [System.StringSplitOptions]::RemoveEmptyEntries

    $GPOSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -Credential $Credential -ADSpath $ADSpath -PageSize $PageSize
    $GPOSearcher.filter="(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))"
    $GPOSearcher.PropertiesToLoad.AddRange(('displayname', 'name', 'gpcfilesyspath'))

    ForEach($GPOResult in $GPOSearcher.FindAll()) {

        $GPOdisplayName = $GPOResult.Properties['displayname']
        $GPOname = $GPOResult.Properties['name']
        $GPOPath = $GPOResult.Properties['gpcfilesyspath']
        Write-Verbose "Get-NetGPOGroup: enumerating $GPOPath"

        $ParseArgs =  @{
            'GptTmplPath' = "$GPOPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            'UsePSDrive' = $UsePSDrive
        }

        # parse the GptTmpl.inf 'Restricted Groups' file if it exists
        $Inf = Get-GptTmpl @ParseArgs

        if($Inf -and ($Inf.psbase.Keys -contains 'Group Membership')) {

            $Memberships = @{}

            # group the members/memberof fields for each entry
            ForEach ($Membership in $Inf.'Group Membership'.GetEnumerator()) {
                $Group, $Relation = $Membership.Key.Split('__', $Option) | ForEach-Object {$_.Trim()}

                # extract out ALL members
                $MembershipValue = $Membership.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}

                if($ResolveMemberSIDs) {
                    # if the resulting member is username and not a SID, attempt to resolve it
                    $GroupMembers = @()
                    ForEach($Member in $MembershipValue) {
                        if($Member -and ($Member.Trim() -ne '')) {
                            if($Member -notmatch '^S-1-.*') {
                                $MemberSID = Convert-NameToSid -Domain $Domain -ObjectName $Member | Select-Object -ExpandProperty SID
                                if($MemberSID) {
                                    $GroupMembers += $MemberSID
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                            else {
                                $GroupMembers += $Member
                            }
                        }
                    }
                    $MembershipValue = $GroupMembers
                }

                if(-not $Memberships[$Group]) {
                    $Memberships[$Group] = @{}
                }
                if($MembershipValue -isnot [System.Array]) {$MembershipValue = @($MembershipValue)}
                $Memberships[$Group].Add($Relation, $MembershipValue)
            }

            ForEach ($Membership in $Memberships.GetEnumerator()) {
                if($Membership -and $Membership.Key -and ($Membership.Key -match '^\*')) {
                    # if the SID is already resolved (i.e. begins with *) try to resolve SID to a name
                    $GroupSID = $Membership.Key.Trim('*')
                    if($GroupSID -and ($GroupSID.Trim() -ne '')) {
                        $GroupName = Convert-SidToName -SID $GroupSID
                    }
                    else {
                        $GroupName = $False
                    }
                }
                else {
                    $GroupName = $Membership.Key

                    if($GroupName -and ($GroupName.Trim() -ne '')) {
                        if($Groupname -match 'Administrators') {
                            $GroupSID = 'S-1-5-32-544'
                        }
                        elseif($Groupname -match 'Remote Desktop') {
                            $GroupSID = 'S-1-5-32-555'
                        }
                        elseif($Groupname -match 'Guests') {
                            $GroupSID = 'S-1-5-32-546'
                        }
                        elseif($GroupName.Trim() -ne '') {
                            $GroupSID = Convert-NameToSid -Domain $Domain -ObjectName $Groupname | Select-Object -ExpandProperty SID
                        }
                        else {
                            $GroupSID = $Null
                        }
                    }
                }

                $GPOGroup = New-Object PSObject
                $GPOGroup | Add-Member Noteproperty 'GPODisplayName' $GPODisplayName
                $GPOGroup | Add-Member Noteproperty 'GPOName' $GPOName
                $GPOGroup | Add-Member Noteproperty 'GPOPath' $GPOPath
                $GPOGroup | Add-Member Noteproperty 'GPOType' 'RestrictedGroups'
                $GPOGroup | Add-Member Noteproperty 'Filters' $Null
                $GPOGroup | Add-Member Noteproperty 'GroupName' $GroupName
                $GPOGroup | Add-Member Noteproperty 'GroupSID' $GroupSID
                $GPOGroup | Add-Member Noteproperty 'GroupMemberOf' $Membership.Value.Memberof
                $GPOGroup | Add-Member Noteproperty 'GroupMembers' $Membership.Value.Members
                $GPOGroup
            }
        }

        $ParseArgs =  @{
            'GroupsXMLpath' = "$GPOPath\MACHINE\Preferences\Groups\Groups.xml"
            'UsePSDrive' = $UsePSDrive
        }

        Get-GroupsXML @ParseArgs | ForEach-Object {
            if($ResolveMemberSIDs) {
                $GroupMembers = @()
                ForEach($Member in $_.GroupMembers) {
                    if($Member -and ($Member.Trim() -ne '')) {
                        if($Member -notmatch '^S-1-.*') {
                            # if the resulting member is username and not a SID, attempt to resolve it
                            $MemberSID = Convert-NameToSid -Domain $Domain -ObjectName $Member | Select-Object -ExpandProperty SID
                            if($MemberSID) {
                                $GroupMembers += $MemberSID
                            }
                            else {
                                $GroupMembers += $Member
                            }
                        }
                        else {
                            $GroupMembers += $Member
                        }
                    }
                }
                $_.GroupMembers = $GroupMembers
            }

            $_ | Add-Member Noteproperty 'GPODisplayName' $GPODisplayName
            $_ | Add-Member Noteproperty 'GPOName' $GPOName
            $_ | Add-Member Noteproperty 'GPOType' 'GroupPolicyPreferences'
            $_
        }
    }
}