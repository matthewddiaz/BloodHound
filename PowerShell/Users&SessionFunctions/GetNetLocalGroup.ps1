########################################################
#
# Functions that enumerate a single host, either through
# WinNT, WMI, remote registry, or API calls
# (with PSReflect).
#
########################################################

function Get-NetLocalGroup {
<#
    .SYNOPSIS

        Gets a list of all current users in a specified local group,
        or returns the names of all local groups with -ListGroups.

    .PARAMETER ComputerName

        The hostname or IP to query for local group users.

    .PARAMETER ComputerFile

        File of hostnames/IPs to query for local group users.

    .PARAMETER GroupName

        The local group name to query for users. If not given, it defaults to "Administrators"

    .PARAMETER Recurse

        Switch. If the local member member is a domain group, recursively try to resolve its members to get a list of domain users who can access this machine.

    .PARAMETER API

        Switch. Use API calls instead of the WinNT service provider. Less information,
        but the results are faster.

    .PARAMETER IsDomain

        Switch. Only return results that are domain accounts.

    .PARAMETER DomainSID

        The SID of the enumerated machine's domain, used to identify if results are domain
        or local when using the -API flag.

    .EXAMPLE

        PS C:\> Get-NetLocalGroup

        Returns the usernames that of members of localgroup "Administrators" on the local host.

    .EXAMPLE

        PS C:\> Get-NetLocalGroup -ComputerName WINDOWSXP

        Returns all the local administrator accounts for WINDOWSXP

    .EXAMPLE

        PS C:\> Get-NetLocalGroup -ComputerName WINDOWS7 -Recurse

        Returns all effective local/domain users/groups that can access WINDOWS7 with
        local administrative privileges.

    .EXAMPLE

        PS C:\> "WINDOWS7", "WINDOWSSP" | Get-NetLocalGroup -API

        Returns all local groups on the the passed hosts using API calls instead of the
        WinNT service provider.

    .LINK

        http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
        http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
#>

    [CmdletBinding(DefaultParameterSetName = 'WinNT')]
    param(
        [Parameter(ParameterSetName = 'API', Position=0, ValueFromPipeline=$True)]
        [Parameter(ParameterSetName = 'WinNT', Position=0, ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String[]]
        $ComputerName = $Env:ComputerName,

        [Parameter(ParameterSetName = 'WinNT')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $ComputerFile,

        [Parameter(ParameterSetName = 'WinNT')]
        [Parameter(ParameterSetName = 'API')]
        [String]
        $GroupName = 'Administrators',

        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,

        [Switch]
        $IsDomain,

        [ValidateNotNullOrEmpty()]
        [String]
        $DomainSID
    )

    process {

        $Servers = @()

        # if we have a host list passed, grab it
        if($ComputerFile) {
            $Servers = Get-Content -Path $ComputerFile
        }
        else {
            # otherwise assume a single host name
            $Servers += $ComputerName | Get-NameField
        }

        # query the specified group using the WINNT provider, and
        # extract fields as appropriate from the results
        ForEach($Server in $Servers) {

            if($API) {
                # if we're using the Netapi32 NetLocalGroupGetMembers API call to get the local group information

                # arguments for NetLocalGroupGetMembers
                $QueryLevel = 2
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0

                # get the local user information
                $Result = $Netapi32::NetLocalGroupGetMembers($Server, $GroupName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

                # Locate the offset of the initial intPtr
                $Offset = $PtrInfo.ToInt64()

                $LocalUsers = @()

                # 0 = success
                if (($Result -eq 0) -and ($Offset -gt 0)) {

                    # Work out how mutch to increment the pointer by finding out the size of the structure
                    $Increment = $LOCALGROUP_MEMBERS_INFO_2::GetSize()

                    # parse all the result structures
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_MEMBERS_INFO_2

                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment

                        $SidString = ''
                        $Result2 = $Advapi32::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if($Result2 -eq 0) {
                            # error?
                        }
                        else {
                            $IsGroup = $($Info.lgrmi2_sidusage -ne 'SidTypeUser')
                            $LocalUsers += @{
                                'ComputerName' = $Server
                                'AccountName' = $Info.lgrmi2_domainandname
                                'SID' = $SidString
                                'IsGroup' = $IsGroup
                                'Type' = 'LocalUser'
                            }
                        }
                    }

                    # free up the result buffer
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)

                    $MachineSid = ($LocalUsers | Where-Object {$_['SID'] -like '*-500'})['SID']
                    $MachineSid = $MachineSid.Substring(0, $MachineSid.LastIndexOf('-'))
                    try {
                        ForEach($LocalUser in $LocalUsers) {
                            if($DomainSID -and ($LocalUser['SID'] -match $DomainSID)) {
                                $LocalUser['IsDomain'] = $True
                            }
                            elseif($LocalUser['SID'] -match $MachineSid) {
                                $LocalUser['IsDomain'] = $False
                            }
                            else {
                                $LocalUser['IsDomain'] = $True
                            }
                            if($IsDomain) {
                                if($LocalUser['IsDomain']) {
                                    $LocalUser
                                }
                            }
                            else {
                                $LocalUser
                            }
                        }
                    }
                    catch { }
                }
                else {
                    # error
                }
            }

            else {
                # otherwise we're using the WinNT service provider
                try {
                    $LocalUsers = @()
                    $Members = @($([ADSI]"WinNT://$Server/$GroupName,group").psbase.Invoke('Members'))

                    $Members | ForEach-Object {
                        $LocalUser = ([ADSI]$_)

                        $AdsPath = $LocalUser.InvokeGet('AdsPath').Replace('WinNT://', '')

                        if(([regex]::Matches($AdsPath, '/')).count -eq 1) {
                            # DOMAIN\user
                            $MemberIsDomain = $True
                            $Name = $AdsPath.Replace('/', '\')
                        }
                        else {
                            # DOMAIN\machine\user
                            $MemberIsDomain = $False
                            $Name = $AdsPath.Substring($AdsPath.IndexOf('/')+1).Replace('/', '\')
                        }

                        $IsGroup = ($LocalUser.SchemaClassName -like 'group')
                        if($IsDomain) {
                            if($MemberIsDomain) {
                                $LocalUsers += @{
                                    'ComputerName' = $Server
                                    'AccountName' = $Name
                                    'SID' = ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet('ObjectSID'),0)).Value)
                                    'IsGroup' = $IsGroup
                                    'IsDomain' = $MemberIsDomain
                                    'Type' = 'LocalUser'
                                }
                            }
                        }
                        else {
                            $LocalUsers += @{
                                'ComputerName' = $Server
                                'AccountName' = $Name
                                'SID' = ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet('ObjectSID'),0)).Value)
                                'IsGroup' = $IsGroup
                                'IsDomain' = $MemberIsDomain
                                'Type' = 'LocalUser'
                            }
                        }
                    }
                    $LocalUsers
                }
                catch {
                    Write-Verbose "Get-NetLocalGroup error for $Server : $_"
                }
            }
        }
    }
}
