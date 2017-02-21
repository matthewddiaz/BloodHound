
filter Get-NetLoggedon {
<#
    .SYNOPSIS

        This function will execute the NetWkstaUserEnum Win32API call to query
        a given host for actively logged on users.

    .PARAMETER ComputerName

        The hostname to query for logged on users.

    .OUTPUTS

        WKSTA_USER_INFO_1 structure. A representation of the WKSTA_USER_INFO_1
        result structure which includes the username and domain of logged on users,
        with the ComputerName added.

    .EXAMPLE

        PS C:\> Get-NetLoggedon

        Returns users actively logged onto the local host.

    .EXAMPLE

        PS C:\> Get-NetLoggedon -ComputerName sqlserver

        Returns users actively logged onto the 'sqlserver' host.

    .EXAMPLE

        PS C:\> Get-NetComputer | Get-NetLoggedon

        Returns all logged on userse for all computers in the domain.

    .LINK

        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost'
    )

    # extract the computer name from whatever object was passed on the pipeline
    $Computer = $ComputerName | Get-NameField

    # Declare the reference variables
    $QueryLevel = 1
    $PtrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get logged on user information
    $Result = $Netapi32::NetWkstaUserEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

    # Locate the offset of the initial intPtr
    $Offset = $PtrInfo.ToInt64()

    # 0 = success
    if (($Result -eq 0) -and ($Offset -gt 0)) {

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $WKSTA_USER_INFO_1::GetSize()

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++) {
            # create a new int ptr at the given offset and cast the pointer as our result structure
            $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
            $Info = $NewIntPtr -as $WKSTA_USER_INFO_1

            # return all the sections of the structure
            $LoggedOn = $Info | Select-Object *
            $LoggedOn | Add-Member Noteproperty 'ComputerName' $Computer
            $Offset = $NewIntPtr.ToInt64()
            $Offset += $Increment
            $LoggedOn
        }

        # free up the result buffer
        $Null = $Netapi32::NetApiBufferFree($PtrInfo)
    }
    else {
        Write-Verbose "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
}


filter Get-NetSession {
<#
    .SYNOPSIS

        This function will execute the NetSessionEnum Win32API call to query
        a given host for active sessions on the host.
        Heavily adapted from dunedinite's post on stackoverflow (see LINK below)

    .PARAMETER ComputerName

        The ComputerName to query for active sessions.

    .PARAMETER UserName

        The user name to filter for active sessions.

    .OUTPUTS

        SESSION_INFO_10 structure. A representation of the SESSION_INFO_10
        result structure which includes the host and username associated
        with active sessions, with the ComputerName added.

    .EXAMPLE

        PS C:\> Get-NetSession

        Returns active sessions on the local host.

    .EXAMPLE

        PS C:\> Get-NetSession -ComputerName sqlserver

        Returns active sessions on the 'sqlserver' host.

    .EXAMPLE

        PS C:\> Get-NetDomainController | Get-NetSession

        Returns active sessions on all domain controllers.

    .LINK

        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [String]
        $UserName = ''
    )

    # extract the computer name from whatever object was passed on the pipeline
    $Computer = $ComputerName | Get-NameField

    # arguments for NetSessionEnum
    $QueryLevel = 10
    $PtrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get session information
    $Result = $Netapi32::NetSessionEnum($Computer, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

    # Locate the offset of the initial intPtr
    $Offset = $PtrInfo.ToInt64()

    # 0 = success
    if (($Result -eq 0) -and ($Offset -gt 0)) {

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $SESSION_INFO_10::GetSize()

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++) {
            # create a new int ptr at the given offset and cast the pointer as our result structure
            $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
            $Info = $NewIntPtr -as $SESSION_INFO_10

            # return all the sections of the structure
            $Sessions = $Info | Select-Object *
            $Sessions | Add-Member Noteproperty 'ComputerName' $Computer
            $Offset = $NewIntPtr.ToInt64()
            $Offset += $Increment
            $Sessions
        }
        # free up the result buffer
        $Null = $Netapi32::NetApiBufferFree($PtrInfo)
    }
    else {
        Write-Verbose "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
}

filter Get-LoggedOnLocal {
<#
    .SYNOPSIS

        This function will query the HKU registry values to retrieve the local
        logged on users SID and then attempt and reverse it.
        Adapted technique from Sysinternal's PSLoggedOn script. Benefit over
        using the NetWkstaUserEnum API (Get-NetLoggedon) of less user privileges
        required (NetWkstaUserEnum requires remote admin access).

        Note: This function requires only domain user rights on the
        machine you're enumerating, but remote registry must be enabled.

        Function: Get-LoggedOnLocal
        Author: Matt Kelly, @BreakersAll

    .PARAMETER ComputerName

        The ComputerName to query for active sessions.

    .EXAMPLE

        PS C:\> Get-LoggedOnLocal

        Returns active sessions on the local host.

    .EXAMPLE

        PS C:\> Get-LoggedOnLocal -ComputerName sqlserver

        Returns active sessions on the 'sqlserver' host.

#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost'
    )

    # process multiple host object types from the pipeline
    $ComputerName = Get-NameField -Object $ComputerName

    try {
        # retrieve HKU remote registry values
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$ComputerName")

        # sort out bogus sid's like _class
        $Reg.GetSubKeyNames() | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | ForEach-Object {
            $UserName = Convert-SidToName $_

            $Parts = $UserName.Split('\')
            $UserDomain = $Null
            $UserName = $Parts[-1]
            if ($Parts.Length -eq 2) {
                $UserDomain = $Parts[0]
            }

            $LocalLoggedOnUser = New-Object PSObject
            $LocalLoggedOnUser | Add-Member Noteproperty 'ComputerName' "$ComputerName"
            $LocalLoggedOnUser | Add-Member Noteproperty 'UserDomain' $UserDomain
            $LocalLoggedOnUser | Add-Member Noteproperty 'UserName' $UserName
            $LocalLoggedOnUser | Add-Member Noteproperty 'UserSID' $_
            $LocalLoggedOnUser
        }
    }
    catch { }
}
