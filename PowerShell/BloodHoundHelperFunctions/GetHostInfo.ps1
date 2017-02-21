
########################################################
#
# Misc. helpers
#
########################################################

filter Get-IniContent {
<#
    .SYNOPSIS

        This helper parses an .ini file into a proper PowerShell object.

        Author: 'The Scripting Guys'
        Link: https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/

    .LINK

        https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [ValidateScript({ Test-Path -Path $_ })]
        [String[]]
        $Path
    )

    ForEach($TargetPath in $Path) {
        $IniObject = @{}
        Switch -Regex -File $TargetPath {
            "^\[(.+)\]" # Section
            {
                $Section = $matches[1].Trim()
                $IniObject[$Section] = @{}
                $CommentCount = 0
            }
            "^(;.*)$" # Comment
            {
                $Value = $matches[1].Trim()
                $CommentCount = $CommentCount + 1
                $Name = 'Comment' + $CommentCount
                $IniObject[$Section][$Name] = $Value
            }
            "(.+?)\s*=(.*)" # Key
            {
                $Name, $Value = $matches[1..2]
                $Name = $Name.Trim()
                $Values = $Value.split(',') | ForEach-Object {$_.Trim()}
                if($Values -isnot [System.Array]) {$Values = @($Values)}
                $IniObject[$Section][$Name] = $Values
            }
        }
        $IniObject
    }
}

filter Get-IPAddress {
<#
    .SYNOPSIS

        Resolves a given hostename to its associated IPv4 address.
        If no hostname is provided, it defaults to returning
        the IP address of the localhost.

    .EXAMPLE

        PS C:\> Get-IPAddress -ComputerName SERVER

        Return the IPv4 address of 'SERVER'

    .EXAMPLE

        PS C:\> Get-Content .\hostnames.txt | Get-IPAddress

        Get the IP addresses of all hostnames in an input file.
#>

    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = $Env:ComputerName
    )

    try {
        # extract the computer name from whatever object was passed on the pipeline
        $Computer = $ComputerName | Get-NameField

        # get the IP resolution of this specified hostname
        @(([Net.Dns]::GetHostEntry($Computer)).AddressList) | ForEach-Object {
            if ($_.AddressFamily -eq 'InterNetwork') {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ComputerName' $Computer
                $Out | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                $Out
            }
        }
    }
    catch {
        Write-Verbose -Message 'Could not resolve host to an IP Address.'
    }
}

filter Get-NameField {
<#
    .SYNOPSIS

        Helper that attempts to extract appropriate field names from
        passed computer objects.

    .PARAMETER Object

        The passed object to extract name fields from.

    .PARAMETER DnsHostName

        A DnsHostName to extract through ValueFromPipelineByPropertyName.

    .PARAMETER Name

        A Name to extract through ValueFromPipelineByPropertyName.

    .EXAMPLE

        PS C:\> Get-NetComputer -FullData | Get-NameField
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Object]
        $Object,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $DnsHostName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $Name
    )

    if($PSBoundParameters['DnsHostName']) {
        $DnsHostName
    }
    elseif($PSBoundParameters['Name']) {
        $Name
    }
    elseif($Object) {
        if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {
            # objects from Get-NetComputer
            $Object.dnshostname
        }
        elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {
            # objects from Get-NetDomainController
            $Object.name
        }
        else {
            # strings and catch alls
            $Object
        }
    }
    else {
        return $Null
    }
}





