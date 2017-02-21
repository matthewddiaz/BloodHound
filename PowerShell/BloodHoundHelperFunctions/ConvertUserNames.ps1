filter Convert-ADName {
<#
    .SYNOPSIS

        Converts user/group names from NT4 (DOMAIN\user) or domainSimple (user@domain.com)
        to canonical format (domain.com/Users/user) or NT4.

        Based on Bill Stewart's code from this article:
            http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats

    .PARAMETER ObjectName

        The user/group name to convert.

    .PARAMETER InputType

        The InputType of the user/group name ("NT4","DN","Simple","Canonical").

    .PARAMETER OutputType

        The OutputType of the user/group name ("NT4","DN","Simple","Canonical").

    .EXAMPLE

        PS C:\> Convert-ADName -ObjectName "dev\dfm"

        Returns "dev.testlab.local/Users/Dave"

    .EXAMPLE

        PS C:\> Convert-SidToName "S-..." | Convert-ADName

        Returns the canonical name for the resolved SID.

    .LINK

        http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $ObjectName,

        [String]
        [ValidateSet("NT4","DN","Simple","Canonical")]
        $InputType,

        [String]
        [ValidateSet("NT4","DN","Simple","Canonical")]
        $OutputType
    )

    $NameTypes = @{
        'DN'        = 1
        'Canonical' = 2
        'NT4'       = 3
        'Simple'    = 5
    }

    if(-not $PSBoundParameters['InputType']) {
        if( ($ObjectName.split('/')).Count -eq 2 ) {
            $ObjectName = $ObjectName.replace('/', '\')
        }

        if($ObjectName -match "^[A-Za-z]+\\[A-Za-z ]+") {
            $InputType = 'NT4'
        }
        elseif($ObjectName -match "^[A-Za-z ]+@[A-Za-z\.]+") {
            $InputType = 'Simple'
        }
        elseif($ObjectName -match "^[A-Za-z\.]+/[A-Za-z]+/[A-Za-z/ ]+") {
            $InputType = 'Canonical'
        }
        elseif($ObjectName -match '^CN=.*') {
            $InputType = 'DN'
        }
        else {
            Write-Warning "Can not identify InType for $ObjectName"
        }
    }
    elseif($InputType -eq 'NT4') {
        $ObjectName = $ObjectName.replace('/', '\')
    }

    if(-not $PSBoundParameters['OutputType']) {
        $OutputType = Switch($InputType) {
            'NT4' {'Canonical'}
            'Simple' {'NT4'}
            'DN' {'NT4'}
            'Canonical' {'NT4'}
        }
    }

    # try to extract the domain from the given format
    $Domain = Switch($InputType) {
        'NT4' { $ObjectName.split("\")[0] }
        'Simple' { $ObjectName.split("@")[1] }
        'Canonical' { $ObjectName.split("/")[0] }
        'DN' {$ObjectName.subString($ObjectName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'}
    }

    # Accessor functions to simplify calls to NameTranslate
    function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
        $Output = $Object.GetType().InvokeMember($Method, "InvokeMethod", $Null, $Object, $Parameters)
        if ( $Output ) { $Output }
    }
    function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
        [Void] $Object.GetType().InvokeMember($Property, "SetProperty", $Null, $Object, $Parameters)
    }

    $Translate = New-Object -ComObject NameTranslate

    try {
        Invoke-Method $Translate "Init" (1, $Domain)
    }
    catch [System.Management.Automation.MethodInvocationException] {
        # Write-Verbose "Error with translate init in Convert-ADName: $_"
    }

    Set-Property $Translate "ChaseReferral" (0x60)

    try {
        Invoke-Method $Translate "Set" ($NameTypes[$InputType], $ObjectName)
        (Invoke-Method $Translate "Get" ($NameTypes[$OutputType]))
    }
    catch [System.Management.Automation.MethodInvocationException] {
        # Write-Verbose "Error with translate Set/Get in Convert-ADName: $_"
    }
}

function Convert-LDAPProperty {
<#
    .SYNOPSIS

        Helper that converts specific LDAP property result fields.
        Used by several of the Get-Net* function.

    .PARAMETER Properties

        Properties object to extract out LDAP fields for display.
#>
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # try to convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}