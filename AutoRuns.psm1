#Requires -Version 4.0

Function Get-PSAutorun {
<#
    .SYNOPSIS
        Get Autorun entries.

    .DESCRIPTION
        Retrieve a list of programs configured to autostart at boot or logon.

    .PARAMETER All
        Switch to gather artifacts from all categories.
        If it's turned on, all other category switches will be ignored.

    .PARAMETER BootExecute
        Switch to gather artifacts from the Boot Execute category.

    .PARAMETER AppinitDLLs
        Switch to gather artifacts from the Appinit category.

    .PARAMETER ExplorerAddons
        Switch to gather artifacts from the Explorer category.

    .PARAMETER ImageHijacks
        Switch to gather artifacts from the Image Hijacks category.

    .PARAMETER InternetExplorerAddons
        Switch to gather artifacts from the Intenet Explorer category.

    .PARAMETER KnownDLLs
        Switch to gather artifacts from the KnownDLLs category.

    .PARAMETER Logon
        Switch to gather artifacts from the Logon category.

    .PARAMETER Winsock
        Switch to gather artifacts from the Winsock and network providers category.

    .PARAMETER Codecs
        Switch to gather artifacts from the Codecs category.

    .PARAMETER OfficeAddins
        Switch to gather artifacts from Office Addins

    .PARAMETER PrintMonitorDLLs
        Switch to gather artifacts from the Print Monitors category.

    .PARAMETER LSAsecurityProviders
        Switch to gather artifacts from the LSA Providers category.

    .PARAMETER ServicesAndDrivers
        Switch to gather artifacts from the Services and Drivers categories.

    .PARAMETER ScheduledTasks
        Switch to gather artifacts from the Scheduled tasks category.

    .PARAMETER Winlogon
        Switch to gather artifacts from the Winlogon category.

    .PARAMETER WMI
        Switch to gather artifacts from the WMI category.

    .PARAMETER PSProfiles
        Switch to gather artifacts from the PowerShell profiles category.

    .PARAMETER ShowFileHash
        Switch to enable and display MD5, SHA1 and SHA2 file hashes.

    .PARAMETER VerifyDigitalSignature
        Switch to report if a file is digitally signed with the built-in Get-AuthenticodeSignature cmdlet.

    .EXAMPLE
        Get-PSAutorun -BootExecute -AppinitDLLs

    .EXAMPLE
        Get-PSAutorun -KnownDLLs -LSAsecurityProviders -ShowFileHash

    .EXAMPLE
         Get-PSAutorun -All -ShowFileHash -VerifyDigitalSignature

    .EXAMPLE
         Get-PSAutorun -All -User * -ShowFileHash -VerifyDigitalSignature
    .NOTES

    DYNAMIC PARAMETER User
        Specify what user hive to be scanned.
        Scans by default HKCU when the parameter isn't explicitly used.
        '*' can be used to indicate that all loaded user hives will be scanned.
#>

    [CmdletBinding(DefaultParameterSetName='Pretty')]
    Param(
        [switch]$All,
        [Switch]$BootExecute,
        [Switch]$AppinitDLLs,
        [Switch]$ExplorerAddons,
        [Switch]$ImageHijacks,
        [Switch]$InternetExplorerAddons,
        [Switch]$KnownDLLs,
        [Switch]$Logon,
        [Switch]$Winsock,
        [Switch]$Codecs,
        [Switch]$OfficeAddins,
        [Switch]$PrintMonitorDLLs,
        [Switch]$LSAsecurityProviders,
        [Switch]$ServicesAndDrivers,
        [Switch]$ScheduledTasks,
        [Switch]$Winlogon,
        [Switch]$WMI,
        [Switch]$PSProfiles,

        [Parameter(ParameterSetName='Plain')]
        [Switch]$Raw,

        [Parameter(ParameterSetName='Pretty')]
        [Switch]$ShowFileHash,

        [Parameter(ParameterSetName='Pretty')]
        [Switch]$VerifyDigitalSignature
    )
DynamicParam  {

    Function Test-isValidSid {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    Param(
    [Parameter(Mandatory,ValueFromPipeline)]
    [string]$SID
    )
    Begin {}
    Process {
        try {
            $null = [System.Security.Principal.SecurityIdentifier]$SID
            $true
        } catch {
            $false
        }
    }
    End {}
    }

    Function Get-UserNameFromSID {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory,ValueFromPipeline)]
    [ValidateScript({ $_ | Test-isValidSid})]
    [string]$SID
    )
    Begin {}
    Process {
        try {
            ([System.Security.Principal.SecurityIdentifier]$SID).Translate(
                [System.Security.Principal.NTAccount]
            ).Value
        } catch {
            Write-Warning -Message "Cannot translate SID to UserName for $($SID)"
        }
    }
    End {}
    }

    $Dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
    $AttribColl1 = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $Param1Att = New-Object System.Management.Automation.ParameterAttribute
    $Param1Att.Mandatory = $false
    $AttribColl1.Add($Param1Att)

    try {
        If (-not(Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
            $null = New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue
        }
        $allUsers = (Get-Item -Path 'HKU:' -ErrorAction SilentlyContinue).GetSubKeyNames() |
        ForEach-Object -Process {
         if ($_ | Test-isValidSid) { $_ | Get-UserNameFromSID }
        } -End {'*'}
    } catch {
        Throw 'Unable list available users'
    }
    if ($allUsers) {
        $AttribColl1.Add((New-Object System.Management.Automation.ValidateSetAttribute($allUsers)))
        $Dictionary.Add('User',(New-Object System.Management.Automation.RuntimeDefinedParameter('User', [string], $AttribColl1)))
        $Dictionary
    }
}
Begin {
    #region Dynamic parameter users:
    $Users = New-Object -TypeName System.Collections.ArrayList
    (Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue).GetSubKeyNames() |
    ForEach-Object -Process {
        if ($_ | Test-isValidSid) { $_ | Get-UserNameFromSID }
    } |
    ForEach-Object {
        $n = $_
        $sid = ([System.Security.Principal.NTAccount]$n).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $null = $Users.Add(
            @{
                UserName = $_
                SID = $sid
                Hive = "HKU:\$($sid)"
                ProfilePath = $(
                    try {
                        (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($sid)" -Name 'ProfileImagePath' -ErrorAction Stop
                        ).'ProfileImagePath' -replace '%(s|S)(y|Y)(s|S)(t|T)(e|E)(m|M)(r|R)(o|O)(o|O)(t|T)%','C:\Windows'
                    } catch {
                       Write-Error 'Failed to get the profilepath'
                    }
                )
            }
        )
    }
    $allUsers = $Users
    if ($PSBoundParameters.ContainsKey('User')) {
        if ($PSBoundParameters['User'] -eq '*') {
            $Users = $Users
        } else {
            $Users = $Users | Where-Object { $_['UserName'] -eq "$($PSBoundParameters['User'])" }
        }
    } else {
        $Users = $Users | Where-Object { $_['UserName'] -eq $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) }
        $Users['Hive'] = 'HKCU:'
    }
    #endregion
    #region Helperfunctions

    Function Get-RegValue {
    [CmdletBinding()]
    Param(
        [string]$Path,
        [string[]]$Name,
        [string]$Category
    )
    Begin{
        if ($Path -match 'Wow6432Node') {
            $cp = 'SOFTWARE\Wow6432Node\Classes\CLSID'
        } else {
            $cp = 'SOFTWARE\Classes\CLSID'
        }
        if ($Path -match '^HKCU:\\') {
            $ClassesPath = Join-Path -Path (Split-Path $Path -Qualifier) -ChildPath $cp
        } else {
            $ClassesPath = Join-Path -Path ((($Path -split '\\',3)[0..1]) -join '\'  ) -ChildPath $cp
        }
        Write-Verbose -Message "Classes path set to $($ClassesPath)"
    }
    Process {
        try {
            $Values = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($Name -eq '*') {
                $Name = $Values.GetValueNames()
            }
            $Name | ForEach-Object -Process {
                # Need to differentiate between empty string and really non existing values
                if ($null -ne $Values.GetValue($_)) {
                    $Value  = Switch -regex($Values.GetValue($_)) {
                        '^\{[A-Z0-9]{4}([A-Z0-9]{4}-){4}[A-Z0-9]{12}\}$' {
                            (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                            break
                        }
                        default {
                            $_
                        }
                    }
                    if ($Value) {
                        [pscustomobject]@{
                            Path = $Path
                            Item = $_
                            Value = $Value
                            Category = $Category
                        }
                    }
                }
            }
        } catch {
        }
    }
    End {}
    }

    Function Get-AllScheduledTask {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
            [System.String[]]$ComputerName = $env:COMPUTERNAME
        )
        Begin {
            Function Get-SubFolder ($folder,[switch]$recurse) {
                $folder
                if ($recurse) {
                    $TaskService.GetFolder($folder).GetFolders(0) | ForEach-Object {
                    Get-SubFolder $_.Path -Recurse
                    }
                } else {
                    $TaskService.GetFolder($folder).GetFolders(0)
                }
            }
        }
        Process {
            $ComputerName | ForEach-Object -Process {
                $alltasks = @()
                $Computer  = $_
                $TaskService = New-Object -com schedule.service
                try {
                    $null = $TaskService.Connect($Computer)

                } catch {
                    Write-Warning "Cannot connect to $Computer because $($_.Exception.Message)"
                    return
                }
                Get-SubFolder -folder '\' -recurse | ForEach-Object -Process {

                    $TaskService.GetFolder($_).GetTasks(1) | ForEach-Object -Process {
                        $obj = New-Object -TypeName pscustomobject -Property @{
                            ComputerName = $Computer
                            Path = Split-Path $_.Path
                            Name = $_.Name
                        }
                        $alltasks += $obj
                    }
                }
                Write-Verbose -Message "There's a total of $($alltasks.Count) tasks on $Computer"
                $alltasks
            }
        }
        End {}
    }

    Function Get-Task {
    [CmdletBinding()]
    [OutputType('System.Object[]')]
        param (
        [parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,Mandatory=$false)]
        [system.string[]] ${ComputerName} = $env:computername,

        [parameter(ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$true,Mandatory=$false,
                    HelpMessage="The task folder string must begin by '\'")]
        [ValidatePattern('^\\')]
        [system.string[]] ${Path} = '\',

        [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [system.string[]] ${Name} = $null
        )
        Begin {}
        Process
        {
            $resultsar = @()
            $ComputerName | ForEach-Object -Process {
                $Computer = $_
                $TaskService = New-Object -com schedule.service
                try {
                    $null = $TaskService.Connect($Computer)
                } catch {
                    Write-Warning "Failed to connect to $Computer"
                }
                if ($TaskService.Connected) {
                    Write-Verbose -Message "Connected to the scheduler service of computer $Computer"
                        Foreach ($Folder in $Path) {
                            Write-Verbose -Message "Dealing with folder task $Folder"
                            $RootFolder = $null
                            try {
                                $RootFolder = $TaskService.GetFolder($Folder)
                            } catch {
                                Write-Warning -Message "The folder task $Folder cannot be found"
                            }
                            if ($RootFolder) {
                                Foreach ($Task in $Name) {
                                    $TaskObject = $null
                                    try {
                                        Write-Verbose -Message "Dealing with task name $Task"
                                        $TaskObject = $RootFolder.GetTask($Task)
                                    } catch {
                                        Write-Warning -Message "The task $Task cannot be found under $Folder"
                                    }
                                    if ($TaskObject) {
                                        # Status
                                        # http://msdn.microsoft.com/en-us/library/windows/desktop/aa383617%28v=vs.85%29.aspx
                                        switch ($TaskObject.State) {
                                            0 { $State = 'Unknown'  ; break}
                                            1 { $State = 'Disabled' ; break}
                                            2 { $State = 'Queued'   ; break}
                                            3 { $State = 'Ready'    ; break}
                                            4 { $State = 'Running'  ; break}
                                            default {$State = $_ }
                                        }

                                        $resultsar += New-Object -TypeName pscustomobject -Property @{
                                            ComputerName = $Computer
                                            Name = $TaskObject.Name
                                            Path = $Folder
                                            State = $State
                                            Enabled = $TaskObject.Enabled
                                            Xml = $TaskObject.XML

                                        }
                                    }
                                }
                            }
                        }
                }
            }
            $resultsar
        }
        End {}
    }

    # From David Wyatt
    # http://gallery.technet.microsoft.com/scriptcenter/Normalize-file-system-5d33985a
    Function Get-NormalizedFileSystemPath {
        <#
        .Synopsis
            Normalizes file system paths.
        .DESCRIPTION
            Normalizes file system paths.  This is similar to what the Resolve-Path cmdlet does, except Get-NormalizedFileSystemPath also properly handles UNC paths and converts 8.3 short names to long paths.
        .PARAMETER Path
            The path or paths to be normalized.
        .PARAMETER IncludeProviderPrefix
            If this switch is passed, normalized paths will be prefixed with 'FileSystem::'.  This allows them to be reliably passed to cmdlets such as Get-Content, Get-Item, etc, regardless of Powershell's current location.
        .EXAMPLE
            Get-NormalizedFileSystemPath -Path '\\server\share\.\SomeFolder\..\SomeOtherFolder\File.txt'

            Returns '\\server\share\SomeOtherFolder\File.txt'
        .EXAMPLE
            '\\server\c$\.\SomeFolder\..\PROGRA~1' | Get-NormalizedFileSystemPath -IncludeProviderPrefix

            Assuming you can access the c$ share on \\server, and PROGRA~1 is the short name for "Program Files" (which is common), returns:

            'FileSystem::\\server\c$\Program Files'
        .INPUTS
            String
        .OUTPUTS
            String
        .NOTES
            Paths passed to this command cannot contain wildcards; these will be treated as invalid characters by the .NET Framework classes which do the work of validating and normalizing the path.
        .LINK
            Resolve-Path
        #>

        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
            [Alias('PSPath', 'FullName')]
            [string[]]
            $Path,

            [switch]
            $IncludeProviderPrefix
        )
        Process{
            foreach ($_path in $Path)
            {
                $_resolved = $_path

                if ($_resolved -match '^([^:]+)::') {
                    $providerName = $matches[1]

                    if ($providerName -ne 'FileSystem') {
                        Write-Error "Only FileSystem paths may be passed to Get-NormalizedFileSystemPath.  Value '$_path' is for provider '$providerName'."
                        continue
                    }

                    $_resolved = $_resolved.Substring($matches[0].Length)
                }

                if (-not [System.IO.Path]::IsPathRooted($_resolved)) {
                    $_resolved = Join-Path -Path $PSCmdlet.SessionState.Path.CurrentFileSystemLocation -ChildPath $_resolved
                }

                try {
                    $dirInfo = New-Object System.IO.DirectoryInfo($_resolved)
                } catch {
                    $exception = $_.Exception
                    while ($null -ne $exception.InnerException) {
                        $exception = $exception.InnerException
                    }
                    Write-Error "Value '$_path' could not be parsed as a FileSystem path: $($exception.Message)"
                    continue
                }

                $_resolved = $dirInfo.FullName

                if ($IncludeProviderPrefix) {
                    $_resolved = "FileSystem::$_resolved"
                }
                Write-Output $_resolved
            }
        }
    }

    Function Get-PSRawAutoRun {
        [CmdletBinding()]
        Param(
            [switch]$All,
            [Switch]$BootExecute,
            [Switch]$AppinitDLLs,
            [Switch]$ExplorerAddons,
            [Switch]$ImageHijacks,
            [Switch]$InternetExplorerAddons,
            [Switch]$KnownDLLs,
            [Switch]$Logon,
            [Switch]$Winsock,
            [Switch]$Codecs,
            [Switch]$OfficeAddins,
            [Switch]$PrintMonitorDLLs,
            [Switch]$LSAsecurityProviders,
            [Switch]$ServicesAndDrivers,
            [Switch]$ScheduledTasks,
            [Switch]$Winlogon,
            [Switch]$WMI,
            [Switch]$PSProfiles,
            [Switch]$ShowFileHash,
            [Switch]$VerifyDigitalSignature,
            [Switch]$Raw,
            [PSObject]$User=$Users

        )
        Begin {
            ## Add 'All' if nothing else was supplied
            $parametersToIgnore = ('ShowFileHash','VerifyDigitalSignature','User','Raw') +
                [System.Management.Automation.PSCmdlet]::CommonParameters +
                [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
            if(($PSBoundParameters.Keys | Where-Object { $_ -notin $parametersToIgnore }).Count -eq 0)
            {
                $All = [switch]::Present
            }
        }
        Process {
            if ($All -or $BootExecute) {
                Write-Verbose -Message 'Looking for Boot Execute entries'
                #region Boot Execute
	            $Category = @{ Category = 'Boot Execute'}

                # REG_MULTI_SZ
	            'BootExecute','SetupExecute','Execute','S0InitialCommand' | ForEach-Object {
		            $item = $_
                    $v = $null
                    $v = (Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Name $_ @Category)
                    if ($v) {
                        $v.Value | ForEach-Object {
                            if ($_ -ne '""') {
                                [pscustomobject]@{
                                    Path = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
                                    Item = $item
                                    Value = $_
                                    Category = 'Boot Execute'
                                }
                            }
                        }
                    }
	            }

                #endregion Boot Execute
            }
            if ($All -or $AppinitDLLs) {
                Write-Verbose -Message 'Looking for Appinit DLLs entries'
                #region AppInit
	            $null,'Wow6432Node' | Foreach-Object {
		            Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows NT\CurrentVersion\Windows" -Name 'Appinit_Dlls' -Category 'AppInit'
	            }

	            if (Test-Path -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCertDlls' -PathType Container) {
		            Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCertDlls' -Name '*' -Category 'AppInit'
	            }
                #endregion AppInit
            }
            if ($All -or $ExplorerAddons) {
                Write-Verbose -Message 'Looking for Explorer Add-ons entries'
                #region Explorer

                $Category = @{ Category = 'Explorer'}

                # Filter & Handler
                'Filter','Handler' | ForEach-Object -Process {
                    $key = "HKLM:\SOFTWARE\Classes\Protocols\$($_)"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            if ($_ -eq 'ms-help') {
                                # if ([environment]::Is64BitOperatingSystem) {
                                #     $ClassesPath = 'HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID'
                                # } else {
                                #     $ClassesPath = 'HKLM:\SOFTWARE\Classes\CLSID'
                                # }
                                $i = (Get-ItemProperty -Path "$key\ms-help" -Name 'CLSID').CLSID
                                [pscustomobject]@{
                                    Path = "$key\ms-help"
                                    Item = $i
                                    Value = $(
                                        (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID' -ChildPath "$($i)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)';
                                        (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($i)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)';
                                    ) | Where-Object { $null -ne $_ } | Sort-Object -Unique
                                    Category = 'Explorer'
                                }
                            } else {
                                Get-RegValue -Path "$key\$($_)" -Name 'CLSID' @Category
                            }
                        }
                    }
                }

                # SharedTaskScheduler
                $null,'Wow6432Node' | Foreach-Object -Process {
                    Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" -Name '*' @Category
                }

                # ShellServiceObjects
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        [pscustomobject]@{
                            Path = $key
                            Item = $_
                            Value = $(
                                try {
                                    (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction Stop).'(default)'
                                } catch {
                                    $null
                                }
                            )
                            Category = 'Explorer'
                        }
                    }
                }

                # ShellExecuteHooks
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
                    if (Test-Path -Path $key -PathType Container) {
                        $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                         (Get-Item -Path $key).GetValueNames() | ForEach-Object {
                            # Get-RegValue -Path $key -Name $_ @Category
                            [pscustomobject]@{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                                Category = 'Explorer'
                            }
                         }
                    }
                }

                # ShellServiceObjectDelayLoad
                $null,'Wow6432Node' | Foreach-Object -Process {
                    Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" -Name '*' @Category
                }

                # Handlers
                @(
                    @{Name = '*' ; Properties = @('ContextMenuHandlers','PropertySheetHandlers')},
                    @{Name ='Drive'  ; Properties = @('ContextMenuHandlers')},
                    @{Name ='AllFileSystemObjects'  ; Properties = @('ContextMenuHandlers','DragDropHandlers','PropertySheetHandlers')},
                    @{Name ='Directory'  ; Properties = @('ContextMenuHandlers','DragDropHandlers','PropertySheetHandlers', 'CopyHookHandlers')},
                    @{Name ='Directory\Background'  ; Properties = @('ContextMenuHandlers')},
                    @{Name ='Folder' ; Properties = @('ColumnHandlers','ContextMenuHandlers','DragDropHandlers','ExtShellFolderViews','PropertySheetHandlers')}
                ) | ForEach-Object -Process {

                    $Name = $_.Name
                    $Properties = $_.Properties

                    $null,'Wow6432Node' | Foreach-Object -Process {
                        $key = "HKLM:\Software\$($_)\Classes\$Name\ShellEx"
                        $ClassPath = "HKLM:\Software\$($_)\Classes\CLSID"
                        $Hive = $_
                        $Properties | ForEach-Object -Process {
                            $subkey = Join-Path -Path $key -ChildPath $_
                            try {
                                (Get-Item -LiteralPath $subkey -ErrorAction SilentlyContinue).GetSubKeyNames() | ForEach-Object -Process {
                                    if ($(try {
                                        [system.guid]::Parse($_) | Out-Null
                                        $true
                                    } catch {
                                        $false
                                    })) {
                                        if (Test-Path -Path (Join-Path -Path $ClassPath -ChildPath "$($_)\InprocServer32") -PathType Container) {
                                            # don't change anything
                                        } else {
                                            if ($Hive) {
                                                $ClassPath = 'HKLM:\Software\Classes\CLSID'
                                            } else {
                                                $ClassPath = 'HKLM:\Software\Wow6432Node\Classes\CLSID'
                                            }
                                        }
                                        if (Test-PAth -Path (Join-Path -Path $ClassPath -ChildPath "$($_)\InprocServer32") -PathType Container) {
                                            [pscustomobject]@{
                                                Path = $key
                                                Item = $_
                                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassPath -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                                Category = 'Explorer'
                                            }
                                        }
                                    } else {
                                        Get-RegValue -Path "$subkey\$($_)" -Name '*' @Category
                                    }
                                }
                             } catch {
                             }
                        }
                    }
                }

                # ShellIconOverlayIdentifiers
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            Get-RegValue -Path "$key\$($_)" -Name '*' @Category
                        }
                    }
                }

                # LangBarAddin
                $null,'Wow6432Node' | Foreach-Object -Process {
                    Get-RegValue -Path "HKLM:\Software\$($_)\Microsoft\Ctf\LangBarAddin" -Name '*' @Category
                }
                #endregion Explorer

                #region User Explorer
                $Users |
                ForEach-Object {
                $Hive = $_['Hive']

                # Filter & Handler
                'Filter','Handler' | ForEach-Object -Process {
                    $key = "$($Hive)\SOFTWARE\Classes\Protocols\$($_)"
                    if (Test-Path -Path $key  -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                                Get-RegValue -Path "$key\$($_)" -Name 'CLSID' @Category
                        }
                    }
                }

                if (Test-Path -Path "$($Hive)\SOFTWARE\Microsoft\Internet Explorer\Desktop\Components" -PathType Container) {
                    $key = "$($Hive)\SOFTWARE\Microsoft\Internet Explorer\Desktop\Components"
	                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
			                Get-RegValue -Path "$key\$($_)" -Name 'Source' @Category
	                }
                }

                # ShellServiceObjects
                if (Test-Path -Path "$($Hive)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects" -PathType Container) {
                    $ClassesPath =  "$($Hive)\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "$($Hive)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        [pscustomobject]@{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                            Category = 'Explorer'
                        }
                    }
                }

                # ShellServiceObjectDelayLoad
                Get-RegValue -Path "$($Hive)\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" -Name '*' @Category

                # Handlers
                @(
                    @{Name = '*' ; Properties = @('ContextMenuHandlers','PropertySheetHandlers')},
                    @{Name ='Drive'  ; Properties = @('ContextMenuHandlers')},
                    @{Name ='AllFileSystemObjects'  ; Properties = @('ContextMenuHandlers','DragDropHandlers','PropertySheetHandlers')},
                    @{Name ='Directory'  ; Properties = @('ContextMenuHandlers','DragDropHandlers','PropertySheetHandlers', 'CopyHookHandlers')},
                    @{Name ='Directory\Background'  ; Properties = @('ContextMenuHandlers')},
                    @{Name ='Folder' ; Properties = @('ColumnHandlers','ContextMenuHandlers','DragDropHandlers','ExtShellFolderViews','PropertySheetHandlers')}
                ) | ForEach-Object -Process {

                    $Name = $_.Name
                    $Properties = $_.Properties

                    $key = "$($Hive)\Software\Classes\$Name\ShellEx"
                    $Properties | ForEach-Object -Process {
                        $subkey = Join-Path -Path $key -ChildPath $_
                        try {
                            (Get-Item -LiteralPath $subkey -ErrorAction SilentlyContinue).GetSubKeyNames() | ForEach-Object -Process {
                                Get-RegValue -Path $subkey\$($_) -Name '*' @Category
                            }
                        } catch {
                        }
                    }
                }

                # ShellIconOverlayIdentifiers
                $key = "$($Hive)\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
                if (Test-Path -Path $key -PathType Container) {
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        Get-RegValue -Path "$key\$($_)" -Name '*' @Category
                    }
                }

                # LangBarAddin
                Get-RegValue -Path "$($Hive)\Software\Microsoft\Ctf\LangBarAddin" -Name '*' @Category

                # NEW! POWELIKS use of Window's thumbnail cache
                if (Test-Path -Path "$($Hive)\Software\Classes\Clsid\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}") {
                    Write-Warning -Message 'Infected by PoweLiks malware'
                    # Step1: restore read access
                    try {
                        $ParentACL = Get-Acl -Path "$($Hive)\Software\Classes\Clsid"
                        # !!! Adapt here current user !!!
                        $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Classes\Clsid\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}','ReadWriteSubTree','TakeOwnership')
                        $acl  = $k.GetAccessControl()
                        $acl.SetAccessRuleProtection($false,$true)
                        $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($ParentACL.Owner,'FullControl','Allow')
                        $acl.SetAccessRule($rule)
                        $k.SetAccessControl($acl)
                        Write-Verbose -Message "Successuflly restored read access for $($ParentACL.Owner) on registry key"
                    } catch {
                        Write-Warning -Message "Failed to restore read access for $($ParentACL.Owner) on registry key"
                    }
                    # Step2: read the content of subkeys
                    'Inprocserver32','localserver32' | ForEach-Object {
                        try {
                            (Get-ItemProperty -Path "$($Hive)\Software\Classes\Clsid\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\$($_)" -Name '(default)' -ErrorAction Stop).'(default)'
                        } catch {
                        }
                    }
                }
                }
                #endregion User Explorer
            }
            if ($All -or $ImageHijacks) {
                Write-Verbose -Message 'Looking for Image hijacks'
                #region Image Hijacks
	            $Category = @{ Category = 'Image Hijacks'}
                $null,'Wow6432Node' | Foreach-Object {
		            $key = "HKLM:\Software\$($_)\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
			            Get-RegValue -Path "$key\$($_)" -Name 'Debugger' @Category
                        if ((Get-ItemProperty -Path "$key\$($_)" -Name 'GlobalFlag' -ErrorAction SilentlyContinue).'GlobalFlag' -eq 512) {
                            Get-RegValue -Path "$($key -replace 'Image\sFile\sExecution\sOptions','SilentProcessExit')\$($_)" -Name 'MonitorProcess' @Category
                        }
		            }
	            }

                # Autorun macro
	            $null,'Wow6432Node' | Foreach-Object {
		            Get-RegValue -Path "HKLM:\Software\$($_)\Microsoft\Command Processor" -Name 'Autorun' @Category
	            }

                # Exefile
                [pscustomobject]@{
                    Path = 'HKLM:\SOFTWARE\Classes\Exefile\Shell\Open\Command'
                    Item = 'exefile'
                    Value = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\Exefile\Shell\Open\Command' -Name '(default)').'(default)'
                    Category = 'Image Hijacks'
                }

	            '.exe','.cmd' | Foreach-Object {
		            $assoc = (Get-ItemProperty -Path "HKLM:\Software\Classes\$($_)" -Name '(default)').'(default)'
                    [pscustomobject]@{
                        Path = "HKLM:\Software\Classes\$assoc\shell\open\command"
                        Item = $_
                        Value = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$assoc\Shell\Open\Command" -Name '(default)').'(default)'
                        Category = 'Image Hijacks'
                    }
	            }

                # Htmlfile
                [pscustomobject]@{
                    Path = 'HKLM:\SOFTWARE\Classes\htmlfile\shell\open\command'
                    Item = 'htmlfile'
                    Value = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\htmlfile\shell\open\command' -Name '(default)').'(default)'
                    Category = 'Image Hijacks'
                }
                #endregion Image Hijacks

                #region User Image Hijacks
                $Users |
                ForEach-Object {
                $Hive = $_['Hive']
                Get-RegValue -Path "$($Hive)\Software\Microsoft\Command Processor" -Name 'Autorun' @Category

                # Exefile
                if (Test-Path -Path "$($Hive)\SOFTWARE\Classes\Exefile\Shell\Open\Command") {
                    [pscustomobject]@{
                        Path = "$($Hive)\SOFTWARE\Classes\Exefile\Shell\Open\Command"
                        Item = 'exefile'
                        Value = (Get-ItemProperty -Path "$($Hive)\SOFTWARE\Classes\Exefile\Shell\Open\Command" -Name '(default)').'(default)'
                        Category = 'Image Hijacks'
                    }
                }

	            '.exe','.cmd' | Foreach-Object {
                    if (Test-Path -Path "$($Hive)\Software\Classes\$($_)") {
		                $assoc = (Get-ItemProperty -Path "$($Hive)\Software\Classes\$($_)" -Name '(default)'-ErrorAction SilentlyContinue).'(default)'
                        if ($assoc) {
                            [pscustomobject]@{
                                Path = "$($Hive)\Software\Classes\$assoc\shell\open\command"
                                Item = $_
                                Value = (Get-ItemProperty -Path "$($Hive)\SOFTWARE\Classes\$assoc\Shell\Open\Command" -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                Category = 'Image Hijacks'
                            }
                        }
                    }
	            }

                # Htmlfile
                if (Test-Path -Path "$($Hive)\SOFTWARE\Classes\htmlfile\shell\open\command") {
                    [pscustomobject]@{
                        Path = "$($Hive)\SOFTWARE\Classes\htmlfile\shell\open\command"
                        Item = 'htmlfile'
                        Value = (Get-ItemProperty -Path "$($Hive)\SOFTWARE\Classes\htmlfile\shell\open\command" -Name '(default)').'(default)'
                        Category = 'Image Hijacks'
                    }
                }
                }
                #endregion User Image Hijacks
            }
            if ($All -or $InternetExplorerAddons) {
                Write-Verbose -Message 'Looking for Internet Explorer Add-ons entries'
                #region Internet Explorer

                $Category = @{ Category = 'Internet Explorer'}

                # Browser Helper Objects
                $null,'Wow6432Node' | Foreach-Object {
                    $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            [pscustomobject]@{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                                Category = 'Internet Explorer'
                            }
                        }
                    }
                }

                # IE Toolbars
                $null,'Wow6432Node' | Foreach-Object -Process {
                    Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Internet Explorer\Toolbar" -Name '*' @Category
                }

                # Explorer Bars
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Internet Explorer\Explorer Bars"
                    try {
                        (Get-Item -Path $key -ErrorAction Stop).GetSubKeyNames() | ForEach-Object -Process {
                            [pscustomobject]@{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                                Category = 'Internet Explorer'
                            }
                        }
                    } catch {
                    }
                }

                # IE Extensions
                $null,'Wow6432Node' | Foreach-Object {
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Internet Explorer\Extensions"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key -ErrorAction SilentlyContinue).GetSubKeyNames() | ForEach-Object -Process {
                            Get-RegValue -Path "$key\$($_)" -Name 'ClsidExtension' @Category
                        }
                    }
                }

                #endregion Internet Explorer

                #region User Internet Explorer
                $Users |
                ForEach-Object {
                $Hive = $_['Hive']
                # UrlSearchHooks
                $ClassesPath =  'HKLM:\SOFTWARE\Classes\CLSID'
                $key = "$($Hive)\Software\Microsoft\Internet Explorer\UrlSearchHooks"
                if (Test-Path -Path $key -PathType Container) {
                    (Get-Item -Path $key).GetValueNames() | ForEach-Object -Process {
                        [pscustomobject]@{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                            Category = 'Internet Explorer'
                        }
                    }
                }

                # Explorer Bars
                $null,'Wow6432Node' | Foreach-Object -Process {
                    $ClassesPath =  "HKLM:\SOFTWARE\$($_)\Classes\CLSID"
                    $key = "$($Hive)\SOFTWARE\$($_)\Microsoft\Internet Explorer\Explorer Bars"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            [pscustomobject]@{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $ClassesPath -ChildPath "$($_)\InprocServer32") -Name '(default)').'(default)'
                                Category = 'Internet Explorer'
                            }
                        }
                    }
                }

                # IE Extensions
                $null,'Wow6432Node' | Foreach-Object {
                    $key = "$($Hive)\SOFTWARE\$($_)\Microsoft\Internet Explorer\Extensions"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key -ErrorAction SilentlyContinue).GetSubKeyNames() | ForEach-Object -Process {
                            Get-RegValue -Path "$key\$($_)" -Name 'ClsidExtension' @Category
                        }
                    }
                }
                }
                #endregion User Internet Explorer
            }
            if ($All -or $KnownDLLs) {
                Write-Verbose -Message 'Looking for Known DLLs entries'
                #region Known Dlls
	            Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' -Name '*' -Category 'Known Dlls'
                #endregion Known Dlls
            }
            if ($All -or $Logon) {
                Write-Verbose -Message 'Looking for Logon Startup entries'
                #region Logon

                $Category = @{ Category = 'Logon'}

                # Winlogon
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'VmApplet','Userinit','Shell','TaskMan','AppSetup' @Category

                # UserInitMprLogonScript
                if (Test-Path -Path 'HKLM:\Environment' -PathType Container) {
                    Get-RegValue -Path 'HKLM:\Environment' -Name 'UserInitMprLogonScript' @Category
                }
                # GPExtensions
	            $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions'
                if (Test-Path -Path $key -PathType Container) {
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        try {
                            [pscustomobject]@{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $key -ChildPath $_) -Name 'DllName' -ErrorAction Stop).'DllName'
                                Category = 'Logon'
                            }
                        } catch {}
		            }
	            }

                # Domain Group Policies scripts
                'Startup','Shutdown','Logon','Logoff' | ForEach-Object -Process {
                    $key = "HKLM:\Software\Policies\Microsoft\Windows\System\Scripts\$($_)"
                    if (Test-Path -Path $key) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            $subkey = (Join-Path -Path $key -ChildPath $_)
                            (Get-Item -Path $subkey).GetSubKeyNames() | ForEach-Object -Process {
                                Get-RegValue -Path (Join-Path -Path $subkey -ChildPath $_) -Name 'script' @Category
                            }
                        }
                    }
                }

                # Local GPO scripts
                'Startup','Shutdown','Logon','Logoff' | ForEach-Object -Process {
                    $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$($_)"
                    if (Test-Path -Path $key) {
                        (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            $subkey = (Join-Path -Path $key -ChildPath $_)
                            (Get-Item -Path $subkey).GetSubKeyNames() | ForEach-Object -Process {
                                Get-RegValue -Path (Join-Path -Path $subkey -ChildPath $_) -Name 'script' @Category
                            }
                        }
                    }
                }

                # Shell override by GPO
                Get-RegValue -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'Shell' @Category

                # AlternateShell
                Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell' @Category

                # AvailableShells
                Get-RegValue -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells' -Name 'AvailableShells' @Category

                # Terminal server
                # Removed from 13.82 but key/value still exist > restored as of 13.90
                Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd' -Name 'StartupPrograms' @Category

                # Restored as of 13.90
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce' -Name '*' @Category
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx' -Name '*' @Category
                $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx'
                if (Test-Path -Path $key -PathType Container) {
                    (Get-Item -Path $key).GetSubKeyNames() |
                    ForEach-Object -Process {
                        Get-RegValue -Path "$key\$($_)" -Name '*' @Category
                        if (Test-Path -Path "$key\$($_)\Depend" -PathType Container) {
                            Get-RegValue -Path "$key\$($_)\Depend" -Name '*' @Category
                        }
                    }
                }

                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run' -Name '*' @Category
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Software\Microsoft\Windows\CurrentVersion\Run' -Name '*' @Category

                # Removed from 13.82 but key/value still exist > restored in 13.90
                Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'  -Name 'InitialProgram' @Category

                # Run
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\Run" -Name '*' @Category }

                # RunOnce
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\RunOnce" -Name '*' @Category }

                # RunOnceEx
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\RunOnceEx" -Name '*' @Category }

                $null,'Wow6432Node' | Foreach-Object {
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\RunOnceEx"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() |
                        ForEach-Object -Process {
                            Get-RegValue -Path "$key\$($_)" -Name '*' @Category
                                if (Test-Path -Path "$key\$($_)\Depend" -PathType Container) {
                                    Get-RegValue -Path "$key\$($_)\Depend" -Name '*' @Category
                                }
                        }
                    }
                }

                if ($PSVersionTable.PSEdition -ne 'Core') {
                    $HT = @{
                        Encoding = 'Byte'
                    }
                } else {
                    $HT = @{
                        AsByteStream = [switch]::Present
                    }
                }

                # HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
                # TODO: iterate on 'Common Startup','Common AltStartup'
                # Read first 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Common Startup' and follow the value
                # LNK files or direct executable
                'Common Startup','Common AltStartup' |
                ForEach-Object -Begin {
                    $key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                } -Process {
                    $n = $PSItem
                    if (Test-Path -Path $key -PathType Container) {
                        # Show what the Startup value contains (could be a file)
                        Get-RegValue -Path $key -Name $PSItem @Category
                        $USF = $null
                        # If it's a folder, explore its content
                        $USF = (Get-ItemProperty -Path $key -Name $PSItem -ErrorAction SilentlyContinue)."$($PSItem)"
                        if ($USF) {
                            if (Test-Path -Path "$($USF)") {
                                $Wsh = New-Object -ComObject 'WScript.Shell'
                                Get-ChildItem -Path "$($USF)" -Force -Exclude 'desktop.ini' |
                                ForEach-Object {
                                    $File = $_
                                    if ($File -is [System.IO.FileInfo]) {
                                        $header = (Get-Content -Path $($_.FullName) @HT -ReadCount 1 -TotalCount 2) -as [string]
                                        Switch ($header) {
                                            '77 90' {
                                                [pscustomobject]@{
                                                    Path = "$($key)\$($n)"
                                                    Item = $File.Name
                                                    Value = $File.FullName
                                                    Category = 'Logon'
                                                }
                                                break
                                            }
                                            '76 0' {
                                                $shortcut = $Wsh.CreateShortcut($File.FullName)
                                                [pscustomobject]@{
                                                    Path = "$($key)\$($n)"
                                                    Item = $File.Name
                                                    Value = "$($shortcut.TargetPath) $($shortcut.Arguments)"
                                                    Category = 'Logon'
                                                }
                                                break
                                            }
                                            # Anything else: not lnk and not PE
                                            default {
                                                [pscustomobject]@{
                                                    Path = "$($key)\$($n)"
                                                    Item = $File.Name
                                                    Value = $File.FullName
                                                    Category = 'Logon'
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                # Run by GPO
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' -Name '*' @Category

                # Show all subkey that have a StubPath value
                $null,'Wow6432Node' | Foreach-Object {
                    $key = "HKLM:\SOFTWARE\$($_)\Microsoft\Active Setup\Installed Components"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        Get-RegValue -Path "$key\$($_)" -Name 'StubPath' @Category
                    }

                }

                Get-RegValue -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'IconServiceLib' @Category

                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows CE Services\AutoStartOnConnect" -Name '*' @Category }
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows CE Services\AutoStartDisconnect" -Name '*' @Category }
                $null,'Wow6432Node' | Foreach-Object { Get-RegValue -Path "HKLM:\SOFTWARE\$($_)\Microsoft\Windows CE Services\AutoStartOnDisconnect" -Name '*' @Category }

                #endregion Logon

                #region User Logon
                $Users |
                ForEach-Object {
                    $Hive = $_['Hive']
                    # Local GPO scripts
                    'Startup','Shutdown','Logon','Logoff' |
                    ForEach-Object -Process {
                        $key = "$($Hive)\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$($_)"
                        if (Test-Path -Path $key) {
                            (Get-Item -Path $key).GetSubKeyNames() |
                            ForEach-Object -Process {
                                $subkey = (Join-Path -Path $key -ChildPath $_)
                                (Get-Item -Path $subkey).GetSubKeyNames() |
                                ForEach-Object -Process {
                                    # (Join-Path -Path $subkey -ChildPath $_)
                                    Get-RegValue -Path (Join-Path -Path $subkey -ChildPath $_) -Name 'script' @Category
                                }
                            }
                        }
                    }

                    # UserInitMprLogonScript
                    if (Test-Path -Path "$($Hive)\Environment" -PathType Container) {
                        Get-RegValue -Path "$($Hive)\Environment" -Name 'UserInitMprLogonScript' @Category
                    }

                    # Shell override by GPO
                    Get-RegValue -Path "$($Hive)\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'Shell' @Category

                    Get-RegValue -Path "$($Hive)\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name 'Load' @Category
                    Get-RegValue -Path "$($Hive)\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name 'Run' @Category

                    # Run by GPO
                    Get-RegValue -Path "$($Hive)\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name '*' @Category

                    # Run
                    $null,'Wow6432Node' | ForEach-Object {
                        Get-RegValue -Path "$($Hive)\Software\$($_)\Microsoft\Windows\CurrentVersion\Run" -Name '*' @Category
                    }

                    # RunOnce
                    $null,'Wow6432Node' | ForEach-Object {
                        Get-RegValue -Path "$($Hive)\Software\$($_)\Microsoft\Windows\CurrentVersion\RunOnce" -Name '*' @Category
                    }

                    # RunOnceEx
                    $null,'Wow6432Node' | ForEach-Object {
                        Get-RegValue -Path "$($Hive)\Software\$($_)\Microsoft\Windows\CurrentVersion\RunOnceEx" -Name '*' @Category
                    }
                    $null,'Wow6432Node' |
                    Foreach-Object {
                        $key = "$($Hive)\SOFTWARE\$($_)\Microsoft\Windows\CurrentVersion\RunOnceEx"
                        if (Test-Path -Path $key -PathType Container) {
                            (Get-Item -Path $key).GetSubKeyNames() |
                            ForEach-Object -Process {
                                Get-RegValue -Path "$key\$($_)" -Name '*' @Category
                                if (Test-Path -Path "$key\$($_)\Depend" -PathType Container) {
                                    Get-RegValue -Path "$key\$($_)\Depend" -Name '*' @Category
                                }
                            }
                        }
                    }

                    # Restored as of 13.90
                    Get-RegValue -Path "$($Hive)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce" -Name '*' @Category
                    Get-RegValue -Path "$($Hive)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx" -Name '*' @Category
                    $key = "$($Hive)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx"
                    if (Test-Path -Path $key -PathType Container) {
                        (Get-Item -Path $key).GetSubKeyNames() |
                        ForEach-Object -Process {
                            Get-RegValue -Path "$key\$($_)" -Name '*' @Category
                            if (Test-Path -Path "$key\$($_)\Depend" -PathType Container) {
                                Get-RegValue -Path "$key\$($_)\Depend" -Name '*' @Category
                            }
                        }
                    }
                    Get-RegValue -Path "$($Hive)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run" -Name '*' @Category

                    # Scan the User Shell Folders key and its startup and AltStartup non expanded value
                    'Startup','AltStartup' |
                    ForEach-Object -Begin {
                        $Wsh = New-Object -ComObject 'WScript.Shell'
                    } -Process {
                        if (Test-Path -Path $key -PathType Container) {
                            $key = "$($Hive)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                            $regKey = '{0}\{1}' -f ($key -replace  ':','' -replace 'HKU','HKEY_USERS'),$PSItem
                            if (Get-ItemProperty -Path $key -Name $PSItem -ErrorAction SilentlyContinue) {
                                [pscustomobject]@{
                                    Path = "$($key)"
                                    Item = $PSItem
                                    Value = $Wsh.RegRead($regKey)
                                    Category = 'Logon'
                                }
                            }
                        }
                    }

                    # Scan the Shell folders key and its startup value if they exist
                    'Startup','AltStartup' |
                    ForEach-Object -Begin {
                        $key = "$($Hive)\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
                    } -Process {
                        $n = $PSItem
                        if (Test-Path -Path $key -PathType Container) {
                            # Show what the Startup value contains (could be a file)
                            Get-RegValue -Path $key -Name $PSItem @Category
                            $USF = $null
                            # If it's a folder, explore its content
                            $USF = (Get-ItemProperty -Path $key -Name $PSItem -ErrorAction SilentlyContinue)."$($PSItem)"
                            if ($USF) {
                                if (Test-Path -Path "$($USF)") {
                                    $Wsh = New-Object -ComObject 'WScript.Shell'
                                    Get-ChildItem -Path "$($USF)" -Force -Exclude 'desktop.ini' |
                                    ForEach-Object {
                                        $File = $_
                                        if ($File -is [System.IO.FileInfo]) {
                                            $header = (Get-Content -Path $($_.FullName) @HT -ReadCount 1 -TotalCount 2) -as [string]
                                            Switch ($header) {
                                                '77 90' {
                                                    [pscustomobject]@{
                                                        Path = "$($key)\$($n)"
                                                        Item = $File.Name
                                                        Value = $File.FullName
                                                        Category = 'Logon'
                                                    }
                                                    break
                                                }
                                                '76 0' {
                                                    $shortcut = $Wsh.CreateShortcut($File.FullName)
                                                    [pscustomobject]@{
                                                        Path = "$($key)\$($n)"
                                                        Item = $File.Name
                                                        Value = "$($shortcut.TargetPath) $($shortcut.Arguments)"
                                                        Category = 'Logon'
                                                    }
                                                    break
                                                }
                                                # Anything else: not lnk and not PE
                                                default {
                                                    [pscustomobject]@{
                                                        Path = "$($key)\$($n)"
                                                        Item = $File.Name
                                                        Value = $File.FullName
                                                        Category = 'Logon'
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                #endregion User Logon

            }
            if ($All -or $Winsock) {
                Write-Verbose -Message 'Looking for Winsock protocol and network providers entries'
                #region Winsock providers

                $Category = @{ Category = 'Winsock Providers'}

                $null,'64' | ForEach-Object -Process {
                    $key = "HKLM:\System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries$($_)"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        [pscustomobject]@{
                            Path = "$key\$($_)"
                            Item = 'PackedCatalogItem'
                            Value = ((New-Object -TypeName System.Text.ASCIIEncoding).GetString(
                                (Get-ItemProperty -Path "$key\$($_)" -Name PackedCatalogItem).PackedCatalogItem,0,211
                            ) -split ([char][int]0))[0]
                            Category = 'Winsock Providers'
                        }
                    }
                }

                $null,'64' | ForEach-Object -Process {
                    $key = "HKLM:\System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries$($_)"
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        Get-RegValue -Path "$key\$($_)" -Name 'LibraryPath' @Category
                    }
                }
                #endregion Winsock providers

                #region Network providers
	            $Category = @{ Category = 'Network Providers'}
                $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order'
	            (Get-RegValue -Path $key -Name 'ProviderOrder' @Category).Value -split ',' | ForEach-Object {
		            Get-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\services\$($_)\NetworkProvider" -Name 'ProviderPath' @Category
	            }
                #endregion Network providers
            }
            if ($All -or $Codecs) {
                Write-Verbose -Message 'Looking for Codecs'
                #region Codecs
	            $Category = @{ Category = 'Codecs'}

                # Drivers32
	            $null,'Wow6432Node' | Foreach-Object {
		            Get-RegValue -Path "HKLM:\Software\$($_)\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name '*' @Category
	            }

                # Filter
                $null,'Wow6432Node' | Foreach-Object {
			        $key = "HKLM:\Software\$($_)Classes\Filter"
                    $clsidp = "HKLM:\Software\$($_)\Classes\CLSID"
                    if (Test-Path -Path $key -PathType Container) {
		                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                            [pscustomobject]@{
                                Path = $key
                                Item = $_
                                Value = (Get-ItemProperty -Path (Join-Path -Path $clsidp -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                Category = 'Codecs'
                            }
		                }
	                }
                }

                # Instances
	            @('{083863F1-70DE-11d0-BD40-00A0C911CE86}','{AC757296-3522-4E11-9862-C17BE5A1767E}',
	            '{7ED96837-96F0-4812-B211-F13C24117ED3}','{ABE3B9A4-257D-4B97-BD1A-294AF496222E}') | Foreach-Object -Process {
		            $Item = $_
		            $null,'Wow6432Node' | Foreach-Object {
			            $key = "HKLM:\Software\$($_)\Classes\CLSID\$Item\Instance"
                        $clsidp = "HKLM:\Software\$($_)\Classes\CLSID"
                        if (Test-Path -Path $key -PathType Container) {
			                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                                try {
	                                [pscustomobject]@{
	                                    Path = $key
	                                    Item = $_
                                        Value = (Get-ItemProperty -Path (Join-Path -Path $clsidp -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction Stop).'(default)'
	                                    Category = 'Codecs'
	                                }
                                } catch {}
			                }
                        }
		            }
	            }
                #endregion Codecs

                #region User Codecs
                $Users |
                ForEach-Object {
                $Hive = $_['Hive']
                # Drivers32
	            $null,'Wow6432Node' | Foreach-Object {
		            Get-RegValue -Path "$($Hive)\Software\$($_)\Microsoft\Windows NT\CurrentVersion\Drivers32" -Name '*' @Category
	            }

                # Filter
	            $key = "$($Hive)\Software\Classes\Filter"
                if (Test-Path -Path $key -PathType Container) {
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        [pscustomobject]@{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path "$($Hive)\SOFTWARE\Classes\CLSID" -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                            Category = 'Codecs'
                        }
		            }
	            }

                # Instances
	            @('{083863F1-70DE-11d0-BD40-00A0C911CE86}','{AC757296-3522-4E11-9862-C17BE5A1767E}',
	            '{7ED96837-96F0-4812-B211-F13C24117ED3}','{ABE3B9A4-257D-4B97-BD1A-294AF496222E}') | Foreach-Object -Process {
		            $Item = $_
		            $null,'Wow6432Node' | Foreach-Object {
			            $key = "$($Hive)\Software\$($_)\Classes\CLSID\$Item\Instance"
                        if (Test-Path -Path $key -PathType Container) {
			                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                                try {
	                                [pscustomobject]@{
	                                    Path = $key
	                                    Item = $_
	                                    Value = (Get-ItemProperty -Path (Join-Path -Path "$($Hive)\SOFTWARE\Classes\CLSID" -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction Stop).'(default)'
	                                    Category = 'Codecs'
	                                }
                                } catch {
                                }
			                }
                        }
		            }
	            }
                }
                #endregion User Codecs
            }
            if ($All -or $OfficeAddins) {
                Write-Verbose -Message 'Looking for Office Addins entries'
                #region Office Addins

                <#
                # FileName value or
                # HKEY_LOCAL_MACHINE\SOFTWARE\Classes\OneNote.OutlookAddin\CLSID
                #>
                $Category = @{ Category = 'Office Addins'}
                $null,'Wow6432Node' | Foreach-Object {
                    $arc = $_
                    'HKLM:',$Users.ForEach({ $_['Hive']}) | ForEach-Object {
                        $root = $_
                        if (Test-Path -Path "$($root)\SOFTWARE\$($arc)\Microsoft\Office") {
                            (Get-Item -Path "$($root)\SOFTWARE\$($arc)\Microsoft\Office").GetSubKeyNames() | ForEach-Object {
                                if (Test-Path -Path (Join-Path -Path "$($root)\SOFTWARE\$($arc)\Microsoft\Office" -ChildPath "$($_)\Addins") -PathType Container) {
                                    $key = (Join-Path -Path "$($root)\SOFTWARE\$($arc)\Microsoft\Office" -ChildPath "$($_)\Addins")
                                    # Iterate through the Addins names
                                    (Get-item -Path $key).GetSubKeyNames() | ForEach-Object {
                                        try {
	                                        [pscustomobject]@{
	                                            Path = $key
	                                            Item = $_
	                                            Value = $(
                                                    $clsid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$($_)\CLSID" -Name '(default)' -ErrorAction Stop).'(default)';
                                                        if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\$arc\Classes\CLSID\$clsid\InprocServer32"  -Name '(default)' -ErrorAction SilentlyContinue).'(default)') {
                                                            (Get-ItemProperty -Path "HKLM:\SOFTWARE\$arc\Classes\CLSID\$clsid\InprocServer32"  -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                                        } else {
                                                            # $clsid
                                                            (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Classes\CLSID\$clsid\InprocServer32"  -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                                        }
                                                        # (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"  -Name '(default)' -ErrorAction SilentlyContinue).'(default)';
                                                ) # | Where-Object { $null -ne $_ } | Sort-Object -Unique # | Select-Object -First 1
                                                Category = 'Office Addins';
	                                        }
                                        } catch {

                                        }
                                    }

                                }
                            }
                        }
                    } # hklm or hkcu
                }
                # Microsoft Office Memory Corruption Vulnerability (CVE-2015-1641)
                'HKLM:',$Users.ForEach({ $_['Hive']}) | ForEach-Object {
                    $root = $_
                    $null,'Wow6432Node' | Foreach-Object {
                        $key = "$($root)\SOFTWARE\$($_)\Microsoft\Office test\Special\Perf"
                        if (Test-Path "$($root)\SOFTWARE\$($_)\Microsoft\Office test\Special\Perf") {
                            if ((Get-ItemProperty -Path "$($root)\SOFTWARE\$($_)\Microsoft\Office test\Special\Perf" -Name '(default)' -ErrorAction SilentlyContinue).'(default)') {
	                            [pscustomobject]@{
	                                Path = $key
	                                Item = '(default)'
                                    Value = (Get-ItemProperty -Path "$($root)\SOFTWARE\$($_)\Microsoft\Office test\Special\Perf" -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                    Category = 'Office Addins';
	                            }
                            }
                        }
                    }
                }
                #endregion Office Addins
            }
            if ($All -or $PrintMonitorDLLs) {
                Write-Verbose -Message 'Looking for Print Monitor DLLs entries'
                #region Print monitors
	            $Category = @{ Category = 'Print Monitors'}
	            $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
		            Get-RegValue -Path "$key\$($_)" -Name 'Driver' @Category
	            }

                Write-Verbose -Message 'Looking for Print Providers DLLs entries'
                $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers'
                (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
		            Get-RegValue -Path "$key\$($_)" -Name 'Name' @Category
	            }

                Write-Verbose -Message 'Looking for Print Ports entries'
                $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports'
                if (Test-Path -Path $key -PathType Container) {
                    (Get-Item -Path $key).GetValueNames() | Where-Object -FilterScript {
                        $_ -notmatch '^(COM|LPT|PORTPROMPT|FILE|nul|Ne)(\d{1,2})?:'
	                } | ForEach-Object -Process {
                        [pscustomobject]@{
	                        Path = $key
	                        Item = 'Port'
	                        Value = "$($_)"
	                        Category = 'Print Monitors'
	                    }
                    }
                }
                #endregion Print monitors
            }
            if ($All -or $LSAsecurityProviders) {
                Write-Verbose -Message 'Looking for LSA Security Providers entries'
                #region LSA providers
	            $Category = @{ Category = 'LSA Providers'}

                # REG_SZ
	            Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders' -Name 'SecurityProviders' @Category

                # REG_MULTI_SZ
	            'Authentication Packages','Notification Packages','Security Packages' | ForEach-Object {
		            $item = $_
                    (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name $_ @Category).Value | ForEach-Object {
                        if ($_ -ne '""') {
                            [pscustomobject]@{
                                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
                                Item = $item
                                Value = $_
                                Category = 'LSA Providers'
                            }
                        }
                    }
	            }

                # HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
                if (Test-Path -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -PathType Container) {
                    (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -Name 'Security Packages' @Category).Value | ForEach-Object {
                        if ($null -ne $_) {
                            [pscustomobject]@{
                                Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig'
                                Item = 'Security Packages'
                                Value = $_
                                Category = 'LSA Providers'
                            }
                        }
                    }
                }
                #endregion LSA providers
            }
            if ($All -or $ServicesAndDrivers) {
                Write-Verbose -Message 'Looking for Services and Drivers'
                #region Services

                (Get-Item -Path 'HKLM:\System\CurrentControlSet\Services').GetSubKeyNames() | ForEach-Object {
                    $Type = $null
                    $key  = "HKLM:\System\CurrentControlSet\Services\$($_)"
                    try {
                        $Type = Get-ItemProperty -Path $key -Name Type -ErrorAction Stop
                    } catch {
                    }
                    if ($Type) {
                        Switch ($Type.Type) {
                            1  {
                                Get-RegValue -Path $key -Name 'ImagePath' -Category 'Drivers'
                                break
                            }
                            16 {
                                Get-RegValue -Path $key -Name 'ImagePath' -Category 'Services'
                                Get-RegValue -Path "$key\Parameters" -Name 'ServiceDll' -Category 'Services'
                                break
                            }
                            32 {
                                Get-RegValue -Path $key -Name 'ImagePath' -Category 'Services'
                                Get-RegValue -Path "$key\Parameters" -Name 'ServiceDll' -Category 'Services'
                                break
                            }
                            default {
                                # $_
                            }
                        }
                    }
                }

                # Font drivers
                Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers' -Name '*' -Category 'Services'

                #endregion Services
            }

            if ($All -or $ScheduledTasks) {
                Write-Verbose -Message 'Looking for Scheduled Tasks'

                #region Scheduled Tasks

                Get-AllScheduledTask | Get-Task |
                ForEach-Object {
                    $Task = $_
                    $node = ([xml]$_.XML).Task.get_ChildNodes() | Where-Object { $_.Name -eq 'Actions'}
                    if ($node.HasChildNodes) {

                        # $node can have Exec or comHandler or both childs (ex: MediaCenter tasks)
                        $node.get_ChildNodes() |
                        ForEach-Object {
                            $Value = $null
                            $subnode = $_
                            $Value = switch ($_.Name) {
                                Exec {
                                    # $subnode = ($node.get_ChildNodes() | Where-Object { $_.Name -eq 'Exec'})
                                    if ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Arguments' } | Select-Object -ExpandProperty '#text') {
                                        '{0} {1}' -f ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Command' } | Select-Object -ExpandProperty '#text'),
                                        ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Arguments' } | Select-Object -ExpandProperty '#text');
                                    } else {
                                        $subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Command' } | Select-Object -ExpandProperty '#text' ;
                                    }
                                    break;
                                }
                                ComHandler {
                                    # $subnode = ($node.get_ChildNodes() | Where-Object { $_.Name -eq 'ComHandler'})
                                    if ($subnode.get_ChildNodes()| Where-Object { $_.Name -eq 'Data'} | Select-Object -ExpandProperty InnerText) {
                                        '{0} {1}'-f ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'ClassId'} | Select-Object -ExpandProperty '#text'),
                                        ($subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'Data'} | Select-Object -ExpandProperty InnerText);
                                    } else {
                                        $subnode.get_ChildNodes() | Where-Object { $_.Name -eq 'ClassId'} | Select-Object -ExpandProperty '#text';
                                    }
                                    break;
                                }
                                default {}
                            }

                            [pscustomobject]@{
                                Path = (Join-Path -Path "$($env:systemroot)\system32\Tasks" -ChildPath "$($Task.Path)\$($Task.Name)") ;
                                Item = $Task.Name
                                Value =  $Value ;
                                Category = 'Task' ;
                            }
                        }
                    }
                }

                #endregion Scheduled Tasks
            }
            if ($All -or $Winlogon) {
                Write-Verbose -Message 'Looking for Winlogon entries'
                #region Winlogon
	            $Category = @{ Category = 'Winlogon'}
                Get-RegValue -Path 'HKLM:\SYSTEM\Setup' -Name 'CmdLine' @Category

	            'Credential Providers','Credential Provider Filters','PLAP Providers' | ForEach-Object {
		            $key = Join-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication' -ChildPath $_
		            (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
                        [pscustomobject]@{
                            Path = $key
                            Item = $_
                            Value = (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($_)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                            Category = 'Winlogon'
                        }
		            }
	            }
                <# # deprecated
	            'System','SaveDumpStart' | ForEach-Object {
		            Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name $_ @Category
	            }
                #>

                # Notify doesn't exist on Windows 8.1
                <# # deprecated
                if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' -PathType Container) {
	                $key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify'
                    (Get-Item -Path $key).GetSubKeyNames() | ForEach-Object -Process {
		                Get-RegValue -Path "$key\$($_)" -Name 'DLLName' @Category
	                }
                }
                #>

	            if (Test-Path -Path 'HKLM:\System\CurrentControlSet\Control\BootVerificationProgram' -PathType Container) {
		            Get-RegValue -Path 'HKLM:\System\CurrentControlSet\Control\BootVerificationProgram' -Name 'ImagePath' @Category
	            }
                #endregion Winlogon

                #region User Winlogon
                $Users |
                ForEach-Object {
                $Hive = $_['Hive']
                Get-RegValue -Path "$($Hive)\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name 'Scrnsave.exe' @Category

                Get-RegValue -Path "$($Hive)\Control Panel\Desktop" -Name 'Scrnsave.exe' @Category
                }
                #endregion User Winlogon
            }
            if ($All -or $WMI) {
                Write-Verbose -Message 'Looking for WMI Database entries'

                # Temporary events created with Register-CimIndicationEvent or Register-WMIEvent
                <#
                Get-EventSubscriber -ErrorAction SilentlyContinue | ForEach-Object -Process {
                    $job = $_ | Select-Object -ExpandProperty Action
                    if ($job.Command) {
                        Write-Warning -Message 'A temporary WMI Event subscription was found'
                    }
                }
                #>
                # Permanent events
                Get-CimInstance -Namespace root\Subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue -Verbose:$false |
                Where-Object { $_.PSBase.CimClass.CimClassName -eq 'ActiveScriptEventConsumer' } |
                ForEach-Object {
                    if ($_.ScriptFileName) {
                        [pscustomobject]@{
                            Path = "\\.\$($_.PSBase.CimSystemProperties.Namespace -replace '/','\'):ActiveScriptEventConsumer.Name='$($_.Name)'" ;
                            Item = $_.Name
                            Value =  $_.ScriptFileName ;
                            Category = 'WMI' ;
                        }

                    } elseif ($_.ScriptText) {
                        [pscustomobject]@{
                            Path = "\\.\$($_.PSBase.CimSystemProperties.Namespace -replace '/','\'):ActiveScriptEventConsumer.Name='$($_.Name)'" ;
                            Item = $_.Name
                            Value =  $null ;
                            Category = 'WMI' ;
                        }
                    }
                }

                Get-CimInstance -Namespace root\Subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue -Verbose:$false |
                Where-Object { $_.PSBase.CimClass.CimClassName -eq 'CommandLineEventConsumer' } |
                ForEach-Object {
                    [pscustomobject]@{
                        Path = "\\.\$($_.PSBase.CimSystemProperties.Namespace -replace '/','\'):CommandLineEventConsumer.Name='$($_.Name)'" ;
                        Item = $_.Name
                        Value =  "$($_.WorkingDirectory)$($_.ExecutablePath)" ;# $($_.CommandLineTemplate)" ;
                        Category = 'WMI' ;
                    }
                }

                # List recursiveley registered and resolved WMI providers
                Function Get-WmiNamespace {
                Param (
                    [string]$Namespace='root'
                )
                    try {
                        Get-CimInstance -Namespace $Namespace -ClassName __Namespace -ErrorAction Stop -Verbose:$false |
                        ForEach-Object {
                            ($ns = '{0}/{1}' -f $_.PSBase.CimSystemProperties.Namespace,$_.Name)
                            Get-WmiNamespace -Namespace $ns
                        }
                    } catch {
                        Write-Warning -Message "Failed to enumerate NS: $ns because $($_.Exception.Message)"
                    }
                }

                Function Get-WmiProvider {
                Param (
                    [string]$Namespace='root'
                )
                    try {
                        Get-CimInstance -Namespace $Namespace -ClassName __Provider -ErrorAction Stop -Verbose:$false
                    } catch {
                        Write-Warning -Message "Failed to enumerate NS: $ns because $($_.Exception.Message)"
                    }
                }

                Get-WmiNamespace |
                ForEach-Object {
                    Get-WmiProvider -Namespace $_ |
                    ForEach-Object {
                        Write-Verbose -Message "Found provider clsid $($_.CLSID) from under the $($_.PSBase.CimSystemProperties.Namespace) namespace"
                        if (($clsid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\CLSID\$($_.CLSID)\InprocServer32" -Name '(default)' -ErrorAction SilentlyContinue).'(default)')) {
                            [pscustomobject]@{
                                Path = "\\.\$($_.PSBase.CimSystemProperties.Namespace -replace '/','\'):__Win32Provider.Name='$($_.Name)'"
                                Item = $_.Name
                                Value = $clsid
                                Category = 'WMI' ;
                            }
                        }
                    }
                }
            }
            if ($All -or $PSProfiles) {

                $profiles = New-Object -TypeName System.Collections.ArrayList
                'C:\Windows\SysWOW64\WindowsPowerShell\v1.0',
                'C:\Windows\System32\WindowsPowerShell\v1.0',
                $global:home | ForEach-Object {
                    $null = $profiles.Add($_)
                }

                if ($PSVersionTable.PSEdition -eq 'Core') {
                    $null = $profiles.Add($global:PSHOME) # for PS Core, use public constant
                }

                $profiles |
                ForEach-Object {

                    $root = $_
                    'profile.ps1',
                    'Microsoft.PowerShell_profile.ps1',
                    'Microsoft.PowerShellISE_profile.ps1' |
                    ForEach-Object {

                        if (Test-Path -Path (Join-Path -Path $root -ChildPath $_) -PathType Leaf) {
                            [pscustomobject]@{
                                Path = $root
                                Item = $_
                                Value = (Join-Path -Path $root -ChildPath $_)
                                Category = 'PowerShell profiles'
                            }
                        }
                    }
                }
            }
        }
        End {
        }
    }

    Function Get-PSPrettyAutorun {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory,ValueFromPipeLine)]
            [system.object[]]$RawAutoRun
        )
        Begin {}
        Process {
            $RawAutoRun | ForEach-Object {
                $Item = $_
                Switch ($Item.Category) {
                    Task {
                        Write-Verbose -Message "Reading Task $($Item.Path)"
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Switch -Regex ($Item.Value ) {
                                #GUID
                                '^(\{)?[A-Za-z0-9]{4}([A-Za-z0-9]{4}\-?){4}[A-Za-z0-9]{12}(\})?' {
                                    # $clsid = ($_ -split '\s')[0]
                                    $clsid = ([system.guid]::Parse( ($_ -split '\s')[0])).ToString('B')
                                    if (Test-Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)\InprocServer32") -PathType Container) {
                                        Write-Verbose -Message 'Reading from InprocServer32'
                                        (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)\InprocServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                    } elseif (Test-Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)\LocalServer32") -PathType Container) {
                                        Write-Verbose -Message 'Reading from LocalServer32'
                                        (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)\LocalServer32") -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
                                    } else {
                                        try {
                                            Write-Verbose -Message 'Reading from AppID'
                                            # $appid = (Get-ItemProperty -Path (Join-Path -Path 'HKLM:\SOFTWARE\Classes\CLSID' -ChildPath "$($clsid)") -Name 'AppId' -ErrorAction Stop).'AppId'
                                            "$($env:systemroot)\system32\sc.exe"
                                        } catch {
                                            # Write-Warning -Message "AppId not found for $clsid"
                                        }
                                    }
                                    break
                                }
                                # Rundll32
                                '^((%windir%|%(s|S)ystem(r|R)oot%)\\(s|S)ystem32\\)?rundll32\.exe\s(/[a-z]\s)?.*,.*' {
                                    Join-Path -Path "$($env:systemroot)\system32" -ChildPath (
                                        @([regex]'^((%windir%|%(s|S)ystem(r|R)oot%)\\(s|S)ystem32\\)?rundll32\.exe\s(/[a-z]\s)?((%windir%|%(s|S)ystem(r|R)oot%)\\(s|S)ystem32\\)?(?<File>.*),').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # cscript
                                '^((%windir%|%(s|S)ystem(r|R)oot%)\\(s|S)ystem32\\)?(c|w)script\.exe\s(//?[a-zA-Z:]+\s){0,}.*' {
                                    Join-Path -Path "$($env:systemroot)\system32" -ChildPath (
                                        @([regex]'^((%windir%|%(s|S)ystem(r|R)oot%)\\(s|S)ystem32\\)?(c|w)script\.exe\s(//?[a-zA-Z:]+\s){0,}((%windir%|%(s|S)ystem(r|R)oot%)\\(s|S)ystem32\\)?(?<File>.*\.[a-zA-Z0-9]{1,3})\s?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # special powershell
                                '[pP][oO][wW][eE][rR][sS][hH][eE][lL]{2}' {
                                    Function Get-EnvReplacement {
                                    [CmdletBinding()]
                                    Param(
                                    [Parameter(Mandatory,ValueFromPipeline)]
                                    [string]$Value
                                    )
                                    Begin {}
                                    Process {}
                                    End {
                                        $envVar= ($Value -split '%')[1]
                                        # Write-Verbose -Message "-$($envVar)-" -Verbose
                                        if ($envVar) {
                                            Get-ChildItem -Path 'Env:' | Where-Object {$_.Name -eq "$($envVar)"} |
                                            ForEach-Object {
                                                if ($Value -match "$($_.Name)") {
                                                    $Value -replace "%$($_.Name)%","$($_.Value)"
                                                }
                                            }
                                        } else {
                                            $Value
                                        }
                                    }
                                    }
                                    switch -regex ($_) {
                                        '\s-[fF]' {
                                            @([regex]'(-[fF][iI]?[lL]?[eE]?)\s{1,}?"?(?<File>.+\.[pP][sS]1)"?\s?').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value | ForEach-Object  { ($_ -replace '"','').Trim()}
                                            break
                                        }
                                        '.[pP][sS]1\s' {
                                            @([regex]'([^\s]+)(?<=\.[pP][sS]1)').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 -ExpandProperty Value | Get-EnvReplacement
                                            break
                                        }
                                        '.[pP][sS]1"' {
                                            @([regex]'([^"]+)(?<=\.[pP][sS]1)').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 -ExpandProperty Value | Get-EnvReplacement
                                            break
                                        }
                                        '.[pP][sS]1' {
                                            @([regex]'\s{1,}"?(?<File>.+\.[pP][sS]1)"?\s?').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                            break
                                        }
                                        default {
                                            $_
                                        }
                                    }
                                    break
                                }
                                # Windir\system32
                                '^"?(%(w|W)in(d|D)ir%|%(s|S)ystem(r|R)oot%|C:\\[Ww][iI][nN][dD][oO][Ww][sS])\\(s|S)ystem32\\.*\.(exe|vbs)' {
                                    Join-Path -Path "$($env:systemroot)\system32" -ChildPath (
                                        @([regex]'^"?(%(w|W)in(d|D)ir%|%(s|S)ystem(r|R)oot%|C:\\[Ww][iI][nN][dD][oO][Ww][sS])\\(s|S)ystem32\\(?<File>.*\.(exe|vbs))("|\s)?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # windir\somethingelse
                                '^(%windir%|%(s|S)ystem(r|R)oot%|C:\\[Ww][iI][nN][dD][oO][Ww][sS])\\.*\\.*\.(exe|vbs)' {
                                    Join-Path -Path "$($env:systemroot)" -ChildPath (
                                        @([regex]'^(%windir%|%(s|S)ystem(r|R)oot%|C:\\[Ww][iI][nN][dD][oO][Ww][sS])\\(?<File>.*\\.*\.(exe|vbs))(\s)?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                '^%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater\.exe\s/reporting' {
                                    $s = $Item.Item -replace 'OneDrive\sReporting\sTask-',''
                                    $f = $allusers | Where-Object { $_.SID -eq $s }
                                    Join-Path -Path "$($f.ProfilePath)\AppData\Local" -ChildPath 'Microsoft\OneDrive\OneDriveStandaloneUpdater.exe'
                                    break
                                }
                                # localappdata variable
                                '^%localappdata%' {
                                    $s = $Item.Item -replace 'OneDrive\sStandalone\sUpdate\sTask-',''
                                    $f = $allusers | Where-Object { $_.SID -eq $s }
                                    Join-Path -Path "$($f.ProfilePath)\AppData\Local" -ChildPath (
                                        @([regex]'^%localappdata%\\(?<File>.*)').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # special W7 case with media center
                                '^%SystemRoot%\\ehome\\.*\s' {
                                    # "$($env:systemroot)\ehome\ehrec.exe"
                                    Join-Path -Path "$($env:systemroot)\ehome" -ChildPath "$(
                                        @([regex]'^%SystemRoot%\\ehome\\(?<FileName>.*)\s').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    ).exe"
                                    break
                                }
                                # special case Office 2016 License Heartbeat
                                '%ProgramFiles%\\Common\sFiles\\Microsoft\sShared\\Office16\\OLicenseHeartbeat\.exe' {
                                    if ([environment]::Is64BitOperatingSystem) {
                                        'C:\Program Files (x86)\Common Files\microsoft shared\OFFICE16\OLicenseHeartbeat.exe'
                                    } else {
                                        'C:\Program Files\Common Files\microsoft shared\OFFICE16\OLicenseHeartbeat.exe'
                                    }
                                    break
                                }
                                # ProgramData
                                '^"?C:\\ProgramData\\' {
                                    Join-Path -Path "$($env:ProgramData)" -ChildPath (
                                        @([regex]'^"?C:\\ProgramData\\(?<File>.*\.exe)("|\s)?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # ProgramFiles starts with a quote
                                '^"(C:\\Program\sFiles|%ProgramFiles%)\\' {
                                    Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                          @([regex]'^"(C:\\Program\sFiles|%ProgramFiles%)\\(?<File>.+\.[A-Za-z0-9]{1,})"').Matches($_)|
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # ProgramFiles with no quote
                                '^(C:\\Program\sFiles|%ProgramFiles%)\\' {
                                 Switch -Regex ($_) {
                                  '^((C|c):\\Program\sFiles|%ProgramFiles%)\\(?<File>.+\.[A-Za-z0-9]{1,})\s' {
                                   Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                    @([regex]'^((C|c):\\Program\sFiles|%ProgramFiles%)\\(?<File>.+\.[A-Za-z0-9]{1,})\s').Matches($_)|
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                   )
                                   break
                                  }
                                  '^(C:\\Program\sFiles|%ProgramFiles%)\\(?<File>.+\.[A-Za-z0-9]{1,})$' {
                                   Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                    @([regex]'^((C|c):\\Program\sFiles|%ProgramFiles%)\\(?<File>.+\.[A-Za-z0-9]{1,})$').Matches($_)|
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                   )
                                   break
                                  }
                                  default {$_}
                                 }
                                 break
                                }
                                # ProgramFilesx86 starts with a quote
                                '^"(C:\\Program\sFiles\s\(x86\)|%ProgramFiles\(x86\)%)\\' {
                                    Join-Path -Path "$(${env:ProgramFiles(x86)})" -ChildPath (
                                        @([regex]'^"(C:\\Program\sFiles\s\(x86\)|%ProgramFiles\(x86\)%)\\(?<File>.*\.[a-z0-9]{1,})"').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # ProgramFilesx86 with no quote
                                '^(C:\\Program\sFiles\s\(x86\)|%ProgramFiles\(x86\)%)\\' {
                                    Join-Path -Path "$(${env:ProgramFiles(x86)})" -ChildPath (
                                        @([regex]'^(C:\\Program\sFiles\s\(x86\)|%ProgramFiles\(x86\)%)\\(?<File>.*\.[a-z0-9]{1,})\s?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # Users
                                '^"?C:\\[uU][sS][eE][rR][sS]\\(?<File>.+\.[A-Za-z0-9]{1,})("|\s)?' {
                                    Join-Path -Path 'C:\Users' -ChildPath (
                                        @([regex]'^"?C:\\[uU][sS][eE][rR][sS]\\(?<File>.+\.[A-Za-z0-9]{1,})("|\s)?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                # C:\users?
                                '^"?[A-Za-z]:\\' {
                                    $_ -replace '"',''
                                    break;
                                }
                                # FileName.exe
                                '[a-zA-Z0-9]*\.exe(\s)?' {
                                # '[a-zA-Z0-9]*(\.exe\s)?' {
                                    Join-Path -Path "$($env:systemroot)\system32" -ChildPath "$(
                                        @([regex]'^(?<FileName>[a-zA-Z0-9]*)(\.exe\s)?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                        ).exe"
                                    break
                                }
                                '^sc\s[a-zA-Z]' {
                                    "$($env:systemroot)\system32\sc.exe"
                                    break
                                }
                                '^aitagent(\s/increment)?' {
                                    "$($env:systemroot)\system32\aitagent.exe"
                                    break
                                }
                                default {
                                    $_
                                }
                        } #endof switch
                        ) -Force -PassThru

                    break;
                    }
                    AppInit {
                        if ($Item.Value -eq [string]::Empty) {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $null -Force -PassThru
                        } else {
                            # Switch ? malware example
                            $Item.Value -split '\s|,' | ForEach-Object {
                                $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value "$($_)" -Force -PassThru
                            }
                        }
                        break
                    }
                    'Boot Execute' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Switch -Regex ($Item.Value) {
                                '^autocheck\sautochk\s' {
                                    "$($env:SystemRoot)\system32\autochk.exe"
                                    break;
                                }
                                '^C:\\Windows\\System32\\poqexec\.exe\s' {
                                    "$($env:SystemRoot)\system32\poqexec.exe"
                                    break;
                                }
                                default {
                                    $Item.Value
                                }
                            }
                        ) -Force -PassThru
                        break
                    }
                    Codecs {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                        Switch -Regex ($Item.Value) {
                            '^[A-Z]:\\Windows\\' {
                                if ($Item.Path -match 'Wow6432Node') {
                                    $_ -replace 'system32','SysWOW64'
                                } else {
                                    $_
                                }
                                break
                            }
                            # '^[A-Z]:\\Program\sFiles' {
                            '^[A-Z]:\\[Pp]rogra' {
                                $_  | Get-NormalizedFileSystemPath
                                break
                            }
                            default {
                                if ($Item.Path -match 'Wow6432Node') {
                                    Join-Path "$($env:systemroot)\Syswow64" -ChildPath $_
                                } else {
                                    Join-Path "$($env:systemroot)\System32" -ChildPath $_
                                }
                            }
                        }
                        ) -Force -PassThru
                        break
                    }
                    Drivers {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            switch -Regex ($Item.Value) {
                                '^\\SystemRoot\\System32\\' {
                                    $_ -replace '\\Systemroot',"$($env:systemroot)"
                                    break;
                                }
                                '^System32\\[dD][rR][iI][vV][eE][rR][sS]\\' {
                                    Join-Path -Path "$($env:systemroot)" -ChildPath $_
                                    break;
                                }
                                '^System32\\DriverStore\\FileRepository\\' {
                                    Join-Path -Path "$($env:systemroot)" -ChildPath $_
                                    break;
                                }
                                '^SysWow64\\[dD][rR][iI][vV][eE][rR][sS]\\' {
                                    Join-Path -Path "$($env:systemroot)" -ChildPath $_
                                    break;
                                }
                                '^\\\?\?\\C:\\Windows\\system32\\drivers' {
                                    $_ -replace '\\\?\?\\',''
                                    break;
                                }
                                '^System32\\CLFS\.sys' {
                                    $_ -replace 'System32\\',"$($env:systemroot)\system32\"
                                }
                                '^("|\\\?\?\\)?[A-Za-z]:\\[Pp]rogram\s[fF]iles\\(?<FilePath>.*\.[A-Za-z]{3})\s?' {
                                    Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                        @([regex]'^("|\\\?\?\\)?[A-Za-z]:\\[Pp]rogram\s[fF]iles\\(?<FilePath>.*\.[A-Za-z]{3})\s?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                '^("|\\\?\?\\)?[A-Za-z]:\\[Pp]rogram\s[fF]iles(\s\(x86\))\\(?<FilePath>.*\.[A-Za-z]{3})\s?' {
                                    Join-Path -Path "$(${env:ProgramFiles(x86)})" -ChildPath (
                                        @([regex]'^("|\\\?\?\\)?[A-Za-z]:\\[Pp]rogram\s[fF]iles(\s\(x86\))\\(?<FilePath>.*\.[A-Za-z]{3})\s?').Matches($_) |
                                        Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    )
                                    break
                                }
                                '^(\\\?\?\\)?C:\\ProgramData' {
                                    $_ -replace '\\\?\?\\',''
                                    break;
                                }
                                '^"?C:\\ProgramData' {
                                    $_ -replace '"',''
                                    break;
                                }
                                'SysmonDrv.sys' {
                                    $env:PATH -split ';'| ForEach-Object {
                                        Get-ChildItem -Path $_\*.sys -Include SysmonDrv.sys -Force -ErrorAction SilentlyContinue
                                    } | Select-Object -First 1 -ExpandProperty FullName
                                    break
                                }
                                default {
                                    $_
                                }
                        }) -Force -PassThru
                        break
                    }
                    Explorer {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            if ($Item.Value) {
                                if ($Item.Value -match '^"?[A-Z]:\\') {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        $Item.Value -replace 'system32','syswow64' | Get-NormalizedFileSystemPath
                                    } else {
                                        $Item.Value -replace '"','' | Get-NormalizedFileSystemPath
                                    }
                                } else {
                                    if ($Item.Path -match 'Wow6432Node') {
                                        Join-Path -Path "$($env:systemroot)\syswow64" -ChildPath $Item.Value
                                    } else {
                                        Join-Path -Path "$($env:systemroot)\system32" -ChildPath $Item.Value
                                    }
                                }
                            }
                        ) -Force -PassThru
                        break
                    }
                    'Image Hijacks' {

                        if ($Item.Value -eq '"%1" %*') {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $null -Force -PassThru
                        } else {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                Switch -Regex ($Item.Value) {
                                '^"?(?<FileName>.*\.[A-Za-z0-9]{3})"?\s?%?' {
                                    @([regex]'^"?(?<FileName>.*\.[A-Za-z0-9]{3})"?\s?%?').Matches($_) |
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                    break
                                }
                                default {
                                    $_
                                }
                            }) -Force -PassThru

                        }
                        break
                    }
                    'Internet Explorer' {
                        if ($Item.Item -ne 'Locked') {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                $Item.Value | Get-NormalizedFileSystemPath
                            ) -Force -PassThru
                        }
                        break
                    }
                    'Known Dlls' {
                        if ( (Test-Path -Path $Item.Value -PathType Container) -and ($Item.Item -match 'DllDirectory')) {
                        } else {
                            # Duplicate objects
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath $Item.Value
                            ) -Force -PassThru
                            if ([environment]::Is64BitOperatingSystem) {
                                # Duplicate if target file exists
                                if (Test-Path -Path (Join-Path -Path "$($env:SystemRoot)\Syswow64" -ChildPath $Item.Value) -PathType Leaf) {
                                    $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                        Join-Path -Path "$($env:SystemRoot)\Syswow64" -ChildPath $Item.Value
                                    ) -Force -PassThru
                                }
                            }
                        }
                        break
                    }
                    Logon {
                        If ($Item.Item -eq 'UserInit') {
                            $Item.Value -split ',' |
                            ForEach-Object {
                                $s = $_
                                if ($_ -ne [string]::Empty) {
                                    $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(

                                        if ($s -match '^"?[A-Z]:\\') {
                                            if ($Item.Path -match 'Wow6432Node') {
                                                $s -replace 'system32','syswow64' | Get-NormalizedFileSystemPath
                                            } else {
                                                $s -replace '"','' | Get-NormalizedFileSystemPath
                                            }
                                        } else {
                                            if ($Item.Path -match 'Wow6432Node') {
                                                Join-Path -Path "$($env:systemroot)\syswow64" -ChildPath $s
                                            } else {
                                                Join-Path -Path "$($env:systemroot)\system32" -ChildPath $s
                                            }
                                        }

                                    ) -Force -PassThru
                                }
                            }
                        } elseif ($Item.Path -imatch 'runonceEx' -and $Item.Value -match '|') {
                            $Item.Value -split '\|' | ForEach-Object {
                                if ($_ -ne [string]::Empty) {
                                    $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                        $_
                                    ) -Force -PassThru
                                }
                            }
                        } else {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                switch -Regex ($Item.Value) {
                                    '\\Rundll32\.exe\s' {
                                        (($_ -split '\s')[1] -split ',')[0]
                                        break
                                    }
                                    '\\Rundll32\.exe"' {
                                        (($_ -split '\s',2)[1] -split ',')[0] -replace '"',''
                                        break;
                                    }
                                    '^"[A-Z]:\\Program' {
                                        ($_ -split '"')[1]
                                        break
                                    }
                                    '^"[A-Z]:\\Windows' {
                                        ($_ -split '"')[1]
                                        break
                                    }
                                    'C:\\WINDOWS\\inf\\unregmp2\.exe\s/ShowWMP' {
                                        'C:\WINDOWS\system32\unregmp2.exe'
                                        break
                                    }
                                    'rdpclip' {
                                        "$($env:SystemRoot)\system32\$($_).exe"
                                        break
                                    }
                                    '^Explorer\.exe$' {
                                        "$($env:SystemRoot)\$($_)"
                                        break
                                    }
                                    # regsvr32.exe /s /n /i:U shell32.dll
                                    '^regsvr32\.exe\s/s\s/n\s/i:U\sshell32\.dll' {
                                        if ($Item.Path -match 'Wow6432Node') {
                                            "$($env:SystemRoot)\syswow64\shell32.dll"
                                        }else {
                                            "$($env:SystemRoot)\system32\shell32.dll"
                                        }
                                        break
                                    }
                                    '^C:\\Windows\\system32\\regsvr32\.exe\s/s\s/n\s/i:/UserInstall\sC:\\Windows\\system32\\themeui\.dll' {
                                        if ($Item.Path -match 'Wow6432Node') {
                                            "$($env:SystemRoot)\syswow64\themeui.dll"
                                        }else {
                                            "$($env:SystemRoot)\system32\themeui.dll"
                                        }
                                        break
                                    }
                                    '^C:\\Windows\\system32\\cmd\.exe\s/D\s/C\sstart\sC:\\Windows\\system32\\ie4uinit\.exe\s\-ClearIconCache' {
                                        if ($Item.Path -match 'Wow6432Node') {
                                            "$($env:SystemRoot)\syswow64\ie4uinit.exe"
                                        }else {
                                            "$($env:SystemRoot)\system32\ie4uinit.exe"
                                        }
                                        break
                                    }
                                    '^[A-Z]:\\Windows\\' {
                                        if ($Item.Path -match 'Wow6432Node') {
                                            (($_ -split '\s')[0] -replace ',','') -replace 'System32','Syswow64'
                                        } else {
                                            (($_ -split '\s')[0] -replace ',','')
                                        }
                                        break
                                    }
                                    '^[a-zA-Z0-9]+\.(exe|dll)' {
                                        if ($Item.Path -match 'Wow6432Node') {
                                            Join-Path -Path "$($env:SystemRoot)\syswow64" -ChildPath ($_ -split '\s')[0]
                                        } else {
                                            Join-Path -Path "$($env:SystemRoot)\system32" -ChildPath ($_ -split '\s')[0]
                                        }
                                        break
                                    }
                                    '^RunDLL32\s' {
                                        Join-Path -Path "$($env:SystemRoot)\system32" -ChildPath (($_ -split '\s')[1] -split ',')[0]
                                        break
                                    }

                                    # ProgramFiles
                                    '^[A-Za-z]:\\Program\sFiles\\' {
                                        Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                            @([regex]'[A-Za-z]:\\Program\sFiles\\(?<File>.*\.(e|E)(x|X)(e|E))\s?').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                        )
                                        break
                                    }
                                    # ProgramFilesx86
                                    '^[A-Za-z]:\\Program\sFiles\s\(x86\)\\' {
                                        Join-Path -Path "$(${env:ProgramFiles(x86)})" -ChildPath (
                                            @([regex]'[A-Za-z]:\\Program\sFiles\s\(x86\)\\(?<File>.*\.(e|E)(x|X)(e|E))\s?').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                        )
                                        break
                                    }
                                    # C:\Users with a quote
                                    '^"C:\\[uU][sS][eE][rR][sS]\\(?<File>.+\.[A-Za-z0-9]{1,})"' {
                                        Join-Path -Path 'C:\Users' -ChildPath (
                                            @([regex]'^"C:\\[uU][sS][eE][rR][sS]\\(?<File>.+\.[A-Za-z0-9]{1,})"').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                        )
                                        break
                                    }
                                    # C:\Users with a space at the end
                                    '^C:\\[uU][sS][eE][rR][sS]\\(?<File>.+\.[A-Za-z0-9]{1,})\s' {
                                        Join-Path -Path 'C:\Users' -ChildPath (
                                            @([regex]'^C:\\[uU][sS][eE][rR][sS]\\(?<File>.+\.[A-Za-z0-9]{1,})\s').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                        )
                                        break
                                    }
                                    # C:\Users with nothing at the end
                                    '^C:\\[uU][sS][eE][rR][sS]\\(?<File>.+\.[A-Za-z0-9]{1,})' {
                                        Join-Path -Path 'C:\Users' -ChildPath (
                                            @([regex]'^C:\\[uU][sS][eE][rR][sS]\\(?<File>.+\.[A-Za-z0-9]{1,})').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                        )
                                        break
                                    }
                                    # "C:\
                                    '^"[A-Za-z]:\\' {
                                        ($_ -split '"')[1]
                                            break
                                    }
                                    # C:\ProgramData\
                                    # '^[A-Za-z]:\\ProgramData\\' {
                                    '^[A-Za-z]:\\[pP][rR][oO][gG][rR][aA][mM][dD][aA][tT][aA]\\(?<File>.+\.[A-Za-z0-9]{1,})' {
                                        Join-Path -Path 'C:\ProgramData' -ChildPath (
                                            @([regex]'C:\\[pP][rR][oO][gG][rR][aA][mM][dD][aA][tT][aA]\\(?<File>.+\.[A-Za-z0-9]{1,})').Matches($_) |
                                            Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                        )
                                    }
                                    default {
                                        Write-Verbose -Message "default: $_"
                                        [string]::Empty
                                        # $_
                                    }
                                }
                            ) -Force -PassThru
                        }
                        break
                    }
                    'LSA Providers' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            if ($Item.Value -match '\.dll$') {
                                Join-Path -Path "$($env:SystemRoot)\system32" -ChildPath $Item.Value
                            } else {
                                Join-Path -Path "$($env:SystemRoot)\system32" -ChildPath "$($Item.Value).dll"
                            }
                        ) -Force -PassThru
                        break
                    }
                    'Network Providers' {
                        $Item | Add-Member -MemberType ScriptProperty -Name ImagePath -Value $({$this.Value}) -Force -PassThru
                    }
                    'Office Addins' {
                        if ($Item.Path -match 'Wow6432Node' -and $Item.Value -imatch 'system32') {
                            $Item.Value = $Item.Value -replace 'system32','syswow64'
                        }
                        if ($Item.Value) {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                Switch -Regex ($Item.Value ) {
                                    #GUID
                                    '^(\{)?[A-Za-z0-9]{4}([A-Za-z0-9]{4}\-?){4}[A-Za-z0-9]{12}(\})?' {
                                        ([system.guid]::Parse( ($_ -split '\s')[0])).ToString('B')
                                        break
                                    }
                                    default {
                                        $Item.Value -replace '"','' | Get-NormalizedFileSystemPath
                                    }
                                }
                            ) -Force -PassThru
                        }
                        break
                    }
                    'Print Monitors' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            switch -Regex ($Item.Value) {
                                '^"?[A-Za-z]:\\' {
                                    $Item.Value
                                }
                                default {
                                    Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath $Item.Value
                                }
                            }

                        ) -Force -PassThru
                        break
                    }
                    Services {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            switch -Regex ($Item.Value) {
                            '^"?[A-Za-z]:\\[Ww][iI][nN][dD][oO][Ww][sS]\\(?<FilePath>.*\.(exe|dll))\s?' {
                                Join-Path -Path "$($env:systemroot)" -ChildPath (
                                    @([regex]'^"?[A-Za-z]:\\[Ww][iI][nN][dD][oO][Ww][sS]\\(?<FilePath>.*\.(exe|dll))\s?').Matches($_) |
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                )
                                break
                            }
                            '^"?[A-Za-z]:\\[Pp]rogram\s[fF]iles\\(?<FileName>.*\.[eE][xX][eE])\s?' {
                                Join-Path -Path "$($env:ProgramFiles)" -ChildPath (
                                    @([regex]'^"?[A-Za-z]:\\[Pp]rogram\s[fF]iles\\(?<FileName>.*\.[eE][xX][eE])\s?').Matches($_) |
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                )
                                break
                            }
                            '^"?[A-Za-z]:\\[Pp]rogram\s[fF]iles\s\(x86\)\\(?<FileName>.*\.[eE][xX][eE])\s?' {
                                Join-Path -Path "$(${env:ProgramFiles(x86)})" -ChildPath (
                                    @([regex]'^"?[A-Za-z]:\\[Pp]rogram\s[fF]iles\s\(x86\)\\(?<FileName>.*\.[eE][xX][eE])\s?').Matches($_) |
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                )
                                break
                            }
                            '^"?[A-Za-z]:\\[Pp]rogram[dD]ata\\(?<FileName>.*\.[eE][xX][eE])\s?' {
                                Join-Path -Path "$($env:ProgramData)" -ChildPath (
                                    @([regex]'^"?[A-Za-z]:\\[Pp]rogram[dD]ata\\(?<FileName>.*\.[eE][xX][eE])\s?').Matches($_) |
                                    Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                )
                                break
                            }
                            '^"?(?<FilePath>[A-Za-z]:\\.*\.[eE][xX][eE])\s?' {
                                @([regex]'^"?(?<FilePath>[A-Za-z]:\\.*\.[eE][xX][eE])\s?').Matches($_) |
                                Select-Object -Expand Groups | Select-Object -Last 1 | Select-Object -ExpandProperty Value
                                break
                            }
                            'winhttp.dll' {
                                Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath 'winhttp.dll'
                                break
                            }
                            'atmfd.dll' {
                                Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath 'atmfd.dll'
                                break
                            }
                            default {
                                $_
                            }

                        }) -Force -PassThru
                        break
                    }
                    Winlogon {
                        # this works on W8.1
                        # $Item | Add-Member -MemberType ScriptProperty -Name ImagePath -Value $({$this.Value}) -Force -PassThru
                        # for backward compatibility with W7 we do:
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Switch -Regex ($Item.Value) {
                                '^[a-zA-Z0-9]*\.[dDlL]{3}' {
                                    Join-Path -Path "$($env:SystemRoot)\System32" -ChildPath $Item.Value
                                    break
                                }
                                default {
                                    $_;
                                }
                            }
                        ) -Force -PassThru
                        break
                    }
                    'Winsock Providers' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                            Switch -Regex ($Item.Value) {
                                '^%SystemRoot%\\system32\\' {
                                    $_ -replace '%SystemRoot%',"$($env:SystemRoot)";
                                    break;
                                }
                                default {
                                    $_;
                                }
                            }
                        ) -Force -PassThru
                        break
                    }
                    WMI {
                        if ($Item.Value) {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $(
                                Switch -Regex (($Item.Value -replace '"','')) {
                                    '^%SystemRoot%\\system32\\' {
                                        $_ -replace '%SystemRoot%',"$($env:SystemRoot)";
                                        break;
                                    }
                                    default {
                                        $_;
                                    }
                                }
                            ) -Force -PassThru
                        } else {
                            $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value $null -Force -PassThru
                        }
                        break
                    }
                    'PowerShell Profiles' {
                        $Item | Add-Member -MemberType NoteProperty -Name ImagePath -Value "$($Item.Value)" -Force -PassThru
                        break
                    }
                    default {
                    }
                }
            }
        }
        End {}
    }


    Function Add-PSAutoRunExtendedInfo {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory,ValueFromPipeLine)]
            [system.object[]]$RawAutoRun
        )
        Begin {}
        Process {
            $RawAutoRun | ForEach-Object {
                $o = [pscustomobject]@{
                        Path = $_.Path ;
                        Item = $_.Item ;
                        Category = $_.Category ;
                        Value = $_.Value
                        ImagePath = $_.ImagePath ;
                        Size = $null;
                        LastWriteTime = $null;
                        Version = $null;
                    }
                If ($_.ImagePath) {
                    try {
                        $extinfo = Get-Item -Path $_.ImagePath -ErrorAction Stop
                        $o.Size = $extinfo.Length;
                        $o.Version = $extinfo.VersionInfo.ProductVersion;
                        $o.LastWriteTime = $extinfo.LastWriteTime;
                        $o
                    } catch {
                        $o
                    }
                } else {
                    $o
                }
            }
        }
        End{}
    }
    Function Add-PSAutoRunHash {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory,ValueFromPipeLine)]
            [system.object[]]$RawAutoRun,
            [Switch]$ShowFileHash
        )
        Begin {}
        Process {
            $RawAutoRun | ForEach-Object {
                If ($ShowFileHash) {
                    if ($_.ImagePath) {
                        If (Test-Path -Path $($_.ImagePath) -PathType Leaf -ErrorAction SilentlyContinue) {
                            $_ | Add-Member -MemberType NoteProperty -Name MD5 -Value $(
                                (Get-FileHash -Path $($_.ImagePath) -Algorithm MD5).Hash
                            ) -Force -PassThru |
                            Add-Member -MemberType NoteProperty -Name SHA1 -Value $(
                                (Get-FileHash -Path $($_.ImagePath) -Algorithm SHA1).Hash
                            ) -Force -PassThru |
                            Add-Member -MemberType NoteProperty -Name SHA256 -Value $(
                                (Get-FileHash -Path $($_.ImagePath) -Algorithm SHA256).Hash
                            ) -Force -PassThru
                        } else {
                            $_ | Add-Member -MemberType NoteProperty -Name MD5 -Value $null -Force -PassThru |
                            Add-Member -MemberType NoteProperty -Name SHA1 -Value $null -Force -PassThru |
                            Add-Member -MemberType NoteProperty -Name SHA256 -Value $null -Force -PassThru
                        }
                    } else {
                        $_ | Add-Member -MemberType NoteProperty -Name MD5 -Value $null -Force -PassThru |
                        Add-Member -MemberType NoteProperty -Name SHA1 -Value $null -Force -PassThru |
                        Add-Member -MemberType NoteProperty -Name SHA256 -Value $null -Force -PassThru
                    }
                } else {
                    $_
                }
            }
        }
        End {}
    }

    Function Add-PSAutoRunAuthentiCodeSignature {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory,ValueFromPipeLine)]
            [system.object[]]$RawAutoRun,
            [Switch]$VerifyDigitalSignature
        )
        Begin {}
        Process {
            $RawAutoRun | ForEach-Object {
                If ($VerifyDigitalSignature) {
                    if ($_.ImagePath) {
                        If (Test-Path -Path $_.ImagePath -PathType Leaf -ErrorAction SilentlyContinue) {

                            ## Add the signature status to the entry
                            $signature = Get-AuthenticodeSignature -FilePath $_.ImagePath -ErrorAction Stop
                            $signed = switch ($signature.Status) {
                                'Valid' {
                                    $true
                                    break
                                }
                                'NotSigned' {
                                    $false
                                    break
                                }
                                default {
                                    $false
                                }
                            }
                            $_ = $_ | Add-Member -MemberType NoteProperty -Name Signed -Value $signed -Force -PassThru

                            ## Add a note whether this is an OS binary to allow for easy filtering:
                            ## Get-PSAutorun -VerifyDigitalSignature | ? { -not $_.IsOSBinary }
                            if($signature.IsOSBinary)
                            {
                                $_ = $_ | Add-Member -MemberType NoteProperty -Name IsOSBinary -Value $signature.IsOSBinary -Force -PassThru
                            }

                            ## Add the signer itself
                            $_ | Add-Member -MemberType NoteProperty -Name Publisher -Value $signature.SignerCertificate.Subject -Force -PassThru
                        } else {
                            $_ = $_ | Add-Member -MemberType NoteProperty -Name Signed -Value $null -Force -PassThru
                            $_ = $_ | Add-Member -MemberType NoteProperty -Name IsOSBinary -Value $null -Force -PassThru
                            $_ | Add-Member -MemberType NoteProperty -Name Publisher -Value $null -Force -PassThru
                        }
                    } else {
                        $_ = $_ | Add-Member -MemberType NoteProperty -Name Signed -Value $null -Force -PassThru
                        $_ = $_ | Add-Member -MemberType NoteProperty -Name IsOSBinary -Value $null -Force -PassThru
                        $_ | Add-Member -MemberType NoteProperty -Name Publisher -Value $null -Force -PassThru
                    }
                } else {
                    $_
                }
            }
        }
        End{}
    }

    #endregion Helperfunctions

}
Process {
    Switch ($PSCmdlet.ParameterSetName) {
        'Plain' {
            Get-PSRawAutoRun @PSBoundParameters
            break
        }
        'Pretty' {
            if ($PSBoundParameters.ContainsKey('ShowFileHash')) {
                $GetHash = $true
            } else {
                $GetHash = $false
            }
            if ($PSBoundParameters.ContainsKey('VerifyDigitalSignature')) {
                $GetSig = $true
            } else {
                $GetSig = $false
            }
            if ($PSBoundParameters.ContainsKey('User')) {
                $null = $PSBoundParameters.Remove('User')
            }
            $PSBoundParameters.Add('User',$Users)
            Get-PSRawAutoRun @PSBoundParameters |
            Get-PSPrettyAutorun |
            Add-PSAutoRunExtendedInfo |
            Add-PSAutoRunHash -ShowFileHash:$GetHash |
            Add-PSAutoRunAuthentiCodeSignature -VerifyDigitalSignature:$GetSig
            break
        }
        default {}
    }
}
End {}
}

<#
Get-PSAutorun -BootExecute -AppinitDLLs
Get-PSAutorun -All | Format-Table -Property Path,ImagePath,Category
Get-PSAutorun -Logon -LSAsecurityProviders | Format-Table -Property Path,ImagePath,Category
Get-PSAutorun -All -ShowFileHash -VerifyDigitalSignature
Get-PSAutorun -ServicesAndDrivers | ? path -match 'OSE' | fl *
Get-PSAutorun -ServicesAndDrivers | ? path -match 'sysmon' | fl *
Get-PSAutorun -ServicesAndDrivers | ? path -match 'psexesvc' | fl *
Get-PSAutorun -OfficeAddins | Format-Table -Property Path,ImagePath,Category
Get-PSAutorun -WMI -VerifyDigitalSignature | Where { -not $_.isOSBinary }

# From 11.70 to 12.0
    +HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
    +WMI Database Entries
# From 12.0 to 12.3
    -HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\System
    -HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
    -HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SaveDumpStart
    +HKCU\SOFTWARE\Classes\Htmlfile\Shell\Open\Command\(Default)
    +HKLM\SOFTWARE\Classes\Htmlfile\Shell\Open\Command\(Default)
# From 12.3 to 13.4
    +HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GpExtensions
    +HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells\AvailableShells
    +HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
    +HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
    +HKCU\Software\Classes\Clsid\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\Inprocserver32
    +Office Addins
# From 13.4 to 13.5
    +HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers
# From 13.5 to 13.51
    +HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx
    +HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
    +HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx
    +HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx
    +HKCU\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx
    +HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx
# From 13.51 to 13.61
    +HKLM\SOFTWARE\Microsoft\Office test\Special\Perf\(Default)
    +HKCU\SOFTWARE\Microsoft\Office test\Special\Perf\(Default)
# From 13.61 to 13.62
    +HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
# From 13.62 to 13.7
    +HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers
# From 13.71 to 13.80
    +HKCU\Environment\UserInitMprLogonScript
    +HKLM\Environment\UserInitMprLogonScript
# From 13.80 to 13.82
    +HKLM\Software\Microsoft\Office\Onenote\Addins
    +HKCU\Software\Microsoft\Office\Onenote\Addins
    +HKLM\Software\Wow6432Node\Microsoft\Office\Onenote\Addins
    +HKCU\Software\Wow6432Node\Microsoft\Office\Onenote\Addins
    -HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AppSetup
    -HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce
    -HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx
    -HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
    -HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce
    -HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx
    -HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
    -HKLM\System\CurrentControlSet\Control\ServiceControlManagerExtension
# From 13.82 to 13.90
    -AppData\Local\Microsoft\Windows Sidebar\Settings.ini
    +HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AppSetup
    +HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup
    +HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown
    +HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon
    +HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff
    +HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce
    +HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx
    +HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
    +HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce
    +HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx
    +HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
#>

Function Get-NewAutoRunsFlatArtifact {
<#
    .SYNOPSIS
        Get a flat autoruns artifact

    .DESCRIPTION
        Get a flat autoruns artifact as strings sent into the output stream to be stored in a .ps1 file

    .PARAMETER InputObject
        Objects produced by the Get-PSAutorun function

    .PARAMETER NoEnd
        Switch to indicate that it should not append a last comma

#>
[CmdletBinding()]
Param(
[Parameter(Mandatory,ValueFromPipeline)]
[object[]]$InputObject,

[switch]$NoEnd
)
Begin{}
Process {
    $properties = $InputObject | Select-Object -First 1 |
    ForEach-Object { $_.PSObject.Properties }| Select-Object -Expand Name
    Write-Verbose -Message "Found $($properties)"

    $InputObject |
    ForEach-Object -Process {

        $Item = $_
        Write-Verbose -Message "Item: $($Item)"
        $properties |
        ForEach-Object -Begin {
            ' [PSCustomObject]@{'
        } -Process {
            $p = $_
            Write-Verbose -Message "Dealing with $($p)"
            if ($null -ne $Item.$p) {
                Switch ($Item.$p) {
                    {$_ -is [string]} {
                        Write-Verbose -Message "Its value $($Item.$p) is a String"
                        "  {0}='{1}'" -f $p,[Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($Item.$p)
                        break
                    }
                    {$_ -eq [string]::Empty} {
                        Write-Verbose -Message "Its value $($Item.$p) is an empty String"
                        "  {0}=''" -f $p

                        break
                    }
                    {$_ -is [long]} {
                        Write-Verbose -Message "Its value $($Item.$p) is an Long"
                        '  {0}=[long]{1}' -f $p,$Item.$p
                        break
                    }
                    {$_ -is [DateTime]} {
                        Write-Verbose -Message "Its value $($Item.$p) is a DateTime"
                        '  {0}=[datetime]{1} # {2}' -f $p,$Item.$p.Ticks,$Item.$p.ToString('u')
                        break
                    }
                    {$_ -is [bool]} {
                        Write-Verbose -Message "Its value $($Item.$p) is a Boolean"
                        "  {0}=[bool]'{1}'" -f $p,$Item.$p
                    }
                    default   {
                        Write-Warning -Message "Shouldn't be here for $($p) = $($Item.$p)"
                    }
                }
            } else {
                '  {0}=$null' -f $p
            }
        } -End {
            if ($NoEnd) {
                ' }'
            } else {
                ' },'
            }
        }
    }
}
End {}
}

Function New-AutoRunsBaseLine {
<#
    .SYNOPSIS
        Create a baseline file from Autoruns artifact(s).

    .DESCRIPTION
        Create a baseline from Autoruns artifact(s) as a PowerShell script (.ps1) file.

    .PARAMETER InputObject
        Objects produced by the Get-PSAutorun function

    .PARAMETER FilePath
        String that indicates an alternative file location.

#>
[CmdletBinding(SupportsShouldProcess)]
Param(
[Parameter(Mandatory,ValueFromPipeline)]
[object[]]$InputObject,

[Parameter()]
[string]$FilePath = "~/Documents/PSAutoRunsBaseLine-$((Get-Date).ToString('yyyyMMddHHmmss')).ps1"

)
Begin {
    $Count = 0
    $Results = New-Object -TypeName System.Collections.ArrayList
    if ($PSBoundParameters.Keys.Contains('InputObject')) {
        $FromPipeLine = $false
    } else {
        $FromPipeLine = $true
    }
    $OFHT = @{
        ErrorAction = 'Stop'
        FilePath = "$($FilePath)"
        NoClobber = ([switch]::Present)
        Force = ([switch]::Present)
        Encoding = 'UTF8'
        Append = $false
    }
}
Process {
    $InputObject |
    ForEach-Object {
        $Count++
        if ($Count -eq 1) {
            $First = $_
        }
        if ($Count -ge 2) {
            $null = $Results.Add(
                ($_ | Get-NewAutoRunsFlatArtifact -Verbose:$false)
            )
        }
    }
}
End {
    try {
        $(
            '@('
            if ($Count -eq 1) {
                $InputObject | Get-NewAutoRunsFlatArtifact -Verbose:$false -NoEnd
            } elseif ($Count -eq 2) {
                $First | Get-NewAutoRunsFlatArtifact -Verbose:$false
                if ($FromPipeLine) {
                    $InputObject | Get-NewAutoRunsFlatArtifact -Verbose:$false -NoEnd
                } else {
                    $InputObject[1] | Get-NewAutoRunsFlatArtifact -Verbose:$false -NoEnd
                }
            } elseif ($Count -gt 2) {
                $First | Get-NewAutoRunsFlatArtifact -Verbose:$false
                $Results[0..$($Results.Count - 2)]
                if ($FromPipeLine) {
                    $InputObject | Get-NewAutoRunsFlatArtifact -Verbose:$false -NoEnd
                } else {
                    $InputObject[-1] | Get-NewAutoRunsFlatArtifact -Verbose:$false -NoEnd
                }
            }
            ')'
        ) |
        Out-File @OFHT
        Write-Verbose -Message "PSAutoRunsBaseLine $($FilePath) successfully created"
    } catch {
        Write-Warning -Message "Failed to create baseline because $($_.Exception.Message)"
    }
}
}

Function Compare-AutoRunsBaseLine {
<#
    .SYNOPSIS
        Compare two baseline files of Autoruns artifact(s).

    .DESCRIPTION
        Compare two baseline files of Autoruns artifact(s).

    .PARAMETER ReferenceBaseLineFile
        String that indicates the location of a baseline file.

    .PARAMETER DifferenceBaseLineFile
        String that indicates the location of the other baseline file.
#>
[CmdletBinding()]
Param(
[Parameter()]
[string]$ReferenceBaseLineFile = "$((Get-Item -Path ~/Documents/PSAutoRunsBaseLine*.ps1 | Select-Object -First 1).FullName)",

[Parameter()]
[string]$DifferenceBaseLineFile = "$((Get-Item -Path ~/Documents/PSAutoRunsBaseLine*.ps1 | Select-Object -First 2 | Select-Object -Last 1).FullName)"
)
Begin {
    Write-Verbose -Message "Reference file set to $($ReferenceBaseLineFile)"
    Write-Verbose -Message "Difference file set to $($DifferenceBaseLineFile)"

    $L1 = . $ReferenceBaseLineFile
    $L2 = . $DifferenceBaseLineFile

    $Props = 'Path','Item','Category','Value','ImagePath','Size','LastWriteTime','Version',
    'MD5','SHA1','SHA256','Signed','IsOSBinary','Publisher'
}
Process {}
End {
    Compare-Object -ReferenceObject $L1 -DifferenceObject ($L2) -Property $Props
}
}
