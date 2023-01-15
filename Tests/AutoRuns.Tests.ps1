<#

Use some Pester tests to find out if the internal Get-PSPrettyAutorun
function:
 -implements fixes
 -doesn't introduce new issues

We want for example to test that the regular expressions inside the
Get-PSPrettyAutorun function work against some known (fixed) issues

Use the AST to find and extract the Get-PSPrettyAutorun function
and load it into a fake module as a function because it's harmless

#>

#region use AST to fake module
$Ast = $File = $predicate = $sb = $flat = $null
$File = (Resolve-Path $PSScriptRoot\..\AutoRuns.psm1).Path
$Ast = [scriptblock]::Create((Get-Content -Path $File -Raw)).Ast

[ScriptBlock] $predicate = {
 Param ([System.Management.Automation.Language.Ast] $Ast)
 $Ast -is [System.Management.Automation.Language.FunctionDefinitionAst]
}

# Parse the AST recursively and find all functions
$sb  = New-Object System.Text.StringBuilder
$AST.FindAll($predicate,$true) | ForEach-Object {
    $null = $sb.Append("function $($_.Name) { $($_.Body.GetScriptBlock()) }`n")
}
$null = $sb.Append("Export-ModuleMember -Function '*'")

$flat = [scriptblock]::Create($sb.ToString())

Remove-Module -Name FakeAutoRuns -Force -ErrorAction SilentlyContinue
New-Module -Name FakeAutoRuns -ScriptBlock ($flat.GetNewClosure()) |
Import-Module -Force -Verbose:$false
#endregion

InModuleScope FakeAutoRuns {

#region Boot Execute

Describe 'Testing Get-PSPrettyAutorun for BootExecute' {

    # https://github.com/p0w3rsh3ll/AutoRuns/issues/100
    It 'issue 100 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\System\CurrentControlSet\Control\Session Manager'
                Item     = 'SetupExecute'
                Category = 'Boot Execute'
                Value    = 'C:\Windows\System32\poqexec.exe /display_progress \SystemRoot\WinSxS\pending.xml'
            }
        } -ParameterFilter { $BootExecute -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -BootExecute | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\Windows\System32\poqexec.exe' | should be $true
    }
}
#endregion

#region Print Monitors

Describe 'Testing Get-PSPrettyAutorun for Print Monitors' {

    #  Fix the ImagePath of Printer port #74
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/74
    It 'issue 74 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Ports'
                Item     = 'Port'
                Category = 'Print Monitors'
                Value    = 'C:\windows\tracing\myport.txt'
            }
        } -ParameterFilter { $PrintMonitorDLLs -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -PrintMonitorDLLs | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\windows\tracing\myport.txt' | should be $true
    }
}
#endregion

#region ScheduledTasks

Describe 'Testing ScheduledTasks' {

    Context 'Inside Add-PSAutoRunHash' {
        It 'issue 80 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path = 'C:\WINDOWS\system32\Tasks\\ConfigAppIdSvc'
                    Item = 'ConfigAppIdSvc'
                    Category = 'Task'
                    Value = 'whatever'
                    # ImagePath = '-Command "& ''C:\Users\username\Documents\script.ps1'
                    ImagePath = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -Exec Bypass -Command "Set-Service -Name AppIDSvc -StartupType Automatic"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            { Get-PSRawAutoRun -ScheduledTasks | Add-PSAutoRunHash -ShowFileHash -ErrorAction Stop } | should not throw
        }
    }

    Context 'Inside Add-PSAutoRunAuthentiCodeSignature' {
        It 'issue 82 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path = 'C:\WINDOWS\system32\Tasks\\ConfigAppIdSvc'
                    Item = 'ConfigAppIdSvc'
                    Category = 'Task'
                    Value = 'whatever'
                    # ImagePath = '-Command "& ''C:\Users\username\Documents\script.ps1'
                    ImagePath = 'C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -Exec Bypass -Command "Set-Service -Name AppIDSvc -StartupType Automatic"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            { Get-PSRawAutoRun -ScheduledTasks | Add-PSAutoRunAuthentiCodeSignature -VerifyDigitalSignature -ErrorAction Stop } | should not throw
        }
    }
# Emulate what Get-PSRawAutoRun -ScheduledTasks returns & pass it to Get-PSPrettyAutorun

    Context 'Inside Get-PSRawAutoRun' {

        # Scheduled tasks with multiple programs started #36
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/36
        It 'issue 36 should be solved' {

            Mock -CommandName Get-AllScheduledTask -MockWith {
                return [PSCustomObject]@{ Path = '\' ; Name = 'test' }
            }

            Mock -CommandName Get-Task -MockWith {
                return [PSCustomObject]@{ Path = '\' ; Name = 'test'
                        Xml = @'
<?xml version="1.0" encoding="UTF-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
        <RegistrationInfo>
        <Date>DontCare</Date>
        <Author>MyComputer\UserName</Author>
        <URI>\test</URI>
        </RegistrationInfo>
        <Principals>
            <Principal id="Author">
                <UserId>S-1-5-18</UserId>
                <LogonType>InteractiveToken</LogonType>
            </Principal>
        </Principals>
        <Settings></Settings>
        <Triggers />
        <Actions Context="Author">
        <Exec>
            <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
            <Arguments>-Exec Bypass -Command "test" -File logoff.pS1 -Verbose</Arguments>
        </Exec>
        <Exec>
            <Command>C:\Windows\system32\wevtutil.exe</Command>
            <Arguments>el</Arguments>
        </Exec>
        </Actions>
    </Task>
'@
                }
            }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Select-Object -First 1)
            $j = (Get-PSRawAutoRun -ScheduledTasks | Select-Object -First 2 | Select-Object -Last 1)

            (($i,$j).Count -eq 2) -and ($j.Value -eq 'C:\Windows\system32\wevtutil.exe el') -and
            ($i.Value -eq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Exec Bypass -Command "test" -File logoff.pS1 -Verbose') |
            Should be $true
        }
    }

    Context 'Inside Get-PSPrettyAutorun' {

        # https://github.com/p0w3rsh3ll/AutoRuns/issues/107
        It 'issue #107 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\windows\system32\Tasks\HP\Consent Manager Launcher'
                    Item     = 'Consent Manager Launcher'
                    Category = 'Task'
                    Value    = 'sc start hptouchpointanalyticsservice'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Windows\System32\sc.exe' | should be $true
        }

        # https://github.com/p0w3rsh3ll/AutoRuns/issues/106
        It 'issue #106 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\windows\system32\Tasks\Microsoft\Office\Office Feature Updates'
                    Item     = 'Office Feature Updates'
                    Category = 'Task'
                    Value    = 'C:\Program Files\Microsoft Office\root\Office16\sdxhelper.exe'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "-$($i)-" -Verbose
            $i -eq 'C:\Program Files\Microsoft Office\root\Office16\sdxhelper.exe' | should be $true
        }

        # https://github.com/p0w3rsh3ll/AutoRuns/issues/105
        It 'issue #105 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\windows\system32\Tasks\HP\Sure Click\Tray icon 4.3.8.391'
                    Item     = 'Tray icon 4.3.8.391'
                    Category = 'Task'
                    Value    = 'c:\Program Files\HP\Sure Click\servers\BrConsole.exe'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Program Files\HP\Sure Click\servers\BrConsole.exe' | should be $true
        }

        # https://github.com/p0w3rsh3ll/AutoRuns/issues/104
        It 'issue #104 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\windows\system32\Tasks\HP\Sure Click\Sure Click 4.3.8.391'
                    Item     = 'Sure Click 4.3.8.391'
                    Category = 'Task'
                    Value    = 'c:\Program Files\HP\Sure Click\servers\BrLauncher.exe vSentry start'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Program Files\HP\Sure Click\servers\BrLauncher.exe' | should be $true
        }

        # https://github.com/p0w3rsh3ll/AutoRuns/issues/103
        It 'issue #103 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Mozilla\Firefox Background Update 308046B0AF4A39CB'
                    Item     = 'Firefox Background Update 308046B0AF4A39CB'
                    Category = 'Task'
                    Value    = 'C:\Program Files\Mozilla Firefox\firefox.exe --MOZ_LOG sync,prependheader,timestamp,append,maxsize:1,Dump:5 --MOZ_LOG_FILE C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38\updates\308046B0AF4A39CB\backgroundupdate.moz_log --backgroundtask backgroundupdate'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Program Files\Mozilla Firefox\firefox.exe' | should be $true
        }

        # https://github.com/p0w3rsh3ll/AutoRuns/issues/102
        It 'issue #102 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\\TaskName'
                    Item     = 'TaskName'
                    Category = 'Task'
                    Value    = '"C:\Windows\Folder1\Folder2\scriptfile.cmd"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Windows\Folder1\Folder2\scriptfile.cmd' | should be $true
        }

        # https://github.com/p0w3rsh3ll/AutoRuns/issues/101
        It 'issue #101 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\\OneDrive Reporting Task-SID'
                    Item     = 'OneDrive Reporting Task-SID'
                    Category = 'Task'
                    Value    = '%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe /reporting'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq '\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe' | should be $true
        }

        # Dropbox tasks #63
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/63
        It 'issue #63.1 should be solved' {

            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\\DropboxUpdateTaskUserS-1-5-21-SIDCore1d2376bef827e9d'
                    Item     = 'DropboxUpdateTaskUserS-1-5-21-SIDCore1d2376bef827e9d'
                    Category = 'Task'
                    Value    = 'C:\Users\username\AppData\Local\Dropbox\Update\DropboxUpdate.exe /c'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "-$($i)-" -Verbose
            $i -eq 'C:\Users\username\AppData\Local\Dropbox\Update\DropboxUpdate.exe' | should be $true
        }

        It 'issue #63.2 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\\DropboxUpdateTaskUserS-1-5-21-SIDUA1d2376befd2c972'
                    Item     = 'DropboxUpdateTaskUserS-1-5-21-SIDUA1d2376befd2c972'
                    Category = 'Task'
                    Value    = 'C:\Users\username\AppData\Local\Dropbox\Update\DropboxUpdate.exe /ua /installsource scheduler'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "-$($i)-" -Verbose
            $i -eq 'C:\Users\username\AppData\Local\Dropbox\Update\DropboxUpdate.exe' | should be $true
        }

        # Lenovo\ImController #61
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/61
        It 'issue #61 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Lenovo\ImController\Lenovo iM Controller Monitor'
                    Item     = 'Lenovo iM Controller Monitor'
                    Category = 'Task'
                    Value    = '"%windir%\system32\ImController.InfInstaller.exe" -checkremoval'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "-$($i)-" -Verbose
            $i -eq 'C:\Windows\system32\ImController.InfInstaller.exe' | should be $true
        }

        # UninstallSMB1ClientTask & UninstallSMB1ServerTask #62
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/62
        It 'issue #62.1 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\SMB\UninstallSMB1ClientTask'
                    Item     = 'UninstallSMB1ClientTask'
                    Category = 'Task'
                    Value    = '%windir%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle Hidden "& %windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1 -Scenario Client"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "#$($i)#" -Verbose
            # !! the end of the above value was truncated, we don't have the parameters inside the scriptblock and its ending double quote
            # $i -eq '%windir%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle Hidden "& %windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1' | should be $true
            # $i -eq '%windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1' | should be $true
            $i -eq 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1' | should be $true
        }
        It 'issue #62.2 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\SMB\UninstallSMB1ServerTask'
                    Item     = 'UninstallSMB1ServerTask'
                    Category = 'Task'
                    Value    = '%windir%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle Hidden "& %windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1 -Scenario Server"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "#$($i)#" -Verbose
            # !! the end of the above value was truncated, we don't have the parameters inside the scriptblock and its ending double quote
            # $i -eq '%windir%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle Hidden "& %windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1' | should be $true
            $i -eq 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\SmbShare\DisableUnusedSmb1.ps1' | should be $true
        }
        It 'issue #62.3 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\FakeTask'
                    Item     = 'FakeTask'
                    Category = 'Task'
                    Value    = '%windir%\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle Hidden "C:\fakepathwith a space\FakeScript.ps1"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "#$($i)#" -Verbose
            $i -eq 'C:\fakepathwith a space\FakeScript.ps1' | should be $true
        }
        It 'issue #62.4 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\FakeTaskPSEncoded'
                    Item     = 'FakeTaskPSEncoded'
                    Category = 'Task'
                    Value    = 'powershell.exe -encodedCommand ZABpAHIAIAAiAGMAOgBcAHAAcgBvAGcAcgBhAG0AIABmAGkAbABlAHMAIgAgAA=='
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "#$($i)#" -Verbose
            $i -eq 'powershell.exe -encodedCommand ZABpAHIAIAAiAGMAOgBcAHAAcgBvAGcAcgBhAG0AIABmAGkAbABlAHMAIgAgAA==' | should be $true
        }

        # ImagePath is wrong for scheduled tasks MicTray #60
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/60
        It 'issue #60 should be solved' {

            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\Conexant\MicTray'
                    Item     = 'MicTray'
                    Category = 'Task'
                    Value    = '"C:\Windows\System32\MicTray64.exe"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Windows\System32\MicTray64.exe' | should be $true
        }

        # ImagePath is wrong for schelued task SA3 #59
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/59
        It 'issue #59 should be solved' {

            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\Conexant\SA3'
                    Item     = 'SA3'
                    Category = 'Task'
                    Value    = '"C:\Program Files\CONEXANT\SA3\HP-NB-AIO\SACpl.exe" /sa3 /nv:3.0+ /uid:HP-NB-AIO /s /dne'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Program Files\CONEXANT\SA3\HP-NB-AIO\SACpl.exe' | should be $true
        }

        # Scheduled task issue: CleanupOldPerfLogs #50
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/50
        It 'issue #50 should be solved' {

            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\Server Manager\CleanupOldPerfLogs'
                    Item     = 'CleanupOldPerfLogs'
                    Category = 'Task'
                    Value    = '%systemroot%\system32\cscript.exe /B /nologo %systemroot%\system32\calluxxprovider.vbs $(Arg0) $(Arg1) $(Arg2)'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\WINDOWS\system32\calluxxprovider.vbs' | should be $true
        }

        # Scheduled task issue: Server Manager Performance Monitor #49
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/49
        It 'issue #49 should be solved' {

            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\PLA\Server Manager Performance Monitor'
                    Item     = 'Server Manager Performance Monitor'
                    Category = 'Task'
                    Value    = '%systemroot%\system32\rundll32.exe %systemroot%\system32\pla.dll,PlaHost "Server Manager Performance Monitor" "$(Arg0)"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\WINDOWS\system32\pla.dll' | should be $true
        }

        # Scheduled task ReplaceOMCert on a Azure VM #41
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/41
        It 'issue #41 should be solved' {

            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Microsoft\Windows\CertificateServicesClient\Notification\ReplaceOMCert'
                    Item     = 'ReplaceOMCert'
                    Category = 'Task'
                    Value    = '%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive -File "C:\Program Files\Microsoft Monitoring Agent\Agent\Tools\UpdateOMCert.ps1" -OldCertHash $(OldCertHash) -NewCertHash $(NewCertHash) -EventRecordId $(EventRecordId)'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Program Files\Microsoft Monitoring Agent\Agent\Tools\UpdateOMCert.ps1' | should be $true
        }

        # ImagePath is wrong for FODCleanupTask #38
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/38
        It 'issue #38 should be solved' {

            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Microsoft\Windows\HelloFace\FODCleanupTask'
                    Item     = 'FODCleanupTask'
                    Category = 'Task'
                    Value    = '%WinDir%\System32\WinBioPlugIns\FaceFodUninstaller.exe'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }

            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\WINDOWS\system32\WinBioPlugIns\FaceFodUninstaller.exe' | should be $true
        }

        # Scheduled tasks with a powershell script file in quotes #37
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/37
        It 'issue #37 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path      = 'C:\Windows\system32\Tasks\Test'
                    Item      = 'Test'
                    Category  = 'Task'
                    Value     = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Windows\TTest.ps1" -CustomParam'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Windows\TTest.ps1' | should be $true
        }
        It 'issue #37.1 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Test'
                    Item     = 'Test'
                    Category = 'Task'
                    Value    = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Windows\TTest.ps1"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Windows\TTest.ps1' | should be $true
        }

        # Change image path for scheduled tasks that run powershell.exe #33
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/33
        It 'issue #33 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\\logoff PS'
                    Item     = 'logoff PS'
                    Category = 'Task'
                    Value    = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Exec Bypass -File c:\windows\system32\logoff.ps1'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'c:\windows\system32\logoff.ps1' | should be $true
        }

        # special powershell.exe file.ps1
        It 'issue #33.1 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Test'
                    Item     = 'Test'
                    Category = 'Task'
                    Value    = 'powershell.exe file.ps1'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "#$($i)#" -Verbose
            $i -eq 'file.ps1' | should be $true
        }

        # special powershell.exe -f file.ps1 -exec bypass
        It 'issue #33.2 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Test'
                    Item     = 'Test'
                    Category = 'Task'
                    Value    = 'powershell.exe -f file.ps1 -exec bypass'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'file.ps1' | should be $true
        }
        # special powershell.exe -fil file.ps1 -exec bypass
        It 'issue #33.3 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Test'
                    Item     = 'Test'
                    Category = 'Task'
                    Value    = 'powershell.exe -fil file.ps1 -exec bypass'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'file.ps1' | should be $true
        }
        # special powershell.exe -exec bypass -file file.ps1
        It 'issue #33.4 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Test'
                    Item     = 'Test'
                    Category = 'Task'
                    Value    = 'powershell.exe -exec bypass -file file.ps1'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'file.ps1' | should be $true
        }
        # special powershell.exe -exec bypass -file file.ps1
        It 'issue #33.5 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Test'
                    Item     = 'Test'
                    Category = 'Task'
                    Value    = 'powershell.exe -exec bypass -file file.ps1'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'file.ps1' | should be $true
        }
        # but not powershell.exe -enc base64 or powershell.exe -command "cmd"
        It 'issue #33.6 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\Windows\system32\Tasks\Test'
                    Item     = 'Test'
                    Category = 'Task'
                    Value    = 'powershell.exe -enc base64 or powershell.exe -command "cmd"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'powershell.exe -enc base64 or powershell.exe -command "cmd"' | should be $true
        }

        # Wrong image path for a scheduled task that runs directly a bat file #32
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/32
        It 'issue #32 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\\action2'
                    Item     = 'action2'
                    Category = 'Task'
                    Value    = '"C:\Program Files\action.bat"'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Program Files\action.bat' | should be $true
        }

        # Wrong imagepath for a scheduled task that runs directly a vbs file #31
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/31
        It 'issue #31 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\\Action!'
                    Item     = 'Action!'
                    Category = 'Task'
                    Value    = 'C:\Program Files (x86)\Mirillis\Action!\Action.vbs'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\Program Files (x86)\Mirillis\Action!\Action.vbs' | should be $true
        }

        # Specific scheduled task for O2016 heartbeat #25
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/25
        It 'issue #25 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Office\Office 15 Subscription Heartbeat'
                    Item     = 'Office 15 Subscription Heartbeat'
                    Category = 'Task'
                    Value    = '%ProgramFiles%\Common Files\Microsoft Shared\Office16\OLicenseHeartbeat.exe'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -match 'C:\\Program\sFiles\s(\(x86\))?\\Common\sFiles\\microsoft\sshared\\OFFICE16\\OLicenseHeartbeat\.exe' | Should be $true
        }

        # Defender related scheduled tasks don't have a correct imagepath #22
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/22
        It 'issue #22 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance'
                    Item     = 'Windows Defender Cache Maintenance'
                    Category = 'Task'
                    Value    = 'C:\ProgramData\Microsoft\Windows Defender\platform\4.12.17007.18022-0\MpCmdRun.exe -IdleTask -TaskName WdCacheMaintenance'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\ProgramData\Microsoft\Windows Defender\platform\4.12.17007.18022-0\MpCmdRun.exe' | should be $true
        }
        It 'issue #22.1 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'C:\WINDOWS\system32\Tasks\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan'
                    Item     = 'Windows Defender Scheduled Scan'
                    Category = 'Task'
                    Value    = 'C:\ProgramData\Microsoft\Windows Defender\platform\4.12.17007.18022-0\MpCmdRun.exe Scan -ScheduleJob -ScanTrigger 55'
                }
            } -ParameterFilter { $ScheduledTasks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ScheduledTasks | Get-PSPrettyAutorun).ImagePath
            $i -eq 'C:\ProgramData\Microsoft\Windows Defender\platform\4.12.17007.18022-0\MpCmdRun.exe' | should be $true
        }
    }
}
#endregion ScheduledTasks

#region WMI

Describe 'Testing Get-PSPrettyAutorun for WMI' {

    # WMI provider issue: MSiSCSIInitiatorProvider #51
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/51
    It 'issue 51 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = "\\.\ROOT\WMI:__Win32Provider.Name='MSiSCSIInitiatorProvider'"
                Item     = 'MSiSCSIInitiatorProvider'
                Category = 'WMI'
                Value    = '%SystemRoot%\System32\iscsiwmi.dll'
            }
        } -ParameterFilter { $WMI -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -WMI | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\WINDOWS\System32\iscsiwmi.dll' | should be $true
    }

# Get-PSAutorun -WMI throws an error in PowerShell Core 6.0 #10
# https://github.com/p0w3rsh3ll/AutoRuns/issues/10
 It 'issue 10 should be solved' {
 }
    #Describe 'Testing WMI' {
    #    It 'Tests the WMI core function' {
    #        { Get-PSRawAutoRun -WMI } | Should not Throw
    #    }
    #}
}

#endregion WMI

#region Logon

Describe 'Testing Get-PSPrettyAutorun for Logon' {

    It 'issue 84 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKCU:\Software\\Microsoft\Windows\CurrentVersion\Run'
                Item     = 'Discord'
                Category = 'Logon'
                Value    = 'C:\ProgramData\Etienne\Discord\app-0.0.0\Discord.exe'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun).ImagePath
        # Write-Verbose -Message "#$($i)#" -Verbose
        $i -eq 'C:\ProgramData\Etienne\Discord\app-0.0.0\Discord.exe' | should be $true
    }

    # fake teams.exe with no quote or space
    It 'issue 70 bis should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKCU:\Software\\Microsoft\Windows\CurrentVersion\Run'
                Item     = 'com.squirrel.Teams.Teams'
                Category = 'Logon'
                Value    = 'C:\Users\username\AppData\Local\Microsoft\Teams\Update.exe'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun).ImagePath
        # Write-Verbose -Message "#$($i)#" -Verbose
        $i -eq 'C:\Users\username\AppData\Local\Microsoft\Teams\Update.exe' | should be $true
    }

    # Teams.exe
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/70
    It 'issue 70 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKCU:\Software\\Microsoft\Windows\CurrentVersion\Run'
                Item     = 'com.squirrel.Teams.Teams'
                Category = 'Logon'
                Value    = 'C:\Users\username\AppData\Local\Microsoft\Teams\Update.exe --processStart "Teams.exe" -process-start-args "--system-initiated"'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun).ImagePath
        # Write-Verbose -Message "#$($i)#" -Verbose
        $i -eq 'C:\Users\username\AppData\Local\Microsoft\Teams\Update.exe' | should be $true
    }

    # Dropbox.lnk #64
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/64
    It 'issue 64 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'C:\Users\username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
                Item     = 'Dropbox.lnk'
                Category = 'Logon'
                Value    = 'C:\Users\username\AppData\Roaming\Dropbox\bin\Dropbox.exe /systemstartup'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun).ImagePath
        # Write-Verbose -Message "#$($i)#" -Verbose
        $i -eq 'C:\Users\username\AppData\Roaming\Dropbox\bin\Dropbox.exe' | should be $true
    }

    # Startup lnk file has a wrong image path #43
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/43
    It 'issue 43 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'C:\Users\myuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
                Item     = 'Send to OneNote.lnk'
                Category = 'Logon'
                Value    = 'C:\Program Files (x86)\Microsoft Office\root\Office16\ONENOTEM.EXE /tsr'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun).ImagePath
        $i -match 'C:\\Program\sFiles(\s\(x86\))?\\Microsoft\sOffice\\root\\Office16\\ONENOTEM.EXE' | should be $true
    }

    # Logon Active Setup Installed Components C:\WINDOWS\inf\unregmp2.exe not found #24
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/24
    # NB: The file unregmp2.exe exists under c:\Windows\System32 and c:\Windows\SysWOW64
    It 'issue 24 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\SOFTWARE\\Microsoft\Active Setup\Installed Components\>{22d6f312-b0f6-11d0-94ab-0080c74c7e95}'
                Item     = 'StubPath'
                Category = 'Logon'
                Value    = 'C:\WINDOWS\inf\unregmp2.exe /ShowWMP'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\WINDOWS\system32\unregmp2.exe' | should be $true
    }

    # https://github.com/p0w3rsh3ll/AutoRuns/issues/18
    # https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/
    # Get-PSAutorun -Logon | ? Path -match 'RunOnceEx'
    # Split on pipe character
    # Detects ...RunonceEx\000x\Depend and RunOnceEx\Depend
    It 'issue 18.1 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx'
                Item     = 'test'
                Category = 'Logon'
                Value    = 'C:\malware.eXe'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\malware.eXe' | should be $true
    }
    It 'issue 18.2 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend'
                Item     = '1'
                Category = 'Logon'
                Value    = 'C:\temp\messageBox64.dll'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\temp\messageBox64.dll' | should be $true
    }
    It 'issue 18.3 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend'
                Item     = 'Line 1'
                Category = 'Logon'
                Value    = 'c:\windows\system32\url.dll|OpenURL|"http://www.google.com"'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun | Select-Object -First 1).ImagePath
        $j = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun | Select-Object -First 2 | Select-Object -Last 1).ImagePath
        $k = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun | Select-Object -Last 1).ImagePath
        (
        ($i -eq 'c:\windows\system32\url.dll') -and
        ($j -eq 'OpenURL') -and
        ($k -eq '"http://www.google.com"')
        ) | should be $true
    }

    # Handling of userinit registry value #17
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/17
    <#
    The \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\userinit value can be of the format:

    C:\Windows\System32\userinit.exe,"C:\malware.exe",
    Note: The trailing comma is necessary.
    It ensures that any settings added by another piece of software or GPO are delimited as necessary.

    #>
    It 'issue 17 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                Item     = 'userinit'
                Category = 'Logon'
                Value    = 'C:\Windows\System32\userinit.exe,"C:\malware.exe",'
            }
        } -ParameterFilter { $Logon -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun | Select-Object -First 1).ImagePath
        $j = (Get-PSRawAutoRun -Logon | Get-PSPrettyAutorun | Select-Object -First 2 | Select-Object -Last 1).ImagePath
        (
        ($i -eq 'C:\Windows\System32\userinit.exe') -and
        ($j -eq 'C:\malware.exe')
        ) | should be $true
    }
}
#endregion Logon

#region AppinitDLLs

Describe 'Testing Get-PSPrettyAutorun for AppinitDLLs' {

    <#
    From https://support.microsoft.com/en-us/help/197571/working-with-the-appinit-dlls-registry-value:

    "The AppInit_DLLs value has type "REG_SZ." This value has to specify a NULL-terminated string of DLLs
    that is delimited by spaces or by commas. Because spaces are used as delimiters, do not use long file names.
    The system does not recognize semicolons as delimiters for these DLLs."

    Your script does not handle comma or space delimited strings, but assumes there is only one string.
    #>
    # comma or space delimited AppInit_DLLs #16
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/16
    # test with a space as delimiter
    It 'issue 16.1 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
                Item     = 'Appinit_Dlls'
                Category = 'AppInit'
                Value    = 'c:\malWare1 C:\malware.eXe'
            }
        } -ParameterFilter { $AppinitDLLs-eq [switch]::Present }
        $i = (Get-PSRawAutoRun -AppinitDLLs | Get-PSPrettyAutorun | Select-Object -First 1).ImagePath
        $j = (Get-PSRawAutoRun -AppinitDLLs | Get-PSPrettyAutorun | Select-Object -First 2 | Select-Object -Last 1).ImagePath
        # Write-Verbose -Message "-$($i)-" -Verbose
        # Write-Verbose -Message "-$($j)-" -Verbose
        (
        ($i -eq 'c:\malWare1') -and
        ($j -eq 'C:\malware.eXe')
        ) | should be $true
    }
    # test with a comma as delimiter
    It 'issue 16.2 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
                Item     = 'Appinit_Dlls'
                Category = 'AppInit'
                Value    = 'c:\malWare1.eXe,C:\malware2.ExE'
            }
        } -ParameterFilter { $AppinitDLLs -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -AppinitDLLs | Get-PSPrettyAutorun | Select-Object -First 1).ImagePath
        $j = (Get-PSRawAutoRun -AppinitDLLs | Get-PSPrettyAutorun | Select-Object -First 2 | Select-Object  -Last 1).ImagePath
        (($i -eq 'c:\malWare1.eXe') -and ($j -eq 'C:\malware2.ExE')) | should be $true
    }
 }
#endregion AppinitDLLs

#region ServicesAndDrivers

Describe 'Testing Get-PSPrettyAutorun for ServicesAndDrivers' {

    # issue with ibtsiva (see also issue 53 below)
    # It 'issue file with no extension should be solved' {
    <#
    # if we had that in default block of the switch
                                if ($_ -match '\.[eEDd][xXlL][eElL]$') {
                                    $_
                                } else {
                                    $Env:PATHEXT -split ';' |
                                    ForEach-Object -Process {
                                        if (Test-Path -Path "$($Item.Value)$_" -PathType Leaf) {
                                            "$($Item.Value)$_"
                                            Continue
                                        }
                                    } -End {
                                        "$($Item.Value)"
                                    }
                                }
    #>
    #     Mock -CommandName Get-PSRawAutoRun -MockWith {
    #         return [PSCustomObject]@{
    #             Path     = 'HKLM:\System\CurrentControlSet\Services\ibtsiva'
    #             Item     = 'ImagePath'
    #             Category = 'Services'
    #             Value    = 'C:\Windows\system32\ibtsiva'
    #         }
    #     } -ParameterFilter { $ServicesAndDrivers -eq [switch]::Present }
    #     Mock -CommandName Test-Path -MockWith { return $true  } -ParameterFilter {
    #         $Path -eq 'C:\Windows\system32\ibtsiva.EXE'
    #     }
    #     $i = (Get-PSRawAutoRun -ServicesAndDrivers | Get-PSPrettyAutorun -Verbose).ImagePath
    #     # Write-Verbose -Message "-$($i)-" -Verbose
    #     $i -eq 'C:\Windows\system32\ibtsiva.EXE' | should be $true
    # }

    # https://github.com/p0w3rsh3ll/AutoRuns/issues/98
    It 'issue 98 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\System\CurrentControlSet\Services\PRM'
                Item     = 'ImagePath'
                Category = 'Drivers'
                Value    = 'System32\DriverStore\FileRepository\prm.inf_amd64_7fc9bb8ba2b73803\PRM.sys'
            }
        } -ParameterFilter { $ServicesAndDrivers -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -ServicesAndDrivers | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\Windows\System32\DriverStore\FileRepository\prm.inf_amd64_7fc9bb8ba2b73803\PRM.sys' | should be $true
    }

    # Service located in C:\packages in Windows 10 Azure VM #40
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/40
    It 'issue 40 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\System\CurrentControlSet\Services\MMAExtensionHeartbeatService'
                Item     = 'ImagePath'
                Category = 'Services'
                Value    = '"C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent\1.0.11081.4\MMAExtensionHeartbeatService.exe"'
            }
        } -ParameterFilter { $ServicesAndDrivers -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -ServicesAndDrivers | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\Packages\Plugins\Microsoft.EnterpriseCloud.Monitoring.MicrosoftMonitoringAgent\1.0.11081.4\MMAExtensionHeartbeatService.exe' |
        should be $true
    }

    # No size, version... for drivers #30
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/30
    It 'issue 30 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\System\CurrentControlSet\Services\BEDaisy'
                Item     = 'ImagePath'
                Category = 'Drivers'
                Value    = '\??\C:\Program Files (x86)\Common Files\BattlEye\BEDaisy.sys'
            }
        } -ParameterFilter { $ServicesAndDrivers -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -ServicesAndDrivers | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\Program Files (x86)\Common Files\BattlEye\BEDaisy.sys' | should be $true
    }

    # No size, version if Drivers is in %programfile% and values has \??\ at the beginning #20
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/20
    It 'issue 20 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\System\CurrentControlSet\Services\LGCoreTemp'
                Item     = 'ImagePath'
                Category = 'Drivers'
                Value    = '\??\C:\Program Files\Logitech Gaming Software\Drivers\LgCoreTemp\lgcoretemp.sys'
            }
        } -ParameterFilter { $ServicesAndDrivers -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -ServicesAndDrivers | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\Program Files\Logitech Gaming Software\Drivers\LgCoreTemp\lgcoretemp.sys' | should be $true
    }

    # No size, version... because of quotes for services located in ProgramData #19
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/19
    It 'issue 19 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\System\CurrentControlSet\Services\WinDefend'
                Item     = 'ImagePath'
                Category = 'Drivers'
                Value    = '"C:\ProgramData\Microsoft\Windows Defender\platform\4.12.17007.18022-0\MsMpEng.exe"'
            }
        } -ParameterFilter { $ServicesAndDrivers -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -ServicesAndDrivers | Get-PSPrettyAutorun).ImagePath
        $i -eq 'C:\ProgramData\Microsoft\Windows Defender\platform\4.12.17007.18022-0\MsMpEng.exe' | should be $true
    }

    # Wrong imagepath when the service value targets a file w/o extension #53
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/53
    It 'issue 53 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\System\CurrentControlSet\Services\ibtsiva'
                Item     = 'ImagePath'
                Category = 'Services'
                Value    = 'C:\Windows\system32\ibtsiva'
            }
        } -ParameterFilter { $ServicesAndDrivers -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -ServicesAndDrivers | Get-PSPrettyAutorun).ImagePath
        # Write-Verbose -Message "-$($i)-" -Verbose
        $i -eq 'C:\Windows\system32\ibtsiva' | should be $true
    }

    # Imagepath for drivers under SysWow64 #52
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/52
    It 'issue 52 should be solved' {
        Mock -CommandName Get-PSRawAutoRun -MockWith {
            return [PSCustomObject]@{
                Path     = 'HKLM:\System\CurrentControlSet\Services\AsIO'
                Item     = 'ImagePath'
                Category = 'Drivers'
                Value    = 'SysWow64\drivers\AsIO.sys'
            }
        } -ParameterFilter { $ServicesAndDrivers -eq [switch]::Present }
        $i = (Get-PSRawAutoRun -ServicesAndDrivers | Get-PSPrettyAutorun).ImagePath
        # Write-Verbose -Message "-$($i)-" -Verbose
        $i -eq 'C:\WINDOWS\SysWow64\drivers\AsIO.sys' | should be $true
    }
}
#endregion

#region Image Hijacks

Describe 'Testing Get-PSPrettyAutorun for ImageHijacks' {

    Context 'Inside Get-PSRawAutoRun' {

        # Persistence using GlobalFlags in Image File Execution Options #27
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/27
        # https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
        <#
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\temp\evil.exe"

        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v ReportingMode /t REG_DWORD /d 1
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /d "C:\temp\evil.exe"
        #>
        It 'issue 27 should be solved' {
            # Make sure the Users variable is defined and empty otherwise
            # it throws a RunTimeException when you call Get-PSRawAutoRun -ImageHijacks
            $Users = @{}
            Mock -CommandName Get-ItemProperty -ParameterFilter { $Name -eq 'GlobalFlag' } -MockWith {
                return [PSCustomObject]@{ 'GlobalFlag' = 512 }
            }
            Mock -CommandName Get-RegValue -ParameterFilter { $Name -eq 'MonitorProcess' } -MockWith {
                return [PSCustomObject]@{
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe'
                    Item = 'MonitorProcess'
                    Value = 'C:\temp\evil.exe'
                    Category = 'Image Hijacks'
                }
            }
            # Write-Verbose -Message "-$(Get-PSRawAutoRun -ImageHijacks | Select -First 1)-" -Verbose
            (Get-PSRawAutoRun -ImageHijacks | Select-Object -First 1).Value -eq 'C:\temp\evil.exe' | should be $true
            Assert-MockCalled -CommandName Get-RegValue -Times 1
        }

        # TODO: Do the same above test with TestRegistry drive
        # https://github.com/pester/Pester/wiki/TestRegistry

    }
    Context 'Inside Get-PSPrettyAutorun' {

        # Image Hijacks: target imagepath is null for htmlfile command #23
        # https://github.com/p0w3rsh3ll/AutoRuns/issues/23
        It 'issue 23 should be solved' {
            Mock -CommandName Get-PSRawAutoRun -MockWith {
                return [PSCustomObject]@{
                    Path     = 'HKLM:\SOFTWARE\Classes\htmlfile\shell\open\command'
                    Item     = 'htmlfile'
                    Category = 'Image Hijacks'
                    Value    = '"C:\Program Files\Internet Explorer\IEXPLORE.EXE" %1'
                }
            } -ParameterFilter { $ImageHijacks -eq [switch]::Present }
            $i = (Get-PSRawAutoRun -ImageHijacks | Get-PSPrettyAutorun).ImagePath
            # Write-Verbose -Message "-$($i)-" -Verbose
            $i -eq 'C:\Program Files\Internet Explorer\IEXPLORE.EXE' | should be $true
        }
    }
}
#endregion Image Hijacks

#region OfficeAddins

Describe 'Testing Get-PSPrettyAutorun for OfficeAddins' {

    # OfficeAddins don't have an imagepath when HKCU hive is in use #26
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/26
    # fix is in Get-PSRawAutoRun
    It 'issue 26 should be solved' {
        $Users = @{ UserName = 'test' ; SID = 'bidon' ; Hive = 'HKCU:' ; ProfilePath = 'bidon' }

        Mock -CommandName Test-Path -MockWith { return $false }
        Mock -CommandName Test-Path -MockWith { return $true  } -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office'
        }
        Mock -CommandName Test-Path -MockWith { return $true  } -ParameterFilter {
            $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Outlook\Addins'
        }

        Mock -CommandName Get-Item -MockWith {
            [PSCustomObject]@{fakekey='valuedontcare'} |
            Add-Member -Type ScriptMethod -Name 'GetSubKeyNames' -Value { return $null } -Force -PassThru
        }

        Mock -CommandName Get-Item -MockWith {
            [PSCustomObject]@{fakekey='valuedontcare'}|
            Add-Member -Type ScriptMethod -Name 'GetSubKeyNames' -Value { return 'Outlook' } -Force -PassThru
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office' }

        Mock -CommandName Get-Item -MockWith {
            [PSCustomObject]@{fakekey='valuedontcare'} |
            Add-Member -Type ScriptMethod -Name 'GetSubKeyNames' -Value { return 'UCAddin.LyncAddin.1' } -Force -PassThru
        } -ParameterFilter { $Path -eq 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office\Outlook\Addins' }

        # mock this def to {a6a2383f-ad50-4d52-8110-3508275e77f7}
        # $clsid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$($_)\CLSID" -Name '(default)' -ErrorAction Stop).'(default)';

        # Get-PSRawAutoRun -OfficeAddins -Verbose
        # Write-Verbose -Message "$((Get-PSRawAutoRun -OfficeAddins | Select-Object -First 1).Value)" -Verbose

        # it appears to be 'solved' but it isn't.
        # TODO: we need a proper valid test

    }
    <#
    Get-PSAutorun -OfficeAddins | ? {-not($_.Size)}
    Path          : HKCU:\SOFTWARE\\Microsoft\Office\Excel\Addins
    Item          : AdHocReportingExcelClientLib.AdHocReportingExcelClientAddIn.1
    Category      : Office Addins
    Value         : {509E7382-B849-49A4-8A3F-BEAB7E7D904C}
    ImagePath     : {509e7382-b849-49a4-8a3f-beab7e7d904c}

    Path          : HKCU:\SOFTWARE\\Microsoft\Office\Excel\Addins
    Item          : PowerPivotExcelClientAddIn.NativeEntry.1
    Category      : Office Addins
    Value         : {A2DBA3BE-42CC-4D0E-95FD-BCAA051BA798}
    ImagePath     : {a2dba3be-42cc-4d0e-95fd-bcaa051ba798}

    Path          : HKCU:\SOFTWARE\\Microsoft\Office\PowerPoint\Addins
    Item          : OneNote.PowerPointAddinTakeNotesService
    Category      : Office Addins
    Value         : {3A7CAEBB-C5C3-4EFF-ADDF-C32663BDF8DA}
    ImagePath     : {3a7caebb-c5c3-4eff-addf-c32663bdf8da}

    Path          : HKCU:\SOFTWARE\\Microsoft\Office\Word\Addins
    Item          : OneNote.WordAddinTakeNotesService
    Category      : Office Addins
    Value         : {C580A1B2-5915-4DC3-BE93-8A51F4CAB320}
    ImagePath     : {c580a1b2-5915-4dc3-be93-8a51f4cab320}
    #>
}
#endregion

#region KnownDLLs

Describe 'Testing Get-PSPrettyAutorun for KnownDLLs' {

    # No size, version for Known dlls where image path is set to C:\WINDOWS\Syswow64 #21
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/21
    It 'issue 21 should be solved' {
    }
    # fix was : always show system32 (untouched) +
    # if ([environment]::Is64BitOperatingSystem) {
    # # Duplicate if target file exists
    # Mock many things...?
    <#
    Get-PSAutorun -KnownDLLs | ? Value -match "wow64" | ? { -not($_.Size)}

    Path          : HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
    Item          : _Wow64
    Category      : Known Dlls
    Value         : Wow64.dll
    ImagePath     : C:\WINDOWS\Syswow64\Wow64.dll

    Path          : HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
    Item          : _Wow64cpu
    Category      : Known Dlls
    Value         : Wow64cpu.dll
    ImagePath     : C:\WINDOWS\Syswow64\Wow64cpu.dll

    Path          : HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
    Item          : _Wow64win
    Category      : Known Dlls
    Value         : Wow64win.dll
    ImagePath     : C:\WINDOWS\Syswow64\Wow64win.dll

    These above dll files only exist in System32
    #>
}
#endregion

#region Other

Describe 'Other' {
    # When ShowFileHash and VerifyDigitalSignature switches are used, don't drop items #34
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/34
    # Get-PSAutorun -ShowFileHash -VerifyDigitalSignature
    # If the ImagePath has a value and Test-Path doesn't equal true, the object in the pipeline was dropped by the Add-PSAutoRunAuthentiCodeSignature function
    It 'issue 34 should be solved' {
    }

    # Question related to service path parsing #2
    # https://github.com/p0w3rsh3ll/AutoRuns/issues/2
    <#
    $value = 'C:\Program Files\te.exe st\te -st.exe -param1 testing'

    For example what if the path was:
    'D:\test test\te.exe st\te -st.exe -param1 test\ing'

    What is the approach to parsing this logically?
    In the above example it seems your parser was specifically looking for Program Files folder but what if this is not the case.
    Would it still handle spaces, dashes,
    and periods in folder names and file names, as well as slashes in parameter values?
    I'm trying to understand your parsing logic for these situations where the file path is very tricky.
    I guess I'm hoping you could elaborate how the parsing is done to handle all these situations as I'm having trouble understanding it in the code.
    #>
    It 'issue 2 should be solved' {
    }
}
#endregion

} #endof inmodulescope
