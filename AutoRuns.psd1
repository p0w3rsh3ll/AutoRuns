@{

# Script module or binary module file associated with this manifest.
RootModule = 'AutoRuns.psm1'

# Version number of this module.
ModuleVersion = '13.95.1'

# ID used to uniquely identify this module
GUID = '5df29b51-5627-43f6-bcae-a07a62887a2f'

# Author of this module
Author = 'Emin Atac'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'AutoRuns is a module that will help do live incident response and enumerate autoruns artifacts that may be used by legitimate programs as well as malware to achieve persistence'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Minimum version of Microsoft .NET Framework required by this module
# DotNetFrameworkVersion = '4.0'

# Minimum version of the common language runtime (CLR) required by this module
# CLRVersion = '4.0'

# Functions to export from this module
FunctionsToExport = @('Get-PSAutorun')
# FunctionsToExport = '*'

PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('security','defense','PSEdition_Core','PSEdition_Desktop')

        # A URL to the license for this module.
        LicenseUri = 'https://opensource.org/licenses/BSD-3-Clause'

        # A URL to the main website for this project.
         ProjectUri = 'https://github.com/p0w3rsh3ll/AutoRuns'

    } # End of PSData hashtable

} # End of PrivateData hashtable


}

