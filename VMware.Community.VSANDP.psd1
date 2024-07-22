#
# Module manifest for module 'VMware.Community.VSANDP'
#
# Generated by: william.lam@broadcom.com
#
# Generated on: 07/01/24
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule        = 'VMware.Community.VSANDP.psm1'
    
    # Version number of this module.
    ModuleVersion     = '1.0.2'
    
    # Supported PSEditions
    # CompatiblePSEditions = @()
    
    # ID used to uniquely identify this module
    GUID              = 'af4d2d2a-7ccb-44bb-af46-8466b334c29a'
    
    # Author of this module
    Author            = 'William Lam'
    
    # Company or vendor of this module
    CompanyName       = 'Broadcom'
    
    # Copyright statement for this module
    Copyright         = '(c) 2024 Broadcom. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description       = 'PowerShell Module for Managing VMware vSAN Data Protection'
    
    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '6.0'
    
    RequiredModules   = @()
    
    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = 'Connect-VSANDataProtection', 'Get-VSANDataProtectionVersion', 'Get-VSANDataProtectionGroup', 'New-VSANDataProtectionGroup', 'Remove-VSANDataProtectionGroup', 'Get-VSANDataProtectionGroupSnapshot', 'New-VSANDataProtectionGroupSnapshot', 'Remove-VSANDataProtectionGroupSnapshot'
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()
    
    # Variables to export from this module
    VariablesToExport = '*'
    
    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()
    
    # DSC resources to export from this module
    # DscResourcesToExport = @()
    
    # List of all modules packaged with this module
    ModuleList        = @()
    
    # List of all files packaged with this module
    # FileList = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{
    
        PSData = @{
    
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags       = @('VMware', 'VCF', 'vSAN')
    
            # A URL to the license for this module.
            # LicenseUri = ''
    
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/lamw/VMware.Community.VSANDP'
    
            # A URL to an icon representing this module.
            IconUri    = 'https://github.com/lamw/VMware.Community.VSANDP/raw/master/vmware-vsan-dp-icon.png'
    
            # ReleaseNotes of this module
            # ReleaseNotes = ''
    
        } # End of PSData hashtable
    
    } # End of PrivateData hashtable
    
    # HelpInfo URI of this module
    # HelpInfoURI = ''
    
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
    
}