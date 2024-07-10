# PowerShell Module for vSphere+ and vSAN+ Subscriptions

![](vmware-vsan-dp-icon.png)

## Summary

PowerShell Module to interact with the [vSAN Data Protection capablity](https://core.vmware.com/resource/data-protection-vmware-vsan) that was introduced in [vSphere 8.0 Update 3](https://core.vmware.com/resource/whats-new-vsphere-8-update-3). For more information on how to use this module, please refer to this [blog post](https://williamlam.com/2024/07/exploring-the-new-vsan-data-protection-api-in-vsphere-8-0-update-3.html).

## Prerequisites
* [vSphere 8.0 Update 3](https://core.vmware.com/resource/whats-new-vsphere-8-update-3) (vCenter Server and ESXi hosts)
* [vSAN Express Storage Architecture (ESA)](https://core.vmware.com/vsan-esa) enabled Cluster
* [vSAN Data Protection Virtual Appliance](https://williamlam.com/2024/07/automating-deployment-of-vsan-data-protection-ova-with-powercli.html) deployed and configured
* [PowerCLI 13](https://developer.vmware.com/web/tool/13.0.0/vmware-powercli) or newer

## Installation

```console
Install-Module VMware.Community.VSANDP
```

## Functions

* Connect-VSANDataProtection
* Get-VSANDataProtectionVersion
* Get-VSANDataProtectionGroup
* New-VSANDataProtectionGroup
* Remove-VSANDataProtectionGroup
* New-VSANDataProtectionGroupSnapshot
* Remove-VSANDataProtectionGroupSnapshot