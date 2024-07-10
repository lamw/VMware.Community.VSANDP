Function Connect-VSANDataProtection {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          07/01/2024
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Connect to the vSAN Data Protection API endpoint
        .DESCRIPTION
            This cmdlet creates $global:vsanDPConnection object containing the vSAN Data Protection URL along with valid vCenter SSO SAML Token
        .PARAMETER Server
            IP Address/Hostname of the vSAN Data Protection Appliance
        .PARAMETER VCenter
            IP Address/Hostname of the vCenter Server where vSAN Data Protection has been deployed
        .PARAMETER SSOUsername
            vCenter SSO Username (default: administrator@vsphere.local)
        .PARAMETER SSOPassword
            Password for SSO Username (SecureString)
        .PARAMETER TokenExpiryInDays
            Expiry (Days) for requested vCenter SSO SAML Token (default: 1)
        .EXAMPLE
            $plainTextPassword = "VMware1!"
            $secureString = ConvertTo-SecureString -String $plainTextPassword -AsPlainText

            Connect-VSANDataProtection -Server "snap.primp-industries.local" -VCenter "vcsa.primp-industries.local" -SSOPassword $secureString
    #>
    Param (
        [Parameter(Mandatory=$true)][String]$Server,
        [Parameter(Mandatory=$true)][String]$VCenter,
        [Parameter(Mandatory=$false)][String]$SSOUsername="administrator@vsphere.local",
        [Parameter(Mandatory=$true)][SecureString]$SSOPassword,
        [Parameter(Mandatory=$false)][Int]$TokenExpiryInDays=1
    )

    $DATE_CURRENT=$(Get-Date -format s)
    $DATE_EXPIRY=$(Get-Date (Get-Date).AddDays($TokenExpiryInDays) -format s)
    $a,$SSDOMAIN = $SSOUsername.split("@")
    $STS_URL="https://${VCENTER}/sts/STSService/${SSDOMAIN}"
    $SSOPasswordPlainText = ConvertFrom-SecureString -SecureString $SSOPassword -AsPlainText

    $stsRequestBody = @"
    <SOAP-ENV:Envelope
    xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
      <SOAP-ENV:Header xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
        <ns5:Security
           xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
           xmlns:ns2="http://www.w3.org/2005/08/addressing"
           xmlns:ns3= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
           xmlns:ns4="http://www.rsa.com/names/2009/12/std-ext/WS-Trust1.4/advice"
           xmlns:ns5="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
           <ns3:Timestamp>
            <ns3:Created>${DATE_CURRENT}.000Z</ns3:Created>
            <ns3:Expires>${DATE_EXPIRY}.000Z</ns3:Expires>
          </ns3:Timestamp>
          <ns5:UsernameToken>
            <ns5:Username>$SSOUsername</ns5:Username>
            <ns5:Password>$SSOPasswordPlainText</ns5:Password>
          </ns5:UsernameToken>
        </ns5:Security>
      </SOAP-ENV:Header>
      <SOAP-ENV:Body xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
        <RequestSecurityToken
          xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
          xmlns:ns2="http://www.w3.org/2005/08/addressing"
          xmlns:ns3=
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
          xmlns:ns4="http://www.rsa.com/names/2009/12/std-ext/WS-Trust1.4/advice"
          xmlns:ns5=
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
          <TokenType>urn:oasis:names:tc:SAML:2.0:assertion</TokenType>
          <RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType>
          <Renewing Allow="true" OK="false" />
          <Delegatable>true</Delegatable>
          <KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</KeyType>
       <SignatureAlgorithm>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256</SignatureAlgorithm>
        </RequestSecurityToken>
      </SOAP-ENV:Body>
    </SOAP-ENV:Envelope>
"@

    $stsHeaders = @{
        "Content-Type" = 'text/xml; charset="UTF-8"'
        "SOAPAction" = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
    }

    $request = Invoke-WebRequest -Method POST -Uri $STS_URL -Headers $stsHeaders -Body $stsRequestBody -SkipCertificateCheck -SkipHeaderValidation
    if($request.StatusCode -eq 200) {
        $samlPattern = '<saml2:Assertion.*>(.*?)</saml2:Assertion>'

        $match = [regex]::Match($request.content, $samlPattern)

        if($match) {
            # https://stackoverflow.com/a/76696489
            $outstream = [System.IO.MemoryStream]::new()
            $gzip = [System.IO.Compression.GZipStream]::new(
                $outstream,
                [System.IO.Compression.CompressionLevel]::Optimal)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($match.Value)
            $gzip.Write($bytes, 0, $bytes.Length)

            $gzip.Dispose()
            $outstream.Dispose()

            $samlToken = [System.Convert]::ToBase64String($outstream.ToArray())
        } else {
            Write-Error "SAML Token request did not return valid results"
        }
    } else {
        Write-Error "Unable to request SAML Token from vCenter SSO"
    }

    $headers = @{
        "Authorization"="SIGN token=$SamlToken"
        "Content-Type"="application/json"
        "Accept"="application/json"
    }

    $global:vsanDPConnection = new-object PSObject -Property @{
        'Server' = "https://${Server}/api/snapservice"
        'headers' = $headers
    }
    $global:vsanDPConnection | Out-Null
}

Function Get-FriendlyVMName {
    Param (
        [Parameter(Mandatory=$True)][String[]]$Morefs
    )

    $newVMs = @()
    foreach ($moref in $Morefs) {
        $vmRef = New-Object VMware.Vim.ManagedObjectReference
        $vmRef.Type = "VirtualMachine"
        $vmRef.Value = $moref
        $VM = Get-View $vmRef -Property Name
        $newVMs+=$VM.Name
    }
    return $newVMs
}

Function Get-VSANDataProtectionVersion {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          07/01/2024
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns the version of the vSAN Data Protection
        .DESCRIPTION
            This cmdlet returns the version of vSAN Data Protection
        .PARAMETER Troubleshoot
            Displays additional output showing both HTTP method and URL for vSAN Data Protection API request
        .EXAMPLE
            Get-VSANDataProtectionVersion
    #>
    Param (
        [Switch]$Troubleshoot
    )

    If (-Not $global:vsanDPConnection) { Write-error "No vSAN Data Protection Connection found, please use Connect-VSANDataProtection" } Else {

        $method = "GET"
        $versionURL = $global:vsanDPConnection.Server + "/info/about"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$versionURL`n"
        }

        try {
            $requests = Invoke-WebRequest -Uri $versionURL -Method $method -Headers $global:vsanDPConnection.headers -SkipCertificateCheck
        } catch {
            Write-Error "Error in retrieving vSAN DP Version"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if($requests.StatusCode -eq 200) {
            $requests.Content | ConvertFrom-Json
        }
    }
}

Function Get-VSANDataProtectionGroup {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          07/01/2024
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns all vSAN Data Protection Groups
        .DESCRIPTION
            This cmdlet returns all vSAN Data Protection Groups
        .PARAMETER Name
            The name of a specific vSAN Data Protection Group to filter on
        .PARAMETER ClusterName
            The name of a vSAN Cluster to list all vSAN Data Protection Groups
        .PARAMETER Troubleshoot
            Displays additional output showing both HTTP method and URL for vSAN Data Protection API request
        .EXAMPLE
            Get-VSANDataProtectionGroup -ClusterName "vSAN-ESA-Cluster"
        .EXAMPLE
            Get-VSANDataProtectionGroup -ClusterName "vSAN-ESA-Cluster" -Name "vSAN-DP-PG-1"
    #>
    Param (
        [Parameter(Mandatory=$False)]$Name,
        [Parameter(Mandatory=$True)]$ClusterName,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vsanDPConnection -or -Not $global:DefaultVIServer) { Write-error "No vSAN Data Protection or VI Server Connection found, please use Connect-VSANDataProtection and/or Connect-VIServer" } Else {

        $ClusterMoRef = (Get-Cluster -Name $ClusterName).ExtensionData.MoRef.Value
        if($ClusterMoRef -eq $null) {
            Write-Error "Unable to find $ClusterName"
            break
        }

        $method = "GET"
        $pgURL = $global:vsanDPConnection.Server + "/clusters/${ClusterMoRef}/protection-groups"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$pgURL`n"
        }

        try {
            $requests = Invoke-WebRequest -Uri $pgURL -Method $method -Headers $global:vsanDPConnection.headers -SkipCertificateCheck
        } catch {
            Write-Error "Error in retrieving vSAN DP Protection Groups for ${ClusterName}"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if($requests.StatusCode -eq 200) {
            $originalResults = ($requests.Content | ConvertFrom-Json).items

            $newResults = @()
            for($i=0; $i -lt $originalResults.Count; $i++){

                # VM output is not user friendly, this converts MoRef ID to human readable labels
                $newVMs = Get-FriendlyVMName -Morefs $originalResults[$i].info.vms

                $tmpResult = $originalResults[$i]
                $tmpResult.info.target_entities.vms = $newVMs

                $tmp = [PSCustomObject][ordered]@{
                    Id = $originalResults[$i].pg
                    Name = $originalResults[$i].info.name
                    Locked = $originalResults[$i].info.locked
                    Status = $originalResults[$i].info.status
                    Snapshots = $originalResults[$i].info.snapshots
                    SnapshotPolicies = $originalResults[$i].info.snapshot_policies
                    Entities = $tmpResult.info.target_entities
                    VMs = $newVMs
                }

                $newResults+=$tmp
            }

            if ($PSBoundParameters.ContainsKey("Name")){
                $newResults | where {$_.Name -eq $Name}
            } else {
                $newResults
            }
        }
    }
}

Function New-VSANDataProtectionGroup {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          07/01/2024
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Creates a new vSAN Data Protection Groups
        .DESCRIPTION
            This cmdlet creates a vSAN Data Protection Groups
        .PARAMETER ClusterName
            The name of a vSAN Cluster to list all vSAN Data Protection Groups
        .PARAMETER Name
            The name of the vSAN Data Protection Group
        .PARAMETER VMNames
            List of VMs to place in vSAN Data Protection Group
        .PARAMETER VMPatterns
            Regular expression pattern for VMs to place in vSAN Data Protection Group
        .PARAMETER PolicyName
            The name of the protection policy (e.g. Weekly) (Only applicable for a single protection policy)
        .PARAMETER PolicyScheduleInterval
            The interval in which the protection policy should run (Only applicable for a single protection policy)
        .PARAMETER PolicyScheduleUnit
            The unit for the protection policy schedule (e.g. HOUR, DAY, WEEK or MONTH)
        .PARAMETER PolicyRetentionInterval
            The interval in which the protection policy should retain snapshots (Only applicable for a single protection policy)
        .PARAMETER PolicyRetentionUnit
            The unit for the protection policy retention (e.g. HOUR, DAY, WEEK or MONTH)
        .PARAMETER PolicySpec
            List of protection policies (see EXAMPLE for more details)
        .PARAMETER ImmutabilityMode
            Enable or Disable vSAN Data Protection Immutability Mode (default: false)
        .PARAMETER Troubleshoot
            Displays additional output showing both HTTP method and URL for vSAN Data Protection API request
        .EXAMPLE
            Create vSAN Data Protection Group using specific VMs and a single protection policy

            New-VSANDataProtectionGroup -ClusterName "vSAN-ESA-Cluster" -Name "VSAN-DP-1" -VMNames @("photon-01") -PolicyName "Daily" -PolicyScheduleInterval 30 -PolicyScheduleUnit MINUTE -PolicyRetentionInterval 1 -PolicyRetentionUnit HOUR
        .EXAMPLE
            Create vSAN Data Protection Group using a VM pattern and a single protection policy

            New-VSANDataProtectionGroup -ClusterName "vSAN-ESA-Cluster" -Name "VSAN-DP-2" -VMPatterns @("photon-02*","photon-03*") -PolicyName "Weekly" -PolicyScheduleInterval 1 -PolicyScheduleUnit WEEK -PolicyRetentionInterval 1 -PolicyRetentionUnit MONTH
        .EXAMPLE
            Create vSAN Data Protection Group using a VM pattern and multiple protection policies

            $policySpec = @(
    @{
        "Name" = "Daily"
        "Schedule" = @{
            "Interval" = 30
            "Unit" = "MINUTE"
        }
        "Retention" = @{
            "Interval" = 1
            "Unit" = "DAY"
        }
    }
    @{
        "Name" = "Weekly"
        "Schedule" = @{
            "Interval" = 1
            "Unit" = "WEEK"
        }
        "Retention" = @{
            "Interval" = 1
            "Unit" = "MONTH"
        }
    }
    @{
        "Name" = "Monthly"
        "Schedule" = @{
            "Interval" = 1
            "Unit" = "MONTH"
        }
        "Retention" = @{
            "Interval" = 6
            "Unit" = "MONTH"
        }
    }
)

        New-VSANDataProtectionGroup -ClusterName "vSAN-ESA-Cluster" -Name "VSAN-DP-3" -VMPatterns @("photon-04*") -PolicySpec $policySpec
    #>
    Param (
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$True)][String]$Name,
        [Parameter(Mandatory=$False)][String[]]$VMNames,
        [Parameter(Mandatory=$False)][String[]]$VMPatterns,
        [Parameter(Mandatory=$False)][String]$PolicyName,
        [Parameter(Mandatory=$False)][Int]$PolicyScheduleInterval,
        [Parameter(Mandatory=$False)][ValidateSet("MINUTE","HOUR","DAY","WEEK","MONTH")][String]$PolicyScheduleUnit,
        [Parameter(Mandatory=$False)][Int]$PolicyRetentionInterval,
        [Parameter(Mandatory=$False)][ValidateSet("MINUTE","HOUR","DAY","WEEK","MONTH")][String]$PolicyRetentionUnit,
        [Parameter(Mandatory=$False)][Object[]]$PolicySpec,
        [Parameter(Mandatory=$False)][Boolean]$ImmutabilityMode=$false,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vsanDPConnection -or -Not $global:DefaultVIServer) { Write-error "No vSAN Data Protection or VI Server Connection found, please use Connect-VSANDataProtection and/or Connect-VIServer" } Else {

        $ClusterMoRef = (Get-Cluster -Name $ClusterName).ExtensionData.MoRef.Value
        if($ClusterMoRef -eq $null) {
            Write-Error "Unable to find $ClusterName"
            break
        }

        $method = "POST"
        $pgURL = $global:vsanDPConnection.Server + "/clusters/${ClusterMoRef}/protection-groups?vmw-task=true"

        $vmMoRefs = @()
        foreach ($vm in $VMNames) {
            $vmMoRefs+=(Get-VM $vm).ExtensionData.MoRef.Value
        }

        if($PolicySpec) {
            $snapshotPolicies = @()

            foreach ($policy in $PolicySpec) {
                $tmp = @{
                    "name" = $policy.Name
                    "schedule" = @{
                        "unit" = $policy.Schedule.Unit
                        "interval" = $policy.Schedule.Interval
                    }
                    "retention" = @{
                        "unit" = $policy.Retention.Unit
                        "duration" = $policy.Retention.Interval
                    }
                }
                $snapshotPolicies+=$tmp
            }

            $payload = @{
                "locked" = $ImmutabilityMode
                "name" = $Name
                "snapshot_policies" = $snapshotPolicies

            }
        } else {
            $payload = @{
                "locked" = $ImmutabilityMode
                "name" = $Name
                "snapshot_policies" = @(
                    @{
                        "name" = $PolicyName
                        "schedule" = @{
                            "unit" = $PolicyScheduleUnit
                            "interval" = $PolicyScheduleInterval
                        }
                        "retention" = @{
                            "duration" = $PolicyRetentionInterval
                            "unit" = $PolicyRetentionUnit
                        }
                    }
                )
            }
        }

        if($VMNames) {
            $payload.add("target_entities",@{"vms" = $vmMoRefs})
        } else {
            $payload.add("target_entities",@{"vm_name_patterns" = $VMPatterns})
        }

        $body = $payload | ConvertTo-Json -depth 4

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$pgURL`n"
            Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
        }

        try {
            $requests = Invoke-WebRequest -Uri $pgURL -Method $method -Headers $global:vsanDPConnection.headers -SkipCertificateCheck -Body $body
        } catch {
            Write-Error "Error in creating vSAN DP Group for ${ClusterName}"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if($requests.StatusCode -eq 202) {
            Write-Host -ForegroundColor Cyan "Creating vSAN DP Group ${Name}"
        }
    }
}

Function Remove-VSANDataProtectionGroup {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          07/01/2024
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Removes a vSAN Data Protection Group
        .DESCRIPTION
            This cmdlet removes a vSAN Data Protection Group
        .PARAMETER Name
            The name of a specific vSAN Data Protection Group to remove
        .PARAMETER ClusterName
            The name of a vSAN Cluster to list all vSAN Data Protection Groups
        .PARAMETER DeleteAllSnapshots
            Delete all vSAN Data Protection Snapshots (default: false)
        .PARAMETER Troubleshoot
            Displays additional output showing both HTTP method and URL for vSAN Data Protection API request
        .EXAMPLE
            Get-VSANDataProtectionGroup -ClusterName "vSAN-ESA-Cluster"
        .EXAMPLE
            Get-VSANDataProtectionGroup -ClusterName "vSAN-ESA-Cluster" -Name "vSAN-DP-PG-1"
    #>
    Param (
        [Parameter(Mandatory=$True)]$Name,
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$False)][Boolean]$DeleteAllSnapshots=$false,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vsanDPConnection -or -Not $global:DefaultVIServer) { Write-error "No vSAN Data Protection or VI Server Connection found, please use Connect-VSANDataProtection and/or Connect-VIServer" } Else {

        $ClusterMoRef = (Get-Cluster -Name $ClusterName).ExtensionData.MoRef.Value
        if($ClusterMoRef -eq $null) {
            Write-Error "Unable to find $ClusterName"
            break
        }

        $vsanDP = (Get-VSANDataProtectionGroup -ClusterName $ClusterName -Name $Name).Id

        $method = "DELETE"
        if($DeleteAllSnapshots) {
            $pgURL = $global:vsanDPConnection.Server + "/clusters/${ClusterMoRef}/protection-groups/${vsanDP}?force=true&vmw-task=true"
        } else {
            $pgURL = $global:vsanDPConnection.Server + "/clusters/${ClusterMoRef}/protection-groups/${vsanDP}?vmw-task=true"
        }

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$pgURL`n"
        }

        try {
            $requests = Invoke-WebRequest -Uri $pgURL -Method $method -Headers $global:vsanDPConnection.headers -SkipCertificateCheck
        } catch {
            Write-Error "Error in deleting vSAN DP Group ${Name}"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if($requests.StatusCode -eq 202) {
            Write-Host -ForegroundColor Cyan  "Removing vSAN DP Group ${Name}"
        }
    }
}

Function Get-VSANDataProtectionGroupSnapshot {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          07/10/2024
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns all snapshots for a vSAN Data Protection Group
        .DESCRIPTION
            This cmdlet returns all snapshots for a vSAN Data Protection Groups
        .PARAMETER Name
            The name of a specific snapshot for a given vSAN Data Protection Group to filter on
        .PARAMETER ClusterName
            The name of a vSAN Cluster to list all vSAN Data Protection Groups
        .PARAMETER ProtectionGroupName
            The name of the vSAN Data Protection Group
        .PARAMETER Troubleshoot
            Displays additional output showing both HTTP method and URL for vSAN Data Protection API request
        .EXAMPLE
            Get-VSANDataProtectionGroupSnapshot -ClusterName "vSAN-ESA-Cluster" -ProtectionGroupName "VSAN-DP-1"
        .EXAMPLE
            Get-VSANDataProtectionGroupSnapshot -ClusterName "vSAN-ESA-Cluster" -ProtectionGroupName "VSAN-DP-1" -Name "My-Snapshot"
    #>
    Param (
        [Parameter(Mandatory=$False)]$Name,
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$True)]$ProtectionGroupName,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vsanDPConnection -or -Not $global:DefaultVIServer) { Write-error "No vSAN Data Protection or VI Server Connection found, please use Connect-VSANDataProtection and/or Connect-VIServer" } Else {

        $ClusterMoRef = (Get-Cluster -Name $ClusterName).ExtensionData.MoRef.Value
        if($ClusterMoRef -eq $null) {
            Write-Error "Unable to find $ClusterName"
            break
        }

        $pg = Get-VSANDataProtectionGroup -ClusterName $ClusterName -Name $ProtectionGroupName

        $method = "GET"
        $snapshotURL = $global:vsanDPConnection.Server + "/clusters/${ClusterMoRef}/protection-groups/$(${pg}.Id)/snapshots"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$snapshotURL`n"
        }

        try {
            $requests = Invoke-WebRequest -Uri $snapshotURL -Method $method -Headers $global:vsanDPConnection.headers -SkipCertificateCheck
        } catch {
            Write-Error "Error in retrieving snapshots for vSAN DP Protection Group ${ProtectionGroupName}"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if($requests.StatusCode -eq 200) {
            $snapshots = ($requests.Content | ConvertFrom-Json).snapshots

            $results = @()
            foreach ($snapshot in $snapshots) {
                $tmp = [pscustomobject][ordered] @{
                    Id = $snapshot.snapshot
                    Name = $snapshot.info.name
                    Type = $snapshot.info.snapshot_type
                    VMs = $snapshot.info.vm_snapshots.count
                    Expiration = $snapshot.info.expires_at
                    StartTime = $snapshot.info.start_time
                    EndTime = $snapshot.info.end_time
                    Snapshots = $snapshot.info.vm_snapshots
                }
                $results+=$tmp
            }

            if ($PSBoundParameters.ContainsKey("Name")){
                $results | where {$_.Name -eq $Name}
            } else {
                $results
            }
        }
    }
}

Function New-VSANDataProtectionGroupSnapshot {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          07/10/2024
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Returns all snapshots for a vSAN Data Protection Group
        .DESCRIPTION
            This cmdlet creates a snapshots for a vSAN Data Protection Groups
        .PARAMETER Name
            The name of the snapshot
        .PARAMETER ClusterName
            The name of a vSAN Cluster to list all vSAN Data Protection Groups
        .PARAMETER ProtectionGroupName
            The name of the vSAN Data Protection Group
        .PARAMETER Troubleshoot
            Displays additional output showing both HTTP method and URL for vSAN Data Protection API request
        .EXAMPLE
            New-VSANDataProtectionGroupSnapshot -ClusterName "vSAN-ESA-Cluster" -ProtectionGroupName "VSAN-DP-1" -Name "My-Snapshot" -RetentionInterval 10 -RetentionUnit DAY
    #>
    Param (
        [Parameter(Mandatory=$True)]$Name,
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$True)]$ProtectionGroupName,
        [Parameter(Mandatory=$True)][Int]$RetentionInterval,
        [Parameter(Mandatory=$True)][ValidateSet("MINUTE","HOUR","DAY","WEEK","MONTH")][String]$RetentionUnit,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vsanDPConnection -or -Not $global:DefaultVIServer) { Write-error "No vSAN Data Protection or VI Server Connection found, please use Connect-VSANDataProtection and/or Connect-VIServer" } Else {

        $ClusterMoRef = (Get-Cluster -Name $ClusterName).ExtensionData.MoRef.Value
        if($ClusterMoRef -eq $null) {
            Write-Error "Unable to find $ClusterName"
            break
        }

        $pg = Get-VSANDataProtectionGroup -ClusterName $ClusterName -Name $ProtectionGroupName

        $method = "POST"
        $snapshotURL = $global:vsanDPConnection.Server + "/clusters/${ClusterMoRef}/protection-groups/$(${pg}.Id)/snapshots?vmw-task=true"

        $payload = @{
            "name" = $Name
            "retention" = @{
                "duration" = $RetentionInterval
                "unit" = $RetentionUnit
            }
        }

        $body = $payload | ConvertTo-Json -depth 2

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$snapshotURL`n"
            Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
        }

        try {
            $requests = Invoke-WebRequest -Uri $snapshotURL -Method $method -Body $body -Headers $global:vsanDPConnection.headers -SkipCertificateCheck
        } catch {
            Write-Error "Error in creating snapshot for vSAN DP Protection Group ${ProtectionGroupName}"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if($requests.StatusCode -eq 202) {
            Write-Host -ForegroundColor Cyan "Creating snapshot ${Name} for vSAN DP Group ${ProtectionGroupName}"
        }
    }
}

Function Remove-VSANDataProtectionGroupSnapshot {
    <#
        .NOTES
        ===========================================================================
        Created by:    William Lam
        Date:          07/10/2024
        Organization:  Broadcom
        Blog:          http://www.williamlam.com
        Twitter:       @lamw
        ===========================================================================
        .SYNOPSIS
            Removes specific snapshot for a vSAN Data Protection Group
        .DESCRIPTION
            This cmdlet removes specific snapshot for a vSAN Data Protection Groups
        .PARAMETER Name
            The name of the snapshot to remove
        .PARAMETER ClusterName
            The name of a vSAN Cluster to list all vSAN Data Protection Groups
        .PARAMETER ProtectionGroupName
            The name of the vSAN Data Protection Group
        .PARAMETER Troubleshoot
            Displays additional output showing both HTTP method and URL for vSAN Data Protection API request
        .EXAMPLE
            Remove-VSANDataProtectionGroupSnapshot -ClusterName "vSAN-ESA-Cluster" -ProtectionGroupName "VSAN-DP-1" -Name "My-Snapshot"
    #>
    Param (
        [Parameter(Mandatory=$True)]$Name,
        [Parameter(Mandatory=$True)]$ClusterName,
        [Parameter(Mandatory=$True)]$ProtectionGroupName,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vsanDPConnection -or -Not $global:DefaultVIServer) { Write-error "No vSAN Data Protection or VI Server Connection found, please use Connect-VSANDataProtection and/or Connect-VIServer" } Else {

        $ClusterMoRef = (Get-Cluster -Name $ClusterName).ExtensionData.MoRef.Value
        if($ClusterMoRef -eq $null) {
            Write-Error "Unable to find $ClusterName"
            break
        }

        $snapshot = Get-VSANDataProtectionGroupSnapshot -ClusterName $ClusterName -ProtectionGroupName $ProtectionGroupName -Name $Name

        $method = "DELETE"
        $snapshotURL = $global:vsanDPConnection.Server + "/clusters/${ClusterMoRef}/protection-groups/$(${pg}.Id)/snapshots/$(${snapshot}.id)"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$snapshotURL`n"
        }

        try {
            $requests = Invoke-WebRequest -Uri $snapshotURL -Method $method -Headers $global:vsanDPConnection.headers -SkipCertificateCheck
        } catch {
            Write-Error "Error in deleting snapshot for vSAN DP Protection Group ${ProtectionGroupName}"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }

        if($requests.StatusCode -eq 204) {
            Write-Host -ForegroundColor Cyan "Deleting snapshot ${Name} for vSAN DP Group ${ProtectionGroupName}"
        }
    }
}