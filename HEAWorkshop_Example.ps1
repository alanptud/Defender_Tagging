##CONFIG
$tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxx"
$clientId = Get-AutomationVariable -Name 'HEATaggingClientID'
$appsecret = Get-AutomationVariable -Name 'HEATaggingSecret'

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Web")
function update-MSSecApiToken{

write-host "Running Update-MSSecAPItoken function"
    if($global:MSSecApiToken.msApiToken -eq $Null -or $global:MSSecApiToken.msApiToken.resource -ne $resource -or ((Get-Date).AddSeconds(600)) -gt ([timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($global:MSSecApiToken.msApiToken.expires_on))))
    {
        write-host "specifying variables..."
        $resource="https://api.securitycenter.microsoft.com"
        $uri = "https://login.microsoftonline.com/$tenantId/oauth2/token"
        $postBody = [Ordered] @{
            resource = "$resource"
            client_id = "$clientId"
            client_secret = "$appsecret"
            grant_type = 'client_credentials'
} 
        #$postBody = "resource=$([System.Web.HttpUtility]::UrlEncode($resource))&client_id=$([System.Web.HttpUtility]::UrlEncode($clientId))&grant_type=password&username=$([System.Web.HttpUtility]::UrlEncode($creds.UserName))&password=$([System.Web.HttpUtility]::UrlEncode($($creds.GetNetworkCredential().Password)))"
        write-host "Creating an empty array...."
        $global:MSSecApiToken = @{}
        write-host "invoking rest method"
        $global:MSSecApiToken.msApiToken = ((Invoke-RestMethod -Uri $uri -Body $postBody -Method POST -ContentType 'application/x-www-form-urlencoded')) 
        $global:MSSecApiToken.headers = @{"Authorization" = "Bearer $($global:MSSecApiToken.msApiToken.access_token)"}
        
    }
    return $global:MSSecApiToken
}

function update-MSGraphApiToken{
write-host "Running update-MSGraphApiToken function"
    if($global:MSGraphApiToken.msApiToken -eq $Null -or $global:MSGraphApiToken.msApiToken.resource -ne $resource -or ((Get-Date).AddSeconds(600)) -gt ([timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($global:MSGraphApiToken.msApiToken.expires_on))))
    {
        write-host "Setting graph variables..."
        $resource="https://graph.microsoft.com"
        $uri = "https://login.microsoftonline.com/$tenantId/oauth2/token"  
        write-host "URI is set to $uri"
        $postBody = [Ordered] @{
            resource = "$resource"
            client_id = "$clientId"
            client_secret = "$appsecret"
            grant_type = 'client_credentials'
        }    
        #$postBody = "resource=$([System.Web.HttpUtility]::UrlEncode($resource))&client_id=$([System.Web.HttpUtility]::UrlEncode($clientId))&grant_type=password&username=$([System.Web.HttpUtility]::UrlEncode($creds.UserName))&password=$([System.Web.HttpUtility]::UrlEncode($($creds.GetNetworkCredential().Password)))"
        write-host "Creating empty array"
        $global:MSGraphApiToken = @{}
       # [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
       write-host "Invoking rest method...."
        $global:MSGraphApiToken.msApiToken = ((Invoke-RestMethod -Uri $uri -Body $postBody -Method POST -ContentType 'application/x-www-form-urlencoded')) 
        $global:MSGraphApiToken.headers = @{"Authorization" = "Bearer $($global:MSGraphApiToken.msApiToken.access_token)"}
    }
    write-host "returning $global:MSGraphApiToken"
    return $global:MSGraphApiToken
}

function New-RetryCommand {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [hashtable]$Arguments,

        [Parameter(Mandatory = $false)]
        [int]$MaxNumberOfRetries = 7,

        [Parameter(Mandatory = $false)]
        [int]$RetryDelayInSeconds = 4
    )

    $RetryCommand = $true
    $RetryCount = 0
    $RetryMultiplier = 1

    while ($RetryCommand) {
        try {
            & $Command @Arguments
            $RetryCommand = $false
        }
        catch {
            if ($RetryCount -le $MaxNumberOfRetries) {
                Start-Sleep -Seconds ($RetryDelayInSeconds * $RetryMultiplier)
                $RetryMultiplier += 1
                $RetryCount++
            }
            else {
                throw $_
            }
        }
    }
}

#try to set TLS to v1.2, Powershell defaults to v1.0
try{
    $res = [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12
    Write-Output "Set TLS protocol version to prefer v1.2"
}catch{
    Write-Output "Failed to set TLS protocol to prefer v1.2, job may fail"
    Write-Error $_ -ErrorAction SilentlyContinue
}


Write-Output "Retrieving MDATP devices through API..."
#retrieve all MDATP devices into a single array
$DeviceData = (New-RetryCommand -Command 'Invoke-RestMethod' -Arguments @{Uri = "https://api.securitycenter.microsoft.com/api/machines"; Method = "GET"; Headers = $(Update-MSSecApiToken).headers; ErrorAction = "Stop"})
$Devices = @()
write-output "List of Devices...$Devices"
$Devices += $DeviceData.value
while($DeviceData.'@odata.nextLink'){
    $DeviceData = (New-RetryCommand -Command 'Invoke-RestMethod' -Arguments @{Uri = $DeviceData.'@odata.nextLink'; Method = "GET"; Headers = $(Update-MSSecApiToken).headers; ErrorAction = "Stop"})
    $Devices += $DeviceData.value
}

Remove-Variable DeviceData
Write-Output "Retrieved $($Devices.count) MDATP devices"
$uniqueCategories = @()

##

##
write-output "setting counter to zero..."
$counter=0
foreach($Device in $Devices)
{

	#Tag Devices that are in the workshop group

    $counter++
    $rbacGroupName = $Device.rbacGroupName
    $nameofdevice = $Device.computerDnsName
    
    $deviceID= $Device.aadDeviceId
    
    #Change "workshopDevice" below to match the device group you wish to target, 
	if($rbacGroupName -eq "WorkshopDevices")
    {
		Write-Output "Name of Device being analyzed is $nameofdevice"
		write-Output "DeviceID is $deviceID"
        $company = "Unknown"
        $AzureADDevice = $Null
        $registeredUsers = $Null
        if($Device.aadDeviceId)
        {
            write-Output "Getting aadDeviceID"
            $AzureADDevice = (New-RetryCommand -Command 'Invoke-RestMethod' -Arguments @{Uri = "https://graph.microsoft.com/beta/devices?`$filter=deviceId eq '$($Device.aadDeviceId)'"; Method = "GET"; Headers = $(Update-MSGraphApiToken).headers; ErrorAction = "Stop"})
        }
        if($AzureADDevice)
        {
            write-Output "getting registered users of device..."
            $registeredUsers = (New-RetryCommand -Command 'Invoke-RestMethod' -Arguments @{Uri = "https://graph.microsoft.com/beta/devices/$($AzureADDevice.value.id)/registeredUsers"; Method = "GET"; Headers = $(Update-MSGraphApiToken).headers; ErrorAction = "Stop"})
        }
        if($registeredUsers)
        {
            write-output "Found registered user for device.  Obtaining CompanyName attribute of User"
            foreach($user in $registeredUsers.value)
            {
                if($user.companyName.Length -gt 0)
                {
                    $company = $user.companyName
                }
            }
        }

        #format the company attribute
        $sb = [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($company))
        $company =($sb -replace '[^a-zA-Z0-9 \-]', '')

        if($uniqueCategories -notcontains $company)
        {
            $uniqueCategories += $company
        }

        #check if device has no tags to begin with
        if($Device.machineTags.Count -eq 0)
        {
                if($company -ne "Unknown")
                {
                write-Output "No Tags Found on device, can apply tag here"
                write-Output "*** For information purposes: This would end up writing tag $company to $nameofdevice"
                $Body = "{`"Value`":`"$company`",`"Action`":`"Add`"}"
                $res = (New-RetryCommand -Command 'Invoke-RestMethod' -Arguments @{Body = $Body; ContentType = "application/json"; Uri = "https://api.securitycenter.windows.com/api/machines/$($Device.id)/tags"; Method = "POST"; Headers = $(Update-MSSecApiToken -creds $o365Creds).headers; ErrorAction = "Stop"})
                write-output "$($Device.id) ($($Device.computerDnsName)): added $company tag"
                $Taggedthisrun++
                }

        }
	}
    

}

Write-Output "All detected categories:"
Write-Output $uniqueCategories
Write-Output "Script has completed"
Write-Output "Devices Checked: "$counter
Write-Output "Devices Tagged this run: "$Taggedthisrun
