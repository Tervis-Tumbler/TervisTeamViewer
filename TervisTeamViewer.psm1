﻿#requires -module TeamViewerPowerShell,WebServicesPowerShellProxyBuilder

function Invoke-TeamViewerApiFunction {
    param (        
        $HTTPMethod,
        $ApiResource,
        $ApiId,
        $ApiVerb,
        $ApiUriParameters,
        [hashtable]$AdditionalHeaders,
        [hashtable]$ApiRequest
    )
    $UserAccessToken = Import-TeamViewerUserAccessTokenFromFile
    $ApiRootUrl = "https://webapi.teamviewer.com/api/v1/"
    $ApiUriString = $ApiRootUrl + $ApiResource
    if ($ApiId) {
        $ApiUriString = $ApiUriString + "/" + $ApiId
        if ($ApiVerb) {
            $ApiUriString = $ApiUriString + "/" + $ApiVerb
        }            
    }
    if ($ApiUriParameters) {
        $ApiUriString = $ApiUriString + "?$(ConvertTo-URLEncodedQueryStringParameterString -PipelineInput $ApiUriParameters)"
    }
    $Headers = @{Authorization = "$($UserAccessToken.TokenType) $($UserAccessToken.UserAccessToken)"}
    if ($AdditionalHeaders) {
        $Headers = $Headers + $AdditionalHeaders
    }
    $ApiRequestBody = $ApiRequest | ConvertTo-Json
    Invoke-RestMethod -Method $HTTPMethod -Uri $ApiUriString -Headers $Headers -Body $ApiRequestBody -ContentType application/json
}

function New-TervisTeamViewerUserAccessToken {
    $Password = Get-PasswordstatePassword -ID 4127
    $ClientId = $Password.UserName
    $ClientSecret = $Password.Password
    $AuthorizationCode = Get-TeamViewerApiAuthorizationCode -ClientId $ClientId
    $TeamViewerApiAccessToken = Get-TeamViewerUserAccessToken -AuthorizationCode $AuthorizationCode -ClientId $ClientId -ClientSecret $ClientSecret
    $TeamViewerApiAccessToken | Export-TeamViewerUserAccessTokenToFile
}

function Update-TervisTeamViewerUserAccessTokenFile {
    $Password = Get-PasswordstatePassword -ID 4127
    $ClientId = $Password.UserName
    $ClientSecret = $Password.Password
    Update-TeamViewerUserAccessTokenFile -ClientId $ClientId -ClientSecret $ClientSecret
}

function Invoke-TervisTeamViewerPingApi {
    $RequestArgs = @{
        ApiResource = "ping"
        HTTPMethod = "Get"
    }
    Invoke-TeamViewerApiFunction @RequestArgs
}

function Get-TervisTeamViewerUsers {
    $RequestArgs = @{
        ApiResource = "users"
        HTTPMethod = "Get"
    }
    (Invoke-TeamViewerApiFunction @RequestArgs).users
}

function Get-TervisTeamViewerUserId {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Name
    )
    begin {
        $Users = Get-TervisTeamViewerUsers
    }
    process {
        $Users | where name -Match $Name
    }    
}

function New-TervisTeamViewerUser {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$SamAccountName
    )
    process {
        $ADUser = Get-ADUser -Identity $SamAccountName -Properties EmailAddress
        $ApiRequest = @{
            email = $ADUser.EmailAddress
            password = (Get-PasswordstatePassword -ID 4126).Password
            name = $ADUser.Name
            language = "en"
        }
        Invoke-TeamViewerApiFunction -ApiResource users -HTTPMethod Post -ApiRequest $ApiRequest
    }        
}

function Get-TervisTeamViewerGroups {
    param (
        $GroupId
    )
    $RequestArgs = @{
        HTTPMethod = "Get"
        ApiResource = "groups"
        ApiId = $GroupId
    }
    $Return = Invoke-TeamViewerApiFunction @RequestArgs
    if ($GroupId) {
        $Return
    } else {
        $Return.Groups
    }
}

function Get-TervisTeamViewerGroupId {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$Name,
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet("True","False")]$Shared
    )
    process {
        if (-not ($Name -or $Shared)) {
            throw "Either Name or Shared parameter required."
        }
        $ApiUriParameters = @{}
        if ($Name) {
            $ApiUriParameters = $ApiUriParameters + @{name = $Name}
        }
        if ($Shared -ne $null) {
            $ApiUriParameters = $ApiUriParameters + @{shared = $Shared}
        }
        $RequestArgs = @{
            HTTPMethod = "Get"
            ApiResource = "groups"
            ApiId = $GroupId
            ApiUriParameters = $ApiUriParameters
        }
        (Invoke-TeamViewerApiFunction @RequestArgs).groups
    }
}

function New-TervisTeamViewerGroup {
    param (
        [Parameter(Mandatory)]$Name,
        $PolicyId
    )
    $RequestArgs = @{
        HTTPMethod = "Post"
        ApiResource = "groups"
        ApiRequest = @{
            name = $Name
            policy_id = $PolicyId
        }
    }
    Invoke-TeamViewerApiFunction @RequestArgs
}

function Get-TervisTeamViewerDevices {
    param (
        $DeviceId
    )
    $RequestArgs = @{
        HTTPMethod = "Get"
        ApiResource = "devices"
        ApiId = $DeviceId
    }
    (Invoke-TeamViewerApiFunction @RequestArgs).devices
}

function Get-TervisTeamViewerDeviceId {
    param (
        [Parameter(ParameterSetName="Alias")]$Alias,
        [Parameter(ParameterSetName="TeamViewerId")][int]$TeamViewerId
    )
    $RequestArgs = @{
        HTTPMethod = "Get"
        ApiResource = "devices"
        ApiId = $DeviceId
    }
    $Return = (Invoke-TeamViewerApiFunction @RequestArgs).devices
    if ($Alias) {
        $Return | where alias -Match $Alias
    } elseif ($TeamViewerId) {
        $Return | where remotecontrol_id -Match $TeamViewerId
    }
}

function Set-TervisTeamViewerDeviceProperties {
    param (
        [Parameter(Mandatory)]$DeviceId,
        $Alias,
        $Description,
        $Password,
        [Parameter(ParameterSetName="PolicyId")]$PolicyId,
        [Parameter(ParameterSetName="GroupId")]$GroupId
    )
    $RequestArgs = @{
        HTTPMethod = "Put"
        ApiResource = "devices"
        ApiId = $DeviceId
        ApiRequest = @{
            alias = $Alias
            description = $Description
            password = $Password
            policy_id = $PolicyId
            groupid = $GroupId
        }
    }
    Invoke-TeamViewerApiFunction @RequestArgs
}

function New-TervisTeamViewerDevice {
    param (
        [Parameter(Mandatory)]$RemoteControlId,
        [Parameter(Mandatory)]$GroupId,
        $Alias,        
        $Description,
        $Password
    )
    $RequestArgs = @{
        HTTPMethod = "Post"
        ApiResource = "devices"
        ApiRequest = @{
            remotecontrol_id = $RemoteControlId
            groupid = $GroupId
            alias = $Alias
            description = $Description
            password = $Password
        }
    }
    Invoke-TeamViewerApiFunction @RequestArgs
}

function Remove-TervisTeamViewerDevice {
    param (
        [Parameter(Mandatory)]$DeviceId
    )
    $RequestArgs = @{
        HTTPMethod = "Delete"
        ApiResource = "devices"
        ApiId = $DeviceId
    }
    Invoke-TeamViewerApiFunction @RequestArgs
}
