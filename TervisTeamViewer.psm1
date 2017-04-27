function Invoke-TeamViewerApiFunction {
    param (
        $ApiResource,
        $HTTPMethod,
        $AdditionalHeaders,
        [hashtable]$ApiRequest
    )
    $TeamViewerPasswordStateEntry = Get-PasswordstateEntryDetails -PasswordID 4125
    $ApiToken = $TeamViewerPasswordStateEntry.Password
    $ApiRootUrl = $TeamViewerPasswordStateEntry.Url
    $ApiVersion = "v1"
    $ApiUriString = $ApiRootUrl + $ApiVersion + "/" + $ApiResource
    $BasicHeaders = @{"Authorization" = "Bearer $TeamViewerApiToken"}
    if ($AdditionalHeaders) {
        $Headers = $BasicHeaders + $AdditionalHeaders
    } else {
        $Headers = $BasicHeaders
    }
    $ApiRequestBody = $ApiRequest | ConvertTo-Json
    Invoke-RestMethod -Method $HTTPMethod -Uri $ApiUriString -Headers $Headers -Body $ApiRequestBody -ContentType application/json
    #Invoke-WebRequest -Uri ($TeamViewerApiRootUrl + $TeamViewerApiResourcePath) -Method $HTTPMethod -Headers $Headers
}

function New-TervisTeamviewerUserAccessToken {
    $ClientId = (Get-PasswordstateCredential -PasswordID 4127 -AsPlainText).UserName
    $ClientSecret = (Get-PasswordstateCredential -PasswordID 4127 -AsPlainText).Password
    $AuthorizationCode = Get-TeamViewerApiAuthorizationCode -ClientId $ClientId
    $TeamviewerApiAccessToken = Get-TeamViewerApiAccessToken -AuthorizationCode $AuthorizationCode
    $TeamviewerApiAccessToken
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
            password = (Get-PasswordstateCredential -PasswordID 4126 -AsPlainText).Password
            name = $ADUser.Name
            language = "en"
        }
        Invoke-TeamViewerApiFunction -ApiResource users -HTTPMethod Post -ApiRequest $ApiRequest
    }        
}

function Update-TervisTeamViewerUser {}