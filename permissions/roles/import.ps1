###################################################################
# HelloID-Conn-Prov-Target-Salesforce-SCIM-ImportPermissions-Role
# PowerShell V2
###################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions
function Get-ScimOAuthToken {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ClientID,

        [Parameter(Mandatory)]
        [string]
        $ClientSecret,

        [Parameter(Mandatory)]
        [string]
        $baseUrl
    )

    try {
        Write-Information "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Uri     = "$($baseUrl)/services/oauth2/token"
            Method  = 'POST'
            Headers =  @{
                "content-type" = "application/x-www-form-urlencoded"
            }
            Body    = @{
                grant_type      = 'client_credentials'
                client_id       = $ClientID
                client_secret   = $ClientSecret
            }
        }

        Invoke-RestMethod @splatParams
        Write-Information 'Finished retrieving accessToken'
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}

function Resolve-SalesforceError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }
        if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
            $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            if ($null -ne $ErrorObject.Exception.Response) {
                $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                    $httpErrorObj.ErrorDetails = $streamReaderResponse
                }
            }
        }
        try {
            $errorDetailsObject = ($httpErrorObj.ErrorDetails | ConvertFrom-Json)
            $httpErrorObj.FriendlyMessage = $errorDetailsObject.detail
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}
#endregion

try {
    Write-Information 'Starting Salesforce-SCIM role entitlement import'

    Write-Information 'Getting instance url'
    $instanceUri = $($actionContext.Configuration.BaseUrl).Trim('/')

    Write-Information 'Retrieving accessToken'
    $splatTokenParams = @{
        ClientID          = $($actionContext.Configuration.ClientID)
        ClientSecret      = $($actionContext.Configuration.ClientSecret)
        BaseUrl           = $instanceUri
    }
    $accessToken = Get-ScimOAuthToken @splatTokenParams

    Write-Information 'Adding token to authorization headers'
    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add("Authorization", "Bearer $($accessToken.access_token)")

    $permissionAccounts = @{}
    $permissionDescriptions = @{}

    $take = 20
    $startIndex = 1
    do {
        $splatImportAccountParams = @{
            Uri     = "$instanceUri/services/scim/v2/Users?startIndex=$($startIndex)&count=$($take)"
            Method  = 'GET'
            Headers = $headers
        }

        $response = Invoke-RestMethod @splatImportAccountParams
        $result = $response.Resources

        if ($null -ne $result) {
            foreach ($importedAccount in $result) {
                if ($null -ne $importedAccount.roles) {
                    foreach ($role in @($importedAccount.roles)) {
                        if ($null -eq $role -or [string]::IsNullOrEmpty($role.value)) {
                            continue
                        }

                        $permissionId = [string]$role.value
                        if (-not $permissionAccounts.ContainsKey($permissionId)) {
                            $permissionAccounts[$permissionId] = [System.Collections.Generic.List[string]]::new()
                            $permissionDescriptions[$permissionId] = [string]$role.display
                        }
                        $permissionAccounts[$permissionId].Add([string]$importedAccount.id)
                    }
                }
                $startIndex++
            }
        }
    } while ($result.count -gt 0)

    $batchSize = 500
    foreach ($permissionId in $permissionAccounts.Keys) {
        $members = $permissionAccounts[$permissionId].ToArray()
        for ($i = 0; $i -lt $members.Count; $i += $batchSize) {
            $end = [Math]::Min($i + $batchSize - 1, $members.Count - 1)
            Write-Output @{
                PermissionReference = @{
                    Reference = $permissionId
                }
                Description       = "$($permissionDescriptions[$permissionId])"
                AccountReferences = @($members[$i..$end])
            }
        }
    }

    Write-Information 'Salesforce-SCIM role entitlement import completed'
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-SalesforceError -ErrorObject $ex
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
        Write-Error "Could not import Salesforce-SCIM role entitlements. Error: $($errorObj.FriendlyMessage)"
    }
    else {
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
        Write-Error "Could not import Salesforce-SCIM role entitlements. Error: $($ex.Exception.Message)"
    }
}
