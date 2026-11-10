#################################################
# HelloID-Conn-Prov-Target-Salesforce-SCIM-Delete
# PowerShell V2
#################################################

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
    # Verify if [aRef] has a value
    if ([string]::IsNullOrEmpty($($actionContext.References.Account))) {
        throw 'The account reference could not be found'
    }

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
    $headers = [System.Collections.Generic.Dictionary[[String],[String]]]::new()
    $headers.Add("Authorization", "Bearer $($accessToken.access_token)")

    Write-Information 'Verifying if a Salesforce-SCIM account exists'
    try {
        $splatGetUserParams = @{
            Uri     = "$instanceUri/services/scim/v2/Users/$($actionContext.References.Account)"
            Headers = $headers
            Body    = $body
            Method  = 'GET'
        }
        $correlatedAccount = Invoke-RestMethod @splatGetUserParams
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 404) {
            $correlatedAccount = $null
        }
        else {
            throw $_
        }
    }

    if ($null -ne $correlatedAccount) {
        $action = 'DeleteAccount'
    }
    else {
        $action = 'NotFound'
    }

    # Process
    switch ($action) {
        'DeleteAccount' {
            if (-not($actionContext.DryRun -eq $true)) {
                Write-Information "Deleting Salesforce-SCIM account with accountReference: [$($actionContext.References.Account)]"
                [System.Collections.Generic.List[object]]$operations = @()
                $operations.Add(
                    [PSCustomObject]@{
                        op    = "Replace"
                        value = @{
                            active = $false
                        }
                    }
                )

                $body = [ordered]@{
                    schemas    = @(
                        "urn:ietf:params:scim:api:messages:2.0:PatchOp"
                    )
                    Operations = $operations
                } | ConvertTo-Json -Depth 10

                $splatDeleteParams = @{
                    Uri     = "$instanceUri/services/scim/v2/Users/$($actionContext.References.Account)"
                    Headers = $headers
                    Body    = $body
                    Method  = 'PATCH'
                }
                $null = Invoke-RestMethod @splatDeleteParams

            }
            else {
                Write-Information "[DryRun] Delete Salesforce-SCIM account with accountReference: [$($actionContext.References.Account)], will be executed during enforcement"
            }

            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Delete account: [$($actionContext.References.Account)] was successful. Action initiated by: [$($actionContext.Origin)]"
                    IsError = $false
                })
            break
        }

        'NotFound' {
            Write-Information "Salesforce-SCIM account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
            $outputContext.Success = $true
            $outputContext.AuditLogs.Add([PSCustomObject]@{
                    Message = "Salesforce-SCIM account: [$($actionContext.References.Account)] could not be found, indicating that it may have been deleted"
                    IsError = $false
                })
            break
        }
    }

}
catch {
    $outputContext.success = $false
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-SalesforceError -ErrorObject $ex
        $auditLogMessage = "Could not delete Salesforce-SCIM account. Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditLogMessage = "Could not delete Salesforce-SCIM account. Error: $($_.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    $outputContext.AuditLogs.Add([PSCustomObject]@{
            Message = $auditLogMessage
            IsError = $true
        })
}