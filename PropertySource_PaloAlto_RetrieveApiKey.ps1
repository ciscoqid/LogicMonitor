Add-Type @"
      using System;
      using System.Net;
      using System.Net.Security;
      using System.Security.Cryptography.X509Certificates;
      public class ServerCertificateValidationCallback
      {
              public static void Ignore()
              {
                      ServicePointManager.ServerCertificateValidationCallback +=
                              delegate
                              (
                                      Object obj,
                                      X509Certificate certificate,
                                      X509Chain chain,
                                      SslPolicyErrors errors
                              )
                              {
                                      return true;
                              };
              }
      }
"@
[ServerCertificateValidationCallback]::Ignore()
# this was added to assist with SSL Trust message
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
# this was added to assist with TLS issues (returning no reponse error)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

##DEVICE ACCESS INFO
$ip = '##system.hostname##';
$userid = '##ssh.user##';
$password = '##ssh.pass##';
##API USE INFO
$accessId = '##api.user##';
$accessKey = '##api.pass##';
$company = '##api.account##';
$devId = '##system.deviceId##';

function EncodePassword() {
    Param(
        [Parameter(position = 0, Mandatory = $true)]
        [string]$password
    )
    #iterate through the $password in order to find possible reserved characters
    #WIKI -> https://tools.ietf.org/html/rfc3986#section-2.2
    if ($password -match '\@'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\@', '%40'
    }
    if ($password -match '\]'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\]', '%5D'
    }
    if ($password -match '\['){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\[', '%5B'
    }
    if ($password -match '\#'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\#', '%23'
    }
    if ($password -match '\?'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\?', '%3F'
    }
    if ($password -match '\/'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\/', '%2F'
    }
    if ($password -match '\:'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\:', '%3A'
    }
    if ($password -match '\!'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\!', '%21'
    }
    if ($password -match '\$'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\$', '%24'
    }
    if ($password -match '\&'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\&', '%26'
    }
    if ($password -match "\'"){
        #replace the " ' " for its actual encoding representation
        $password = $password -replace "\'", '%27'
    }
    if ($password -match '\('){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\(', '%28'
    }
    if ($password -match '\)'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\)', '%29'
    }
    if ($password -match '\*'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\*', '%2A'
    }
    if ($password -match '\+'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\+', '%2B'
    }
    if ($password -match '\,'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\,', '%2C'
    }
    if ($password -match '\;'){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\;', '%3B'
    }
    if ($password -match '\='){
        #replace the '@' for its actual encoding representation
        $password = $password -replace '\=', '%3D'
    }

Return $password
}

##Defining MakeRequest function
function Send-Request() {
    Param(
        [Parameter(position = 0, Mandatory = $true)]
        [string]$path,
        [Parameter(position = 1, Mandatory = $false)]
        [string]$httpVerb = 'GET',
        [Parameter(position = 2, Mandatory = $false)]
        [string]$queryParams,
        [Parameter(position = 3, Mandatory = $false)]
        [PSObject]$data
    )
    # Use TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    <# Construct URL #>
    $url = "https://$company.logicmonitor.com/santaba/rest$path$queryParams"
    <# Get current time in milliseconds #>
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
    <# Concatenate Request Details #>
    $requestVars = $httpVerb + $epoch + $data + $path
    <# Construct Signature #>
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))
    <# Construct Headers #>
    $auth = 'LMv1 ' + $accessId + ':' + $signature + ':' + $epoch
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $auth)
    $headers.Add("Content-Type", 'application/json')
    $headers.Add("X-version", '2')
    <# Make request & retry if failed due to rate limiting #>
    $Stoploop = $false
    do {
        try {
            <# Make Request #>
            $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Body $data -Header $headers
            $Stoploop = $true
        } catch {
            switch ($_) {
                { $_.Exception.Response.StatusCode.value__ -eq 429 } {
                    Write-Host "Request exceeded rate limit, retrying in 60 seconds..."
                    Start-Sleep -Seconds 60
                    $response = Invoke-RestMethod -Uri $url -Method $httpVerb -Body $data -Header $headers
                }
                { $_.Exception.Response.StatusCode.value__ } {
                    Write-Host "Request failed, not as a result of rate limiting"
                    # Dig into the exception to get the Response details.
                    # Note that value__ is not a typo.
                    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__
                    Write-Host "StatusDescription:" $_.Exception.Response.StatusCode
                    $_.ErrorDetails.Message -match '{"errorMessage":"([\d\S\s]+)","errorCode":(\d+),'
                    Write-Host "LM ErrorMessage" $matches[1]
                    Write-Host "LM ErrorCode" $matches[2]
                    $response = $null
                    $Stoploop = $true
                }
                default {
                    Write-Host "An Unknown Exception occurred:"
                    Write-Host $_ | Format-List -Force
                $response = $null
                $Stoploop = $true
            }
        }
    }
} While ($Stoploop -eq $false)
Return $response
}

#EncodingPassword
$password_encoded = EncodePassword($password)

##RETRIEVING APIKEY
    #construct URL
    $apicall = "/api/?type=keygen"
    $uri = "https://"+$ip+$apicall+"&user="+$userid+"&password="+$password_encoded
    #Write-Host $uri #DEBUG ENTRY
    ##Request
    $tempvar = New-Object System.Net.WebClient
    [xml] $xmlresult = $tempvar.DownloadString($uri)
    #apikey result
    $apikey = $xmlresult.response.result.key
    #Write-Host "APIKEY -> " + $apikey #DEBUG ENTRY

##DEFINING 'paloalto.apikey.pass' on the device (customProperty)
    $httpVerb = 'PATCH'
    $resourcePath = "/device/devices/"+$devId
    $queryParams = "?patchFields=customProperties&opType=replace"
    $data = '{"customProperties":[{"name":"paloalto.apikey.pass","value":"' + $apikey + '"}]}'
    $results = Send-Request $resourcePath $httpVerb $queryParams $data

Exit 0;