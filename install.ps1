<#
Copyright (c) AppDynamics, Inc., and its affiliates 2017
All rights reserved

Install script for private agents.

Usage:

Install with a valid config.json
================================
> install.ps1 -Config config.json

Install in an interactive fashion
================================
> install.ps1

#>

Param(
  [string]$Config
)

######################################################
#                   Helpers                          #
######################################################
Function ConsoleLog($Message) {
  Write-Host $Message -ForegroundColor Cyan
}

Function ConsoleErr($Message) {
  Write-Host ">>> ERROR: $Message <<<" -ForegroundColor Red
}

Function ReadInput {
  [cmdletbinding(DefaultParameterSetName="_All")]
  Param(
    [Parameter(Mandatory=$True, Position=0)]
    [Alias("m", "message", "msg")]
    [ValidateNotNullorEmpty()]
    [string]$Prompt,
    [Alias("foregroundcolor","fg")]
    [consolecolor]$PromptColor = "Green",
    [Alias("secure")]
    [switch]$AsSecureString,
    [switch]$ValidateNotNull,
    [ValidateNotNullorEmpty()]
    [double[]]$ValidateRange,
    [ValidateNotNullorEmpty()]
    [regex]$ValidatePattern,
    [ValidateNotNullorEmpty()]
    [string]$ValidatePatternErrorMessage
  )

  $Result = ""
  Do {
    $Valid = $True
    # Display the prompt
    Write-Host -NoNewline -ForegroundColor $PromptColor "$($Prompt): "
    # Now read the value
    If ($AsSecureString) {
      $val = $host.ui.ReadLineAsSecureString()
      $credential = New-Object System.Management.Automation.PSCredential -ArgumentList "dummy", $val
      $r = $credential.GetNetworkCredential().Password
    } Else {
      $r = $host.ui.ReadLine()
    }

    $Result = $r

    # Validate
    If ($ValidateNotNull) {
      If ($r.length -eq 0 -OR $r -notmatch "\S" -OR $r -eq $Null) {
        ConsoleErr "Value cannot be null or empty"
        $Valid = $False
      }
    }
    If ($ValidatePattern) {
      If ($r -notmatch $ValidatePattern) {
        ConsoleErr "Please enter a string that conforms to the specified pattern ($ValidatePatternErrorMessage)"
        $Valid = $False
      }
    }
    If ($ValidateRange) {
      Try {
        If ( -NOT ([double]$r -ge $ValidateRange[0] -AND [double]$r -le $ValidateRange[1])) {
          ConsoleErr "Please enter a valid number in the range ($($ValidateRange[0]), $($ValidateRange[1]))"
          $Valid = $False
        }
      } Catch {
        ConsoleErr "Please enter a valid number in the range ($($ValidateRange[0]), $($ValidateRange[1]))"
        $Valid = $False
      }
    }
  } Until ($Valid)
  $Result
}

Function CheckIsAdmin() {
  If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
  {
    Write-Output "You are not an administrator, exiting"
    Exit
  }
}

Function CheckIsRunning() {
  $agent_process=wmic process where "Name='cmd.exe' AND CommandLine LIKE '%%start_agent%%'" GET processid /value 2> $null | Select-String ProcessId
  If ($agent_process) {
    Write-Output "Synthetic agent is running.  Please exit before running installer"
    Exit
  }
}

Function CheckAllowUserLogon() {
  $users_sid = (New-Object System.Security.Principal.NTAccount("Users")).Translate([System.Security.Principal.SecurityIdentifier]).value

  secedit /export /cfg original.inf > $null
  $match = Get-Content original.inf | Select-String -Pattern "SeInteractiveLogonRight" | Select-String "$users_sid" -ErrorAction SilentlyContinue
  del original.inf

  if (-NOT($match)) {
    Write-Output "Users do not have allow logon permissions.  Please add 'Users' to 'Allow log on locally' group policy"
    Exit
  }
}

Function IsPlatformSupported() {
  $majorVer = [System.Environment]::OSVersion.Version.Major
  $minorVer = [System.Environment]::OSVersion.Version.Minor
  $productType = (Get-WmiObject -Class Win32_OperatingSystem).ProductType

  If ($productType -eq 3 -and $majorVer -eq 6 -and ($minorVer -eq 2 -or $minorVer -eq 3)) {
      # Server class machine and 2012 or 2012R2.
      Return $true
  }

  Return $false
}

# Formats JSON in a nicer format than the built-in ConvertTo-Json does.
# This code is taken from: https://github.com/PowerShell/PowerShell/issues/2736
Function Format-Json([Parameter(Mandatory = $True, ValueFromPipeline = $True)][String] $json) {
  $indent = 0;
  ($json -Split '\n' |
    % {
      if ($_ -match '[\}\]]') {
        # This line contains  ] or }, decrement the indentation level
        $indent--
      }
      $line = (' ' * $indent * 2) + $_.TrimStart().Replace(':  ', ': ')
      if ($_ -match '[\{\[]') {
        # This line contains [ or {, increment the indentation level
        $indent++
      }
      $line
  }) -Join "`n"
}

######################################################
#                   Chef Helpers                     #
######################################################
Function InstallChef() {
  ""
  ConsoleLog "Installing Chef..."
  mv cookbooks\synthagent\files\assets\chef-client*.msi chef-client.msi
  Start-Process -FilePath msiexec -ArgumentList /qn, /i, chef-client.msi -Wait
  if (!$?) {
    ConsoleErr "Failed to install chef: $($error[0].Exception.Message)"
    Exit
  }
  $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
}

Function InstallChefIfNeeded() {
  if ((Get-Command "chef-client.bat" -ErrorAction SilentlyContinue) -eq $null) {
    # Chef doesn't seem to have been installed. Let's first get that installed.
    InstallChef
    if ((Get-Command "chef-client.bat" -ErrorAction SilentlyContinue) -eq $null) {
      ConsoleErr "Failed to install Chef. Exiting..."
      Exit
    }
  }
}

Function RunChefAsAdmin($ConfigFile) {
  $config = Get-Content -Raw $ConfigFile | ConvertFrom-Json

  $install_home = "C:\appdynamics"
  if ($config.synthagent.dir.home) {
    $install_home = $config.synthagent.dir.home
  }

  if (Test-Path $install_home) {
    ConsoleLog "Removing $install_home"
    Remove-Item -Path $install_home -Recurse -Force
  }

  ""
  ConsoleLog "Running Chef as $env:UserName..."

  $cwd = (Get-Location).path
  chef-client -z -j $cwd\$ConfigFile -o 'recipe[synthagent::fetch_local_artifacts],recipe[synthagent]' -l info -L C:\opscode\chef.log | Out-Null
  if (!$?) {
    ConsoleErr "Failed to run 'recipe[synthagent]'. Error code: $lastExitCode"
    ConsoleErr "See C:\opscode\chef.log for details"
    Exit
  }
  Copy-Item cookbooks $install_home -recurse -force
}

Function ConstructConfigJson($ConfigFile) {
  ""
  ConsoleLog "Please provide the following details to configure this synthetic agent"
  ""
  # Read EUM details
  $eumAccountName = ReadInput "EUM account name" -ValidateNotNull
  $eumAccountPassword = ReadInput "EUM license key" -AsSecureString -ValidateNotNull
  ConsoleLog ""

  # Read location data
  $locationId = ReadInput "Specify the ID you would like to use for this location" -ValidateNotNull -ValidatePattern "^[a-zA-Z0-9-]*$" -ValidatePatternErrorMessage "only numbers, letters and dashes allowed"
  $displayName = ReadInput "Specify the name that you would like to see in the controller for this location" -ValidateNotNull
  $city = ReadInput "Which city is this agent located (e.g., San Francisco)?" -ValidateNotNull
  $state = ReadInput "Which state is this agent located (e.g., California)?" -ValidateNotNull
  $country = ReadInput "Which country is this agent located (e.g., United States)?" -ValidateNotNull
  $latitude = ReadInput "Specify the geographical latitude coordinate for this location (e.g., 37.427619)" -ValidateNotNull -ValidateRange -90.0,90.0
  $longitude = ReadInput "Specify the geographical longtitude coordinate for this location (e.g., -122.166972)" -ValidateNotNull -ValidateRange -180.0,180.0

  $config = [ordered]@{
    "synthagent" = [ordered]@{
      "location_data" = [ordered]@{
        "code" = $locationId
        "name" = $displayName
        "city" = $city
        "state" = $state
        "country" = $country
        "latitude" = $latitude
        "longitude" = $longitude
      }
      "shepherd" = [ordered]@{
        "url" = "https://synthetic.api.appdynamics.com"
        "eum-account" = $eumAccountName
        "eum-key" = $eumAccountPassword
      }
    }
  }

  $json = ($config | ConvertTo-Json -Depth 5 | Format-Json)
  Try {
    # First try to write the content as UTF-8 (no BOM)
    $ConfigFileAbsPath = (Resolve-Path -Path $ConfigFile).Path
    [System.IO.File]::WriteAllLines($ConfigFileAbsPath, $json)
  } Catch {
    # [System.IO.File] is probably unavailable. Fallback to UTF-8.
    $json | Out-File -Encoding ascii $ConfigFile
  }
}

Function PromptRestart($ConfigFile) {
  $config = Get-Content -Raw $ConfigFile | ConvertFrom-Json

  $install_home = "C:\appdynamics"
  if ($config.synthagent.dir.home) {
    $install_home = $config.synthagent.dir.home
  }

  ""
  ConsoleLog "############################################################################################"
  ConsoleLog "AppDynamics Synthetic Agent installed in $install_home\synthetic-agent!"
  ConsoleLog " To start the agent, double-click on the 'Start Agent' icon found in your desktop"
  ConsoleLog " To stop the agent, double-click on the 'Stop Agent' icon found in your desktop"
  ""
  ConsoleLog "The system must be restarted for the changes to take effect. Press the return key to restart"
  ConsoleLog "############################################################################################"
  Read-Host
  Restart-Computer
}

######################################################
#                   Main                             #
######################################################

If (!(IsPlatformSupported)) {
  ConsoleErr "Unsupported platform. This installer is supported only on Windows Server 2012 and Windows Server 2012R2"
  Exit 1
}

CheckIsAdmin
CheckIsRunning
CheckAllowUserLogon

cd $PSScriptRoot
$ConfigFile = $Config

# If config file is not passed in, create config.json interactively
If (!$Config) {
  $ConfigFile = "config.json"
  ConstructConfigJson $ConfigFile
}

InstallChefIfNeeded
RunChefAsAdmin $ConfigFile
PromptRestart $ConfigFile

# SIG # Begin signature block
# MIIXqQYJKoZIhvcNAQcCoIIXmjCCF5YCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVgLEhz90ga5Whhi717FrB7xH
# gS6gghLLMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggTRMIIDuaADAgECAhBNS++O02XcGDYWVIZbERJTMA0GCSqGSIb3DQEBCwUAMH8x
# CzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0G
# A1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEwMC4GA1UEAxMnU3ltYW50ZWMg
# Q2xhc3MgMyBTSEEyNTYgQ29kZSBTaWduaW5nIENBMB4XDTE1MDYxOTAwMDAwMFoX
# DTE4MDcxODIzNTk1OVowZjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3Ju
# aWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xFDASBgNVBAoUC0FwcGR5bmFtaWNz
# MRQwEgYDVQQDFAtBcHBkeW5hbWljczCCASAwCwYJKoZIhvcNAQEBA4IBDwAwggEK
# AoIBAQCrbmQUhAWzbvINrmL2aSaIdyR3/aKT42LrY9h49r59Nr3c/JUjD1RYSjRr
# RzLCGQQzcqvWlzxFwsvaQ1xyFQ9Stlx3uxjVBOcSPgbf1z3GJ+X9omJPSI1Ocl74
# njSahJnKLnaA60p+CuadoFB9Tyu5oXxD+fdKgOMmvxjysEj19pOXqr3MaKbcQVzf
# wTCcL7PB5Q8iBBVLLbNTXVw2yoU6ihly6dcy3BhLLC8j1yxynIIJ7IuzCq3MPIOL
# +7TMJ41r4cXlPRBvlf/jAot2xR1q5i/VrfgqL0rCHat3hGGGPdz8nyROfBPA1CTY
# YTB4HzbsTpGS7/xUewBmmADuBqhnAgMBAAGjggFiMIIBXjAJBgNVHRMEAjAAMA4G
# A1UdDwEB/wQEAwIHgDArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vc3Yuc3ltY2Iu
# Y29tL3N2LmNybDBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUH
# AgEWF2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkMF2h0dHBz
# Oi8vZC5zeW1jYi5jb20vcnBhMBMGA1UdJQQMMAoGCCsGAQUFBwMDMFcGCCsGAQUF
# BwEBBEswSTAfBggrBgEFBQcwAYYTaHR0cDovL3N2LnN5bWNkLmNvbTAmBggrBgEF
# BQcwAoYaaHR0cDovL3N2LnN5bWNiLmNvbS9zdi5jcnQwHwYDVR0jBBgwFoAUljtT
# 8Hkzl699g+8uK8zKt4YecmYwHQYDVR0OBBYEFMclqq5govUqhVU0y5ovaSLI73qY
# MA0GCSqGSIb3DQEBCwUAA4IBAQABgYCAsbHIlZ3oVSHvpiPnw1IzHgwPZ+bvWSC4
# nJA6rbCMYCKv10qEUg3zGvaanClflPfD2Qw7N18Qu7GrURJ9m4xqFipM7uWVfJ4O
# ghqZhEwFWFjN9fuoZVkfDbwPPI1T3jurNSmlkGhcvKhByRCUCcchjm3t5i0jsCOy
# d8+vK8JwFnm95xIoHH7UJJIQh/N34E2bhLjRUsPMIH3pSURs2UaGNxmBsWqijQJx
# KLbW6rj1DjnJYGoLf/pADbhlkJHi3MFCYt1OQnHZi3XG/hL1M3ORT0zjpX+weqi/
# p+ULLC39sEDio0R5pUMnZsH18DW5weCjy4foE5cGcT0S7esRMIIFWTCCBEGgAwIB
# AgIQPXjX+XZJYLJhffTwHsqGKjANBgkqhkiG9w0BAQsFADCByjELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBU
# cnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2lnbiwgSW5jLiAt
# IEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJpU2lnbiBDbGFz
# cyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IC0gRzUw
# HhcNMTMxMjEwMDAwMDAwWhcNMjMxMjA5MjM1OTU5WjB/MQswCQYDVQQGEwJVUzEd
# MBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVj
# IFRydXN0IE5ldHdvcmsxMDAuBgNVBAMTJ1N5bWFudGVjIENsYXNzIDMgU0hBMjU2
# IENvZGUgU2lnbmluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AJeDHgAWryyx0gjE12iTUWAecfbiR7TbWE0jYmq0v1obUfejDRh3aLvYNqsvIVDa
# nvPnXydOC8KXyAlwk6naXA1OpA2RoLTsFM6RclQuzqPbROlSGz9BPMpK5KrA6Dmr
# U8wh0MzPf5vmwsxYaoIV7j02zxzFlwckjvF7vjEtPW7ctZlCn0thlV8ccO4XfduL
# 5WGJeMdoG68ReBqYrsRVR1PZszLWoQ5GQMWXkorRU6eZW4U1V9Pqk2JhIArHMHck
# EU1ig7a6e2iCMe5lyt/51Y2yNdyMK29qclxghJzyDJRewFZSAEjM0/ilfd4v1xPk
# OKiE1Ua4E4bCG53qWjjdm9sCAwEAAaOCAYMwggF/MC8GCCsGAQUFBwEBBCMwITAf
# BggrBgEFBQcwAYYTaHR0cDovL3MyLnN5bWNiLmNvbTASBgNVHRMBAf8ECDAGAQH/
# AgEAMGwGA1UdIARlMGMwYQYLYIZIAYb4RQEHFwMwUjAmBggrBgEFBQcCARYaaHR0
# cDovL3d3dy5zeW1hdXRoLmNvbS9jcHMwKAYIKwYBBQUHAgIwHBoaaHR0cDovL3d3
# dy5zeW1hdXRoLmNvbS9ycGEwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3MxLnN5
# bWNiLmNvbS9wY2EzLWc1LmNybDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
# AwMwDgYDVR0PAQH/BAQDAgEGMCkGA1UdEQQiMCCkHjAcMRowGAYDVQQDExFTeW1h
# bnRlY1BLSS0xLTU2NzAdBgNVHQ4EFgQUljtT8Hkzl699g+8uK8zKt4YecmYwHwYD
# VR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJKoZIhvcNAQELBQADggEB
# ABOFGh5pqTf3oL2kr34dYVP+nYxeDKZ1HngXI9397BoDVTn7cZXHZVqnjjDSRFph
# 23Bv2iEFwi5zuknx0ZP+XcnNXgPgiZ4/dB7X9ziLqdbPuzUvM1ioklbRyE07guZ5
# hBb8KLCxR/Mdoj7uh9mmf6RWpT+thC4p3ny8qKqjPQQB6rqTog5QIikXTIfkOhFf
# 1qQliZsFay+0yQFMJ3sLrBkFIqBgFT/ayftNTI/7cmd3/SeUx7o1DohJ/o39KK9K
# Er0Ns5cF3kQMFfo2KwPcwVAB8aERXRTl4r0nS1S+K4ReD6bDdAUK75fDiSKxH3fz
# vc1D1PFMqT+1i4SvZPLQFCExggRIMIIERAIBATCBkzB/MQswCQYDVQQGEwJVUzEd
# MBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVj
# IFRydXN0IE5ldHdvcmsxMDAuBgNVBAMTJ1N5bWFudGVjIENsYXNzIDMgU0hBMjU2
# IENvZGUgU2lnbmluZyBDQQIQTUvvjtNl3Bg2FlSGWxESUzAJBgUrDgMCGgUAoHww
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwHAYKKwYBBAGCNwIBDDEOMAygCoAIAFMAaQBnAG4wIwYJKoZIhvcN
# AQkEMRYEFNNned86X8TuHCkun52dAJvZRAisMA0GCSqGSIb3DQEBAQUABIIBAGEO
# QaHqEDPXTE9DIc0fFwkzoYK1eo3ltmjqWay6IUDnDP4N6rf89Z9xBVtnlnTS4vqa
# cu1Cvk/kNnkcawdjSIj4F26t2nne5JF2Yj7dJ55mYuOLfw8WnVWsn63zGcmWtPUN
# SONZC5RBkBMn1pMSJez/Gz0xOPtAUXcvULAzoQ8jd+OktHInnc+SFy9wURpKCedW
# deEb6eeT5N9YB8T4WPjwPuRwVW/1Ce0ifjzjVdQwBhLv9Tuh3KpNj9TzDJsF1IgS
# ngeVq7xtnCDHRlRQmwlKzTXr18T9DSwjWqpSDG8WJ9F2It6Yv6aU6iPt5bdzapV8
# MwtmfGiOE7bmnr46S0ShggILMIICBwYJKoZIhvcNAQkGMYIB+DCCAfQCAQEwcjBe
# MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAu
# BgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMgIQ
# Ds/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqG
# SIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwNjA2MDU1MzM0WjAjBgkqhkiG9w0B
# CQQxFgQUj31KxJnup3V3yUWpjLM+3I/I87AwDQYJKoZIhvcNAQEBBQAEggEAcQ0L
# THDqRCOT/WwrJe1/qCxr7XZiphA59z98dEL2djdpCmVXhjT2Jm4qawSYUu6wqzfK
# As7fBN0r6VI4yPyloUE6IxIF0tly8V8DcZy17ujVt+1wYZmIUkH23+ug4JSr1ekg
# EcPaSjrC8NO/Y9zLoQfN33hAzlHg3hDuidQVcfRw7zMJ2vwcbEGB1xtYuKcL0SdK
# c7LP58VzUgRv96EDdKTo3mN0usReaaVuyaa98YdYH06pql71L+RoWsEX3PTRgjfx
# ydmtDch/MR19gjHf+MGPuNJIPc9GrFOSYlyIG11oyU/sggGi7hR7jxn3MsKPfcxW
# s4C4JiaR+LP8ho/Z3w==
# SIG # End signature block
