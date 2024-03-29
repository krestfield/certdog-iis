﻿# ------------------------------------------------------------------------------------------------
# Krestfield Certdog IIS Certificate Management Script
# ------------------------------------------------------------------------------------------------
# 
# Copyright (c) 2021, Krestfield Limited
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted 
# provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice, this list of conditions 
#     and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice, this list of conditions 
#     and the following disclaimer in the documentation and/or other materials provided with the distribution.
#   * Neither the name of Krestfield Limited nor the names of its contributors may be used to endorse or 
#     promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, 
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# ------------------------------------------------------------------------------------------------
#
# For an official supported, signed version of this script contact support@krestfield.com
#
# For more details on this script go here
#     https://krestfield.github.io/docs/certdog/iis_powershell.html
#
# This script requires the certdog application to issue certificates
#     More information: https://krestfield.com/certdog
#     Free docker image: https://hub.docker.com/r/krestfield/certdog
#
# Simple run options:
#
#   .\certdog-iis.ps1 -new
#
# This will prompt for all information including the certdog login as well as
# the binding and certificate details
# To provide the certdog login details without being prompted, run:
#
#   .\certdog-iis.ps1 -new -username [certdoguser] -password [certdogpassword]
#
#
# Once the above has been performed the script saves the required information. Running:
#
#   .\certdog-iis.ps1 -renew
#
# Will check and process any renewals required for the sites and bindings configured when
# the -new switch was used
#
# If credentials are not saved, this can be run with the username and password options:
#
#   .\certdog-iis.ps1 -renew -username [certdoguser] -password [certdogpassword]
#
#
# To list what bindings are being monitored:
#
#   .\certdog-iis.ps1 -list
#
#
# To create a scheduled task that runs the .\certdog-iis.ps1 -renew script daily, run
#
#   .\certdog-iis.ps1 -taskonly
#
#
# To override the certdog URL as specified in the settings.json file, use -certdogUrl e.g.
#
#   .\certdog-iis.ps1 -new -certdogUrl https://certdog.org.com/certdog/api
#
#
# To ignore any SSL errors (if the certdog URL is not protected with a trusted cert), 
# use -ignoreSslErrors e.g.
#
#   .\certdog-iis.ps1 -new -ignoreSslErrors
# 
# ------------------------------------------------------------------------------------------------
Param (
    [switch]
    $new,
    [switch]
    $renew,
    [switch]
    $list,
    [switch]
    $taskonly,
    [switch]
    $setcreds,
    [switch]
    $ignoreSslErrors,
    [Parameter(Mandatory=$false)]
    $username,
    [Parameter(Mandatory=$false)]
    $password,
    [Parameter(Mandatory=$false)]
    $certdogUrl
)
 
Import-Module WebAdministration

# 0 : Regular certificate in Windows cert storage
# 1 : SNI (Server Name Indication) certificate
# 2 : Central Certificate Store
# 3 : SNI cert in central store
$script:sslFlags = 0

$script:scriptName = "certdog-iis.ps1"

# By default we do not ignore SSL errors
$script:IgnoreTlsErrors = $false

# The list of updated bindings, if any, that may be saved
$script:UpdatedBindings = @()
$script:CertdogSecureUsername=$null
$script:CertdogSecurePassword=$null

$CREDS_REGISTRY_PATH = "HKLM:\Software\Krestfield\Certdog"

$script:loggedIn = $false

# -----------------------------------------------------------------------------
# When -ignoreSslErrors is called, this is set which ignores https TLS errors
# due to untrusted certificates etc.
# -----------------------------------------------------------------------------
Function IgnoreSSLErrors
{
    $script:IgnoreTlsErrors = $true

	if ("TrustAllCertsPolicy" -as [type]) {} 
	else 
	{
	# NOTE: This skips the SSL certificate check
	add-type @"
	using System.Net;
	using System.Security.Cryptography.X509Certificates;
	public class TrustAllCertsPolicy : ICertificatePolicy {
		public bool CheckValidationResult(
			ServicePoint srvPoint, X509Certificate certificate,
			WebRequest request, int certificateProblem) {
			return true;
		}
	}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy 
	}
}

# -----------------------------------------------------------------------------
# Logs in the user and retains the authorization token for use by other
# functions
# -----------------------------------------------------------------------------
Function login
{
    Param(
        [Parameter(Mandatory=$true)]
        $username,
        [Parameter(Mandatory=$true)]
        $password
    )
       
    $initialHeaders = @{
        'Content-Type' = 'application/json'
    }
    
    $body = [Ordered]@{
        'username' = "$username"
        'password' = "$password"
    } | ConvertTo-Json -Compress

    try 
    {
        $response = Invoke-RestMethod "$certdogUrl/login" -Method "POST" -Headers $initialHeaders -Body $body
        
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $authToken = $response.token
        $headers.Add("Authorization", "Bearer $authToken")
        Set-Variable -Name "HEADERS" -Force -Value $headers -Visibility Private -Scope Global
	$script:loggedIn = $true
    }
    catch 
    {
	$script:loggedIn = $false
        Throw "Authentication to certdog at $certdogUrl failed`nError: $_" 
    }
}

# -----------------------------------------------------------------------------
# Logs out a user from this IP
# 
# -----------------------------------------------------------------------------
Function Logout
{
    $body = [Ordered]@{}
    
    Run-Rest-Command -endPoint "logouthere" -method "GET" -body $body -methodName "Logout-Here"
}

# -----------------------------------------------------------------------------
# Makes a generic REST call requiring the end point, body, method etc.
# Returns the response
# -----------------------------------------------------------------------------
Function Run-Rest-Command
{
    Param(
        [Parameter(Mandatory=$true)]
        $endPoint,
        [Parameter(Mandatory=$true)]
        $method,
        [Parameter(Mandatory=$true)]
        $body,
        [Parameter(Mandatory=$true)]
        $methodName
    )

    try {
		
        $headers = Get-Variable -Name "HEADERS" -ValueOnly -ErrorAction SilentlyContinue
        if (!$headers)
        {
            Write-Host "Please authenticate with Login -username [username] -password [password] (or just type Login to be prompted)"
            Return
        }

        $response = Invoke-RestMethod "$certdogUrl/$endPoint" -Headers $headers -Method $method -Body $body

        return $response
    }
    catch 
    {
        Write-Host "$methodName failed: $_" 
    
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $responseBody = $reader.ReadToEnd();
        
        #Write-Host responseBody = $responseBody

        $output = $responseBody | ConvertFrom-Json
        $output | Format-List

        throw $output
    }
}

# -----------------------------------------------------------------------------
# Requests a cert with a CSR
# 
# -----------------------------------------------------------------------------
Function Request-CertP10
{
    [alias("request-csr")]
    Param(
        [Parameter(Mandatory=$true)]
        $caName,
        [Parameter(Mandatory=$false)]
        $csr,
        [Parameter(Mandatory=$false)]
        $teamName,
        [Parameter(Mandatory=$false)]
        $extraInfo,
        [Parameter(Mandatory=$false)]
        [string[]]$extraEmails
    )

	if ($script:loggedIn -eq $false)
	{
		Throw "Not logged in. Unable to request certificate from certdog"
	}

	if (!$csr)
    {
		Throw "Unable to request a certificate from certdog as no CSR data was provided"
    }
    
	try
	{
		$body = [Ordered]@{
			'caName' = "$caName"
			'csr' = "$csr"
			'teamName' = "$teamName"
			'extraInfo' = "$extraInfo"
			'extraEmails' = @($extraEmails)
		} | ConvertTo-Json -Compress
		$response = Run-Rest-Command -endPoint "certs/requestp10" -method "POST" -body $body -methodName "Request-CertP10"

		return $response
	}
	catch
	{
		Throw "Unable to obtain certificate from certdog. Error: $_"
	}
}


# ------------------------------------------------------------------------------------------------
# Generates a certificate request in the local machine store
#
#
# ------------------------------------------------------------------------------------------------
Function Generate-Csr
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $dn,
        [Parameter(Mandatory=$false)]
        $sans
    )

    try
	{
		# Temp filename for CSR and INF file
		$UID = [guid]::NewGuid()
		$settingsInfFile = "$($env:TEMP)\$($UID)-settings.inf";
		$csrFile = "$($env:TEMP)\$($UID)-csr.req"

		# Create the settings.inf
		$keySize = $global:Settings.csrKeyLength
		$hash = $global:Settings.csrHash
		$provider = $global:Settings.csrProvider
		$providerType = $global:Settings.csrProviderType
		$exportable = $global:Settings.exportable
		
		$settingsInf = "
[Version]
Signature=`"`$Windows NT`$
[NewRequest]
KeyLength = $keySize
Exportable = $exportable
MachineKeySet = TRUE
SMIME = FALSE
RequestType =  PKCS10
ProviderName = `"$provider`"
ProviderType =  $providerType
HashAlgorithm = $hash
;Variables
Subject = `"$dn`"
[Extensions]
	"
		# Add the SANs
		if ($sans) {
			$settingsInf += "2.5.29.17 = `"{text}`"
	"
			foreach ($sanItem In $sans) 
			{
				$settingsInf += "_continue_ = `"$sanItem`&`"
	"       }
		}
		# Save settings to file in temp
		Set-Content -Path $settingsInfFile -Value $settingsInf

		$resp = certreq -q -new $settingsInfFile $csrFile
		if ($LASTEXITCODE -ne 0)
		{
			Throw $resp
		}

		$csr = Get-Content $csrFile

		Remove-Item $csrFile -ErrorAction SilentlyContinue
		Remove-Item $settingsInfFile -ErrorAction SilentlyContinue

		return $csr
	}
	catch
	{
		Throw "There was an error whilst creating the CSR for the requested DN of $dn. Error: $_"
	}
}

# ------------------------------------------------------------------------------------------------
# Requests a certificate from certdog
#
# ------------------------------------------------------------------------------------------------
Function Request-Cert
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $username,
        [Parameter(Mandatory=$true)]
        [string]
        $password,
        [Parameter(Mandatory=$true)]
        [string]
        $caName,
        [Parameter(Mandatory=$true)]
        [string]
        $csr,
        [Parameter(Mandatory=$true)]
        [string]
        $teamName
    )

	if ($script:loggedIn -eq $false)
	{
		login -username $username -password $password
		$script:loggedIn = $true
	}
	
	$cert = Request-CertP10 -caName $caName -csr $csr -teamName $teamName

	#Logout
	
	return $cert.pemCert
}

# ------------------------------------------------------------------------------------------------
# Imports a certificate into the local machine store
#
# ------------------------------------------------------------------------------------------------
Function Import-Cert
{
	Param(
        [Parameter(Mandatory=$true)]
        [string]
        $certData
	)
	
	$tmpId = [guid]::NewGuid()
	$tmpFilename = "$($env:TEMP)\$($UID).cer";
	Set-Content -Path $tmpFilename -Value $certData

	try
	{		
		if (Test-Path $tmpFilename)
		{
			Get-ChildItem -Path $tmpFilename | Import-Certificate -CertStoreLocation cert:\LocalMachine\My > $null
			
			# Get Thumbprint
			$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmpFilename)
			
			# Store the Thumbprint in a global ready for use by any subsequent script
			$global:thumbprint = $cert.Thumbprint
					
			Remove-Item $tmpFilename -ErrorAction SilentlyContinue
			
			return $cert
		}
		else
		{
			Throw "Could not install certificate into local store, the certificate file at $tmpFilename could not be found." 
		}
	}
	catch
	{
		Throw "Importing of the certdog issued certificate failed. Error: $_"
	}
}

# ------------------------------------------------------------------------------------------------
# Given the DN returns the common name
#
# e.g. 
# Given: CN=test,O=Org,C=GB 
# will return: test
#
# ------------------------------------------------------------------------------------------------
Function Get-CommonNameFromDn
{
	Param(
        [Parameter(Mandatory=$true)]
        [string]
        $dn
	)
	
	$cn = $dn -replace "(CN=)(.*?),.*",'$2'
	$cn = $cn -replace "CN=",""
	
	return $cn
}

# ------------------------------------------------------------------------------------------------
# Gather any additional SANs
#
# Note that the common name is added automatically
#
# ------------------------------------------------------------------------------------------------
Function Get-Sans
{
	Param(
        [Parameter(Mandatory=$true)]
        [string]
        $cn
	)
	
	$addMoreSans = Read-Host "`nDo you wish to add any other additional names to this certificate? (y/n)"
	if ($addMoreSans -eq "y")
	{
		$sansOk = $false
		do
		{
			$addSans = Read-Host "`nEnter names separated with a comma e.g. test1.com,test2.com"		
			$sanArray = @()
			$sanArray += "DNS=$cn"
			
			Write-Host "`nAdditional Names:"
			Foreach ($sanItem In $addSans -split ",") 
			{
				Write-Host "   " $sanItem -ForegroundColor Yellow
				$sanArray = $sanArray + "DNS=$sanItem"
			}
			$allOk = Read-Host "`nAll ok? (y/n)"
			if ($allOk -eq "y")
			{
				$sansOk = $true
			}
		}
		while ($sansOk -ne $true)
	}
	else
	{
		$sanArray = @()
		$sanArray = $sanArray + "DNS=$cn"		
	}
	
	return $sanArray
}

# -----------------------------------------------------------------------------
# Presents the list of IIS sites for the user to choose
# Either the SSL binding will be updated or a new binding will be created
# from this information
#
# -----------------------------------------------------------------------------
Function User-SelectSite
{
	$webSites = Get-ChildItem IIS:\Sites
	if ($webSites.length -eq 0)
	{
		Write-Host "There are no sites configured in this IIS instance`n"
		return
	}
	
	if ($webSites.length -eq 1)
	{
		return $webSites.name
	}
	
	$inputOk = $false
	do
	{
		Write-Host "`nSelect the IIS Site`n"
		$siteNum = 1;
		foreach ($Site in $webSites)
		{
			$binding = $Site.bindings
			[string]$bindingInfo = $binding.Collection
			#[string]$ip = $bindingInfo.SubString($bindingInfo.IndexOf(" "),$bindingInfo.IndexOf(":")-$bindingInfo.IndexOf(" "))         
			#[string]$port = $bindingInfo.SubString($bindingInfo.IndexOf(":")+1,$bindingInfo.LastIndexOf(":")-$bindingInfo.IndexOf(":")-1) 

			Write-Host "  " $siteNum"." $Site.name
			$siteNum = $siteNum + 1
		}	
		
		$selectedSite = Read-Host "`nEnter the site number" 
	
	    if ($selectedSite -gt 0 -and $selectedSite -le $webSites.length)
        {           			
			$inputOk = $true
            
            $selectedSiteName = $webSites[$selectedSite - 1].name
			
			return $selectedSiteName
        }
        else 
        {
            Write-Host "`nPlease enter a value between 1 and "$webSites.length
        }
    } while ($inputOk -eq $false)	
}

# ------------------------------------------------------------------------------------------------
# Creates a new binding
#
# Prompts for the hostname/host-header, port and IP
#
# ------------------------------------------------------------------------------------------------
Function Create-NewBinding
{
	Param(
        [Parameter(Mandatory=$true)]
        [string]
        $siteName
	)
	
	$hostname = Read-Host "`nEnter Host Header (hostname)"
	$port = Read-Host "Enter Port"
	$ip = Read-Host "Enter IP Address (Enter * for all)"
	$newBinding = New-WebBinding -name $siteName -HostHeader $hostname -Protocol https -Port $port -SslFlags $script:sslFlags -IPAddress $ip
	$binding = Get-WebBinding -Name $siteName -Protocol https
	
	Bind-Certificate -binding $binding
}

# ------------------------------------------------------------------------------------------------
# Binds a certificate to the provided site binding and adds the details to the
# UpdatedBindings list 
#
# ------------------------------------------------------------------------------------------------
Function Bind-Certificate
{
	Param(
        [Parameter(Mandatory=$true)]
        $binding
	)
	
	$binding.AddSslCertificate($global:thumbprint, "my")
	
	# Save this as we will retain this data to auto-renew
	$script:UpdatedBindings += $binding
	
}

# ------------------------------------------------------------------------------------------------
# Presents a list of bindings for the site provided
# User can then choose which to update, or to add a new binding
# Binding is then created or updated
#
# ------------------------------------------------------------------------------------------------
Function User-SelectBindingAndUpdate
{
	Param(
        [Parameter(Mandatory=$true)]
        [string]
        $siteName,
		[switch]
		$update
	)
	
	Write-Host "`nBindings for site: $siteName`n"
	$bindings = Get-WebBinding -Name $siteName -Protocol https
	if ($bindings)
	{
		if ($bindings.length -eq 1)
		{			
			Bind-Certificate -binding $bindings
		}
		else
		{		
			# Display available bindings + Update All and Create New
			$bindingNum = 1
			foreach ($binding in $bindings)
			{
				Write-Host "  " $bindingNum"." $binding
				$bindingNum = $bindingNum + 1
			}

			Write-Host "  " $bindingNum". Update All"
			$bindingNum = $bindingNum + 1
			
			Write-Host "  " $bindingNum". Create New Binding"
			
			$selectedBindingId = Read-Host "`nEnter selection" 
			
			# Processing based on selection
			if ($selectedBindingId -eq $bindings.length + 1)
			{
				# Update All				
				foreach ($binding in $bindings)
				{
					Bind-Certificate -binding $binding
				}
			}
			else 
			{
				# Create New
				if ($selectedBindingId -eq $bindings.length + 2)
				{
					Create-NewBinding -siteName $siteName
				}
				else
				{
					# Update selected binding
					$selectedBinding = $bindings[$selectedBindingId - 1]
					
					Bind-Certificate -binding $selectedBinding
				}
			}
		}								
	}
	else
	{
		$addNew = Read-Host "There are no https bindings for site $siteName, do you want to add one? (y/n)"
		if ($addNew)
		{
			Create-NewBinding -siteName $siteName
		}
	}				
}

# ------------------------------------------------------------------------------------------------
# Updates the IIS Bindings
#
# ------------------------------------------------------------------------------------------------
Function Update-Bindings
{
	$confimUpdate = Read-Host "`nDo you want to update the IIS site bindings? (y/n)"
	if ($confimUpdate -eq "y")
	{
		$siteName = User-SelectSite
		
		$siteBinding = User-SelectBindingAndUpdate $siteName
				
		Write-Host "Bindings set OK"
	}
	else
	{
		Write-Host "`nYou will need to update the IIS bindings manually for your site to make use of this new certificate`n"
		Write-Host "Bye"
		Exit 0
	}
}

# ------------------------------------------------------------------------------------------------
# If the .\config dir is not present, creates it
# ------------------------------------------------------------------------------------------------
Function Check-ConfigDir
{
	$dirLoc = "$PSScriptRoot\config"
	if (!(Test-Path $dirLoc))
	{
		New-Item -ItemType directory -Path $dirLoc -Force > $null
	}	
}

# ------------------------------------------------------------------------------------------------
# Saves the updated bindings for the site specified
#
# ------------------------------------------------------------------------------------------------
Function Save-Bindings
{
	Check-ConfigDir
	
	# Save the binding details
	foreach($binding in $script:UpdatedBindings)
	{
		$filename = Get-BindingAsString -bindingData $binding
		$binding | Export-Clixml $PSScriptRoot\config\$($filename).xml
	}
}

# ------------------------------------------------------------------------------------------------
# Saves the user credentials which means the renew option can be run 
# without requiring the credentials to be passed
#
# ------------------------------------------------------------------------------------------------
Function Save-Credentials
{
	$saveCreds = Read-Host "Do you wish to save your credentials so they are not required when 'renew' is run? (y/n)"
	if ($saveCreds -eq "y")
	{		
		if (!$script:CertdogSecureUsername)
		{
			$user = Get-Username
			$pass = Get-Password
		}
		# Save the certdog credentials to the registry
		$secureUsername = $script:CertdogSecureUsername | ConvertFrom-SecureString
		$securePassword = $script:CertdogSecurePassword | ConvertFrom-SecureString

		if (!(Test-Path $CREDS_REGISTRY_PATH))
		{
			New-Item -Path $CREDS_REGISTRY_PATH -Force | Out-Null
		}
		New-ItemProperty -Path $CREDS_REGISTRY_PATH -Name "SecureUsername" -Value $secureUsername -PropertyType String -Force | Out-Null
		New-ItemProperty -Path $CREDS_REGISTRY_PATH -Name "SecurePassword" -Value $securePassword -PropertyType String -Force | Out-Null
		
		Write-Host "Credentials saved OK. They can only be accessed by the account running this script. Run '$script:scriptName -setcreds' to update"
	}
}

# ------------------------------------------------------------------------------------------------
# Loads the certdog secure credentials from the registry
#
# ------------------------------------------------------------------------------------------------
Function Load-Credentials
{
	# If username and password passed in, use those, otherwise get from the registry
	if ($username -and $password)
	{
		$script:CertdogSecureUsername = ConvertTo-SecureString -String $username -AsPlainText -Force		
		$script:CertdogSecurePassword = ConvertTo-SecureString -String $password -AsPlainText -Force				
	}
	else
	{
		# Load the certdog credentials from the registry
		try 
		{
			if (Test-Path $CREDS_REGISTRY_PATH)
			{
				Get-ItemProperty -Path $CREDS_REGISTRY_PATH | Select-Object -ExpandProperty "SecureUsername" -ErrorAction Stop | Out-Null
				$secureUsername = (Get-ItemProperty -Path $CREDS_REGISTRY_PATH -Name "SecureUsername").SecureUsername         
				$script:CertdogSecureUsername = $secureUsername | ConvertTo-SecureString
				if (!$script:CertdogSecureUsername)
				{
					Throw "Unable to obtain credentials from the store"
				}

				Get-ItemProperty -Path $CREDS_REGISTRY_PATH | Select-Object -ExpandProperty "SecurePassword" -ErrorAction Stop | Out-Null
				$SecurePassword = (Get-ItemProperty -Path $CREDS_REGISTRY_PATH -Name "SecurePassword").SecurePassword     
				$script:CertdogSecurePassword = $securePassword | ConvertTo-SecureString				
				if (!$script:CertdogSecurePassword)
				{
					Throw "Unable to obtain credentials from the store"
				}
			}
			else
			{
				Throw "No credentials could be found in the registry. Either run .\$script:scriptName -new to have them stored on this machine or provide to this script"
			}
		}
		catch 
		{
			Throw "Failed to load username or password from registry. $_"
		}
	}
}

# ------------------------------------------------------------------------------------------------
# Loads the binding settings for the site
# Also loads the secured username and password from the registry
#
# ------------------------------------------------------------------------------------------------
Function Load-Bindings
{
	Param(
        [Parameter(Mandatory=$true)]
        $filename
	)
	
	$script:UpdatedBindings = @()

	# Load the bindings
	if (Test-Path $filename)
	{
		$script:UpdatedBindings = Import-Clixml $filename
	}
	else
	{
		throw "No bindings have been configured to be renewed. Run ths script with the -new switch to set this up"
	}
}

# ------------------------------------------------------------------------------------------------
# Writes the message to a log file and optionally the event log
#
# ------------------------------------------------------------------------------------------------
Function Write-Event
{
	Param(
        [Parameter(Mandatory=$true)]
        $message,
		[Switch]
		$toEventLog,
		[Switch]
		$isError
	)
	
	$EventLogSource="certdog"
	$EventLogID=$global:Settings.eventLogId
	
	Add-Content $global:RenewLogFile "$message"
	
	if ($toEventLog)
	{
		if (![System.Diagnostics.EventLog]::SourceExists($EventLogSource))
		{
			New-EventLog –LogName Application –Source $EventLogSource
		}
		
		$entryType = "Information"
		if ($isError)
		{
			$entryType = "Error"
			$EventLogID=$global:Settings.errorLogId
		}
		Write-EventLog –LogName Application –Source $EventLogSource –EntryType $entryType –EventID $EventLogID –Message $message -Category 0
	}
	
	#Write-Host $message
}

# ------------------------------------------------------------------------------------------------
# Creates a scheduled task which will call this script with the -renew switch
# Task will run once a day between 1 and 3am
#
# ------------------------------------------------------------------------------------------------
Function Create-Task()
{
	try
	{
		$createTask = Read-Host "`nDo you want to create a task to automatically renew certificates? (y/n)"
		if ($createTask -eq "y")
		{		
			Write-Host "`nThe script will use saved credentials to authenticate to certdog"
			Write-Host "Only the account that saved those credentials will have access to them"
			Write-Host "The task must run under this same account"
			$username = Read-Host "`nEnter the username of this account"	
			$securePassword = Read-Host -assecurestring "Enter the password"	
			$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
		
			$description = "Checks for expiry of TLS certificates bound to IIS"
			$taskName = "Certdog Cert Expiry Check"
			
			$scriptLoc = "$PSScriptRoot\$script:scriptName"
			$arg = "-Command `"& '$scriptLoc' -renew`""
			if ($script:IgnoreTlsErrors)
			{
				$arg = "-Command `"& '$scriptLoc' -renew -ignoreSslErrors`""
			}
			$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $arg -WorkingDirectory $PSScriptRoot

			# Run every day a random time between 1am and 3am
			$trigger =  New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At 1am -RandomDelay (New-TimeSpan -minutes 120)

			# Create the task (if not already present)
			$taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName}
			if($taskExists) 
			{
				Write-Host "`nDid not create a new task as a task already exists to monitor TLS certificates called $taskName"
			} 
			else 
			{        
				$newTask = Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -User $username -Password $password -Description $description -ErrorAction Stop | Out-Null
				Write-Host "`nTask: '"$taskName"' created OK"
			}
			Write-Host "If required, you can manually edit the timings of this task from the Task Scheduler"

			Write-Host "`nBye`n"
		}
		else
		{
			Write-Host "`nThis certificate will not auto-renew"
			Write-Host "`nYou can manually renew this certificate and update the bindings by running"
			Write-Host "    $script:scriptName -renew" -ForegroundColor Gray
			Write-Host "`nSee: https://krestfield.github.io/docs/certdog/certdogiis.html for more information"
			Write-Host "`nBye`n"
		}
	}
	catch 
	{
		Throw "Unable to create scheduled task. Error: $_"
	}
}

# ------------------------------------------------------------------------------------------------
# If a username has not been passed in, prompt for it
# Store this username in the CertdogSecureUsername secure string
#
# ------------------------------------------------------------------------------------------------
Function Get-Username()
{
	# If not passed in, prompt the operator
	if (!$username)
	{
		$username = Read-Host "`nEnter your certdog username"
	}
	
	# Store as a secure string
	$script:CertdogSecureUsername = ConvertTo-SecureString -String $username -AsPlainText -Force
	
	return $username
}

# ------------------------------------------------------------------------------------------------
# If a password has not been passed in, prompt for it
# Store this password in the CertdogSecurePassword secure string
#
# ------------------------------------------------------------------------------------------------
Function Get-Password()
{
	if (!$password)
	{
		$script:CertdogSecurePassword = Read-Host -assecurestring "Enter your certdog password"
		
		$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:CertdogSecurePassword))
	
		return $password
	}
	else
	{
		$script:CertdogSecurePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
		
		return $password
	}
}

# ------------------------------------------------------------------------------------------------
# Extracts the SANS from a certificate and returns an array
#
# ------------------------------------------------------------------------------------------------
Function getSansFromCert
{
    Param(
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $cert
    )

    try
	{
		# Get all SAN extensions
		$sanExt = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "subject alternative name"}
		if ($sanExt)
		{
			$sanString = $sanExt.Format(1) -replace "DNS Name", "DNS"	
			$sanString = $sanString -replace "IP Address", "IPAddress"    			
			$sanString = $sanString -replace "`r`n", ";" 
			$sanArray = $sanString.split(";")

			return $sanArray
		}
		else
		{
			Write-Host "No SAN Extensions"
		}
	}
	catch 
	{
		Throw "There was an error obtaining the SANs from certificate cert.SubjectDN Error: $_"
	}		
}

# ------------------------------------------------------------------------------------------------
# Returns the binding information as a string so it can be used as a filename
# when saving the settings
#
# ------------------------------------------------------------------------------------------------
Function Get-BindingAsString
{
	Param(
        [Parameter(Mandatory=$true)]        
        $bindingData
    )
	
	$xpath = $bindingData.ItemXPath
	$bindingInfo = $bindingData.bindingInformation
	
	$siteName = $xpath.substring($xpath.IndexOf("@name")).Split("'")[1]

	# If IPV6 we want to replace everything between square brackets
	$ipV6IpAddress = ($bindingInfo | Select-String '(?<=\[)[^]]+(?=\])' -AllMatches).Matches.Value
	$ipAddress = ""
	if ($ipV6IpAddress)
	{
	    $bindingInfo = $bindingInfo -replace $ipV6IpAddress, ""
	    $bindingInfo = $bindingInfo -replace "[[\]]","_"

        $ipV6IpAddress = $ipV6IpAddress -replace ":", "_"
        $ipAddress = $ipV6IpAddress
	}
	else 
	{
		$ipAddress = $bindingInfo.Split(":")[0]			
	}

	$port = $bindingInfo.Split(":")[1]
	$hostHeader = $bindingInfo.Split(":")[2]

	if ($ipAddress -eq "*")
	{
		$ipAddress = "all"
	}

	$fname = "$($siteName)_$($ipAddress)_$($port)_$($hostHeader)"	
	
	return $fname
}

# ------------------------------------------------------------------------------------------------
# Given the binding object - loaded from settings - obtain the actual binding object
# that will aloow the call to set the TLS certificate etc.
#
# ------------------------------------------------------------------------------------------------
Function Get-BindingObj
{
	Param(
        [Parameter(Mandatory=$true)]        
        $bindingData
    )
	
	$xpath = $bindingData.ItemXPath
	$bindingInfo = $bindingData.bindingInformation
	
	$siteName = $xpath.substring($xpath.IndexOf("@name")).Split("'")[1]

	# If IPV6 we want to replace everything between square brackets
	$ipV6IpAddress = ($bindingInfo | Select-String '(?<=\[)[^]]+(?=\])' -AllMatches).Matches.Value
	$ipAddress = ""
	if ($ipV6IpAddress)
	{
	    $bindingInfo = $bindingInfo -replace $ipV6IpAddress, ""
	    $bindingInfo = $bindingInfo -replace "[[\]]","_"

        #$ipAddress = $ipV6IpAddress
		$ipAddress = "::1"
	}
	else 
	{
		$ipAddress = $bindingInfo.Split(":")[0]			
	}

	$port = $bindingInfo.Split(":")[1]
	$hostHeader = $bindingInfo.Split(":")[2]
	
	#Write-Host "Site: $siteName, Port: $port, HostHeader: $hostHeader, IP: $ipAddress"
	
	return Get-WebBinding -Name $siteName -Protocol https -Port $port -HostHeader $hostHeader -IPAddress $ipAddress
}


# ------------------------------------------------------------------------------------------------
# For the site provided, read the bindings from the global variable (that would have been loaded
# from settings). Obtain the cert for each binding and check if it is expiring in $settings.renewalDays
# If so, renew the cert and update the binding
#
# ------------------------------------------------------------------------------------------------
Function CheckFor-ExpiringCerts
{
	if ($script:UpdatedBindings)
	{				
		foreach($binding in $script:UpdatedBindings)
		{
			$xpath = $binding.ItemXPath
			$siteName = $xpath.substring($xpath.IndexOf("@name")).Split("'")[1]
			#Write-Event -message "`nChecking certificates for site: $siteName..."

			Write-Event -message "`nChecking site: $siteName, binding: $binding"

			$currentCertificate = Get-ChildItem -Path CERT:LocalMachine/My | Where-Object -Property Thumbprint -EQ -Value $binding.certificateHash
			if (!$currentCertificate)
			{
				Write-Event -message "`nNo certificate bound to site: $siteName, binding: $binding"
			}
			else
			{
				$certSubject = $currentCertificate.Subject
				$certThumbprint = $currentCertificate.Thumbprint
				$expiring = $currentCertificate.NotAfter
				Write-Event -message "Current Certificate - $certSubject Thumbprint: $certThumbprint Expiring $expiring"

				$renewalDays = $global:Settings.renewalDays
				if ($currentCertificate.NotAfter -le (get-date).AddDays($renewalDays))
				{
					Write-Event -message "Is expiring in less than $renewalDays days. Renewing now..."

					# If already renewed - see if we have renewed this one
					$getNewCert = $true;
					if ($renewedCert -eq $true)
					{
						foreach ($tp in $global:renewedCertThumbprints)
						{
							if ($tp.oldCertThumbprint -eq $certThumbprint)
							{
								$Global:thumbprint = $tp.newCertThumbprint
								$getNewCert = $false
								Write-Event -message "Already renewed this cert - just updating bindings"
							}
						}					
					}

					if ($getNewCert)
					{
						# Get certificate dn and common name
						$certDn = $currentCertificate.Subject
						
						$certSans = getSansFromCert $currentCertificate
						
						$csr = Generate-Csr -dn $certDn -sans $certSans
						
						# Need to convert from secure
						$username = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:CertdogSecureUsername))
						$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:CertdogSecurePassword))						
						$cert = Request-Cert -username $username -password $password -caName $global:Settings.certIssuerName -csr "$csr" -teamName $global:Settings.teamName
						Write-Event -message "Obtained new certificate from certdog OK"
						
						# Import the certificate
						$newCert = Import-Cert $cert
						$newCertThumbprint = $newCert.Thumbprint
						$newCertExpiry = $newCert.NotAfter
						Write-Event -message "New Certificate - Thumbprint: $newCertThumbprint Expiring: $newCertExpiry"

						$global:renewedCert = $true
						$global:renewedCertThumbprints += [PSCustomObject]@{
							oldCertThumbprint = $certThumbprint;newCertThumbprint = $newCertThumbprint
						}	
					}

					Write-Event -message "Setting website bindings..."
					
					$bindingObj = Get-BindingObj -bindingData $binding
					$bindingObj.AddSslCertificate($Global:thumbprint, "my")
					Write-Event -message "Bindings set OK.  Certificate renewed OK"
				}
				else
				{
					Write-Event -message "Is not expiring (in the next $renewalDays days)"
				}
			}
		}
	}
	else
	{
		Write-Event -message "No certificates bound to this site`n"
	}
}

# ------------------------------------------------------------------------------------------------
# Displays the startup header
#
# ------------------------------------------------------------------------------------------------
Function Show-Heading
{
	Write-Host "`n`nCertdog Certificate Manager for IIS" -ForegroundColor Gray
	Write-Host "-----------------------------------`n" -ForegroundColor Green
}

# ------------------------------------------------------------------------------------------------
# Updates the Get New Certificate
#
# Prompts for input regarding DN, username and password then requests the cert
# and installs to the machine store.
#
# Optionally can also update the IIS bindings
#
# ------------------------------------------------------------------------------------------------
Function Get-NewCert
{
	Show-Heading
	$commonName = Read-Host "Enter the domain name (e.g. domain.com)"
	if (!$commonName)
	{
		Throw "A domain name is required"
	}
	$dn = "CN=$commonName"
	
	Write-Host "`nCertificate DN will be: " -NoNewline
	Write-Host $dn -ForegroundColor Yellow
	$moreAtttribs = Read-Host "`nDo you wish to add more attributes e.g. O=Org,C=GB? (y/n)"
	if ($moreAtttribs -eq "y")
	{
		$otherDnAttribs = Read-Host "`nEnter additional attributes"
		$dn = "$dn,$otherDnAttribs"		
		Write-Host "`nCertificate DN will be: " -NoNewline
		Write-Host $dn -ForegroundColor Yellow
		$continue = Read-Host "`nContinue? (y/n)"
	}
	else
	{
		$continue = "y"
	}

	
	if ($continue -eq "y")
	{
		
		$cn = Get-CommonNameFromDn -dn $dn

		$sans = Get-Sans -cn $cn

		$username = Get-Username
		
		$password = Get-Password

		$caName = $global:Settings.certIssuerName

		# Generate the CSR
		Write-Host "`nGenerating certificate request..."
		$csr = Generate-Csr -dn $dn -sans $sans
		Write-Host "Request created OK"
		
		# Request and obtain the certificate
		Write-Host "`nRequesting certificate..."
		$cert = Request-Cert -username $username -password $password -caName $caName -csr "$csr" -teamName $global:Settings.teamName
		Write-Host "Obtained certificate OK"
		
		# Import the certificate
		Write-Host "`nImporting certificate..."
		$newCert = Import-Cert $cert
		
		Write-Host "`nCertificate has been issued and imported OK`n"
		
		Save-Credentials	
				
		# Update bindings		
		Update-Bindings
		
		Save-Bindings
		
		# Create scheduled task
		Create-Task		
	}
}

# ------------------------------------------------------------------------------------------------
# Gets the renew log filename - creates the log directory if doesn't already exist
#
# ------------------------------------------------------------------------------------------------
Function Get-RenewLogFile
{
	$dateStamp = get-date -Format yyyyMMddTHHmmss
	$logDir = "$PSScriptRoot\logs"

	if (!(Test-Path $logDir))
	{
		New-Item -ItemType directory -Path $logDir -Force > $null
	}	
	$RenewLogFile = "$($logDir)\$($dateStamp)_certdogrenew.log"	

	return $RenewLogFile
}

# ------------------------------------------------------------------------------------------------
# Renews certs by loading the settings. Each setting file is named:
# [site name]_settings.xml and contains the bindings that have been configured
# when this script was run with the -new switch
# For each site, check the cert associated with the binding. If expiring in $settings.renewalDays
# or sooner, renew the cert and update the binding
#
# ------------------------------------------------------------------------------------------------
Function Renew-Cert
{
	$global:RenewLogFile = Get-RenewLogFile
	
	# all files named *.xml in the .\config dir
	$settingsFiles = Get-ChildItem -Path "$PSScriptRoot\config" -Name -Include *.xml -ErrorAction SilentlyContinue
	
	if ($settingsFiles)
	{
		try
		{
			Write-Event -message "'$script:scriptName -renew' was started. Checking for expiring certs...";
			
			# Keep track of whether we have already renewed a cert and the thumbprints
			# As if already renewed we only want to update the other bindings - not create a new cert
			$global:renewedCertThumbprints = @()
			$global:renewedCert = $false

			foreach ($filename in $settingsFiles)
			{
				Load-Bindings "$PSScriptRoot\config\$filename"
				Load-Credentials
					
				# Check for expiring certs - 
				# For each of the bindings - check 
				CheckFor-ExpiringCerts
			}
			
			#Write-Host "`nCert Check Complete`n`nBye`n"
			
			$log = Get-Content -Raw $global:RenewLogFile
			Write-Host $log
			Write-Event -toEventLog -message $log
		}
		catch 
		{
			Write-Event -message "`nRenew Failed with the following error:`r`n $_"
	
			$log = Get-Content -Raw $global:RenewLogFile
			Write-Host $log
			Write-Event -toEventLog -message $log -isError
			Exit 2
		}
	}
	else
	{
		Write-Event -message "$script:scriptName -renew was run but could not check the expiry of any certificates as there is no config available. First run $script:scriptName -new to configure the certificates and bindings" -isError
		$log = Get-Content -Raw $global:RenewLogFile
		Write-Host $log
		Write-Event -toEventLog -message $log -isError
	}
}

# ------------------------------------------------------------------------------------------------
# Lists the bindings saved in the .\config area that are monitored when -renew is 
# used
# ------------------------------------------------------------------------------------------------
Function List-MonitoredBindings
{
	Write-Host "`nThe following bindings are being monitored:`n"

	$settingsFiles = Get-ChildItem -Path "$PSScriptRoot\config" -Name -Include *.xml
	foreach ($settingsFile in $settingsFiles)
	{
		Load-Bindings "$PSScriptRoot\config\$settingsFile"
		foreach ($binding in $script:UpdatedBindings)
		{
			Write-Host "  $binding"

			$currentCertificate = Get-ChildItem -Path CERT:LocalMachine/My | Where-Object -Property Thumbprint -EQ -Value $binding.certificateHash
			if (!$currentCertificate)
			{
				Write-Host "      No certificate bound`n"
			}
			else
			{
				$certSubject = $currentCertificate.Subject
				$certThumbprint = $currentCertificate.Thumbprint
				$expiring = $currentCertificate.NotAfter

				Write-Host "      Certificate DN: $certSubject Expiring: $expiring`n"
			}
		}
	}
}

# ------------------------------------------------------------------------------------------------
# Load settings from the settings.json file
#
# ------------------------------------------------------------------------------------------------
Function Load-Settings
{
	$settingsPath = "$PSScriptRoot\settings.json"
	if (Test-Path $settingsPath)
	{
		$global:Settings = Get-Content -Path $settingsPath | ConvertFrom-Json
	}
	else 
	{
		Write-Host "Settings could not be located. Searched for $settingsPath"
		Exit
	}
}

Function Setup-Monitor
{
	# TODO: 
	# Don't generate any new certs but just select
	# site and bindings for monitoring when -renew called
	# I.e. monitor existing certificates and renew when required
}

# ------------------------------------------------------------------------------------------------
# This script will read/write to the registry and import certificates to the machine store
# Admin rights are therefore required
#
# ------------------------------------------------------------------------------------------------
Function Exit-IfNotAdmin
{
	If (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
	{
		Write-Host "`nAdministrator privileges are required. Please restart this script with elevated rights`n" -ForegroundColor Yellow
		
		Exit
	}	
}

# -------------------------------------------------------------------------------------------
#
#
#
# -------------------------------------------------------------------------------------------
Exit-IfNotAdmin

try {	
	Load-Settings

	#
	# If URL passed in we use that otherwise what is provided in settings.json
	#
	if (!$certdogUrl)
	{
		$certdogUrl = $global:Settings.certdogUrl
	}

	#
	# If using a non-trusted SSL certificate, provide the -ignoreSslErrors switch
	#
	if ($ignoreSslErrors)
	{
		IgnoreSSLErrors
	}

	if ($new)
	{
		# Run the initial process to create a new certificate, binding and set to auto-renew
		Get-NewCert -username $username -password $password
	}
	elseif ($renew)
	{
		# Run the renewal check and auto-renew process
		Renew-Cert
	}
	elseif ($list)
	{
		# List the monitored URLs
		List-MonitoredBindings
	}
	elseif ($taskonly)
	{
		# Only create the scheduled task
		Create-Task
	}
	elseif ($setcreds)
	{
		# Only update or save credentials
		Save-Credentials
	}
	else {
		Write-Host "Nothing to do. Call either -new, -renew, -list, -taskonly or -setcreds"
	}
}
catch {
	Write-Host $_	
}

# -------------------------------------------------------------------------------------------
# 
# -------------------------------------------------------------------------------------------
# SIG # Begin signature block
# MIIk+gYJKoZIhvcNAQcCoIIk6zCCJOcCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUaHnpgMwYR895I3amRQqGeaCN
# HW2ggh7hMIIFZDCCBEygAwIBAgIRAM25j/9Lvs20l95S6qzivfkwDQYJKoZIhvcN
# AQELBQAwfDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQw
# IgYDVQQDExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwHhcNMjAwNTIwMDAw
# MDAwWhcNMjMwNTIwMjM1OTU5WjCBqTELMAkGA1UEBhMCR0IxETAPBgNVBBEMCEhQ
# MTMgNVVZMRgwFgYDVQQIDA9CdWNraW5naGFtc2hpcmUxFTATBgNVBAcMDEhpZ2gg
# V3ljb21iZTEcMBoGA1UECQwTNzkgTGl0dGxld29ydGggUm9hZDEbMBkGA1UECgwS
# S3Jlc3RmaWVsZCBMaW1pdGVkMRswGQYDVQQDDBJLcmVzdGZpZWxkIExpbWl0ZWQw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCo00r3I7IbUV+cRM5rij46
# vp9j89hIPS4q0cKauz/JLuUIAILUtSUVt9ANLxl45FbTwLSD/S9NXRAKcSejIzS/
# aadkE/taxIJ07fM1208MPrMKVA6EtmfbJ61c/LrZc0097n/oHzqPZHL06+7PoN0P
# 9OWoDF2o0xf5wOKT7ztnNjpfVUcR9QIZOGgqIK5Cdl0ZR/gYW2ZvlWQ3jAIsKQOJ
# m+8Pw5VykR7vQcRl20Dl1txZwnXSScml16mp5fAWVjxMg5bMORoNc8lhit/mUw0E
# jQba6leB7h9BDCfx7bSYfq2BfGdP4bdNQfIu7nZKV7yzjP+iehFQHQnOJguRPzrV
# AgMBAAGjggGxMIIBrTAfBgNVHSMEGDAWgBQO4TqoUzox1Yq+wbutZxoDha00DjAd
# BgNVHQ4EFgQUklhmmnHnHkti7YYbhjHWCUVZTxAwDgYDVR0PAQH/BAQDAgeAMAwG
# A1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEQYJYIZIAYb4QgEBBAQD
# AgQQMEoGA1UdIARDMEEwNQYMKwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0
# dHBzOi8vc2VjdGlnby5jb20vQ1BTMAgGBmeBDAEEATBDBgNVHR8EPDA6MDigNqA0
# hjJodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29SU0FDb2RlU2lnbmluZ0NB
# LmNybDBzBggrBgEFBQcBAQRnMGUwPgYIKwYBBQUHMAKGMmh0dHA6Ly9jcnQuc2Vj
# dGlnby5jb20vU2VjdGlnb1JTQUNvZGVTaWduaW5nQ0EuY3J0MCMGCCsGAQUFBzAB
# hhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTAfBgNVHREEGDAWgRRzYWxlc0BrcmVz
# dGZpZWxkLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAbe/ejc5na4yymmLj2BntXz5U
# K63p/XJ/Pzy6htophko+bjOP7ZzA4o6OgIv4Gtw83usduQJ4EYulXwPGD+fJwUCE
# DjoVbdmCIjzdNmKUcDtAlVB4KCByU1dfHFzAyWqFaj2zdUAwSiNz3sj/sjgFDv6A
# fzPIKvzEgI0mB/8vR63K027/PVlh2sVZk2vyw6mbhfTb9mQASq6zYQZh+tkjkdog
# Aa2gdeySl7r5rEE2TMZMmBX+9sLWT5lSVVh9wGWH6Z436ADjVtdOWh/PJ+B8R0JM
# DaCC/BocCdF9A1khSBdSTOMLXegRByb7yGlli/GbRpugnJub6rnfhb0ifdgUIDCC
# BYEwggRpoAMCAQICEDlyRDr5IrdR19NsEN0xNZUwDQYJKoZIhvcNAQEMBQAwezEL
# MAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
# BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
# GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0xOTAzMTIwMDAwMDBaFw0yODEy
# MzEyMzU5NTlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKTmV3IEplcnNleTEU
# MBIGA1UEBxMLSmVyc2V5IENpdHkxHjAcBgNVBAoTFVRoZSBVU0VSVFJVU1QgTmV0
# d29yazEuMCwGA1UEAxMlVVNFUlRydXN0IFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhv
# cml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIASZRc2DsPbCLPQ
# rFcNdu3NJ9NMrVCDYeKqIE0JLWQJ3M6Jn8w9qez2z8Hc8dOx1ns3KBErR9o5xrw6
# GbRfpr19naNjQrZ28qk7K5H44m/Q7BYgkAk+4uh0yRi0kdRiZNt/owbxiBhqkCI8
# vP4T8IcUe/bkH47U5FHGEWdGCFHLhhRUP7wz/n5snP8WnRi9UY41pqdmyHJn2yFm
# sdSbeAPAUDrozPDcvJ5M/q8FljUfV1q3/875PbcstvZU3cjnEjpNrkyKt1yatLcg
# Pcp/IjSufjtoZgFE5wFORlObM2D3lL5TN5BzQ/Myw1Pv26r+dE5px2uMYJPexMcM
# 3+EyrsyTO1F4lWeL7j1W/gzQaQ8bD/MlJmszbfduR/pzQ+V+DqVmsSl8MoRjVYnE
# DcGTVDAZE6zTfTen6106bDVc20HXEtqpSQvf2ICKCZNijrVmzyWIzYS4sT+kOQ/Z
# Ap7rEkyVfPNrBaleFoPMuGfi6BOdzFuC00yz7Vv/3uVzrCM7LQC/NVV0CUnYSVga
# f5I25lGSDvMmfRxNF7zJ7EMm0L9BX0CpRET0medXh55QH1dUqD79dGMvsVBlCeZY
# Qi5DGky08CVHWfoEHpPUJkZKUIGy3r54t/xnFeHJV4QeD2PW6WK61l9VLupcxigI
# BCU5uA4rqfJMlxwHPw1S9e3vL4IPAgMBAAGjgfIwge8wHwYDVR0jBBgwFoAUoBEK
# Iz6W8Qfs4q8p74Klf9AwpLQwHQYDVR0OBBYEFFN5v1qqK0rPVIDh2JvAnfKyA2bL
# MA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MBEGA1UdIAQKMAgwBgYE
# VR0gADBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
# QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AQEAGIdR3HQhPZyK4Ce3M9AuzOzw5steEd4ib5t1jp5y/uTW/qofnJYt7wNKfq70
# jW9yPEM7wD/ruN9cqqnGrvL82O6je0P2hjZ8FODN9Pc//t64tIrwkZb+/UNkfv3M
# 0gGhfX34GRnJQisTv1iLuqSiZgR2iJFODIkUzqJNyTKzuugUGrxx8VvwQQuYAAoi
# AxDlDLH5zZI3Ge078eQ6tvlFEyZ1r7uq7z97dzvSxAKRPRkA0xdcOds/exgNRc2T
# hZYvXd9ZFk8/Ub3VRRg/7UqO6AZhdCMWtQ1QcydER38QXYkqa4UxFMToqWpMgLxq
# eM+4f452cpkMnf7XkQgWoaNflTCCBfUwggPdoAMCAQICEB2iSDBvmyYY0ILgln0z
# 02owDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpOZXcg
# SmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UEChMVVGhlIFVTRVJU
# UlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNBIENlcnRpZmljYXRp
# b24gQXV0aG9yaXR5MB4XDTE4MTEwMjAwMDAwMFoXDTMwMTIzMTIzNTk1OVowfDEL
# MAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UE
# BxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQwIgYDVQQDExtT
# ZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
# DwAwggEKAoIBAQCGIo0yhXoYn0nwli9jCB4t3HyfFM/jJrYlZilAhlRGdDFixRDt
# socnppnLlTDAVvWkdcapDlBipVGREGrgS2Ku/fD4GKyn/+4uMyD6DBmJqGx7rQDD
# YaHcaWVtH24nlteXUYam9CflfGqLlR5bYNV+1xaSnAAvaPeX7Wpyvjg7Y96Pv25M
# QV0SIAhZ6DnNj9LWzwa0VwW2TqE+V2sfmLzEYtYbC43HZhtKn52BxHJAteJf7wtF
# /6POF6YtVbC3sLxUap28jVZTxvC6eVBJLPcDuf4vZTXyIuosB69G2flGHNyMfHEo
# 8/6nxhTdVZFuihEN3wYklX0Pp6F8OtqGNWHTAgMBAAGjggFkMIIBYDAfBgNVHSME
# GDAWgBRTeb9aqitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQUDuE6qFM6MdWKvsG7
# rWcaA4WtNA4wDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0lBBYwFAYIKwYBBQUHAwMGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQ
# BgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBo
# MD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0
# UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0
# cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAE1jUO1HNEphpNveaiqMm/EAAB4d
# Yns61zLC9rPgY7P7YQCImhttEAcET7646ol4IusPRuzzRl5ARokS9At3WpwqQTr8
# 1vTr5/cVlTPDoYMot94v5JT3hTODLUpASL+awk9KsY8k9LOBN9O3ZLCmI2pZaFJC
# X/8E6+F0ZXkI9amT3mtxQJmWunjxucjiwwgWsatjWsgVgG10Xkp1fqW4w2y1z99K
# eYdcx0BNYzX2MNPPtQoOCwR/oEuuu6Ol0IQAkz5TXTSlADVpbL6fICUQDRn7UJBh
# vjmPeo5N9p8OHv4HURJmgyYZSJXOSsnBf/M6BZv5b9+If8AjntIeQ3pFMcGcTanw
# WbJZGehqjSkEAnd8S0vNcL46slVaeD68u28DECV3FTSK+TbMQ5Lkuk/xYpMoJVcp
# +1EZx6ElQGqEV8aynbG8HArafGd+fS7pKEwYfsR7MUFxmksp7As9V1DSyt39ngVR
# 5UR43QHesXWYDVQk/fBO4+L4g71yuss9Ou7wXheSaG3IYfmm8SoKC6W59J7umDIF
# hZ7r+YMp08Ysfb06dy6LN0KgaoLtO0qqlBCk4Q34F8W2WnkzGJLjtXX4oemOCiUe
# 5B7xn1qHI/+fpFGe+zmAEc3btcSnqIBv5VPU4OOiwtJbGvoyJi1qV3AcPKRYLqPz
# W0sH3DJZ84enGm1YMIIG7DCCBNSgAwIBAgIQMA9vrN1mmHR8qUY2p3gtuTANBgkq
# hkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkx
# FDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5l
# dHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRo
# b3JpdHkwHhcNMTkwNTAyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjB9MQswCQYDVQQG
# EwJHQjEbMBkGA1UECBMSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHEwdTYWxm
# b3JkMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxJTAjBgNVBAMTHFNlY3RpZ28g
# UlNBIFRpbWUgU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDIGwGv2Sx+iJl9AZg/IJC9nIAhVJO5z6A+U++zWsB21hoEpc5Hg7XrxMxJ
# NMvzRWW5+adkFiYJ+9UyUnkuyWPCE5u2hj8BBZJmbyGr1XEQeYf0RirNxFrJ29dd
# SU1yVg/cyeNTmDoqHvzOWEnTv/M5u7mkI0Ks0BXDf56iXNc48RaycNOjxN+zxXKs
# Lgp3/A2UUrf8H5VzJD0BKLwPDU+zkQGObp0ndVXRFzs0IXuXAZSvf4DP0REKV4TJ
# f1bgvUacgr6Unb+0ILBgfrhN9Q0/29DqhYyKVnHRLZRMyIw80xSinL0m/9NTIMdg
# aZtYClT0Bef9Maz5yIUXx7gpGaQpL0bj3duRX58/Nj4OMGcrRrc1r5a+2kxgzKi7
# nw0U1BjEMJh0giHPYla1IXMSHv2qyghYh3ekFesZVf/QOVQtJu5FGjpvzdeE8Nfw
# KMVPZIMC1Pvi3vG8Aij0bdonigbSlofe6GsO8Ft96XZpkyAcSpcsdxkrk5WYnJee
# 647BeFbGRCXfBhKaBi2fA179g6JTZ8qx+o2hZMmIklnLqEbAyfKm/31X2xJ2+opB
# JNQb/HKlFKLUrUMcpEmLQTkUAx4p+hulIq6lw02C0I3aa7fb9xhAV3PwcaP7Sn1F
# NsH3jYL6uckNU4B9+rY5WDLvbxhQiddPnTO9GrWdod6VQXqngwIDAQABo4IBWjCC
# AVYwHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZsswHQYDVR0OBBYEFBqh
# +GEZIA/DQXdFKI7RNV8GEgRVMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAG
# AQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBEGA1UdIAQKMAgwBgYEVR0gADBQ
# BgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVzdC5jb20vVVNFUlRy
# dXN0UlNBQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwdgYIKwYBBQUHAQEEajBo
# MD8GCCsGAQUFBzAChjNodHRwOi8vY3J0LnVzZXJ0cnVzdC5jb20vVVNFUlRydXN0
# UlNBQWRkVHJ1c3RDQS5jcnQwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnVzZXJ0
# cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAG1UgaUzXRbhtVOBkXXfA3oyCy0l
# hBGysNsqfSoF9bw7J/RaoLlJWZApbGHLtVDb4n35nwDvQMOt0+LkVvlYQc/xQuUQ
# ff+wdB+PxlwJ+TNe6qAcJlhc87QRD9XVw+K81Vh4v0h24URnbY+wQxAPjeT5OGK/
# EwHFhaNMxcyyUzCVpNb0llYIuM1cfwGWvnJSajtCN3wWeDmTk5SbsdyybUFtZ83J
# b5A9f0VywRsj1sJVhGbks8VmBvbz1kteraMrQoohkv6ob1olcGKBc2NeoLvY3NdK
# 0z2vgwY4Eh0khy3k/ALWPncEvAQ2ted3y5wujSMYuaPCRx3wXdahc1cFaJqnyTdl
# Hb7qvNhCg0MFpYumCf/RoZSmTqo9CfUFbLfSZFrYKiLCS53xOV5M3kg9mzSWmglf
# jv33sVKRzj+J9hyhtal1H3G/W0NdZT1QgW6r8NDT/LKzH7aZlib0PHmLXGTMze4n
# muWgwAxyh8FuTVrTHurwROYybxzrF06Uw3hlIDsPQaof6aFBnf6xuKBlKjTg3qj5
# PObBMLvAoGMs/FwWAKjQxH/qEZ0eBsambTJdtDgJK0kHqv3sMNrxpy/Pt/360KOE
# 2See+wFmd7lWEOEgbsausfm2usg1XTN2jvF8IAwqd661ogKGuinutFoAsYyr4/kK
# yVRd1LlqdJ69SK6YMIIHBzCCBO+gAwIBAgIRAIx3oACP9NGwxj2fOkiDjWswDQYJ
# KoZIhvcNAQEMBQAwfTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFu
# Y2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMSUwIwYDVQQDExxTZWN0aWdvIFJTQSBUaW1lIFN0YW1waW5nIENBMB4XDTIw
# MTAyMzAwMDAwMFoXDTMyMDEyMjIzNTk1OVowgYQxCzAJBgNVBAYTAkdCMRswGQYD
# VQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNV
# BAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAwwjU2VjdGlnbyBSU0EgVGltZSBT
# dGFtcGluZyBTaWduZXIgIzIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQCRh0ssi8HxHqCe0wfGAcpSsL55eV0JZgYtLzV9u8D7J9pCalkbJUzq70DWmn4y
# yGqBfbRcPlYQgTU6IjaM+/ggKYesdNAbYrw/ZIcCX+/FgO8GHNxeTpOHuJreTAdO
# hcxwxQ177MPZ45fpyxnbVkVs7ksgbMk+bP3wm/Eo+JGZqvxawZqCIDq37+fWuCVJ
# wjkbh4E5y8O3Os2fUAQfGpmkgAJNHQWoVdNtUoCD5m5IpV/BiVhgiu/xrM2HYxiO
# dMuEh0FpY4G89h+qfNfBQc6tq3aLIIDULZUHjcf1CxcemuXWmWlRx06mnSlv53mT
# DTJjU67MximKIMFgxvICLMT5yCLf+SeCoYNRwrzJghohhLKXvNSvRByWgiKVKoVU
# rvH9Pkl0dPyOrj+lcvTDWgGqUKWLdpUbZuvv2t+ULtka60wnfUwF9/gjXcRXyCYF
# evyBI19UCTgqYtWqyt/tz1OrH/ZEnNWZWcVWZFv3jlIPZvyYP0QGE2Ru6eEVYFCl
# sezPuOjJC77FhPfdCp3avClsPVbtv3hntlvIXhQcua+ELXei9zmVN29OfxzGPATW
# McV+7z3oUX5xrSR0Gyzc+Xyq78J2SWhi1Yv1A9++fY4PNnVGW5N2xIPugr4srjcS
# 8bxWw+StQ8O3ZpZelDL6oPariVD6zqDzCIEa0USnzPe4MQIDAQABo4IBeDCCAXQw
# HwYDVR0jBBgwFoAUGqH4YRkgD8NBd0UojtE1XwYSBFUwHQYDVR0OBBYEFGl1N3u7
# nTVCTr9X05rbnwHRrt7QMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYG
# A1UdJQEB/wQMMAoGCCsGAQUFBwMIMEAGA1UdIAQ5MDcwNQYMKwYBBAGyMQECAQMI
# MCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20vQ1BTMEQGA1UdHwQ9
# MDswOaA3oDWGM2h0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRpbWVT
# dGFtcGluZ0NBLmNybDB0BggrBgEFBQcBAQRoMGYwPwYIKwYBBQUHMAKGM2h0dHA6
# Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1JTQVRpbWVTdGFtcGluZ0NBLmNydDAj
# BggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEM
# BQADggIBAEoDeJBCM+x7GoMJNjOYVbudQAYwa0Vq8ZQOGVD/WyVeO+E5xFu66ZWQ
# Nze93/tk7OWCt5XMV1VwS070qIfdIoWmV7u4ISfUoCoxlIoHIZ6Kvaca9QIVy0RQ
# mYzsProDd6aCApDCLpOpviE0dWO54C0PzwE3y42i+rhamq6hep4TkxlVjwmQLt/q
# iBcW62nW4SW9RQiXgNdUIChPynuzs6XSALBgNGXE48XDpeS6hap6adt1pD55aJo2
# i0OuNtRhcjwOhWINoF5w22QvAcfBoccklKOyPG6yXqLQ+qjRuCUcFubA1X9oGsRl
# KTUqLYi86q501oLnwIi44U948FzKwEBcwp/VMhws2jysNvcGUpqjQDAXsCkWmcmq
# t4hJ9+gLJTO1P22vn18KVt8SscPuzpF36CAT6Vwkx+pEC0rmE4QcTesNtbiGoDCn
# i6GftCzMwBYjyZHlQgNLgM7kTeYqAT7AXoWgJKEXQNXb2+eYEKTx6hkbgFT6R4no
# mIGpdcAO39BolHmhoJ6OtrdCZsvZ2WsvTdjePjIeIOTsnE1CjZ3HM5mCN0TUJikm
# QI54L7nu+i/x8Y/+ULh43RSW3hwOcLAqhWqxbGjpKuQQK24h/dN8nTfkKgbWw/HX
# aONPB3mBCBP+smRe6bE85tB4I7IJLOImYr87qZdRzMdEMoGyr8/fMYIFgzCCBX8C
# AQEwgZEwfDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3Rl
# cjEQMA4GA1UEBxMHU2FsZm9yZDEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSQw
# IgYDVQQDExtTZWN0aWdvIFJTQSBDb2RlIFNpZ25pbmcgQ0ECEQDNuY//S77NtJfe
# Uuqs4r35MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkG
# CSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEE
# AYI3AgEVMCMGCSqGSIb3DQEJBDEWBBQBxJSSxmcpjAU6goc8NTkq2TEW6DANBgkq
# hkiG9w0BAQEFAASCAQAho224q/K5jT1QY7/U2N/uscBScr1DqxPnloFPHaLmm6AD
# VTQlp4sUQDYkhjDn8eeoXhuaZfBOGudFy97QjHEqrNm0ckckLpNwNWEzLN0OWnNA
# SRCSkVls5xMjvQliGW02lgbBjukWDmLuyt1nbgr/gJspaZHF95jTyuel5KYckcEt
# NfhvsfqzRyMTXo1+svIChu1bJX0ylyrnulWgrYIZg7kCkmMNPBI39yMSu8AuiY94
# UwebtGA15zgvXL1vttMkqHRfZN7IjoKsME1+wJYVdkv3i4oDoOSOgZQJWtJ0atjA
# kATaCI96JyW8boEZGEAQ0q2vdGc1CRAmHzIOLsYjoYIDTDCCA0gGCSqGSIb3DQEJ
# BjGCAzkwggM1AgEBMIGSMH0xCzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVy
# IE1hbmNoZXN0ZXIxEDAOBgNVBAcTB1NhbGZvcmQxGDAWBgNVBAoTD1NlY3RpZ28g
# TGltaXRlZDElMCMGA1UEAxMcU2VjdGlnbyBSU0EgVGltZSBTdGFtcGluZyBDQQIR
# AIx3oACP9NGwxj2fOkiDjWswDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG9w0BCQMx
# CwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMTAzMjkxNDMwMTBaMD8GCSqG
# SIb3DQEJBDEyBDCpSPP6fvfHZqsMxXDVJa4u8AsQ3VkG9/17US9Mx4+8eFoUYR0S
# zwgPQ2qy02X+SogwDQYJKoZIhvcNAQEBBQAEggIAIuJZz0dGlTQXlG2mJTWM+Oei
# YrLwDkG4S8Lr8l82cQJQTez56NfzAXVESd5ztD41dj7bo6v8LGCz79cTv+4L8gY3
# YOAIXOA8+Rm00hSyztD8FOy16rIP6DmRdpePDxZxVH4b4fKVm1iBHiK/E5443Dco
# x6PdMBmr0i5L4uDvi7vt1ccFcNqQcpoeJe06xayGLbO4RhU2g6uiAcZaNBEHGES2
# FSpc/0FT+nIkx/rkQ4u1ZvMhhXDoIwm6Xti/ZTZERgM0OjkuGsiPpmxMAp0gWqOY
# P0LRrZCREzjrO/LMyUyOSa+KZRtRKEc2geto/7+HT2xxy2VS68xN2NLfJ05sNezp
# /HGLwMlV4tgmGx1IRPjXl3mBJi1Unm2JWvNzbMovdOMMO+s2Rmz0hqGL9o72hw/C
# tDYOFLP1Fha6I39HyDqgsYVMcXx3BRycJZ2qmCW7aoHSO2S/uGER10xpHYEyfiyG
# 11KH7qTSBYTWv3f/r7IjuLcwnmXhHlQTDxaj3z0kM2R54zMF5t3AQEMFBjq9JRu+
# 44GAc+b5k6i882N9qK2oIEPXUHxNfurG1QmcJeR1DDA42nzEtrgffmRwceT962xh
# YtMbmOYisgVERl/YbBqNtSkZZTgMmM0idkvg/k/dtpgunCjXSUifq7qRg3Ouq74f
# wuCIIRwOIzBc+KmwqaM=
# SIG # End signature block
