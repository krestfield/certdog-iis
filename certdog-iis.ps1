# ------------------------------------------------------------------------------------------------
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
        $extraInfo,
        [Parameter(Mandatory=$false)]
        [string[]]$extraEmails,
        [Parameter(Mandatory=$false)]
        $display
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
        $csr
    )

	if ($script:loggedIn -eq $false)
	{
		login -username $username -password $password
		$script:loggedIn = $true
	}
	
	$cert = Request-CertP10 -caName $caName -csr $csr

	#Logout
	
	return $cert
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
						$cert = Request-Cert -username $username -password $password -caName $global:Settings.certIssuerName -csr "$csr"
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
		$csr = Generate-Csr -dn $dn -sans $sans
		
		# Request and obtain the certificate
		$cert = Request-Cert -username $username -password $password -caName $caName -csr "$csr"
		
		# Import the certificate
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
	$settingsFiles = Get-ChildItem -Path "$PSScriptRoot\config" -Name -Include *.xml
	
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
		Write-Event -message "Nothing to do. Call either -new, -renew, -list, -taskonly or -setcreds"
	}
}
catch {
	Write-Host $_	
}


# -------------------------------------------------------------------------------------------
# 
# -------------------------------------------------------------------------------------------
