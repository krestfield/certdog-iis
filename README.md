# Certdog IIS PowerShell Script

This script can be used to generate certificates, bind them to IIS sites and then automatically renew  

Full details on this script can be found here [https://krestfield.github.io/docs/certdog/iis_powershell.html](https://krestfield.github.io/docs/certdog/iis_powershell.html)



## Pre-requisites

An instance of certdog is required. A Docker image of certdog can be obtained from here:  

[https://hub.docker.com/r/krestfield/certdog](https://hub.docker.com/r/krestfield/certdog)

You may also install the application locally. Contact [Krestfield Support](mailto:support@krestfield.com) to obtain the installer



Certdog can interface to your Microsoft CAs or PrimeKey EJBCAs providing a simple UI or a REST API (as is used by this script) to automate the issuance of certificates

To learn more about certdog, go [here](https://krestfield.com/certdog)



## Overview

The script can generate a local CSR (stored in the Local Machine certificate store), with additional SANs (subject alternative names), if required  

This can be processed by the certdog application, and the issued certificate installed  

IIS bindings can then be updated with the new certificate details  

The script can also create a scheduled task which will, by default, run every day and check the expiry of the certificates bound to the bindings selected. When nearing expiry, the certificate will be automatically renewed and the relevant IIS binding updated



## Running

Open a PowerShell window as Administrator



Simple run options:

```powershell
.\certdog-iis.ps1 -new
```

This will prompt for all information including the certdog login as well as the binding and certificate details



To provide the certdog authentication details (and not be prompted for username/password), run:

```powershell
.\certdog-iis.ps1 -new -username [certdoguser] -password [certdogpassword]
```

  

 Once the above has been performed the script saves the required information. Running:

```powershell
.\certdog-iis.ps1 -renew
```

Will check and process any renewals required for the sites and bindings configured when the ``-new`` switch was used

  

As above, this can be run with the username and password options:

```powershell
.\certdog-iis.ps1 -renew -username [certdoguser] -password [certdogpassword]
```

 



 To list what bindings are being monitored:

```powershell
.\certdog-iis.ps1 -list
```

   

 To just create a scheduled task that runs the ``.\certdog-iis.ps1 -renew`` script daily, run

```powershell
.\certdog-iis.ps1 -taskonly
```



To override the certdog URL as specified in the ``settings.json`` file, use ``-certdogUrl`` e.g.

```powershell
.\certdog-iis.ps1 -new -certdogUrl https://certdog.org.com/certdog/api
```

   

To ignore any SSL errors (if the certdog URL is not protected with a trusted cert), use ``-ignoreSslErrors`` e.g.

```powershell
.\certdog-iis.ps1 -new -ignoreSslErrors
```

   

## Settings (settings.json)

Settings are stored within the ``settings.json`` file. Sample contents:

```json
{
	"certdogUrl" : "https://127.0.0.1/certdog/api",
	"certIssuerName" : "Test CA",
	"renewalDays" : 30,
	"csrKeyLength" : 2048,
	"csrHash" : "sha256",
	"csrProvider" : "Microsoft RSA SChannel Cryptographic Provider",
	"csrProviderType" : 12,
	"exportable" : "FALSE",
	"eventLogId" : 5280,
	"errorLogId" : 5281
}
```

* certdogUrl

The URL of the certdog installation's api. If using the Docker image the default setting will operate OK

* certIssuer

The name of the certificate issuer as configured in certdog (e.g. Certdog TLS Issuer)

* renewalDays

When the script is run with the *-renew* option this value will be used when deciding whether to renew certificates or not

If a certificate is expiring in *renewalDays* (or fewer) the renewal process will initiate

* csrKeyLength

When a new CSR is generated (when creating a new or renewing a current certificate), this key length will be used

* csrHash

The hash used to generate the CSR

* csrProvider

This is the Microsoft provider that will be used to generate the CSR

* csrProviderType

This depends on the csrProvider selected and must match. See [here](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.cspparameters.providertype?view=net-5.0) for more information

* exportable

If TRUE then it will be permitted for the private key of the issued certificate to be exported (e.g. as a password protected PFX/PKCS#12 file)

* eventLogId

This is the Event Log ID that will be assigned to entries the script adds. If monitoring events, you may need to note this value. It can also be updated here

* errorLogId

This is the Event Log ID that will be assigned to entries the script adds when errors occur. If monitoring error events, you may need to note this value. It can also be updated here



