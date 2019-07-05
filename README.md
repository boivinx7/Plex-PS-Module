# Plex-PS-Module

Powershell Module based on Plex Web API
https://github.com/Arcanemagus/plex-api/wiki/Plex-Web-API-Overview

I'm building this module Since there are some functions I wanted to modify collections in Batchs.
And it now can work, But I never continued.

You Will need to Find your token to work with this
You can Either use
https://support.plex.tv/articles/204059436-finding-an-authentication-token-x-plex-token/

Or Continue Reading

![alt text](https://i.imgur.com/VaxfaAq.png)

# Getting started
## One-time setup (PowerShell Gallery)
1. Install the Plex-PS-Module module from: https://www.powershellgallery.com/packages/Plex-PS-Module
```PowerShell
Install-Module -Name Plex-PS-Module
```

## To Find your Token by Script
You will need to create a Secure String and PSCreditial Object.
```PowerShell
$UserName = "USER NAME"
$PlexPassword = "Change ME"
$password = ConvertTo-SecureString $PlexPassword -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($UserName, $password)
Get-PlexTVToken -Credentials $Cred
```
## Exemple
```PowerShell
$PLEXHOST = "192.168.1.111:32400"
$PLEXTOKEN = "Token"
Get-PlexSessionsHistory -hostname $PLEXHOST -token $PLEXTOKEN
```

## Note
Verb-PlexTV****  Functions Use Plex.tv and not your server that's why you need to authenticate with pscredentials
