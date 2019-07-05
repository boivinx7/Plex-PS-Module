<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.163
	 Created on:   	2019-05-23 9:44 AM
	 Created by:   	Administrator
	 Organization: 	
	 Filename:     	Plex-PS-Module.psm1
	-------------------------------------------------------------------------
	 Module Name: Plex-PS-Module
	===========================================================================
#>

<#
	.SYNOPSIS
		Get plex user toker from plex.tv
	
	.DESCRIPTION
		Can be use for the Token parameter in othe functions
		if you dont know how to get it yourself
	
	.PARAMETER Credentials
		A description of the Credentials parameter.
	
	.EXAMPLE
				PS C:\> Get-PlexTVToken
	
	.NOTES
		Additional information about the function.
#>
function Get-PlexTVToken
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $false)]
		[pscredential]$Credentials
	)
	
	$url = "https://plex.tv/users/sign_in.xml"
	if ([string]::IsNullOrEmpty($Credentials) -ne $true)
	{
		$cred = Get-Credential -Credential $Credentials
	}
	else
	{
		$cred = Get-Credential
	}
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $cred.GetNetworkCredential().UserName, $cred.GetNetworkCredential().Password)))
	$headers = @{ }
	$headers.Add("Authorization", "Basic $($base64AuthInfo)") | out-null
	$headers.Add("X-Plex-Client-Identifier", "TESTSCRIPTV1") | Out-Null
	$headers.Add("X-Plex-Product", "Test script") | Out-Null
	$headers.Add("X-Plex-Version", "V1") | Out-Null
	[xml]$res = Invoke-RestMethod -Headers $headers -Method Post -Uri:$url
	$token = $res.user.authenticationtoken
	return $token
}

<#
	.SYNOPSIS
		Use to Get list of Servers and the IP and Ports
	
	.DESCRIPTION
		Use this to fill the $hostname Variable for all other founctions if you dont know it by heart
	
	.PARAMETER Credentials
		A description of the Credentials parameter.
	
	.EXAMPLE 1
		PS C:\> $UserName = PLEX_USERNAME
		PS C:\> $PlexPassword = PLEX_PASSWORD
		PS C:\> $password = ConvertTo-SecureString $PlexPassword -AsPlainText -Force
		PS C:\> $Cred = New-Object System.Management.Automation.PSCredential ($UserName, $password)
		PS C:\> $PlexServerList = Get-PlexServerList -Credentials $Cred | where-object {$_.Name -eq "PLEX_SERVER_NAME"}
		PS C:\> $PlexServerList.HostAdress

	.EXAMPLE 2
		PS C:\> $UserName = PLEX_USERNAME
		PS C:\> $PlexPassword = PLEX_PASSWORD
		PS C:\> $password = ConvertTo-SecureString $PlexPassword -AsPlainText -Force
		PS C:\> $Cred = New-Object System.Management.Automation.PSCredential ($UserName, $password)
		PS C:\> Get-PlexServerList -Credentials $Cred

	.EXAMPLE 3
		PS C:\> Get-PlexServerList

	.EXAMPLE 4
		PS C:\> $PlexServerList = Get-PlexServerList | where-object {$_.Name -eq "PLEX_SERVER_NAME"}
		PS C:\> $PlexServerList.HostAdress
	
	.NOTES
		The Credential Parameter is not Mandatory.
		Also it is best to use exemple 2,3 first and then use 1,4 to put in variable this way you will see the list first.
#>
function Get-PlexTVServerList
{
	[CmdletBinding()]
	[OutputType([array])]
	param
	(
		[Parameter(Mandatory = $false)]
		[pscredential]$Credentials
	)
	
	$url = "https://plex.tv/pms/servers.xml"
	if ([string]::IsNullOrEmpty($Credentials) -ne $true)
	{
		$cred = Get-Credential -Credential $Credentials
	}
	else
	{
		$cred = Get-Credential
	}
	$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $cred.GetNetworkCredential().UserName, $cred.GetNetworkCredential().Password)))
	$headers = @{ }
	$headers.Add("Authorization", "Basic $($base64AuthInfo)") | out-null
	$headers.Add("X-Plex-Client-Identifier", "TESTSCRIPTV1") | Out-Null
	$headers.Add("X-Plex-Product", "Test script") | Out-Null
	$headers.Add("X-Plex-Version", "V1") | Out-Null
	[xml]$res = Invoke-RestMethod -Headers $headers -Method GET -Uri $url
	$Servers = $res.MediaContainer.Server | select name, localAddresses, port
	$array = @()
	foreach ($Server in $Servers)
	{
		$Object = New-Object PSObject
		Add-Member -InputObject $Object -TypeName Noteproperty -NotePropertyName Name -NotePropertyValue $Server.name
		$IpAdress = $Server.localAddresses
		if ($IpAdress -like '*,*')
		{
			$IP = $IpAdress.split(',')
			$HostAddress = $IP[0] + ":" + $Server.port
		}
		else
		{
			$HostAddress = $IpAdress + ":" + $Server.port
		}
		Add-Member -InputObject $Object -TypeName Noteproperty -NotePropertyName HostAdress -NotePropertyValue $HostAddress
		$array += $object
	}
	return $array
}

function Test-PlexConnection ($hostname, $Token)
{
	$URI = "http://$hostname/?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer
}

<#
	.SYNOPSIS
		Get the Section Key From Library Sections
	
	.DESCRIPTION
		A detailed description of the Get-PlexSectionKey function.
	
	.PARAMETER hostname
		A description of the hostname parameter.
	
	.PARAMETER Token
		A description of the Token parameter.
	
	.PARAMETER Libraryname
		A description of the Library parameter.
	
	.EXAMPLE
		PS C:\> Get-PlexSectionKey -Library $value1
	
	.NOTES
		Additional information about the function.
#>
function Get-PlexSectionKey
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$hostname,
		[Parameter(Mandatory = $true)]
		[string]$Token,
		[Parameter(Mandatory = $true)]
		[string]$LibraryName
	)
	
	$Libraries = Get-PlexLibrarieSections -hostname $hostname -Token $Token
	$SelectedSection = $Libraries | Where-Object { $_.title -eq $LibraryName }
	$SelectedSection.key
}

function Get-PlexLibrarieSections ($hostname, $Token)
{
	$URI = "http://$hostname/library/sections?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.Directory | Select-Object title, type, key
}

function Get-PlexOnDeck ($hostname, $Token)
{
	$URI = "http://$hostname/library/onDeck?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.Video
}


<#function Get-PlexUpdateLibrary ($hostname, $Token, $Section) 
{
    $URI = "http://$hostname/library/sections/$Section/refresh?X-Plex-Token=$Token"
    Invoke-WebRequest -Uri $URI
}

function Get-PlexRefreshEntireLibrary ($hostname, $Token, $Section) 
{
    $URI = "http://$hostname/library/sections/$Section/refresh?force=1&X-Plex-Token=$Token"
    Invoke-WebRequest -Uri $URI
}
#>
function Get-PlexListLibraryContent ($hostname, $Token, $LibraryName)
{
	$Section = Get-PlexSectionKey -hostname $hostname -Token $Token -LibraryName $LibraryName
	$URI = "http://$hostname/library/sections/$Section/all?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.Video
}

function Get-PlexVideoMetadata ($hostname, $Token, $RatingKey)
{
	$URI = "http://$hostname/library/metadata/$RatingKey" + "?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.Video
	
}

function Set-PlexVideoWatchedStatus
{
	Param (
		[Parameter(Mandatory = $True, Position = 1)]
		[string]$hostname,
		[Parameter(Mandatory = $True, Position = 1)]
		[string]$token,
		[Parameter(Mandatory = $True, ValueFromPipeline = $true, Position = 0)]
		[PSobject[]]$RatingKey,
		[Parameter(Mandatory = $True)]
		[ValidateSet('Watched', 'Unwatched')]
		[string]$ViewedStatus
	)
	
	If ($ViewedStatus.ToLower() -eq "watched")
	{
		$ScrobbleAction = "scrobble"
	}
	Else
	{
		$ScrobbleAction = "unscrobble"
	}
	$URI = "http://$hostname/:/$ScrobbleAction" + "?key=" + $RatingKey + "&identifier=com.plexapp.plugins.library&" + "X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Invoke
	
}

function Get-PlexSearchMedia ($hostname, $Token, $Search)
{
	$URI = "http://$hostname/search/?query=$Search&" + "X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.Video
}

function Set-PlexCollectionMovie ($hostname, $Token, $CollectionName, $Section, $RatingKey)
{
	$URL = @"
type=1&id=$RatingKey&collection[0].tag.tag=$CollectionName
"@
	$Encode = [uri]::EscapeUriString($URL)
	$Encode = $Encode.Replace('%20', '+')
	$URI = "http://$hostname/library/sections/$Section/all?" + $Encode + "&X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI -Method PUT
	$Invoke.StatusDescription
}


function Get-PlexServerPreferences ($hostname, $Token)
{
	$URI = "http://$hostname/:/prefs/?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.setting
}

function Get-PlexLocalServers ($hostname, $Token)
{
	$URI = "http://$hostname/servers/?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.server
}

function Get-PlexSystemInformation ($hostname, $Token)
{
	$URI = "http://$hostname/system/?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.Directory
}

function Get-PlexAvailableAgents ($hostname, $Token)
{
	$URI = "http://$hostname/system/agents/?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.agent
}

function Get-PlexSessionsStatus ($hostname, $Token)
{
	$URI = "http://$hostname/status/sessions/?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.video
}

function Get-PlexSessionsHistory ($hostname, $Token)
{
	$URI = "http://$hostname/status/sessions/history/all/?X-Plex-Token=$Token"
	$Invoke = Invoke-WebRequest -Uri $URI
	$Xmlfile = [XML]$Invoke.content
	$Xmlfile.MediaContainer.video
}
