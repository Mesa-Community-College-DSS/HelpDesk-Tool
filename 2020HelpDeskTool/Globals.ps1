#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------
#$global:tagnumber = $txtBoxTag.Text
#$global:devicename = $txtBoxTag.Text

#Sample function that provides the location of the script
function Get-ScriptDirectory
{
<#
	.SYNOPSIS
		Get-ScriptDirectory returns the proper location of the script.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory

function Write-Status
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Message
	)
	$statusBar1.Text = $Message
}

function Connect-MC1
{
	[CmdletBinding()]
	[Alias()]
	[OutputType([int])]
	Param
	(
		# Param1 help description
		[Parameter(Mandatory = $false,
				   ValueFromPipelineByPropertyName = $true,
				   Position = 0)]
		$Param1,
		# Param2 help description

		[int]$Param2
	)
	
	# This script was auto-generated at '6/3/2020 11:30:56 AM'.
	
	# Uncomment the line below if running in an environment where script signing is 
	# required.
	#Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
	
	# Site configuration
	$SiteCode = "MC1" # Site code 
	$ProviderMachineName = "sdcm01.ad.mc.local" # SMS Provider machine name
	
	# Customizations
	$initParams = @{ }
	#$initParams.Add("Verbose", $true) # Uncomment this line to enable verbose logging
	#$initParams.Add("ErrorAction", "Stop") # Uncomment this line to stop the script on any errors
	
	# Do not change anything below this line
	
	# Import the ConfigurationManager.psd1 module 
	if ((Get-Module ConfigurationManager) -eq $null)
	{
		Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams
	}
	
	# Connect to the site's drive if it is not already present
	if ((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null)
	{
		New-PSDrive -Credential $global:underscore -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName -Scope Script @initParams
	} 
	
	# Set the current location to be the site code.
	Set-Location "$($SiteCode):\" @initParams
	
	
}


Function Start-CMClientAction
{
	[cmdletbinding()]
	Param
	(
		[Parameter(ValueFromPipeline = $True,
				   ValueFromPipelineByPropertyName = $True,
				   HelpMessage = 'Enter the name of either one or more computers')]
		[Alias('CN')]
		$ComputerName = $env:COMPUTERNAME,
		[Parameter(ParameterSetName = 'Set 1',
				   HelpMessage = 'Enter the SCCM client action numerical value')]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(1, 49)]
		[Alias('SCA')]
		[Int]$SCCMClientAction,
		[Parameter(ParameterSetName = 'Set 2',
				   HelpMessage = 'Use this switch parameter to run the following 3 SCCM client actions: Machine Policy Retrieval & Evaluation Cycle, Software Updates Scan Cycle, and Software Updates Deployment Evaluation Cycle')]
		[Alias('SMB')]
		[Switch]$SCCMMachineBundle,
		[Parameter(ParameterSetName = 'Set 3',
				   HelpMessage = 'Use this switch parameter to run the following 3 SCCM client actions: Machine Policy Retrieval & Evaluation Cycle, Software Updates Scan Cycle, and Software Updates Deployment Evaluation Cycle')]
		[Alias('SAB')]
		[Switch]$SCCMActionsBundle,
		[Parameter(ParameterSetName = 'Set 4',
				   HelpMessage = 'Use this switch parameter to run the following 3 SCCM client actions: Machine Policy Retrieval & Evaluation Cycle, Software Updates Scan Cycle, and Software Updates Deployment Evaluation Cycle')]
		[Alias('SSA')]
		[Switch]$SCCMSoftwareAction
		
	)
	
	Begin
	{
		$NewLine = "`r`n"
		
		If ($ComputerName -eq $env:COMPUTERNAME)
		{
			$ComputerVar = $ComputerName.ToUpper()
		}
		
	}
	
	Process
	{
		Switch ($SCCMSoftwareAction)
		{
			'1' { $ClientAction = '{00000000-0000-0000-0000-000000000001}' }
			
		}
		
		If ($PSBoundParameters.Keys.Contains('SCCMActionsBundle'))
		{
			Foreach ($Computer in $ComputerVar)
			{
				Write-Output -Verbose '---------- Running Full SCCM Actions Bundle ----------'
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '========================'
					Write-Output -Verbose 'Hardware Inventory Cycle'
					Write-Output -Verbose '========================'
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000001}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Hardware Inventory Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '==============================='
					Write-Output -Verbose 'Discovery Data Collection Cycle'
					Write-Output -Verbose '==============================='
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000003}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Discovery Data Collection Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '==========================================='
					Write-Output -Verbose 'Machine Policy Retrieval & Evaluation Cycle'
					Write-Output -Verbose '==========================================='
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000021}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Machine Policy Retrieval and Evaluation Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '==========================='
					Write-Output -Verbose 'Software Updates Scan Cycle'
					Write-Output -Verbose '==========================='
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000113}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Software Updates Scan Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '======================================='
					Write-Output -Verbose 'Application Deployment Evaluation Cycle'
					Write-Output -Verbose '======================================='
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000121}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Application Deployment Evaluation Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '========================'
					Write-Output -Verbose 'Software Inventory Cycle'
					Write-Output -Verbose '========================'
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000002}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Software Inventory Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '============================================'
					Write-Output -Verbose 'Software Updates Deployment Evaluation Cycle'
					Write-Output -Verbose '============================================'
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000108}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Software Updates Deployment Evaluation Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
			}
		}
		elseif ($PSBoundParameters.Keys.Contains('SCCMMachineBundle'))
		{
			Foreach ($Computer in $ComputerVar)
			{
				Write-Output -Verbose '---------- Running SCCM Machine Actions Bundle ----------'
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '========================'
					Write-Output -Verbose 'Hardware Inventory Cycle'
					Write-Output -Verbose '========================'
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000001}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Hardware Inventory Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '==============================='
					Write-Output -Verbose 'Discovery Data Collection Cycle'
					Write-Output -Verbose '==============================='
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000003}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Discovery Data Collection Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '==========================================='
					Write-Output -Verbose 'Machine Policy Retrieval & Evaluation Cycle'
					Write-Output -Verbose '==========================================='
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000021}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Machine Policy Retrieval and Evaluation Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
			}
		}
		elseif ($PSBoundParameters.Keys.Contains('SCCMSoftwareAction'))
		{
			Foreach ($Computer in $ComputerVar)
			{
				Write-Output -Verbose '---------- Running SCCM Client Actions Bundle ----------'
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '==========================='
					Write-Output -Verbose 'Software Updates Scan Cycle'
					Write-Output -Verbose '==========================='
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000113}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Software Updates Scan Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '======================================='
					Write-Output -Verbose 'Application Deployment Evaluation Cycle'
					Write-Output -Verbose '======================================='
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000121}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Application Deployment Evaluation Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '========================'
					Write-Output -Verbose 'Software Inventory Cycle'
					Write-Output -Verbose '========================'
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000002}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Software Inventory Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
				
				Try
				{
					$NewLine
					
					Write-Output -Verbose '============================================'
					Write-Output -Verbose 'Software Updates Deployment Evaluation Cycle'
					Write-Output -Verbose '============================================'
					
					$NewLine
					
					Invoke-WmiMethod -ComputerName $Computer -Namespace root\ccm -Class sms_client -Name TriggerSchedule -ArgumentList '{00000000-0000-0000-0000-000000000108}' -ErrorAction Stop
					
					$NewLine
					
					Write-Output -Verbose 'Software Updates Deployment Evaluation Cycle action successfully initiated'
					
					$NewLine
					
					Write-Output -Verbose 'Waiting 30 Second before running next SCCM client action...'
					
					Start-Sleep -Seconds 30
					
					$NewLine
				}
				
				Catch
				{
					$NewLine
					
					Write-Warning -Message "The following error occurred when trying to run the specified SCCM client action on computer ${Computer}: $_"
					
					$Newline
					
					Break
				}
			}
		}
		
	}
	
	End { }
}

Function Install-RSAT
{
	
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[switch]$All,
		[parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[switch]$Basic,
		[parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[switch]$ServerManager,
		[parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[switch]$Uninstall
	)
	
	# Check for administrative rights
	if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		Write-Warning -Message "The script requires elevation"
		break
	}
	
	# Create Pending Reboot function for registry
	function Test-PendingRebootRegistry
	{
		$CBSRebootKey = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction Ignore
		$WURebootKey = Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction Ignore
		if (($CBSRebootKey -ne $null) -OR ($WURebootKey -ne $null))
		{
			$true
		}
		else
		{
			$false
		}
	}
	
	# Windows 10 1809 build
	$1809Build = "17763"
	# Windows 10 1903 build
	$1903Build = "18362"
	# Windows 10 1909 build
	$1909Build = "18363"
	# Get running Windows build
	$WindowsBuild = (Get-CimInstance -Class Win32_OperatingSystem).BuildNumber
	# Get information about local WSUS server
	$WUServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction Ignore).WUServer
	#$DualScan = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name DisableDualScan -ErrorAction Ignore).DisableDualScan
	$TestPendingRebootRegistry = Test-PendingRebootRegistry
	
	if (($WindowsBuild -eq $1809Build) -OR ($WindowsBuild -eq $1903Build) -OR ($WindowsBuild -eq $1909Build))
	{
		Write-Verbose -Verbose "Running correct Windows 10 build number for installing RSAT with Features on Demand. Build number is: $WindowsBuild"
		Write-Verbose -Verbose "***********************************************************"
		
		if ($WUServer -ne $null)
		{
			Write-Verbose -Verbose "A local WSUS server was found configured by group policy: $WUServer"
			Write-Verbose -Verbose "You might need to configure additional setting by GPO if things are not working"
			Write-Verbose -Verbose "The GPO of interest is following: Specify settings for optional component installation and component repair"
			Write-Verbose -Verbose "Check ON: Download repair content and optional features directly from Windows Update..."
			Write-Verbose -Verbose "***********************************************************"
		}
		
		if ($TestPendingRebootRegistry -eq "True")
		{
			Write-Verbose -Verbose "Reboots are pending. The script will continue, but RSAT might not install successfully"
			Write-Verbose -Verbose "***********************************************************"
		}
		
		if ($PSBoundParameters["All"])
		{
			Write-Verbose -Verbose "Script is running with -All parameter. Installing all available RSAT features"
			$Install = Get-WindowsCapability -Online | Where-Object { $_.Name -like "Rsat*" -AND $_.State -eq "NotPresent" }
			if ($Install -ne $null)
			{
				$currentWU = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" | select -ExpandProperty UseWUServer
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value 0
				Restart-Service wuauserv
				
				foreach ($Item in $Install)
				{
					$RsatItem = $Item.Name
					Write-Verbose -Verbose "Adding $RsatItem to Windows"
					try
					{
						Add-WindowsCapability -Online -Name $RsatItem
					}
					catch [System.Exception]
					{
						Write-Verbose -Verbose "Failed to add $RsatItem to Windows"
						Write-Warning -Message $_.Exception.Message
					}
				}
				
				Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Value $currentWU
				Restart-Service wuauserv
			}
			else
			{
				Write-Verbose -Verbose "All RSAT features seems to be installed already"
			}
		}
		
		if ($PSBoundParameters["Basic"])
		{
			Write-Verbose -Verbose "Script is running with -Basic parameter. Installing basic RSAT features"
			# Querying for what I see as the basic features of RSAT. Modify this if you think something is missing. :-)
			$Install = Get-WindowsCapability -Online | Where-Object { $_.Name -like "Rsat.ActiveDirectory*" -OR $_.Name -like "Rsat.DHCP.Tools*" -OR $_.Name -like "Rsat.Dns.Tools*" -OR $_.Name -like "Rsat.GroupPolicy*" -OR $_.Name -like "Rsat.ServerManager*" -AND $_.State -eq "NotPresent" }
			if ($Install -ne $null)
			{
				foreach ($Item in $Install)
				{
					$RsatItem = $Item.Name
					Write-Verbose -Verbose "Adding $RsatItem to Windows"
					try
					{
						Add-WindowsCapability -Online -Name $RsatItem
					}
					catch [System.Exception]
					{
						Write-Verbose -Verbose "Failed to add $RsatItem to Windows"
						Write-Warning -Message $_.Exception.Message
					}
				}
			}
			else
			{
				Write-Verbose -Verbose "The basic features of RSAT seems to be installed already"
			}
		}
		
		if ($PSBoundParameters["ServerManager"])
		{
			Write-Verbose -Verbose "Script is running with -ServerManager parameter. Installing Server Manager RSAT feature"
			$Install = Get-WindowsCapability -Online | Where-Object { $_.Name -like "Rsat.ServerManager*" -AND $_.State -eq "NotPresent" }
			if ($Install -ne $null)
			{
				$RsatItem = $Install.Name
				Write-Verbose -Verbose "Adding $RsatItem to Windows"
				try
				{
					Add-WindowsCapability -Online -Name $RsatItem
				}
				catch [System.Exception]
				{
					Write-Verbose -Verbose "Failed to add $RsatItem to Windows"
					Write-Warning -Message $_.Exception.Message; break
				}
			}
			
			else
			{
				Write-Verbose -Verbose "$RsatItem seems to be installed already"
			}
		}
		
		if ($PSBoundParameters["Uninstall"])
		{
			Write-Verbose -Verbose "Script is running with -Uninstall parameter. Uninstalling all RSAT features"
			# Querying for installed RSAT features first time
			$Installed = Get-WindowsCapability -Online | Where-Object { $_.Name -like "Rsat*" -AND $_.State -eq "Installed" -AND $_.Name -notlike "Rsat.ServerManager*" -AND $_.Name -notlike "Rsat.GroupPolicy*" -AND $_.Name -notlike "Rsat.ActiveDirectory*" }
			if ($Installed -ne $null)
			{
				Write-Verbose -Verbose "Uninstalling the first round of RSAT features"
				# Uninstalling first round of RSAT features - some features seems to be locked until others are uninstalled first
				foreach ($Item in $Installed)
				{
					$RsatItem = $Item.Name
					Write-Verbose -Verbose "Uninstalling $RsatItem from Windows"
					try
					{
						Remove-WindowsCapability -Name $RsatItem -Online
					}
					catch [System.Exception]
					{
						Write-Verbose -Verbose "Failed to uninstall $RsatItem from Windows"
						Write-Warning -Message $_.Exception.Message
					}
				}
			}
			# Querying for installed RSAT features second time
			$Installed = Get-WindowsCapability -Online | Where-Object { $_.Name -like "Rsat*" -AND $_.State -eq "Installed" }
			if ($Installed -ne $null)
			{
				Write-Verbose -Verbose "Uninstalling the second round of RSAT features"
				# Uninstalling second round of RSAT features
				foreach ($Item in $Installed)
				{
					$RsatItem = $Item.Name
					Write-Verbose -Verbose "Uninstalling $RsatItem from Windows"
					try
					{
						Remove-WindowsCapability -Name $RsatItem -Online
					}
					catch [System.Exception]
					{
						Write-Verbose -Verbose "Failed to remove $RsatItem from Windows"
						Write-Warning -Message $_.Exception.Message
					}
				}
			}
			else
			{
				Write-Verbose -Verbose "All RSAT features seems to be uninstalled already"
			}
		}
	}
	else
	{
		Write-Warning -Message "Not running correct Windows 10 build: $WindowsBuild"
		
	}
}

