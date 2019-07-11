# Rule Shot
#
# Britton Manahan | The Crypsis Group
# Special thanks to Paul Benoit
#-----------------------------------
#
# Collect all current O365 email rules, Mail Flow Rules,
# and Mailbox Forwarding from an environment (based on provided credentials)
# 
# All parameters are optional
#
# .\rule_shot.ps1 [-mfa (-m) admin_account] [-user (-u) [user | user csv string | filepath]] [-csv (-c)] [-help -(h)]
    

#Parameters
Param(
	#Authenticate with MFA Account
    [Parameter(Mandatory=$false)]
    [alias("m")]
    [string]$mfa,
	
	#Filter on certain users when applicable
    [Parameter(Mandatory=$false)]
    [alias("u")]
    [string]$user,

	#Output rules in csv format
    [Parameter(Mandatory=$false)]
    [alias("c")]
    [switch]$csv,
	
	#Display help page
	[Parameter(Mandatory=$false)]
    [alias("h")]
    [switch]$help
)

#Set timeStamp variable for output files
$TimeStamp = (Get-Date -Format "MM-dd-yyyy_HHmmss").ToString()

#Set output file for Inbox rules
#csv rule output file
if($csv)
{
	$RuleFile = "InboxRules_" + $TimeStamp + ".csv"
	$outrules = [System.Collections.ArrayList]@()
}
#json rule output file
else
{
	$RuleFile = "InboxRules_" + $TimeStamp + ".json"
}

#Set csv output file for  Mail Flow rules
$MailFlowFile = "MailFlow_" + $TimeStamp + ".csv"

#Set csv output file for Mailbox Forwarding
$MailBoxForwardingFile = "MailboxForwarding_" + $TimeStamp + ".csv"

$failedRulesLog = "Failed_Rules_" + $TimeStamp + ".txt"
$failedForwardingLog = "Failed_Forwarding_" + $TimeStamp + ".txt"

#Script Banner
$banner = @'
--------------------------------------------------------
     Created by Britton Manahan - The Crypsis Group
--------------------------------------------------------
'@

#Help Page
$help_page = @'
	Rule Shot	
-----------------------------------------------
Purpose
    Collects Mail Flow, SMTP Forwarding, and Inbox Rules 
	from an O365 Tenant
Requirements
    Admin Credentials to an Office365 instance
Usage
    .\rule_shot.ps1 [optional parameters]
	.\rule_shot.ps1 [-mfa (-m) admin_account] [-user (-u) [user | user csv string | filepath]] [-csv (-c)] [-help -(h)]
    
    
Parameters (all optional)

	-mfa (-m)
		Authenicate using Multi-factor Authentication with the username
		provided to allow for session extension
        
	-user (-u) 
		Provide a single user, csv string, or filepath to a
		line seperated list of users to collect mailbox forwarding
		and inbox rules for
	
	-csv (-c)
		Output inbox rules in csv format
	
	-help (-h)
		Display this help page
		
'@

#Function for printing out information in color
function color_out { param( [string]$mstring, [string]$mcolor )
	
	#Get the current console foregroundcolor
	$current_fc = $host.ui.RawUI.ForegroundColor
	#Change the console foregroundcolor
	$host.ui.RawUI.ForegroundColor = $mcolor 
	#Write out string passed to function
	Write-Output $mstring
	#Revert console back to original foregroundcolor
	$host.ui.RawUI.ForegroundColor = $current_fc
}

#Parse a rule description and add contents to provided custom PSObject
function rule_parser 
{
	
	$description = $args[0]
	$PsObject = $args[1]
	
	#break up the description into an array based on the newline character
	$description = ($description.Split([Environment]::NewLine) | ?{$_ -match "\S"})
	
	#track where we are in the rule description
	$ifSection = $False
	$takeSection = $False
	
	#keep track of what "if" and "take action" currently on
	$ifCount = 1
	$takeCount = 1
	
	#loop through the lines in the rule description
	foreach($line in $description)
	{
		#Trim whitespace from the line
		$line = $line.Trim()
		
		#check if entering condition or action section 
		if($line.startswith("If"))
		{
			$ifSection = $True
			$takeSection = $False
		}
		elseif($line.startswith("Take")) 
		{
			$ifSection = $False
			$takeSection = $True
		}
		#if already in a section
		else
		{
			#add new condition property to object
			if($ifSection)
			{
				$name = "condition" + [string]$ifCount
				$ifcount += 1
				Add-Member -InputObject $PsObject -NotePropertyName $name -NotePropertyValue $line
			}
			#add new action property to object
			elseif($takeSection)
			{
				$name = "action" + [string]$takeCount
				$takeCount += 1
				Add-Member -InputObject $PsObject  -NotePropertyName $name -NotePropertyValue $line
			}
		}  
	}
}

function O365_permission_check { param( $session_import_result )

	if($session_import_result)
	{
		#ACCESS CHECK 1
		if($session_import_result.ExportedCommands.Count -lt 4)
		{
			color_out "[-] ERROR!: O365 PSSession failed admin check! [1/2]" "Red"
			color_out "[-] ERROR!: O365 PSSession failed imported command check!`n" "Red"
			Exit
		}
	}

	#ACCESS CHECK 2
	if(((Get-Mailbox -ResultSize 2 -WarningAction "SilentlyContinue").Count) -lt 2)
	{
		color_out "[-] ERROR!: O365 PSSession failed admin check! [2/2]" "Red"	
		color_out "[-] ERROR!: O365 PSSession failed Get-Mailbox check!`n" "Red"
		Exit
	}

	color_out "[+] Passed O365 permission check" "Green"
}

################
#Start of Script

#Print out help page
if($help)
{
	Write-Output $help_page
	Exit
}

#Write out script banner
Write-Output $banner

# C# Code for fixing powershell console window freeze issue
$QuickEditCodeSnippet=@" 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;


public static class DisableConsoleQuickEdit_RuleShot
{

const uint ENABLE_QUICK_EDIT = 0x0040;
const uint ENABLE_INSERT_MODE = 0x0020;

// STD_INPUT_HANDLE (DWORD): -10 is the standard input device.
const int STD_INPUT_HANDLE = -10;

[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr GetStdHandle(int nStdHandle);

[DllImport("kernel32.dll")]
static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

[DllImport("kernel32.dll")]
static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

public static bool SetQuickEdit_RuleShot(bool SetEnabled)
{

    IntPtr consoleHandle = GetStdHandle(STD_INPUT_HANDLE);

    // get current console mode
    uint consoleMode;
    if (!GetConsoleMode(consoleHandle, out consoleMode))
    {
        // ERROR: Unable to get console mode.
        return false;
    }

    // Clear the quick edit bit in the mode flags
    if (SetEnabled)
    {
        consoleMode &= ~ENABLE_QUICK_EDIT;
    }
    else
    {
        consoleMode |= ENABLE_QUICK_EDIT;
    }
	
	// Clear the insert mode bit in the mode flags
    if (SetEnabled)
    {
        consoleMode &= ~ENABLE_INSERT_MODE;
    }
    else
    {
        consoleMode |= ENABLE_INSERT_MODE;
    }
	
    // set the new mode
    if (!SetConsoleMode(consoleHandle, consoleMode))
    {
        // ERROR: Unable to set console mode
        return false;
    }

    return true;
}
}

"@

$QuickEditMode_RuleShot=add-type -TypeDefinition $QuickEditCodeSnippet -Language CSharp

function Set-QuickEdit() 
{
	[CmdletBinding()]
		param(
		[Parameter(Mandatory=$false)]
		[switch]$DisableQuickEdit=$false
	)

    [DisableConsoleQuickEdit_RuleShot]::SetQuickEdit_RuleShot($DisableQuickEdit) | Out-Null
}

#Fixes bug with the PowerShell Console Window Hanging during long running scripts
Set-QuickEdit -DisableQuickEdit

############################
#Login Process

#Non MFA Login
if(!($mfa))
{
	do
	{
		do
		{
			try
			{
				$credObject = Get-Credential -Credential $null
			}
			catch
			{
				color_out "[-] ERROR!: Failed to provide O365 Credentials" "Red"
			}
		}While(!($credObject))

		$ErrorActionPreference = "Stop"
		try
		{
			$New_Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $credObject -Authentication Basic -AllowRedirection
		}
		catch
		{
			color_out "[-] ERROR!: Failed to create O365 PSSession" "Red"
		}
		$ErrorActionPreference = "Continue"
				
	}While(!($New_Session))
	
	color_out "[+] Credentials are valid!" "Green"

	$Session = $New_Session
	
	$Session_Import = Import-PSSession -AllowClobber $Session -DisableNameChecking -CommandName Get-Mailbox,Get-InboxRule,Get-User,Get-TransportRule

	O365_permission_check $Session_Import
}
#MFA Login
else
{
	#Find and load the separate O365 MFA powershell library
	$cwd = Convert-Path .
	$CreateEXOPSSession = (Get-ChildItem -Path $env:userprofile -Filter CreateExoPSSession.ps1 -Recurse -ErrorAction SilentlyContinue -Force | Select -Last 1).DirectoryName
	. "$CreateEXOPSSession\CreateExoPSSession.ps1" *>$null
	cd $cwd
	
		try
		{
			Connect-EXOPSSession -UserPrincipalName $mfa
		}
		catch
		{
			color_out "[-] ERROR!: Failed to create O365 PSSession" "Red"
			exit
		}
	 
		color_out "[+] Credentials are valid!" "Green"	
		
		O365_permission_check $null
}

###########################
#Collect Mailflow Rules

color_out "[+] Collecting Mail Flow Rules" "Green"
$Mail_Flow_Fail = $False
$preErrorCount = $Error.Count
$ErrorActionPreference = "Stop"
try
{
	$TP_Rules = iex "Get-TransportRule -ResultSize Unlimited | Select Name,WhenChanged,State,Description,GUID" -ErrorAction Stop -ErrorVariable errvar
}
catch
{
	color_out "[-] Failed to collect Mail Flow Rules!" "Red"
	$Mail_Flow_Fail = $True	
}
$postErrorCount = $Error.Count
$ErrorActionPreference = "Continue"

if($errvar -And (!($Mail_Flow_Fail)))
{
	color_out "[-] Failed to collect Mail Flow Rules!" "Red"
	$Mail_Flow_Fail = $True	
}

if($postErrorCount -gt $preErrorCount -And (!($Mail_Flow_Fail)))
{
	color_out "[-] Failed to collect Mail Flow Rules!" "Red"
	$Mail_Flow_Fail = $True	
}

if(!($Mail_Flow_Fail))
{
	if($TP_Rules)
	{
		$TP_Rules | Export-Csv -NoTypeInformation $MailFlowFile
	}
	color_out "[+] Successfully collected Mail Flow Rules" "Green"
}


######################################3
#Build User List

if($user)
{
	$All_Mailboxes = $False
	$temp=""
	if(Test-Path $user)
	{
		color_out "[+] User parameter detected as a file" "Green"
		[array]$u_array = (Get-Content $user | Where-Object {$_} | Foreach {$_.Trim()})
	}
	elseif($user.contains(","))
	{
		color_out "[+] User parameter detected as csv string" "Green"
		[array]$u_array = $user.split(",")
	}
	else
	{
		color_out "[+] User parameter detected as single user string" "Green"
		[array]$u_array = @($user)
	}	
}
else
{
	[array]$u_array = Get-Mailbox -ResultSize Unlimited | foreach{$_.PrimarySmtpAddress}
	$All_Mailboxes = $True
}

color_out "[+] User list created!" "Green"

$userCount = $u_array.count

color_out "[*] Number of users in list: $userCount" "Cyan"

################################
#Collect any SMTP Email Forwarding Settings

color_out "[+] Collecting any Forwarding Email Addresses" "Green"

if($All_Mailboxes)
{
	$Mail_Forwarding_Fail = $False
	$preErrorCount = $Error.Count
	$ErrorActionPreference = "Stop"
	Try
	{
		[array]$Forwards = iex -Command "Get-Mailbox -ResultSize Unlimited | Select UserPrincipalName,ForwardingSmtpAddress,DelivertoMailboxAndForward" -ErrorAction Stop -ErrorVariable errvar
		[array]$Forwards = $Forwards | Where-Object {$_.ForwardingSmtpAddress -ne $null}
	}
	Catch
	{
		color_out "[-] Failed to collect Mail Forwarding Settings!" "Red"
		$Mail_Forwarding_Fail = $True	
	}
	$postErrorCount = $Error.Count
	$ErrorActionPreference = "Continue"
	
	if($errvar -And (!($Mail_Forwarding_Fail)))
	{
		color_out "[-] Failed to collect Mail Forwarding Settings!" "Red"
		$Mail_Forwarding_Fail = $True	
	}

	if($postErrorCount -gt $preErrorCount -And (!($Mail_Forwarding_Fail)))
	{
		color_out "[-] Failed to collect Mail Forwarding Settings!" "Red"
		$Mail_Forwarding_Fail = $True	
	}
		
	if(!($Mail_Forwarding_Fail))
	{
		if($Forwards.Count -gt 0)
		{
			$Forwards | ConvertTo-Csv -NoTypeInformation | Out-File $MailBoxForwardingFile -Encoding UTF8 
		}
		
		color_out "[+] Forwarding Email Addresses Successfully Collected" "Green"
	}
}
else
{
	$SMTP_Forwards = [System.Collections.ArrayList]@()

	For ($i=0; $i -lt $userCount; $i++) 
	{
		$currentAccount = $u_array[$i]
		Write-Progress -Id 1 -Activity $("Working on mailbox: " + $currentAccount) -PercentComplete (($i / $u_array.count) * 100) 
		
		$preErrorCount = $Error.Count
		$ErrorActionPreference = "Stop"
		try
		{
			$mb = iex "Get-Mailbox ""$currentAccount""" -ErrorAction Stop -ErrorVariable errvar
		}
		catch
		{
			color_out "[-] Error caught and logged for $currentAccount" "Red"
			$u_array[$i] | Out-File $failedForwardingLog -Encoding UTF8 -Append
			$ErrorActionPreference = "Continue"
			continue
		}
		$postErrorCount = $Error.Count
		$ErrorActionPreference = "Continue"
		
		if($errvar)
		{
			color_out "[-] Error caught and logged for $currentAccount" "Red"
			$u_array[$i] | Out-File $failedForwardingLog -Encoding UTF8 -Append
			continue
		}
		
		if($postErrorCount -gt $preErrorCount)
		{
			color_out "[-] Error caught and logged for $currentAccount" "Red"
			$u_array[$i] | Out-File $failedForwardingLog -Encoding UTF8 -Append
			continue
		}
		
		if($mb.ForwardingSmtpAddress -ne $null)
		{
			$SMTP_Forwards.Add(($mb | Select UserPrincipalName,ForwardingSmtpAddress,DelivertoMailboxAndForward)) | Out-Null
		}
	}
	
	if($SMTP_Forwards.Count -gt 0)
	{
		$SMTP_Forwards | ConvertTo-Csv -NoTypeInformation | Out-File $MailBoxForwardingFile -Encoding UTF8 
	}
}

################################
#Collect Inbox Rules

color_out "[+] Collecting Mailbox Rules" "Green"	

For ($i=0; $i -lt $userCount; $i++) 
{
	$currentAccount = $u_array[$i]
	Write-Progress -Id 1 -Activity $("Working on mailbox: " + $currentAccount) -PercentComplete (($i / $u_array.count) * 100) 
	While($True)
	{
		#Small Sleep
		Start-Sleep -m 200
		try
		{
			if(!(Get-PSSession | Where { $_.ConfigurationName -eq "Microsoft.Exchange" -And $_.State -eq "Opened"}))
			{
				While(!(Test-Connection outlook.office365.com -Count 1 -Quiet -ErrorAction SilentlyContinue))
				{
					color_out "[-] ERROR!: Unable to ping outlook.office365.com, will retry in 30 seconds..." "Red"		
					Start-Sleep -s 30
				}
				
				color_out "[-] ERROR!: Microsoft.Exchange PSSession is broken" "Red"
				
				if(!($mfa))
				{
					if($Session)
					{
						Remove-PSSession $Session
					}
				
					color_out "[-] Creating new Microsoft.Exchange PSSession" "Magenta"
					$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $credObject -Authentication Basic -AllowRedirection
					if(!($Session))
					{
						color_out "[-] ERROR!: Failed to create O365 PSSession`n" "Red"
					}
					else
					{
						color_out "[+] New Microsoft.Exchange PSSession created" "Green"
						$session_import_result = Import-PSSession -AllowClobber $Session -DisableNameChecking -CommandName Get-Mailbox,Get-InboxRule
					}
				}
				else
				{
					Connect-EXOPSSession -UserPrincipalName $MFA  | Out-Null
				}
			}
		}
		catch
		{
			continue
		}
		
		#canary check to ensure everything is working before calling Get-InboxRule
		$canary = $null
		$canary = Get-User -ResultSize 1 -WarningAction silentlyContinue

		if(!($canary))
		{
			continue
		}
	
		#It's never a bad time for Garbage Collection
		[System.GC]::Collect()
		
		$preErrorCount = $Error.Count
		
		$ErrorActionPreference = "Stop"
		try
		{
			[array]$rules = iex -Command "Get-InboxRule -Mailbox ""$currentAccount"" -WarningAction silentlyContinue | Select Name,Priority,Description" -ErrorAction Stop -ErrorVariable errvar
		}
		catch
		{
			color_out "[-] Error caught and logged for $currentAccount" "Red"
			$u_array[$i] | Out-File $failedRulesLog -Encoding UTF8 -Append
			$ErrorActionPreference = "Continue"
			break
		}
		$postErrorCount = $Error.Count
		$ErrorActionPreference = "Continue"

		if($errvar)
		{
			color_out "[-] Error caught and logged for $currentAccount" "Red"
			$u_array[$i] | Out-File $failedRulesLog -Encoding UTF8 -Append
			break
		}
		
		if($postErrorCount -gt $preErrorCount)
		{
			color_out "[-] Error caught and logged for $currentAccount" "Red"
			$u_array[$i] | Out-File $failedRulesLog -Encoding UTF8 -Append
			break
		}
	
		#Handle any rules, if there are any for the mailbox
		if($Rules) 
		{
			foreach($rule in $rules)
			{
				if($csv)
				{
					$outrule = $rule | Select name,priority,description
					Add-Member -InputObject $outrule -NotePropertyName "user" -NotePropertyValue $u_array[$i]				
					$outrules.Add($outrule) | Out-Null
				}
				else
				{
					$tempPsObject = New-Object PsObject -property @{
						'user' = $u_array[$i]
						'name' = $rule.name
						'priority' = $rule.priority
						}	
					rule_parser $rule.description $tempPSobject
					$tempPsObject | ConvertTo-Json | Out-File $RuleFile -Encoding UTF8 -Append
				}
			}
		}
		break
	}
}

if($csv)
{
	$outrules | Export-Csv -NoTypeInformation $RuleFile
}

######################################
#Script Ending
if(!($mfa))
{
	Remove-PSSession $Session
	color_out "[*] Removing Created Microsoft.Exchange PSSession" "Green"
}
else
{
	Get-PSSession | Remove-PSSession
}

[System.GC]::Collect()
Set-QuickEdit
color_out "[+] Script Complete!" "Green"
color_out "[+] Goodbye!`n" "Green"
