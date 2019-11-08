# O365_And_Azure

Get-O365Rules.ps1
------------------------------------------

https://www.crypsisgroup.com/powershell-malicious-o365-email-rules/

Collect all current O365 email rules from an environment based on provided credentials, and convert them into json.

All parameters are optional

User parameter can be a single user string, a csv string in quotes, or a path to a line-seperated file.

The MFA switch requires that the MFA library for O365 Powershell is installed on the local machine

https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

.\rule_shot.ps1 [-user (-u) user | user csv string | filepath] [-mfa (-m)] [-outputfile (-o) output-file]

