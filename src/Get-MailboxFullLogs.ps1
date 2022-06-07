<#
.SYNOPSIS
	Script makes a pst file with mailbox content from given timespan.
	
.PARAMETER mailAddress
	Parameter needs an alias of the mailbox, e.g. "user@contoso.com"
	
.PARAMETER startDate
	Parameter needs start date of mailbox search as DateTime format. Write output of Get-Date function for specific date to a variable and attach to command.
	Without the startDate parameter the script copies all old content.

.PARAMETER endDate
	Parameter needs end date of mailbox search as DateTime format. Write output of Get-Date function for specific date to a variable and attach to command.
	Without the endDate parameter the script copies all newest content.

.EXAMPLE
	$startDate = Get-Date -Day 1 -Month 1 -Year 2022
	PS C:\>$endDate = Get-Date -Day 20 -Month 1 -Year 2022

	PS C:\>.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com -startDate $startDate -endDate $endDate
	
.EXAMPLE
	.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com -startDate $(Get-Date -Day 17 -Month 1 -Year 2022) -endDate $(Get-Date -Day 20 -Month 1 -Year 2022)

.EXAMPLE
	.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com -startDate $startDate

.EXAMPLE
	.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com -endDate $endDate

.EXAMPLE
	.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com

.EXAMPLE
	.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com -LitigationHoldEnabled:$false -createJournalRole:$false
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [string]$mailAddress,
    [Parameter(Mandatory = $false)]
    [string]$startDate = "",
    [Parameter(Mandatory = $false)]
    [string]$endDate = "",
    [Parameter(Mandatory = $false)]
    [switch]$LitigationHoldEnabled = $true,
    [Parameter(Mandatory = $false)]
    [switch]$createJournalRole = $true
)

# writing logs
function write-log {
#function created by NexoR
    param(
        #message to display - can be an object
        [parameter(mandatory=$true,position=0)]
              $message,
        #adds description and colour dependently on message type
        [parameter(mandatory=$false,position=1)]
            [string][validateSet('error','info','info2','warning','ok')]$type,
        #do not output to a screen - logfile only
        [parameter(mandatory=$false,position=2)]
            [switch]$silent,
        # do not show timestamp with the message
        [Parameter(mandatory=$false,position=3)]
            [switch]$skipTimestamp
    )

    #ensure that whatever the type is - array, object.. - it will be output as string, add runtime
    if($null -eq $message) {$message=''}
    $message=($message|out-String).trim() 
    
    try {
        if(-not $skipTimestamp) {
            $message = "$(Get-Date -Format "hh:mm:ss>") "+$type.ToUpper()+": "+$message
        }
        Add-Content -Path $logFile -Value $message
        if(-not $silent) {
            switch($type) {
                'error' {
                    write-host -ForegroundColor Red $message
                }
                'info' {
                    Write-Host -ForegroundColor DarkGray $message
                }
                'info2' {
                    Write-Host -ForegroundColor Blue $message
                }
                'warning' {
                    Write-Host -ForegroundColor Yellow $message
                }
                'ok' {
                    Write-Host -ForegroundColor Green $message
                }
                default {
                    Write-Host $message 
                }
            }
        }
    } catch {
        Write-Error 'not able to write to log. suggest to cancel the script run.'
        $_
    }    
}

function new-RandomPassword {
#function created by NexoR
    param( 
        [int]$length=8,
        [int][validateSet(1,2,3,4)]$uniqueSets=4,
        [int][validateSet(1,2,3)]$specialCharacterRange=1
            
    )
    function generate-Set {
        param(
            [int]$length,
            #number of 'sets of sets'
            [int]$setSize
            #number of available sets to be drawn
            #[int]$complexity=3
            #minimum number of different sets in set of sets
        )
        $safe=0
        while ($safe++ -lt 100) {
            $array=@()
            1..$length|%{
                $array+=(Get-Random -Maximum ($setSize) -Minimum 0)
            }
            if(($array|Sort-Object -Unique|Measure-Object).count -ge $setSize) {
                return $array
            } else {
                Write-Verbose "[generate-Set]bad array: $($array -join ',')"
            }
        }
        return $null
    }
    #prepare char-sets 
    $smallLetters=$null
    97..122|%{$smallLetters+=,[char][byte]$_}
    $capitalLetters=$null
    65..90|%{$capitalLetters+=,[char][byte]$_}
    $numbers=$null
    48..57|%{$numbers+=,[char][byte]$_}
    $specialCharacterL1=$null
    @(33;35..38;43;45..46;95)|%{$specialCharacterL1+=,[char][byte]$_} #!"#$%&
    $specialCharacterL2=$null
    58..64|%{$specialCharacterL2+=,[char][byte]$_} #:;<=>?@
    $specialCharacterL3=$null
    @(34;39..42;44;47;91..94;96;123..125)|%{$specialCharacterL3+=,[char][byte]$_} #[\]^`  
      
    $ascii=@()
    $ascii+=,$smallLetters
    $ascii+=,$capitalLetters
    $ascii+=,$numbers
    if($specialCharacterRange -ge 2) { $specialCharacterL1+=,$specialCharacterL2 }
    if($specialCharacterRange -ge 3) { $specialCharacterL1+=,$specialCharacterL3 }
    $ascii+=,$specialCharacterL1
    #prepare set of character-sets ensuring that there will be at least one character from at least 3 different sets
    $passwordSet=generate-Set -length $length -setSize $uniqueSets 

    $password=$NULL
    0..($length-1)|% {
        $password+=($ascii[$passwordSet[$_]] | Get-Random)
    }
    return $password
}

# get next number of case in proper organizational unit
function Get-nextNumber
{
    $i = 1
    $matched = $true

    while($matched -and $i -le 999)
    {
        $currentName = "journal.case.$("{0:d3}" -f $i)"
        
	try
	{
        	if($(Get-ADUser $currentName -erroraction silentlycontinue -warningaction silentlycontinue -verbose) -eq $null)
        	{
            		write-log -message "Name $currentName is available." -type ok
            		$matched = $false
        	}
	}

	catch
	{
		write-log -message "Name $currentName is available." -type ok		
		return $("{0:d3}" -f $i)
	}

        $i++
    }

    if($matched -eq $true)
    {
        write-log -message "All names journal.case.001-999 are used now." -type error
        return
    }

    return $("{0:d3}" -f $($i-1))
}

$findUser = $mailAddress
$exportRequestName = "$((get-date).tostring('yyyyMMddhhmmss'))_$($findUser -replace '@', '_')"
$folder = mkdir \\EX-1\C$\\Journal\$exportRequestName
$logFile = "\\EX-1\C$\Journal\$exportRequestName\log_$($mailaddress -replace '@', '_').log"
$errorOccurred = $false

write-log "Directory for logs '\\EX-1\C$\Journal\$exportRequestName' has been created" -type info

# check if admin is using correct account (admin.* is necessary)
$currentUser = whoami

if($currentUser -notlike "contoso.com\admin.*")
{
    write-log -message "Switch to admin. user." -type error
    return
}

# admin.* account has to have enabled mailbox and has been assigned to Discovery Management Role
else
{
    $adminName = $currentUser.substring(9)
    $mbx_admin = Get-Mailbox $adminName -ErrorAction SilentlyContinue
    Start-Sleep -s 2

    if($mbx_admin -eq $null)
    {
        write-log -message "Your account $adminName hasn't got any mailbox." -type error
        write-log -message "Enable mailbox on your admin account. Use command: enable-mailbox $adminName" -type info
        return 
    }

    if($(Get-RoleGroupMember -Identity "Discovery Management" | select -ExpandProperty name) -notcontains $adminName)
    {
        write-log -message "Your account $adminName is not a member of Discovery Management Role." -type error
        write-log -message "Add admin account to Discovery Management Role. Use command: Add-RoleGroupMember -Identity 'Discovery Management' -Member $adminName" -type info
        return 
    }

    write-log -message "You're using correct admin account $adminName with set SMTP address. The Discovery Management Role is assigned." -type ok
}

$number = Get-nextNumber

if($number -eq -1)
{
    return
}

$journalCN = "contoso.com/Administration/JournalEX"
$journalOU = "OU=JournalEX,OU=Administration,DC=contoso,DC=com"
$journalNr = "Journal_$number"
$journalName = "journal.case.$number"
$password = new-RandomPassword

# checking if mailbox exists
$findMailbox = Get-Mailbox $findUser -erroraction silentlycontinue
Start-Sleep -s 3

if ($findMailbox -eq $null)
{
    write-log -message "Mailbox $findUser doesn't exist!" -type error
    return
}
else
{
    write-log -message "Mailbox $findUser is existing." -type ok
}

$aduserName = $findMailbox | 
    select -ExpandProperty name

$internalMail = "$($aduserName)@contoso.com"

set-mailbox $findMailbox -EmailAddresses @{add=$internalMail} -warningaction silentlycontinue
write-log -message "EmailAddress $internalMail added successfully." -type info

# enabling litigation hold - user cannot delete messages now
if($LitigationHoldEnabled -eq $true)
{
	$findMailbox | 
    		set-mailbox -LitigationHoldEnabled $true
	Start-Sleep -s 3
	write-log -message "Litigation Hold on $findUser is enabled now." -type info
}
else
{
	write-log -message "Litigation hold on mailbox has not been set. To enable it, use 'Set-Mailbox X -LitigationHoldEnabled `$true' cmdlet." -type info
}

# creating journal mailbox
$newMailbox = New-Mailbox -Name $journalName -Alias $journalName -OrganizationalUnit $journalCN -UserPrincipalName "$($journalName)@contoso.com" `
            -SamAccountName $journalName -FirstName $number -Initials "" -LastName "Journal" -Password $(convertto-securestring $password -asplaintext -force) -ResetPasswordOnNextLogon $false 
Start-Sleep -s 3

write-log -message "Journal mailbox $($journalName)@contoso.com has been created." -type ok
write-log -message "Starting password: $password" -type info

$newADGroup = New-ADGroup -Name "group.$journalName" -GroupScope Universal -GroupCategory Security -Description "Group with permissions to $journalName" -Path $journalOU
$ADGroupPermissions = Add-MailboxPermission -Identity $journalName -User "group.$journalName" -AccessRights "FullAccess"
write-log -message "Security group group.$journalName with FullAccess permission is created." -type ok


# setting parameters to source mailbox and displaying them
Get-Mailbox $journalName | 
    Set-Mailbox -CustomAttribute3 "Journal" -HiddenFromAddressListsEnabled $true -ProhibitSendQuota "Unlimited" -IssueWarningQuota "Unlimited" -ProhibitSendReceiveQuota "Unlimited" -EmailAddressPolicyEnabled $false
Start-Sleep -s 3
write-log -message "Parameters have been set on journal mailbox." -type ok

# creating journal rule
write-log -message "Creating new journal rule..." -type info

if($createJournalRole -eq $true)
{
	$newJournalRole = New-JournalRule -Name $journalName -JournalEmailAddress "$journalName@contoso.com" -Scope Global -Enabled $true -Recipient $findUser
	Start-Sleep -s 3
	write-log -message "New journal role has been created." -type ok
}
else
{
	write-log -message "Journal role has not been created. To create it, use 'New-JournalRole' cmdlet." -type info
}

# creating new mailbox search to export pst file
$newMailboxSearchCommand = "New-MailboxSearch -TargetMailbox $journalName -SourceMailboxes $internalMail -MessageTypes email -ExcludeDuplicateMessages `$true -LogLevel Full -Name 'Case $($number)'"

if ($startDate -ne "")
{
    $newMailboxSearchCommand += " -startDate '$($startDate -f "MM/dd/yyyy")'"
}
if ($endDate -ne "")
{
    $newMailboxSearchCommand += " -endDate '$($endDate -f "MM/dd/yyyy")'"
}
write-log -message "Starting mailbox search with command: $newMailboxSearchCommand" -type info
# execute command from string
Invoke-Expression -Command $newMailboxSearchCommand
Start-Sleep -s 5
write-log "New mailbox search has been initialized." -type ok

Get-MailboxSearch "Case $($number)" | 
    Start-MailboxSearch

Start-Sleep -s 3
write-log -message "Wait until mailbox search is finished." -type info

$ok = $true
while($(Get-MailboxSearch "Case $($number)" | select -expandproperty status) -notlike "*Succeeded*")
{
	$ms = get-mailboxsearch "Case $($number)" | 
        	select -ExpandProperty percentcomplete

	write-progress -activity "Case $($number)" -percentcomplete $ms
	
	if ($(Get-MailboxSearch "Case $($number)" | 
        select -expandproperty status) -like "Failed" -or $(Get-MailboxSearch "Case $($number)" | 
            select -expandproperty status) -like "NotStarted")
	{
		write-log -message '$(Get-MailboxSearch "Case $($number)" | select -expandproperty errors)' -type error
		$ok = $false
		$errorOccurred = $true
		break
	}
}

if ($ok -eq $true)
{
	write-log -message "Mailbox search completed." -type ok
	Get-MailboxSearch "Case $($number)" | 
        	Format-List name, sourcemailboxes, targetmailbox, status, percentcomplete, errors, resultsize, resultsizecopied, createdby, laststarttime, lastendtime, resultslink, targetmailbox, startdate

	if($(get-mailboxsearch "Case $($number)" | select -ExpandProperty status) -like "*Succeeded")
	{
		$fileName = "$($exportRequestName).pst"

    		$newMailboxExportRequest = New-MailboxExportRequest -Name $exportRequestName -Mailbox $journalName -FilePath "\\EX-1\C$\Journal\$exportRequestName\$fileName"
    		write-log -message "The content of journal mailbox $journalName is going to be exported to \\EX-1\C$\Journal\$exportRequestName\$fileName" -type ok
    		write-log -message "Check the status by running command: Get-MailboxExportRequest -Name '$fileName' | select name, status" -type info
	}

	else
	{
    		write-log -message "The mailbox search 'Case $($number)' is not completed yet." -type error 
    		write-log -message "Check if status of the search is completed by command: Get-MailboxSearch 'Case $($number)' | fl name, sourcemailboxes, targetmailbox, status, percentcomplete" -type info -skipTimestamp
    		write-log -message "Then run command: New-MailboxExportRequest -Mailbox $journalName -FilePath '\\EX-1\C$\Journal\$exportRequestName\$($journalName)_$($findUser -replace '@', '_').pst'" -type info -skipTimestamp
	}
}

else
{
	write-log -message "Check the status of mailbox search by command: Get-MailboxSearch 'Case $($number)' | fl name, sourcemailboxes, targetmailbox, status, percentcomplete, errors" -type info -skipTimestamp
	write-log -message "Try to run it manually."
   	write-log -message "Then run command: New-MailboxExportRequest -Mailbox $journalName -FilePath '\\EX-1\C$\Journal\$exportRequestName\$($journalName)_$($findUser -replace '@', '_').pst' to export mails to pst file." -type info -skipTimestamp
}

$senderLogsFileName = "$($exportRequestName)_senderLogs.log"
$recipientLogsFileName = "$($exportRequestName)_recipientLogs.log"
if($errorOccurred -eq $false)
{
	$senderLogsCommand = ""
	$recipientLogsCommand = ""

	$senderLogsCommand += "get-transportservice | 
		Get-MessageTrackingLog -sender $findUser"
	$recipientLogsCommand = "get-transportservice | 
		Get-MessageTrackingLog -recipients $findUser"

	if ($startDate -ne "")
	{
    		$senderLogsCommand += " -Start '$($startDate -f "MM/dd/yyyy")'"
    		$recipientLogsCommand += " -Start '$($startDate -f "MM/dd/yyyy")'"

	}

	if ($endDate -ne "")
	{
    		$senderLogsCommand += " -End '$($endDate -f "MM/dd/yyyy")'"
    		$recipientLogsCommand += " -End '$($endDate -f "MM/dd/yyyy")'"
	}

	$senderLogsCommand += " | fl timestamp, eventid, source, sender, recipients, messagesubject"
	$recipientLogsCommand += " | fl timestamp, eventid, source, sender, recipients, messagesubject"

	write-log -message "Searching transport logs for $findUser as sender." -type info
	$senderLogs = Invoke-Expression $senderLogsCommand
	$senderLogs >> "\\EX-1\C$\Journal\$exportRequestName\$senderLogsFileName"
	write-log -message "Transport logs has been written to \\EX-1\C$\Journal\$exportRequestName\$senderLogsFileName" -type ok

	write-log -message "Searching transport logs for $findUser as recipient." -type info
	$recipientLogs = Invoke-Expression $recipientLogsCommand
	$recipientLogs >> "\\EX-1\C$\Journal\$exportRequestName\$recipientLogsFileName"
	write-log -message "Transport logs has been written to \\EX-1\C$\Journal\$exportRequestName\$recipientLogsFileName" -type ok
	ls \\EX-1\C$\Journal\$exportRequestName
}

if($errorOccurred -eq $true)
{
	write-log -message "Error occurred. Do you want to remove all AD and Exchange objects? It is recommended."
	$a = Read-Host("y/n")
	if($a -eq "y")
	{
		remove-mailboxsearch 'Case $number'
		write-log -message "Mailbox Search removed." -type info

		get-journalrule 'journal.case.$number' | Remove-JournalRule
		write-log -message "Journal rule removed." -type info

		remove-mailbox "journal.case.$number" -ErrorAction silentlycontinue
		write-log -message "Mailbox removed." -type info

		Remove-ADGroup "group.journal.case.$($number)"
		write-log -message "AD Group removed." -type info

		remove-mailboxsearch "Case $number"

		return
	}
}

#write-log -message "If some errors have been occurred, you can use this command to delete all stuff:"
#write-log -message "remove-mailboxsearch "Case $number"; get-journalrule journal.case.$number | Remove-JournalRule; remove-mailbox journal.case.$number -ErrorAction silentlycontinue; Remove-ADGroup group.journal.case.$($number)"
#Copy-Item "\\EX-1\C$\Journal\$exportRequestName" -Destination "\\s7-szk-cmdp-001\EX\"


