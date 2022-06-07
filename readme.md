# Getting full logs of mailbox

Script makes a pst file with mailbox content and all message tracking logs (receive and send) from given timespan.

## Description

Script is prepared for Exchange Server called EX-1 and contoso.com domain (you should also specific OUs and paths). It allows administrator to get all content from mailbox. It generates pst file, creating new user with journal role, group, AD and EX permissions and connect pst file to new user. It is also setting litigation hold so user cannot delete existing mails from his own mailbox.
It is neccessary to know that using the script breaks the confidentiality of correspondence, so the script should only be used in specific cases (e.g. prosecutor's office investigation).
I used here two functions created by NeXoR. Password set to new account is generated randomly, but nobody has to know it - all users in group have permissions to get into mailbox of new user.

## Getting Started

### Executing program

Firstly, you have to be an admin in Organization Management Group (default for EX admins). In this script admins have index "admin." in their account names.
Admin must have connected mailbox (Enable-Mailbox) and have assigned Discovery Management Role.
```
Add-RoleGroupMember -Identity 'Discovery Management' -Member $adminName
``` 

To run the program, just run the command in the proper path:

* Example 1
```
$startDate = Get-Date -Day 1 -Month 1 -Year 2022
$endDate = Get-Date -Day 20 -Month 1 -Year 2022
.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com -startDate $startDate -endDate $endDate
```

* Example 2
```
.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com -startDate $(Get-Date -Day 17 -Month 1 -Year 2022) -endDate $(Get-Date -Day 20 -Month 1 -Year 2022)
```

* Example 3
```
.\Get-MailboxFullLogs.ps1 -mailAddress user@contoso.com -LitigationHoldEnabled:$false -createJournalRole:$false
```

## Help

```
Get-Help Get-MailboxFullLogs.ps1
```

## Authors

[@MatekStatek](https://twitter.com/matekstatek)

## Version History

* 1.0
    * Initial Release