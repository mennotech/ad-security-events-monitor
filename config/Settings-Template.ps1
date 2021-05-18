#Script Configurations
#Copy template file a rename to Settings.ps1

#Comma separated list of servers
$Servers = "server1,server2"

$Interval = 5 #How often the script is run in minutes

$SMTPFrom = 'email@address.com'
$SMTPTo = 'email@address.com'
$SMTPMailServer = 'mailserver'

#List of, use * for wild card, this is ignored using the "like" keyword
$IgnoreDN = @(
    "CN=GroupName,OU=Groups,DC=demo,DC=com",
    "*cn=MicrosoftDNS,DC=DomainDnsZones,DC=demo,DC=com"
    )

$IgnoreObjectAttributes = @(
    "computer:servicePrincipalName"
    )