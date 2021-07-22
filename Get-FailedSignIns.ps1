param (
    [boolean]$Debug = $false
)

#Load current script path
$PSScriptRootFolder = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
write-host $PSScriptRootFolder

try {
 . ("$PSScriptRootFolder\config\FailedSignIns-Settings.ps1")
}
catch {
    Write-Error "Failed to load configuration file"
    exit -1
}



$HTML = ""


function Main {
    $HTML += Get-FailedSignInEvents
     Send-MailMessage `
        -From $SMTPFrom `
        -To $SMTPTo `
        -Subject 'Failed Logon Events' `
        -SmtpServer $SMTPMailServer `
        -BodyAsHtml:$true `
        -Body $HTML 
}



function Get-FailedSignInEvents {
    $StartTime = (Get-Date).AddMinutes(- $Interval)
    $StartTime = $StartTime.AddMinutes(- $StartTime.Minute % $Interval)
    $StartTime = $StartTime.AddSeconds(- $StartTime.Second)
    $StartTime = $StartTime.AddMilliseconds(- $StartTime.Millisecond)
    $EndTime = $StartTime.AddMinutes($Interval)
    $Filter = @{
        LogName='Security';
        ID = 4625;
        StartTime = $StartTime;
        EndTime = $EndTime;
    }

    $Events = @(Get-ServerWinEvents -ServersList $Servers -Filter $Filter)
    
    if (!$($Events | Measure-Object).count) {
        Write-Host "No events found"
        exit
    }

    #Enumerate XML Namespace
    $NameSpace = New-Object System.Xml.XmlNamespaceManager($Events[0].NameTable)
    $NameSpace.AddNamespace("ns", $Events[0].DocumentElement.NamespaceURI)

    $MyEvents = @()
    #Process Events
    foreach ($event in $Events) {
        $EventObj = [pscustomobject]@{
            TargetUserName = $Event.SelectNodes("//ns:Data[@Name='TargetUserName']",$NameSpace).'#text';
            TargetDomainName = $Event.SelectNodes("//ns:Data[@Name='TargetDomainName']",$NameSpace).'#text';
            LogonType = $Event.SelectNodes("//ns:Data[@Name='LogonType']",$NameSpace).'#text';
            Status = $Event.SelectNodes("//ns:Data[@Name='Status']",$NameSpace).'#text';
            SubStatus = $Event.SelectNodes("//ns:Data[@Name='SubStatus']",$NameSpace).'#text';
            AuthenticationPackageName = $Event.SelectNodes("//ns:Data[@Name='AuthenticationPackageName']",$NameSpace).'#text';
            IpAddress = $Event.SelectNodes("//ns:Data[@Name='IpAddress']",$NameSpace).'#text';
            IpPort = $Event.SelectNodes("//ns:Data[@Name='IpPort']",$NameSpace).'#text';
            EventTime = $Event.event.system.timecreated.systemtime;
            EventID = $Event.event.system.eventid;
            Computer = $Event.event.system.computer;
            Event = $Event;
        }
        $MyEvents += $EventObj

    }



    #Sort Objects
    $MyEvents = $MyEvents | Sort-Object EventTime -Descending


    #Exits if no events left
    if (!$($MyEvents | Measure-Object).count) {
        Write-Host "No matching events found"
        exit
    }

    #Write to host if debug mode
    if ($Debug) { Write-Host ($MyEvents | Out-String) }
    #Output Message
    $Body = ""
    foreach ($event in $MyEvents) {
        $Body +=  "<h3>$($event.Computer) : $($event.TargetDomainName) \ $($event.TargetUserName) @ $($event.IpAddress) </h3>`n"
        $Body += "<p>$($event.EventTime)</p>`n"
        $Body += Convert-EventDataToHtmlTable -XmlPath 'Data' -EventObject $event.event
        $Body += "<hr />`n"
    }
    return $Body
}

function Convert-EventDataToHtmlTable {
    param (
        $EventObject,
        $XmlPath
    )
    $TableHTML = ""
    $NameSpace = New-Object System.Xml.XmlNamespaceManager($EventObject.NameTable)
    $NameSpace.AddNamespace("ns", $EventObject.DocumentElement.NamespaceURI)
    $Data = $EventObject.SelectNodes("//ns:$XmlPath",$NameSpace)
    foreach ($row in $Data) {
        $TableHTML += "<tr><td>$($row.Name)</td><td>$($row.'#text')</td></tr>`n"
    }
    if ($TableHTML) {
        return "<table>`n<tr><th>Name</th><th>Value</th></tr>`n$TableHTML</table>"
    } else {
        return
    }
}

function Get-ServerWinEvents {
    param (
        [string]$ServersList,
        [object]$Filter
    )
    $TotalWinEvents = @()
    $ServersArray = $ServersList.split(",")
    foreach ($Server in $ServersArray) {
        [xml[]]$WinEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue -ComputerName $Server | ForEach-Object { $_.ToXml() }
        if ($WinEvents.count) {
            $TotalWinEvents = $TotalWinEvents + $WinEvents
        }    
    }
    return @($TotalWinEvents)
}


Main