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


function ConvertTo-HtmlEncoded {
    param ([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    return $Value.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}


function Main {
    $HTML += Get-FailedSignInEvents
    try {
        Send-MailMessage `
            -From $SMTPFrom `
            -To $SMTPTo `
            -Subject 'Failed Logon Events' `
            -SmtpServer $SMTPMailServer `
            -BodyAsHtml:$true `
            -Body $HTML
    } catch {
        Write-Error "Failed to send email alert: $_"
    }
}



function Get-FailedSignInEvents {
    $StartTime = (Get-Date).AddMinutes(- $Interval)
    $StartTime = $StartTime.AddMinutes(- $StartTime.Minute % $Interval)
    $StartTime = $StartTime.AddSeconds(- $StartTime.Second)
    $StartTime = $StartTime.AddMilliseconds(- $StartTime.Millisecond)
    $EndTime = $StartTime.AddMinutes($Interval)
    $Filter = @{
        LogName='Security';
        ID = 4625,4740;
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
        switch ($Event.event.system.eventid) {
            4740 { #Account Lock Out
                $EventObj = [pscustomobject]@{
                    TargetUserName = $Event.SelectNodes("//ns:Data[@Name='TargetUserName']",$NameSpace).'#text';
                    TargetDomainName = $Event.SelectNodes("//ns:Data[@Name='TargetDomainName']",$NameSpace).'#text';
                    LogonType = ""
                    Status = ""
                    SubStatus = ""
                    AuthenticationPackageName = ""
                    IpAddress = ""
                    IpPort = ""
                    EventTime = $Event.event.system.timecreated.systemtime;
                    EventID = $Event.event.system.eventid;
                    Computer = $Event.event.system.computer;
                    Event = $Event;
                }
            }
            4625 { #Failed Auth
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
            }
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
        $Body +=  "<h3>$(ConvertTo-HtmlEncoded $event.Computer) : $(ConvertTo-HtmlEncoded $event.TargetDomainName) \ $(ConvertTo-HtmlEncoded $event.TargetUserName) @ $(ConvertTo-HtmlEncoded $event.IpAddress) </h3>`n"
        $Body += "<p>$(ConvertTo-HtmlEncoded $event.EventTime)</p>`n"
        $Body += "<p><strong>ID:</strong> $(ConvertTo-HtmlEncoded $event.EventID)</p>`n"
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
        $TableHTML += "<tr><td>$(ConvertTo-HtmlEncoded $row.Name)</td><td>$(ConvertTo-HtmlEncoded $row.'#text')</td></tr>`n"
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
        $Server = $Server.Trim()
        if ($Server -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$') {
            Write-Warning "Skipping invalid server name: $Server"
            continue
        }
        [xml[]]$WinEvents = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue -ComputerName $Server | ForEach-Object { $_.ToXml() }
        if ($WinEvents.count) {
            $TotalWinEvents = $TotalWinEvents + $WinEvents
        }    
    }
    return @($TotalWinEvents)
}


Main
