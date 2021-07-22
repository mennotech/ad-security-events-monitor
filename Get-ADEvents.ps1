param (
    [boolean]$Debug = $false
)

#Load current script path
$PSScriptRootFolder = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
write-host $PSScriptRootFolder

try {
 . ("$PSScriptRootFolder\config\ADEvents-Settings.ps1")
}
catch {
    Write-Error "Failed to load configuration file"
    exit -1
}



$ParsedEvents = @{}
$HTML = ""


function Main {
    $HTML += Get-ADChangeEvents
    Send-MailMessage `
        -From $SMTPFrom `
        -To $SMTPTo `
        -Subject 'AD Changed Attributes' `
        -SmtpServer $SMTPMailServer `
        -BodyAsHtml:$true `
        -Body $HTML 

}



function Get-ADChangeEvents {
    $StartTime = (Get-Date).AddMinutes(- $Interval)
    $StartTime = $StartTime.AddMinutes(- $StartTime.Minute % $Interval)
    $StartTime = $StartTime.AddSeconds(- $StartTime.Second)
    $StartTime = $StartTime.AddMilliseconds(- $StartTime.Millisecond)
    $EndTime = $StartTime.AddMinutes($Interval)
    $Filter = @{
        LogName='Security';
        ID = @(5136,5137,5139,5141);
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

    #Join events by correlationID
    foreach ($event in $Events) {
        $match = @{}
        $EventID = $event.event.system.EventID
        $CorrelationID = ($event.SelectNodes("//ns:Data[@Name='OpCorrelationID']",$NameSpace)).'#text'
        $OperationType = ($event.SelectNodes("//ns:Data[@Name='OperationType']",$NameSpace)).'#text'
        if ($ParsedEvents[$CorrelationID]) {
            $match = $ParsedEvents[$CorrelationID]
        }
        if ($EventID -eq 5136) {
            switch ($OperationType) {
                "%%14675" {
                    $match['old'] = $event
                }
                "%%14674"{
                    $match['new'] = $event
                }
            }
        } else {
            $match['new'] = $event
        }
        $ParsedEvents[$CorrelationID] = $match
    }

    #Convert events into objects
    $MyEvents = @()
    foreach ($event in $ParsedEvents.values) {
        if ($event.new) {
            $OldValue = ""
            $NewValue = $event.new.SelectNodes("//ns:Data[@Name='AttributeValue']",$NameSpace).'#text'
            $ObjectDN = ($event.new.SelectNodes("//ns:Data[@Name='ObjectDN']",$NameSpace).'#text')
            $AttributeChanged = ($event.new.SelectNodes("//ns:Data[@Name='AttributeLDAPDisplayName']",$NameSpace).'#text')    
            $PrimaryEvent = $event.new
        } elseif ($event.old) {
            $OldValue = $event.old.SelectNodes("//ns:Data[@Name='AttributeValue']",$NameSpace).'#text'    
            $NewValue = ""
            $ObjectDN = ($event.old.SelectNodes("//ns:Data[@Name='ObjectDN']",$NameSpace).'#text')
            $AttributeChanged = ($event.old.SelectNodes("//ns:Data[@Name='AttributeLDAPDisplayName']",$NameSpace).'#text')                
            $PrimaryEvent = $event.old
        }
        if ($event.old -AND $event.new) {
            $OldValue = $event.old.SelectNodes("//ns:Data[@Name='AttributeValue']",$NameSpace).'#text'
            $PrimaryEvent = $event.new
        }
        

        
        switch ($PrimaryEvent.event.system.eventid) {
            5136 {
                $EventAction = 'Modified'
            }
            5137 {
                $EventAction = 'Created'
            }
            5139 {
                $EventAction = 'Moved'
                $OldValue = ($PrimaryEvent.SelectNodes("//ns:Data[@Name='OldObjectDN']",$NameSpace).'#text')
                $NewValue = ($PrimaryEvent.SelectNodes("//ns:Data[@Name='NewObjectDN']",$NameSpace).'#text')
                $ObjectDN = ($PrimaryEvent.SelectNodes("//ns:Data[@Name='OldObjectDN']",$NameSpace).'#text')
            }
            5141 {
                $EventAction = 'Deleted'
            }
            default {
                $EventAction = "Unknown: $($PrimaryEvent.system.eventid)"                
            }
        }

        $EventObj = [pscustomobject]@{
            ObjectDN = $ObjectDN;
            ObjectClass = ($PrimaryEvent.SelectNodes("//ns:Data[@Name='ObjectClass']",$NameSpace).'#text');
            SubjectUserName = ($PrimaryEvent.SelectNodes("//ns:Data[@Name='SubjectUserName']",$NameSpace).'#text');
            EventAction = $EventAction;
            AttributeChanged = $AttributeChanged;
            OldValue = $OldValue;
            NewValue = $NewValue;
            EventTime = $PrimaryEvent.event.system.timecreated.systemtime;
            EventID = $PrimaryEvent.event.system.eventid;
            Computer = $PrimaryEvent.event.system.computer;
            Event = $PrimaryEvent;
        }
        $MyEvents += $EventObj

    }

    #Sort Objects
    $MyEvents = $MyEvents | Sort-Object EventTime -Descending

    #Remove matches in $IgnoreObjectAttributes array
    foreach ($Match in $IgnoreObjectAttributes) {
        $ObjectClass, $AttributeName = $Match.Split(":");
        $MyEvents = $MyEvents | Where-Object {!($_.ObjectClass -eq $ObjectClass -AND $_.AttributeChanged -eq $AttributeName)}
    }
    
    #Remove matches in $IgnoreDN array
    foreach ($Match in $IgnoreDN) {
        $MyEvents = $MyEvents | Where-Object {!($_.ObjectDN -like $Match)}
    }

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
        $Body +=  "<h3>$($event.EventAction) : $($event.ObjectDN)</h3>`n"
        $Body += "<p>$($event.ObjectClass) : <strong>$($event.AttributeChanged)</strong></p>`n"
        if ($event.OldValue -AND $event.NewValue) {
            $Body += "<code>$($event.OldValue)<br/>------&gt;<br/>$($event.NewValue)</code>`n"
        } elseif ($event.NewValue) {
            $Body += "<code>Added: $($event.NewValue)</code>`n"
        } elseif ($event.OldValue) {
            $Body += "<code>Removed: $($event.OldValue)</code>`n"
        }
        if ($Debug) { $Body += Convert-EventDataToHtmlTable -XmlPath 'Data' -EventObject $event.event }
        $Body += "<p>Changed $($event.EventTime) by <strong>$($event.SubjectUserName)</strong> @$($event.Computer)</p>`n"
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