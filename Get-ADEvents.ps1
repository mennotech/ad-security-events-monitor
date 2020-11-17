param(
    [string]$Servers = "dc5,dc6"
)

$ParsedEvents = @{}
$HTML = ""


function Main {
    $HTML += Get-ADChangeEvents
    Send-MailMessage `
        -From 'roland.admin@steinbachchristian.ca' `
        -To 'roland.penner@steinbachchristian.ca' `
        -Subject 'AD Changed Attributes' `
        -SmtpServer 'mail3.scs.internal' `
        -BodyAsHtml:$true `
        -Body $HTML 

}



function Get-ADChangeEvents {
    $StartTime = (Get-Date).AddMinutes(-15)
    $StartTime = $StartTime.AddMinutes(- $StartTime.Minute % 15)
    $StartTime = $StartTime.AddSeconds(- $StartTime.Second)
    $StartTime = $StartTime.AddMilliseconds(- $StartTime.Millisecond)
    $EndTime = $StartTime.AddMinutes(15)
    $Filter = @{
        LogName='Security';
        ID = @(5136,5137,5139,5141);
        StartTime = $StartTime;
        EndTime = $EndTime;
    }

    $Events = @(Get-ServerWinEvents -ServersList $Servers -Filter $Filter)
    
    if (!$Events.count) {
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
        if ($event.old) {
            [string]$OldValue = $event.old.SelectNodes("//ns:Data[@Name='AttributeValue']",$NameSpace).'#text'
        } else {
            $OldValue = ""
        }
        [String]$NewValue = $event.new.SelectNodes("//ns:Data[@Name='AttributeValue']",$NameSpace).'#text'
        $ObjectDN = ($event.new.SelectNodes("//ns:Data[@Name='ObjectDN']",$NameSpace).'#text')
        $AttributeChanged = ($event.new.SelectNodes("//ns:Data[@Name='AttributeLDAPDisplayName']",$NameSpace).'#text')
        
        switch ($event.new.event.system.eventid) {
            5136 {
                $EventAction = 'Modified'
            }
            5137 {
                $EventAction = 'Created'
            }
            5139 {
                $EventAction = 'Moved'
                $OldValue = ($event.new.SelectNodes("//ns:Data[@Name='OldObjectDN']",$NameSpace).'#text')
                $NewValue = ($event.new.SelectNodes("//ns:Data[@Name='NewObjectDN']",$NameSpace).'#text')
                $ObjectDN = ($event.new.SelectNodes("//ns:Data[@Name='OldObjectDN']",$NameSpace).'#text')
            }
            5141 {
                $EventAction = 'Deleted'
            }
            default {
                $EventAction = "Unknown: $($event.new.system.eventid)"                
            }
        }

        $EventObj = [pscustomobject]@{
            ObjectDN = $ObjectDN;
            ObjectClass = ($event.new.SelectNodes("//ns:Data[@Name='ObjectClass']",$NameSpace).'#text');
            SubjectUserName = ($event.new.SelectNodes("//ns:Data[@Name='SubjectUserName']",$NameSpace).'#text');
            EventAction = $EventAction;
            AttributeChanged = $AttributeChanged;
            OldValue = $OldValue;
            NewValue = $NewValue;
            EventTime = $event.new.event.system.timecreated.systemtime;
            EventID = $event.new.event.system.eventid
            Event = $event.new
        }
        $MyEvents += $EventObj

    }

    #Sort Objects
    $MyEvents = $MyEvents | Sort-Object EventTime -Descending

    #Output Message
    $Body = ""
    foreach ($event in $MyEvents) {
        $Body +=  "<h3>$($event.EventAction) : $($event.ObjectDN)</h3>`n"
        $Body += "<p>$($event.ObjectClass) : <strong>$($event.AttributeChanged)</strong></p>`n"
        if ($event.OldValue -AND $event.NewValue) {
            $Body += "<code>$($event.OldValue)<br/>------&gt;<br/>$($event.NewValue)</code>`n"
        } elseif ($event.NewValue) {
            $Body += "<code>$($event.NewValue)</code>`n"
        }
        if ($Debug) { $Body += Convert-EventDataToHtmlTable -XmlPath 'Data' -EventObject $event.event }
        $Body += "<p>Changed $($event.EventTime) by <strong>$($event.SubjectUserName)</strong></p>`n"
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