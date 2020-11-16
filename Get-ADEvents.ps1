param(
    [string]$Servers = "dc5,dc6"
)

$ParsedEvents = @{}
$TotalADChanges = @()


$StartTime = (Get-Date).AddMinutes(-15)
$StartTime = $StartTime.AddMinutes(- $StartTime.Minute % 15)
$StartTime = $StartTime.AddSeconds(- $StartTime.Second)
$StartTime = $StartTime.AddMilliseconds(- $StartTime.Millisecond)
$EndTime = $StartTime.AddMinutes(15)

$ServersObj = $Servers.split(",")
foreach ($Server in $ServersObj) {
    #Write-Host "Searching $server for events..."
    $Filter = @{
        LogName='Security';
        ID = 5136;
        StartTime = $StartTime;
        EndTime = $EndTime;
    }
    [xml[]]$ADChanges = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue -ComputerName $Server | ForEach-Object { $_.ToXml() }
    if ($ADChanges.count) {
        $TotalADChanges = $TotalADChanges + $ADChanges
    }
    
}
if (!$TotalADChanges.Count) {
    Write-Host "No events found"
    exit
}

#Enumerate XML Namespace
$NameSpace = New-Object System.Xml.XmlNamespaceManager($TotalADChanges[0].NameTable)
$NameSpace.AddNamespace("ns", $TotalADChanges[0].DocumentElement.NamespaceURI)

#Join events by correlationID
foreach ($event in $TotalADChanges) {
    $match = @{}
    $CorrelationID = ($event.SelectNodes("//ns:Data[@Name='OpCorrelationID']",$NameSpace)).'#text'
    $OperationType = ($event.SelectNodes("//ns:Data[@Name='OperationType']",$NameSpace)).'#text'
    if ($ParsedEvents[$CorrelationID]) {
        $match = $ParsedEvents[$CorrelationID]
    }
    switch ($OperationType) {
        "%%14675" {
            $match['old'] = $event
        }
        "%%14674"{
            $match['new'] = $event
        }
    }
    $ParsedEvents[$CorrelationID] = $match
}

#Convert events into objects
$MyEvents = @()
foreach ($event in $ParsedEvents.values) {
    if ($event.old) {
        [string]$Old = $event.old.SelectNodes("//ns:Data[@Name='AttributeValue']",$NameSpace).'#text'
    } else {
        $Old = ""
    }
    $EventObj = [pscustomobject]@{
        AttributeChanged = ($event.new.SelectNodes("//ns:Data[@Name='AttributeLDAPDisplayName']",$NameSpace).'#text');
        ObjectDN = ($event.new.SelectNodes("//ns:Data[@Name='ObjectDN']",$NameSpace).'#text');
        SubjectUserName = ($event.new.SelectNodes("//ns:Data[@Name='SubjectUserName']",$NameSpace).'#text');
        Old = $Old;
        New = ($event.new.SelectNodes("//ns:Data[@Name='AttributeValue']",$NameSpace).'#text');
        EventTime = $event.new.event.system.timecreated.systemtime;
        Event = $event.new;       
    }
    $MyEvents += $EventObj

}

#Sort Objects
$MyEvents = $MyEvents | Sort-Object EventTime -Descending

#Output Message
$Body = ""
foreach ($event in $MyEvents) {
    $Body +=  "<h3>$($event.ObjectDN)</h3>`n"
    $Body += "<p><strong>$($event.AttributeChanged)</strong></p>`n"
    $Body += "<code>$($event.Old) ==> $($event.New)</code>`n"
    $Body += "<p>Changed $($event.EventTime) by <strong>$($event.SubjectUserName)</strong></p>`n"
    $Body += "<hr />`n"
}

Send-MailMessage `
    -From 'roland.admin@steinbachchristian.ca' `
    -To 'roland.penner@steinbachchristian.ca' `
    -Subject 'AD Changed Attributes' `
    -SmtpServer 'mail3.scs.internal' `
    -BodyAsHtml:$true `
    -Body $Body
