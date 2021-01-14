param(
    [string]$Servers = "files"
)

$Interval = 5 #How often the script is run
$ParsedEvents = @{}
$HTML = ""
$Debug = $false


function Main {
    $HTML += Get-PermissionChangeEvents
    $HTML    
    Send-MailMessage `
        -From 'roland.admin@steinbachchristian.ca' `
        -To 'roland.penner@steinbachchristian.ca' `
        -Subject 'Server File Permissions Changed' `
        -SmtpServer 'mail3.scs.internal' `
        -BodyAsHtml:$true `
        -Body $HTML 

}



function Get-PermissionChangeEvents {
    $StartTime = (Get-Date).AddMinutes(- $Interval)
    $StartTime = $StartTime.AddMinutes(- $StartTime.Minute % $Interval)
    $StartTime = $StartTime.AddSeconds(- $StartTime.Second)
    $StartTime = $StartTime.AddMilliseconds(- $StartTime.Millisecond)
    $EndTime = $StartTime.AddMinutes($Interval)
    $Filter = @{
        LogName='Security';
        ID = @(4670);
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

    
    #Convert events into objects
    $MyEvents = @()
    foreach ($event in $Events) {
        $EventObj = [pscustomobject]@{
            ObjectName = ($event.SelectNodes("//ns:Data[@Name='ObjectName']",$NameSpace).'#text');
            ObjectType = ($event.SelectNodes("//ns:Data[@Name='ObjectType']",$NameSpace).'#text');
            SubjectUserName = ($event.SelectNodes("//ns:Data[@Name='SubjectUserName']",$NameSpace).'#text');
            ModifiedBy = ($event.SelectNodes("//ns:Data[@Name='SubjectDomainName']",$NameSpace).'#text') + "\" + ($event.SelectNodes("//ns:Data[@Name='SubjectUserName']",$NameSpace).'#text');
            OldSd = ($event.SelectNodes("//ns:Data[@Name='OldSd']",$NameSpace).'#text');
            NewSd = ($event.SelectNodes("//ns:Data[@Name='NewSd']",$NameSpace).'#text');
            SdDiff = "";
            EventTime = $event.event.system.timecreated.systemtime;
            EventID = $event.event.system.eventid;
            Computer = $event.event.system.computer;
            Event = $event;
        }
        $MyEvents += $EventObj

    }

    #Sort Objects
    $MyEvents = $MyEvents | Sort-Object EventTime -Descending

    #Remove "Token" ObjectTypes
    $MyEvents = $MyEvents | Where-Object { $_.ObjectType -ne 'Token' }
    #$MyEvents | ft

    #Process Access Change
    foreach ($event in $MyEvents) {
        $event.SdDiff = Compare-SD -OldSd $event.OldSd -NewSd $event.NewSd
    }
    
    
    if (!$($MyEvents | measure).count) {
        Write-Host "No matching events found"
        exit
    }

    #Output Message
    $Body = ""
    foreach ($event in $MyEvents) {
        $Body +=  "<h3>$($event.ObjectType) - $($event.ObjectName)</h3>`n"
        $Body += "<pre>`n$($event.SdDiff)</pre>`n"
        if ($Debug) { $Body += Convert-EventDataToHtmlTable -XmlPath 'Data' -EventObject $event.event }
        $Body += "<p>Changed $($event.EventTime) by <strong>$($event.SubjectUserName)</strong> @$($event.Computer)</p>`n"
        $Body += "<hr />`n"
    }
    return $Body
}

function Compare-Sd {
    param (
        [string]$OldSd,
        [string]$NewSd
    )
    #Split out objects



    $NewItems = $NewSd.split("(")
    $NewItems = $NewItems | ForEach-Object { $_.replace(")","") }

    $OldItems = $OldSd.split("(")
    $OldItems = $OldItems | ForEach-Object { $_.replace(")","") }

    $Additions = @()
    #Check for new permissions
    foreach($Item in $NewItems) {
        if($Item -like "*;*") {
            if ($OldItems -notcontains $Item) {
                $Additions += $Item
            }
        }
    }    

    $Subtractions = @()
    #Check for removed permissions
    foreach($Item in $OldItems) {
        if($Item -like "*;*") {
            if ($NewItems -notcontains $Item) {
                $Subtractions += $Item
            }
        }
    }    

    #0 ACE Type,1 ACE Flags,2 Permission,5 Trustee
    $Diff = ""
    Foreach($Addition in $Additions) {
        $Addition = @($Addition.Split(";"))

        if($Addition[5] -like "S-1*") {
            $Name = Convert-SidtoName $Addition[5]
        } else {
            $Name = Convert-TrusteetoName -Abrv $Addition[5]
        }
        $PermissionName = Convert-PermissiontoName -Abrv $Addition[2]

        $Modified = $false
        Foreach ($Subtraction in $Subtractions) {
            $Subtraction = $Subtraction.Split(";")
            if ($Subraction[0] -eq $Addition[0] -and $Subtraction[5] -eq $Addition[5]) {
              $Modified = $Subraction;
            }
        }
        

        if ($Modified) {          
          $Diff += "$($Modified[0]) / $Name / $(Convert-PermissiontoName -Abrv $Modified[2]) => $PermissionName`n"
        } else {
          $Diff += "$($Addition[0]) / $Name / + $PermissionName`n"
        }
    }

    Foreach($Subtraction in $Subtractions) {
        $Subtraction = @($Subtraction.Split(";"))

        if($Subtraction[5] -like "S-1*") {
            $Name = Convert-SidtoName $Subtraction[5]
        } else {
            $Name = Convert-TrusteetoName -Abrv $Subtraction[5]
        }
        $PermissionName = Convert-PermissiontoName -Abrv $Subtraction[2]
        
        $Modified = $false
        Foreach ($Addition in $Additions) {
            $Addition = $Addition.Split(";")
            if ($Subraction[0] -eq $Addition[0] -and $Subtraction[5] -eq $Addition[5]) {
              $Modified = $Addition;
            }
        }

        if ($Modified) {          
            #Already displayed above...
        } else {
          $Diff += "$($Subtraction[0]) / $Name / - $PermissionName`n"
        }
    }
    return $Diff
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

function Convert-SidtoName {
param ([string]$Sid)

    $object = Get-AdObject -Filter "objectSid -eq '$sid'"
    if ($object) {
        return $object.Name
    } else {
        return $sid
    }

}







### SDDL (Security Descriptor Definition Language) ###

#0 ACE Type A-Allowed,D-Denied,OA-Object Allowed,OD-Object Denied,AU-System Audit,AL-System Alarm,OU-Object Sys Audit,OL-Object Sys Alarm
#============
#“A” 	ACCESS ALLOWED
#“D” 	ACCESS DENIED
#“OA” 	OBJECT ACCESS ALLOWED: ONLY APPLIES TO A SUBSET OF THE OBJECT(S).
#“OD” 	OBJECT ACCESS DENIED: ONLY APPLIES TO A SUBSET OF THE OBJECT(S).
#“AU” 	SYSTEM AUDIT
#“AL” 	SYSTEM ALARM
#“OU” 	OBJECT SYSTEM AUDIT
#“OL” 	OBJECT SYSTEM ALARM

#1 ACE Flags
#============
#“CI” 	CONTAINER INHERIT: Child objects that are containers, such as directories, inherit the ACE as an explicit ACE.
#“OI” 	OBJECT INHERIT: Child objects that are not containers inherit the ACE as an explicit ACE.
#“NP” 	NO PROPAGATE: ONLY IMMEDIATE CHILDREN INHERIT THIS ACE.
#“IO” 	INHERITANCE ONLY: ACE DOESN’T APPLY TO THIS OBJECT, BUT MAY AFFECT CHILDREN VIA INHERITANCE.
#“ID” 	ACE IS INHERITED
#“SA” 	SUCCESSFUL ACCESS AUDIT
#“FA” 	FAILED ACCESS AUDIT

#2 Permissions Bits
#============
#“CC” 	Create All Child Objects Bit 0
#“DC” 	Delete All Child Objects Bit 1
#“LC” 	List Contents 	         Bit 2
#“SW” 	All Validated Writes 	 Bit 3
#“RP” 	Read All Properties 	 Bit 4
#“WP” 	Write All Properties 	 Bit 5
#“DT” 	Delete Subtree 	         Bit 6
#“LO” 	List Object 	         Bit 7
#“CR” 	All Extended Rights 	 Bit 8

#“SD” 	Delete 	                 Bit 16
#“RC” 	Read Permissions 	     Bit 17
#“WD” 	Modify Permissions 	     Bit 18
#“WO” 	Modify Owner 	         Bit 19

#“GA” 	GENERIC ALL              Bit 28
#“GR” 	GENERIC READ 	         Bit 31
#“GW” 	GENERIC WRITE 	         Bit 30
#“GX” 	GENERIC EXECUTE 	     Bit 29
    
#File access rights
#“FA” 	FILE ALL ACCESS
#“FR” 	FILE GENERIC READ
#“FW” 	FILE GENERIC WRITE
#“FX” 	FILE GENERIC EXECUTE       



function Convert-PermissiontoName {
    param (
        [string]$Abrv
    )
    switch ($Abrv) {
        "CC" { return "Create All Child Objects" }
        "DC" { return "Delete All Child Objects" }
        "LC" { return "List Contents" }
        "SW" { return "All Validated Writes" }
        "RP" { return "Read All Properties" }
        "WP" { return "Write All Properties" }
        "DT" { return "Delete Subtree" }
        "LO" { return "List Object" }
        "CR" { return "All Extended Rights" }
        "SD" { return "Delete" }
        "RC" { return "Read Permissions" }
        "WD" { return "Modify Permissions" }
        "WO" { return "Modify Owner" }
        "GA" { return "GENERIC ALL" }
        "GR" { return "GENERIC READ" }
        "GW" { return "GENERIC WRITE" }
        "GX" { return "GENERIC EXECUTE" }
        "FA" { return "FILE ALL ACCESS" }
        "FR" { return "FILE GENERIC READ" }
        "FW" { return "FILE GENERIC WRITE" }
        "FX" { return "FILE GENERIC EXECUTE" }
        default { return $Abrv }
    }
}

#3 Object Type (GUID)
#4 Inherited Object Type (GUID)

function Convert-TrusteetoName {
    param (
        [string]$Abrv
    )

    switch ($Abrv) {
        "AO" { return "Account operators" }
        "RU" { return "Alias to allow previous Windows 2000" }
        "AN" { return "Anonymous logon" }
        "AU" { return "Authenticated users" }
        "BA" { return "Built-in administrators" }
        "BG" { return "Built-in guests" }
        "BO" { return "Backup operators" }
        "BU" { return "Built-in users" }
        "CA" { return "Certificate server administrators" }
        "CG" { return "Creator group" }
        "CO" { return "Creator owner" }
        "DA" { return "Domain administrators" }
        "DC" { return "Domain computers" }
        "DD" { return "Domain controllers" }
        "DG" { return "Domain guests" }
        "DU" { return "Domain users" }
        "EA" { return "Enterprise administrators" }
        "ED" { return "Enterprise domain controllers" }
        "WD" { return "Everyone" }
        "PA" { return "Group Policy administrators" }
        "IU" { return "Interactively logged-on user" }
        "LA" { return "Local administrator" }
        "LG" { return "Local guest" }
        "LS" { return "Local service account" }
        "SY" { return "Local system" }
        "NU" { return "Network logon user" }
        "NO" { return "Network configuration operators" }
        "NS" { return "Network service account" }
        "PO" { return "Printer operators" }
        "PS" { return "Personal self" }
        "PU" { return "Power users" }
        "RS" { return "RAS servers group" }
        "RD" { return "Terminal server users" }
        "RE" { return "Replicator" }
        "RC" { return "Restricted code" }
        "SA" { return "Schema administrators" }
        "SO" { return "Server operators" }
        "SU" { return "Service logon user" }
        default { return "#UNKNOWN:$($Abrv)#" }
    }
}



Main