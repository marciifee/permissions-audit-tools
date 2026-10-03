<#
.SYNOPSIS
    Exportiert die Postfachberechtigungen einer Exchange-On-Premises-Organisation als CSV
    für die "Exchange Permission Audit WebGUI" (Need-to-know / Least-Privilege-Nachweis).

.DESCRIPTION
    Das Skript arbeitet ausschließlich LESEND. Es liest keine Postfachinhalte, sondern nur Berechtigungen:

      - Postfachberechtigungen   (Get-MailboxPermission: FullAccess, ReadPermission, ChangePermission, ...)
      - Senden als               (Get-ADPermission, Extended Right "Send-As")
      - Senden im Auftrag        (GrantSendOnBehalfTo)
      - optional Kalenderrechte  (Get-MailboxFolderPermission, Schalter -IncludeCalendar)

    Berechtigte Gruppen werden im Active Directory rekursiv aufgelöst (inkl. verschachtelter Gruppen).
    Mitglieder werden als "Anzeigename [DOMÄNE\sAMAccountName]" geschrieben, deaktivierte Konten mit
    dem Zusatz "(deaktiviert)". Deny-Einträge sind KEIN Zugriff und landen in einer eigenen Datei.

    Ergebnisdateien im Ausgabeordner:
      01_Exchange_Mailbox_Permissions.csv   -> in die WebGUI laden
      02_Exchange_Deny_Entries.csv          -> Deny-Einträge (Dokumentation)
      03_Exchange_Errors.csv                -> Fehler je Postfach/Schritt
      09_RunInfo.csv                        -> Laufparameter, Zähler, Dauer
      99_Manifest.sha256                    -> SHA-256 aller Dateien (Integritätsnachweis)

    Spalten der Hauptdatei (Reihenfolge fest, von der WebGUI erwartet):
      Mailbox, PrimarySmtpAddress, MailboxType, Permission, AD Group or User, FirstName, LastName,
      GroupMembers, Inherited  + Zusatzspalten: Source, TrusteeType, TrusteeEnabled,
      TrusteeLastLogonDate, GroupMemberCount

.PARAMETER OutputPath
    Ausgabeordner. Standard: .\Exchange_Audit_<JJJJMMTT_HHMM>

.PARAMETER RecipientTypeDetails
    Postfachtypen. Standard: UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox, LinkedMailbox

.PARAMETER Identity
    Nur diese Postfächer exportieren (z. B. für einen Testlauf).

.PARAMETER OrganizationalUnit
    Nur Postfächer aus dieser OU.

.PARAMETER Database
    Nur Postfächer dieser Postfachdatenbank.

.PARAMETER IncludeCalendar
    Zusätzlich die Berechtigungen auf dem Standardkalender exportieren (deutlich längere Laufzeit).

.PARAMETER SkipSendAs
    "Senden als" nicht auslesen (Get-ADPermission ist der langsamste Schritt).

.PARAMETER SkipSendOnBehalf
    "Senden im Auftrag" nicht auslesen.

.PARAMETER ExcludeSystemEntries
    SELF, NT AUTHORITY\* und Exchange-Systemgruppen nicht exportieren (kleinere Datei).
    Standard ist der vollständige Export – die WebGUI blendet diese Einträge selbst aus und zählt sie.

.PARAMETER MaxGroupMembers
    Maximale Anzahl Mitglieder, die je Gruppe in GroupMembers geschrieben werden (Standard 5000).
    Die tatsächliche Anzahl steht immer in GroupMemberCount.

.PARAMETER Delimiter
    CSV-Trennzeichen: ';' (Standard, Excel DE), ',' oder Tab. Die WebGUI erkennt alle drei.

.PARAMETER EntireForest
    Set-ADServerSettings -ViewEntireForest $true (Gesamtstruktur mit mehreren Domänen).

.PARAMETER ThrottleMs
    Pause je Postfach in Millisekunden (gegen Exchange-Throttling bei sehr großen Umgebungen).

.EXAMPLE
    .\Exchange-Permission-Export-v1_0.ps1
    Vollständiger Export aller Benutzer-, Freigegebenen-, Raum- und Gerätepostfächer.

.EXAMPLE
    .\Exchange-Permission-Export-v1_0.ps1 -Identity info@firma.de,max.mustermann@firma.de -OutputPath C:\Audit\Test
    Testlauf mit zwei Postfächern.

.EXAMPLE
    .\Exchange-Permission-Export-v1_0.ps1 -IncludeCalendar -OutputPath D:\Audit\Exchange\2026-10
    Export inkl. Kalenderberechtigungen.

.NOTES
    Version : 1.0
    Ausführen in der Exchange Management Shell (Exchange 2013/2016/2019/SE, Windows PowerShell 5.1).
    Benötigt Lesezugriff auf Exchange (z. B. Rollengruppe "View-Only Organization Management")
    und Lesezugriff auf das Active Directory (Standard für Domänenbenutzer).
    Die Ausgabedateien enthalten personenbezogene Daten -> geschützt ablegen, Löschfrist beachten.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ('Exchange_Audit_' + (Get-Date -Format 'yyyyMMdd_HHmm'))),
    [string[]]$RecipientTypeDetails = @('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox', 'LinkedMailbox'),
    [string[]]$Identity,
    [string]$OrganizationalUnit,
    [string]$Database,
    [switch]$IncludeCalendar,
    [switch]$SkipSendAs,
    [switch]$SkipSendOnBehalf,
    [switch]$ExcludeSystemEntries,
    [ValidateRange(1, 100000)][int]$MaxGroupMembers = 5000,
    [ValidateSet(';', ',', "`t")][string]$Delimiter = ';',
    [switch]$EntireForest,
    [ValidateRange(0, 5000)][int]$ThrottleMs = 0
)

$ScriptVersion = '1.0'
$StartTime = Get-Date

# ----------------------------------------------------------------------------------------------
#  Bekannte Identitäten
# ----------------------------------------------------------------------------------------------
# breite Identitäten (faktisch "alle Benutzer") – werden nicht aufgelöst
$BroadNameRx = '(?i)^(everyone|jeder|default|standard|anonymous|anonym)$|(^|\\)(everyone|jeder|authenticated users|authentifizierte benutzer|domain users|dom(ä|ae)nen-benutzer|domain computers|dom(ä|ae)nencomputer|anonymous logon|anonymous-anmeldung)$'
$BroadSidRx  = '^S-1-1-0$|^S-1-5-(7|11)$|^S-1-5-32-545$|^S-1-5-21-[\d-]+-(513|515)$'
# Systemidentitäten (NT-AUTORITÄT, SELF)
$WellKnownRx = '(?i)^(nt authority|nt-autorit(ä|ae)t|autorite nt)\\|^S-1-5-(10|18|19|20)$'
# Exchange-Systemgruppen (für -ExcludeSystemEntries)
$ExchangeSystemRx = '(?i)(^|\\)(exchange servers|exchange trusted subsystem|exchange windows permissions|exchange organization administrators|exchange domain servers|exchange enterprise servers|exchange view-only administrators|exchange public folder administrators|exchange recipient administrators|exchange install domain servers|exchangelegacyinterop|managed availability servers|delegated setup|public folder management|recipient management|view-only organization management|discovery management|records management|compliance management|hygiene management|server management|um management|help desk|organization management|domain admins|dom(ä|ae)nen-admins|enterprise admins|organisations-admins)$'

$LdapProps = [string[]]@('objectsid', 'objectclass', 'samaccountname', 'displayname', 'givenname', 'sn', 'useraccountcontrol', 'lastlogontimestamp', 'distinguishedname')

$script:PrincipalCache = @{}
$script:GroupCache = @{}
$script:SidCache = @{}
$script:RecipientCache = @{}
$script:Count = [ordered]@{ MailboxesTotal = 0; MailboxesProcessed = 0; Rows = 0; DenyRows = 0; SystemSkipped = 0; Errors = 0; GroupsExpanded = 0; GroupsTruncated = 0 }

# ----------------------------------------------------------------------------------------------
#  CSV-Ausgabe (Streaming, UTF-8 mit BOM, alle Felder in Anführungszeichen)
# ----------------------------------------------------------------------------------------------
$Utf8Bom = New-Object System.Text.UTF8Encoding($true)
function ConvertTo-CsvLine {
    param([object[]]$Values)
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Values.Count; $i++) {
        if ($i -gt 0) { [void]$sb.Append($Delimiter) }
        $v = [string]$Values[$i]
        $v = $v -replace "[\r\n]+", ' '
        [void]$sb.Append('"').Append($v.Replace('"', '""')).Append('"')
    }
    return $sb.ToString()
}
function New-CsvWriter {
    param([string]$Path, [string[]]$Header)
    $w = New-Object System.IO.StreamWriter($Path, $false, $Utf8Bom)
    $w.WriteLine((ConvertTo-CsvLine -Values $Header))
    return $w
}
function Write-AuditError {
    param([string]$Mailbox, [string]$Step, [string]$Message)
    $script:Count.Errors++
    $script:ErrWriter.WriteLine((ConvertTo-CsvLine -Values @((Get-Date -Format 's'), $Mailbox, $Step, $Message)))
    Write-Verbose "FEHLER [$Step] $Mailbox : $Message"
}

# ----------------------------------------------------------------------------------------------
#  Active Directory (System.DirectoryServices – kein AD-Modul erforderlich)
# ----------------------------------------------------------------------------------------------
function Get-SidString {
    param([byte[]]$Bytes)
    return (New-Object System.Security.Principal.SecurityIdentifier($Bytes, 0)).Value
}
function Convert-SidToAccount {
    param([string]$Sid)
    if ($script:SidCache.ContainsKey($Sid)) { return $script:SidCache[$Sid] }
    $acc = $Sid
    try { $acc = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
    $script:SidCache[$Sid] = $acc
    return $acc
}
function Convert-AccountToSid {
    param([string]$Account)
    try { return (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { return $null }
}
function ConvertTo-AdsPath {
    param([string]$Prefix, [string]$DistinguishedName)
    return $Prefix + $DistinguishedName.Replace('/', '\/')
}
function ConvertTo-LdapFilterValue {
    param([string]$Value)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ([int]$ch) {
            92 { [void]$sb.Append('\5c') }   # \
            42 { [void]$sb.Append('\2a') }   # *
            40 { [void]$sb.Append('\28') }   # (
            41 { [void]$sb.Append('\29') }   # )
            0  { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}
function Get-LdapObject {
    # Liest ein einzelnes Objekt (Base-Suche). $Path z. B. "LDAP://<SID=S-1-5-...>" oder "LDAP://CN=...,DC=..."
    param([string]$Path)
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry($Path)
        $s = New-Object System.DirectoryServices.DirectorySearcher($root, '(objectClass=*)', $LdapProps, [System.DirectoryServices.SearchScope]::Base)
        $r = $s.FindOne()
        $s.Dispose(); $root.Dispose()
        return $r
    } catch { return $null }
}
function Invoke-LdapSearch {
    # Seitenweise Suche, liefert die Treffer als Liste
    param([string]$RootPath, [string]$Filter)
    $root = New-Object System.DirectoryServices.DirectoryEntry($RootPath)
    $s = New-Object System.DirectoryServices.DirectorySearcher($root, $Filter, $LdapProps, [System.DirectoryServices.SearchScope]::Subtree)
    $s.PageSize = 1000
    $list = New-Object System.Collections.Generic.List[object]
    $all = $s.FindAll()
    try { foreach ($r in $all) { $list.Add($r) } } finally { $all.Dispose(); $s.Dispose(); $root.Dispose() }
    return , $list
}
function Get-LdapValue {
    param($Result, [string]$Name)
    if ($null -eq $Result -or -not $Result.Properties.Contains($Name)) { return $null }
    $v = $Result.Properties[$Name]
    if ($null -eq $v -or $v -is [string] -or $v -is [byte[]]) { return $v }
    if ($v.Count -gt 0) { return $v[0] }
    return $null
}
function Get-LdapClasses {
    param($Result)
    if ($null -ne $Result -and $Result.Properties.Contains('objectclass')) { return @($Result.Properties['objectclass'] | ForEach-Object { ([string]$_).ToLowerInvariant() }) }
    return @()
}
function Test-AccountDisabled {
    param($Result)
    $uac = Get-LdapValue $Result 'useraccountcontrol'
    return ($null -ne $uac -and (([int64]$uac) -band 2) -ne 0)
}
function Get-LastLogonDate {
    param($Result)
    $v = Get-LdapValue $Result 'lastlogontimestamp'
    if ($null -ne $v -and [int64]$v -gt 0) { return [DateTime]::FromFileTimeUtc([int64]$v).ToString('yyyy-MM-dd') }
    return ''
}
function Get-DomainDN {
    param([string]$DistinguishedName)
    return (($DistinguishedName -split '(?<!\\),') | Where-Object { $_ -match '^(?i)DC=' }) -join ','
}

function New-PrincipalInfo {
    param([string]$Account, [string]$Type)
    return [pscustomobject]@{ Account = $Account; Type = $Type; FirstName = ''; LastName = ''; DisplayName = ''; Enabled = ''; LastLogon = ''; Members = ''; MemberCount = ''; DN = ''; Sid = '' }
}

function Set-PrincipalFromLdap {
    param($Info, $Result)
    $cls = Get-LdapClasses $Result
    $sidBytes = Get-LdapValue $Result 'objectsid'
    if ($null -ne $sidBytes) { $Info.Sid = Get-SidString ([byte[]]$sidBytes); $Info.Account = Convert-SidToAccount $Info.Sid }
    $Info.DN = [string](Get-LdapValue $Result 'distinguishedname')
    $Info.DisplayName = [string](Get-LdapValue $Result 'displayname')
    if ($cls -contains 'group') { $Info.Type = 'Group' }
    elseif ($cls -contains 'msds-groupmanagedserviceaccount' -or $cls -contains 'msds-managedserviceaccount') { $Info.Type = 'ServiceAccount' }
    elseif ($cls -contains 'computer') { $Info.Type = 'Computer' }
    elseif ($cls -contains 'foreignsecurityprincipal') { $Info.Type = 'ForeignPrincipal' }
    elseif ($cls -contains 'user') { $Info.Type = 'User' }
    else { $Info.Type = 'Other' }
    if ($Info.Type -in @('User', 'ServiceAccount', 'Computer')) {
        $Info.FirstName = [string](Get-LdapValue $Result 'givenname')
        $Info.LastName = [string](Get-LdapValue $Result 'sn')
        $Info.Enabled = if (Test-AccountDisabled $Result) { 'False' } else { 'True' }
        $Info.LastLogon = Get-LastLogonDate $Result
    }
    if ($Info.Sid -match $BroadSidRx -or $Info.Account -match $BroadNameRx) { $Info.Type = 'Broad' }
}

function Get-GroupMembers {
    # Rekursive Auflösung über LDAP_MATCHING_RULE_IN_CHAIN (inkl. verschachtelter Gruppen, ohne 5000er-Grenze)
    param([string]$GroupDN, [string]$GroupName)
    if ($script:GroupCache.ContainsKey($GroupDN)) { return $script:GroupCache[$GroupDN] }
    $res = [pscustomobject]@{ Text = ''; Count = 0; Disabled = 0; Truncated = $false }
    try {
        $filter = '(&(memberOf:1.2.840.113556.1.4.1941:=' + (ConvertTo-LdapFilterValue $GroupDN) + ')(!(objectClass=group)))'
        $hits = Invoke-LdapSearch -RootPath (ConvertTo-AdsPath 'LDAP://' (Get-DomainDN $GroupDN)) -Filter $filter
        $items = New-Object System.Collections.Generic.List[string]
        foreach ($r in $hits) {
            $res.Count++
            if ($items.Count -ge $MaxGroupMembers) { $res.Truncated = $true; continue }
            $sidBytes = Get-LdapValue $r 'objectsid'
            $acc = if ($null -ne $sidBytes) { Convert-SidToAccount (Get-SidString ([byte[]]$sidBytes)) } else { [string](Get-LdapValue $r 'samaccountname') }
            $name = [string](Get-LdapValue $r 'displayname')
            if (-not $name) { $name = ('{0} {1}' -f (Get-LdapValue $r 'givenname'), (Get-LdapValue $r 'sn')).Trim() }
            $name = ($name -replace '[;\[\]\|]', ' ' -replace '\s{2,}', ' ').Trim()
            $txt = if ($name) { "$name [$acc]" } else { "[$acc]" }
            if ((Get-LdapClasses $r) -notcontains 'foreignsecurityprincipal' -and (Test-AccountDisabled $r)) { $txt += ' (deaktiviert)'; $res.Disabled++ }
            $items.Add($txt)
        }
        $res.Text = (@($items | Sort-Object) -join '; ')
        $script:Count.GroupsExpanded++
        if ($res.Truncated) { $script:Count.GroupsTruncated++ }
    } catch {
        Write-AuditError -Mailbox '' -Step "Gruppenauflösung $GroupName" -Message $_.Exception.Message
    }
    $script:GroupCache[$GroupDN] = $res
    return $res
}

function Get-PrincipalInfo {
    # Löst einen Berechtigten auf (Name wie "DOMÄNE\konto", SID oder DistinguishedName). Ergebnisse werden zwischengespeichert.
    param([string]$Name, [string]$DistinguishedName)
    $key = if ($DistinguishedName) { 'dn:' + $DistinguishedName.ToLowerInvariant() } else { 'n:' + ([string]$Name).ToLowerInvariant() }
    if ($script:PrincipalCache.ContainsKey($key)) { return $script:PrincipalCache[$key] }

    $info = New-PrincipalInfo -Account $Name -Type 'Unresolved'
    if ($DistinguishedName) {
        $info.Account = $DistinguishedName
        $r = Get-LdapObject (ConvertTo-AdsPath 'LDAP://' $DistinguishedName)
        if ($r) { Set-PrincipalFromLdap $info $r }
    } elseif ($Name -match $BroadNameRx -or $Name -match $BroadSidRx) {
        $info.Type = 'Broad'
    } elseif ($Name -match $WellKnownRx) {
        $info.Type = 'WellKnown'
    } else {
        $sid = $null
        if ($Name -match '^S-1-\d+(-\d+)+$') {
            $sid = $Name
            $acc = Convert-SidToAccount $sid
            if ($acc -eq $sid -and $sid -match '^S-1-5-21-') { $info.Type = 'Orphan'; $sid = $null } else { $info.Account = $acc }
        } else {
            $sid = Convert-AccountToSid $Name
        }
        if ($sid) {
            $r = Get-LdapObject "LDAP://<SID=$sid>"
            if (-not $r) {
                # Objekt in einer anderen Domäne der Gesamtstruktur: über den Global Catalog suchen
                $g = Get-LdapObject "GC://<SID=$sid>"
                if ($g) { $dn = [string](Get-LdapValue $g 'distinguishedname'); $r = Get-LdapObject (ConvertTo-AdsPath 'LDAP://' $dn); if (-not $r) { $r = $g } }
            }
            if ($r) { Set-PrincipalFromLdap $info $r }
            elseif ($sid -notmatch '^S-1-5-21-') { $info.Type = 'WellKnown' }
            if ($sid -match $BroadSidRx) { $info.Type = 'Broad' }
        }
    }
    if ($info.Type -eq 'Group' -and $info.DN) {
        $m = Get-GroupMembers -GroupDN $info.DN -GroupName $info.Account
        $info.Members = $m.Text
        $info.MemberCount = [string]$m.Count
    }
    $script:PrincipalCache[$key] = $info
    return $info
}

function Test-SystemPrincipal {
    param($Info)
    return ($Info.Type -eq 'WellKnown' -or $Info.Account -match $ExchangeSystemRx)
}

# ----------------------------------------------------------------------------------------------
#  Exchange-Hilfsfunktionen
# ----------------------------------------------------------------------------------------------
function Join-Rights {
    param($Rights)
    return ((@($Rights) | ForEach-Object { [string]$_ }) -join ', ') -replace '[{}]', ''
}
function Test-True { param($Value) return ([string]$Value -eq 'True') }

function Resolve-RecipientDN {
    param([string]$Recipient, [string]$Mailbox)
    if ($script:RecipientCache.ContainsKey($Recipient)) { return $script:RecipientCache[$Recipient] }
    $dn = ''
    try { $rc = @(Get-Recipient -Identity $Recipient -ErrorAction Stop); if ($rc.Count -gt 0) { $dn = [string]$rc[0].DistinguishedName } }
    catch { Write-AuditError -Mailbox $Mailbox -Step 'Get-Recipient' -Message ("{0}: {1}" -f $Recipient, $_.Exception.Message) }
    $script:RecipientCache[$Recipient] = $dn
    return $dn
}

$Header = @('Mailbox', 'PrimarySmtpAddress', 'MailboxType', 'Permission', 'AD Group or User', 'FirstName', 'LastName', 'GroupMembers', 'Inherited', 'Source', 'TrusteeType', 'TrusteeEnabled', 'TrusteeLastLogonDate', 'GroupMemberCount')

function Write-PermissionRow {
    param($Mailbox, [string]$Permission, $Info, [bool]$Inherited, [string]$Source, [bool]$Deny)
    if ($ExcludeSystemEntries -and (Test-SystemPrincipal $Info)) { $script:Count.SystemSkipped++; return }
    $values = @($Mailbox.DisplayName, $Mailbox.PrimarySmtpAddress, $Mailbox.RecipientTypeDetails, $Permission, $Info.Account,
        $Info.FirstName, $Info.LastName, $Info.Members, $(if ($Inherited) { 'True' } else { 'False' }),
        $Source, $Info.Type, $Info.Enabled, $Info.LastLogon, $Info.MemberCount)
    if ($Deny) {
        $script:DenyWriter.WriteLine((ConvertTo-CsvLine -Values ($values + @('True'))))
        $script:Count.DenyRows++
    } else {
        $script:MainWriter.WriteLine((ConvertTo-CsvLine -Values $values))
        $script:Count.Rows++
    }
}

# ----------------------------------------------------------------------------------------------
#  Vorprüfung
# ----------------------------------------------------------------------------------------------
foreach ($c in @('Get-Mailbox', 'Get-MailboxPermission', 'Get-Recipient')) {
    if (-not (Get-Command $c -ErrorAction SilentlyContinue)) {
        throw "Cmdlet '$c' nicht gefunden. Bitte das Skript in der Exchange Management Shell ausführen."
    }
}
if (-not $SkipSendAs -and -not (Get-Command 'Get-ADPermission' -ErrorAction SilentlyContinue)) {
    Write-Warning "Get-ADPermission ist nicht verfügbar (fehlende RBAC-Rolle?) – 'Senden als' wird übersprungen."
    $SkipSendAs = [switch]$true
}
if ($IncludeCalendar -and -not (Get-Command 'Get-MailboxFolderPermission' -ErrorAction SilentlyContinue)) {
    Write-Warning "Get-MailboxFolderPermission ist nicht verfügbar – Kalenderrechte werden übersprungen."
    $IncludeCalendar = [switch]$false
}
if ($EntireForest -and (Get-Command 'Set-ADServerSettings' -ErrorAction SilentlyContinue)) { Set-ADServerSettings -ViewEntireForest $true }

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).Path
$FileMain  = Join-Path $OutputPath '01_Exchange_Mailbox_Permissions.csv'
$FileDeny  = Join-Path $OutputPath '02_Exchange_Deny_Entries.csv'
$FileErr   = Join-Path $OutputPath '03_Exchange_Errors.csv'
$FileRun   = Join-Path $OutputPath '09_RunInfo.csv'
$FileMan   = Join-Path $OutputPath '99_Manifest.sha256'

$script:MainWriter = New-CsvWriter -Path $FileMain -Header $Header
$script:DenyWriter = New-CsvWriter -Path $FileDeny -Header ($Header + @('Deny'))
$script:ErrWriter  = New-CsvWriter -Path $FileErr  -Header @('Time', 'Mailbox', 'Step', 'Message')

try {
    # ------------------------------------------------------------------------------------------
    #  Postfächer ermitteln (vollständig einlesen – parallele Pipelines sind in der
    #  Exchange-Remote-Shell nicht erlaubt)
    # ------------------------------------------------------------------------------------------
    Write-Host 'Postfächer werden ermittelt ...' -ForegroundColor Cyan
    $selectProps = @('DisplayName', 'PrimarySmtpAddress', 'RecipientTypeDetails', 'DistinguishedName', 'GrantSendOnBehalfTo', 'Alias')
    if ($Identity) {
        $mailboxes = @(foreach ($id in $Identity) {
            try { Get-Mailbox -Identity $id -ErrorAction Stop | Select-Object $selectProps }
            catch { Write-AuditError -Mailbox $id -Step 'Get-Mailbox' -Message $_.Exception.Message }
        })
    } else {
        $gm = @{ ResultSize = 'Unlimited'; RecipientTypeDetails = $RecipientTypeDetails; ErrorAction = 'Stop' }
        if ($OrganizationalUnit) { $gm.OrganizationalUnit = $OrganizationalUnit }
        if ($Database) { $gm.Database = $Database }
        $mailboxes = @(Get-Mailbox @gm | Select-Object $selectProps)
    }
    $mailboxes = @($mailboxes | Sort-Object -Property DisplayName)
    $script:Count.MailboxesTotal = $mailboxes.Count
    Write-Host ("{0} Postfächer gefunden." -f $mailboxes.Count) -ForegroundColor Cyan

    $i = 0
    foreach ($m in $mailboxes) {
        $i++
        $mbxName = [string]$m.DisplayName
        if ($i -eq 1 -or $i % 5 -eq 0 -or $i -eq $mailboxes.Count) {
            $elapsed = ((Get-Date) - $StartTime).TotalSeconds
            $remain = [int]([math]::Max(0, $elapsed / $i * ($mailboxes.Count - $i)))
            Write-Progress -Activity 'Exchange-Postfachberechtigungen' -Status ("{0} / {1}: {2}" -f $i, $mailboxes.Count, $mbxName) -PercentComplete ([int]($i * 100 / [math]::Max(1, $mailboxes.Count))) -SecondsRemaining $remain
        }

        # 1) Postfachberechtigungen
        try {
            $perms = @(Get-MailboxPermission -Identity $m.DistinguishedName -ErrorAction Stop)
            foreach ($p in $perms) {
                $rights = Join-Rights $p.AccessRights
                if (-not $rights) { continue }
                $info = Get-PrincipalInfo -Name ([string]$p.User)
                Write-PermissionRow -Mailbox $m -Permission $rights -Info $info -Inherited (Test-True $p.IsInherited) -Source 'MailboxPermission' -Deny (Test-True $p.Deny)
            }
        } catch { Write-AuditError -Mailbox $mbxName -Step 'Get-MailboxPermission' -Message $_.Exception.Message }

        # 2) Senden als
        if (-not $SkipSendAs) {
            try {
                $aces = @(Get-ADPermission -Identity $m.DistinguishedName -ErrorAction Stop)
                foreach ($a in $aces) {
                    if ((Join-Rights $a.ExtendedRights) -notmatch '(?i)Send-As') { continue }
                    $info = Get-PrincipalInfo -Name ([string]$a.User)
                    Write-PermissionRow -Mailbox $m -Permission 'SendAs' -Info $info -Inherited (Test-True $a.IsInherited) -Source 'ADPermission' -Deny (Test-True $a.Deny)
                }
            } catch { Write-AuditError -Mailbox $mbxName -Step 'Get-ADPermission' -Message $_.Exception.Message }
        }

        # 3) Senden im Auftrag
        if (-not $SkipSendOnBehalf) {
            foreach ($d in @($m.GrantSendOnBehalfTo)) {
                if (-not $d) { continue }
                $dn = Resolve-RecipientDN -Recipient ([string]$d) -Mailbox $mbxName
                $info = if ($dn) { Get-PrincipalInfo -DistinguishedName $dn } else { Get-PrincipalInfo -Name ([string]$d) }
                Write-PermissionRow -Mailbox $m -Permission 'SendOnBehalf' -Info $info -Inherited $false -Source 'GrantSendOnBehalfTo' -Deny $false
            }
        }

        # 4) Kalender (optional)
        if ($IncludeCalendar) {
            try {
                $cal = @(Get-MailboxFolderStatistics -Identity $m.DistinguishedName -FolderScope Calendar -ErrorAction Stop | Where-Object { [string]$_.FolderType -eq 'Calendar' })
                if ($cal.Count -gt 0) {
                    $folderId = ([string]$m.PrimarySmtpAddress) + ':' + (([string]$cal[0].FolderPath) -replace '/', '\')
                    $fps = @(Get-MailboxFolderPermission -Identity $folderId -ErrorAction Stop)
                    foreach ($fp in $fps) {
                        $rights = Join-Rights $fp.AccessRights
                        if (-not $rights -or $rights -match '^(?i)\s*none\s*$') { continue }
                        $u = $fp.User
                        $userType = [string]$u.UserType
                        $display = [string]$u.DisplayName; if (-not $display) { $display = [string]$u }
                        if ($userType -eq 'Default' -or $display -eq 'Default' -or $display -eq 'Standard') { $info = Get-PrincipalInfo -Name 'Default' }
                        elseif ($userType -eq 'Anonymous' -or $display -eq 'Anonymous' -or $display -eq 'Anonym') { $info = Get-PrincipalInfo -Name 'Anonymous' }
                        else {
                            $dn = ''
                            try { $dn = [string]$u.ADRecipient.DistinguishedName } catch { }
                            if (-not $dn) { $dn = Resolve-RecipientDN -Recipient $display -Mailbox $mbxName }
                            $info = if ($dn) { Get-PrincipalInfo -DistinguishedName $dn } else { Get-PrincipalInfo -Name $display }
                        }
                        $perm = (@($rights -split ',\s*') | ForEach-Object { 'Calendar:' + $_.Trim() }) -join ', '
                        Write-PermissionRow -Mailbox $m -Permission $perm -Info $info -Inherited $false -Source ('FolderPermission ' + $folderId) -Deny $false
                    }
                }
            } catch { Write-AuditError -Mailbox $mbxName -Step 'Kalenderberechtigungen' -Message $_.Exception.Message }
        }

        $script:Count.MailboxesProcessed++
        if ($ThrottleMs -gt 0) { Start-Sleep -Milliseconds $ThrottleMs }
    }
    Write-Progress -Activity 'Exchange-Postfachberechtigungen' -Completed
}
finally {
    $script:MainWriter.Close(); $script:DenyWriter.Close(); $script:ErrWriter.Close()
}

# ----------------------------------------------------------------------------------------------
#  RunInfo + Manifest
# ----------------------------------------------------------------------------------------------
$EndTime = Get-Date
$params = ($PSBoundParameters.GetEnumerator() | ForEach-Object { '{0}={1}' -f $_.Key, (@($_.Value) -join ',') }) -join '; '
$run = [ordered]@{
    ScriptName           = 'Exchange-Permission-Export'
    ScriptVersion        = $ScriptVersion
    StartTime            = $StartTime.ToString('s')
    EndTime              = $EndTime.ToString('s')
    DurationSeconds      = [int]($EndTime - $StartTime).TotalSeconds
    ComputerName         = $env:COMPUTERNAME
    UserName             = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
    PowerShellVersion    = $PSVersionTable.PSVersion.ToString()
    Parameters           = $(if ($params) { $params } else { '(Standard)' })
    RecipientTypeDetails = ($RecipientTypeDetails -join ',')
    SendAs               = $(if ($SkipSendAs) { 'nicht erfasst' } else { 'erfasst' })
    SendOnBehalf         = $(if ($SkipSendOnBehalf) { 'nicht erfasst' } else { 'erfasst' })
    Calendar             = $(if ($IncludeCalendar) { 'erfasst' } else { 'nicht erfasst' })
    SystemEntries        = $(if ($ExcludeSystemEntries) { 'ausgeschlossen' } else { 'enthalten' })
    MemberFormat         = 'Anzeigename [DOMÄNE\Konto] (deaktiviert); getrennt durch "; "'
    MaxGroupMembers      = $MaxGroupMembers
    Delimiter            = $(if ($Delimiter -eq "`t") { 'TAB' } else { $Delimiter })
    PrincipalsResolved   = $script:PrincipalCache.Count
}
foreach ($k in $script:Count.Keys) { $run[$k] = $script:Count[$k] }
$rw = New-CsvWriter -Path $FileRun -Header @('Key', 'Value')
try { foreach ($k in $run.Keys) { $rw.WriteLine((ConvertTo-CsvLine -Values @($k, $run[$k]))) } } finally { $rw.Close() }

$hashes = foreach ($f in @($FileMain, $FileDeny, $FileErr, $FileRun)) {
    $h = Get-FileHash -LiteralPath $f -Algorithm SHA256
    '{0}  {1}' -f $h.Hash.ToLowerInvariant(), (Split-Path -Leaf $f)
}
[System.IO.File]::WriteAllLines($FileMan, [string[]]$hashes, (New-Object System.Text.UTF8Encoding($false)))

$mainHash = ($hashes[0] -split '\s+')[0]
Write-Host ''
Write-Host 'Export abgeschlossen.' -ForegroundColor Green
Write-Host ("  Postfächer        : {0} von {1}" -f $script:Count.MailboxesProcessed, $script:Count.MailboxesTotal)
Write-Host ("  Berechtigungszeilen: {0}  (Deny separat: {1}, System übersprungen: {2})" -f $script:Count.Rows, $script:Count.DenyRows, $script:Count.SystemSkipped)
Write-Host ("  Gruppen aufgelöst : {0}  (gekürzt: {1})" -f $script:Count.GroupsExpanded, $script:Count.GroupsTruncated)
Write-Host ("  Laufzeit          : {0:n0} s" -f ($EndTime - $StartTime).TotalSeconds)
if ($script:Count.Errors -gt 0) { Write-Host ("  Fehler            : {0} -> {1}" -f $script:Count.Errors, $FileErr) -ForegroundColor Yellow }
Write-Host ("  Ausgabe           : {0}" -f $OutputPath)
Write-Host ("  SHA-256 (für das Feld 'Erwarteter SHA-256' der WebGUI):") -ForegroundColor Cyan
Write-Host ("  {0}" -f $mainHash)
