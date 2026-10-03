<#
.SYNOPSIS
    FileServer Permission Audit v1.3 - Evidence Edition

.DESCRIPTION
    Erfasst SMB- und NTFS-Berechtigungen eines Windows-Fileservers so, dass
    Need-to-know und Least Privilege nachvollziehbar dokumentiert und spätere
    Läufe verglichen werden können.

    Neu gegenüber v1.2:
      - Rechteklassifikation (Read / ReadExecute / Write / Modify / FullControl / Special)
        inkl. numerischer Maske (RightsMask), Generic-Rights-Auflösung und
        "gilt für" (AppliesTo) aus Vererbungs-/Propagationsflags
      - Identitätsklassen (Broad / Admin / System / Service / Standard) für
        Everyone, Authenticated Users, BUILTIN\Users, Domänen-Benutzer usw.
      - Auflösung lokaler Gruppen des Fileservers (BUILTIN\Users, BUILTIN\Administrators, …)
      - AD-Auflösung per LDAP (Get-ADObject): Gruppen, Benutzer, Computer, gMSA,
        Foreign Security Principals, Gruppen-Scope/-Kategorie, primaryGroupID,
        kein 5000-Mitglieder-Limit
      - Kontoattribute: LastLogon, PasswordLastSet, AccountExpires, adminCount,
        Inaktivitätstage
      - Owner-Erfassung und -Bewertung je Ordner (10_Folder_Index.csv)
      - Echte Streaming-Enumeration (iterativ, ohne Get-ChildItem -Recurse),
        Enumerationsfehler werden protokolliert (Vollständigkeitsnachweis),
        Reparse Points erkannt, Long-Path-Versuch (\\?\)
      - SMB-Share-Eigenschaften (ABE / FolderEnumerationMode, EncryptData, CachingMode)
      - 09_RunInfo.csv (wer, wo, wann, womit, Skript-Hash, Parameter)
      - 11_Principals.csv (alle aufgelösten Identitäten mit Attributen)
      - 99_Manifest.sha256 (SHA-256 aller Ausgabedateien) für die Beweissicherung

    AclMode:
      ChangesOnly = Root vollständig, Unterordner nur explizite ACEs.
                    Die WebGUI berechnet daraus die wirksame Berechtigung je Ordner.
      Full        = jede ACL vollständig. Sehr große CSVs.

.PARAMETER TargetsFile
    CSV (Delimiter ;) mit Spalten Drive;Path. Ohne Angabe gelten die Targets
    im Konfigurationsblock.

.NOTES
    PowerShell 5.1 kompatibel. Benötigt Modul ActiveDirectory (RSAT) für die
    Gruppenauflösung. Das Audit-Konto benötigt Leserecht auf ACLs
    (z. B. Backup Operators / "Manage auditing" oder Administratorrechte auf dem Server).
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = "C:\Temp\FileServerPermissionAudit",

    [string]$TargetsFile = "",

    [ValidateSet("ChangesOnly","Full")]
    [string]$AclMode = "ChangesOnly",

    [switch]$IncludeFiles,

    [switch]$SkipGroupExpansion,

    [switch]$SkipLocalGroupExpansion,

    [switch]$SkipSmbAudit,

    [switch]$FollowReparsePoints,

    [switch]$ExportExcel,

    [switch]$DisableLocalPathOptimization,

    [string]$AdServer = "",

    [ValidateRange(1,3650)]
    [int]$InactiveDays = 90,

    [ValidateRange(0,200)]
    [int]$MaxDepth = 0,

    [ValidateRange(10,10000)]
    [int]$StatusEvery = 50,

    [ValidateRange(10,10000)]
    [int]$FlushEvery = 200
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptVersion = "1.3.0"

# ============================================================================
# KONFIGURATION
# ============================================================================

$Targets = @(
    [PSCustomObject]@{ Drive = "P:"; Path = "\\blaq-fs01\blaq-fs01-storage1" },
    [PSCustomObject]@{ Drive = "S:"; Path = "\\blaq-fs01\Backup3\WebDAV" }
)

if ($TargetsFile) {
    $Targets = @(Import-Csv -LiteralPath $TargetsFile -Delimiter ";" | ForEach-Object {
        [PSCustomObject]@{ Drive = [string]$_.Drive; Path = [string]$_.Path }
    })
}

$ExcludedIdentityPatterns = @()

# ============================================================================
# INITIALISIERUNG
# ============================================================================

$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$OverallStart = Get-Date

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

$RunDirectory = Join-Path $OutputDirectory "Audit_$Timestamp"
New-Item -Path $RunDirectory -ItemType Directory -Force | Out-Null

$StatusLog      = Join-Path $RunDirectory "00_Live_Status.log"
$MatrixCsv      = Join-Path $RunDirectory "01_Permission_Matrix.csv"
$NtfsCsv        = Join-Path $RunDirectory "02_NTFS_ACL.csv"
$SmbCsv         = Join-Path $RunDirectory "03_SMB_Share_ACL.csv"
$GroupsCsv      = Join-Path $RunDirectory "04_AD_Group_Expansion.csv"
$InheritanceCsv = Join-Path $RunDirectory "05_Inheritance_Breaks.csv"
$OrphanSidCsv   = Join-Path $RunDirectory "06_Orphaned_SIDs.csv"
$ErrorsCsv      = Join-Path $RunDirectory "07_Errors.csv"
$SummaryCsv     = Join-Path $RunDirectory "08_Summary.csv"
$RunInfoCsv     = Join-Path $RunDirectory "09_RunInfo.csv"
$FoldersCsv     = Join-Path $RunDirectory "10_Folder_Index.csv"
$PrincipalsCsv  = Join-Path $RunDirectory "11_Principals.csv"
$ManifestFile   = Join-Path $RunDirectory "99_Manifest.sha256"
$ExcelPath      = Join-Path $OutputDirectory "FileServer_Permission_Audit_$Timestamp.xlsx"

@($StatusLog,$MatrixCsv,$NtfsCsv,$SmbCsv,$GroupsCsv,$InheritanceCsv,$OrphanSidCsv,$ErrorsCsv,$SummaryCsv,$RunInfoCsv,$FoldersCsv,$PrincipalsCsv) |
    ForEach-Object { New-Item -Path $_ -ItemType File -Force | Out-Null }

# Puffer für inkrementellen Export
$MatrixBuffer      = [System.Collections.Generic.List[object]]::new()
$NtfsBuffer        = [System.Collections.Generic.List[object]]::new()
$SmbBuffer         = [System.Collections.Generic.List[object]]::new()
$GroupsBuffer      = [System.Collections.Generic.List[object]]::new()
$InheritanceBuffer = [System.Collections.Generic.List[object]]::new()
$OrphanSidBuffer   = [System.Collections.Generic.List[object]]::new()
$ErrorBuffer       = [System.Collections.Generic.List[object]]::new()
$FolderBuffer      = [System.Collections.Generic.List[object]]::new()
$PrincipalsBuffer  = [System.Collections.Generic.List[object]]::new()

$AdCache             = @{}   # Identity/SID -> Principal
$GroupExpansionCache = @{}   # GroupKey -> Member-Liste (flach)
$LocalGroupCache     = @{}
$ShareInfoCache      = @{}
$SmbAudited          = @{}
$PrincipalsWritten   = @{}

$script:AdAvailable   = $false
$script:DomainNetBIOS = ""
$script:DomainSID     = ""
$script:AdParams      = @{}
$script:MachineSids   = @{}  # Server -> lokale Maschinen-SID (S-1-5-21-...)


# ============================================================================
# HILFSFUNKTIONEN
# ============================================================================

function Write-LiveStatus {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","OK","WARN","ERR","PROGRESS")][string]$Type = "INFO"
    )
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Type) {
        "OK"       { Write-Host "[OK]       $Message" -ForegroundColor Green }
        "WARN"     { Write-Host "[WARN]     $Message" -ForegroundColor Yellow }
        "ERR"      { Write-Host "[ERR]      $Message" -ForegroundColor Red }
        "PROGRESS" { Write-Host "[PROGRESS] $Message" -ForegroundColor Cyan }
        default    { Write-Host "[INFO]     $Message" -ForegroundColor Gray }
    }
    Add-Content -LiteralPath $StatusLog -Value "[$Stamp] [$Type] $Message" -Encoding UTF8
}

function Add-AuditError {
    param([string]$Target,[string]$Operation,[string]$Identity = "",[string]$Message,[string]$Severity = "Error")
    $ErrorBuffer.Add([PSCustomObject]@{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Severity  = $Severity
        Target    = $Target
        Operation = $Operation
        Identity  = $Identity
        Error     = $Message
    })
}

function Write-CsvBuffer {
    param([Parameter(Mandatory)][System.Collections.IEnumerable]$Rows,[Parameter(Mandatory)][string]$Path)
    $Array = @($Rows)
    if ($Array.Count -eq 0) { return }
    $HasContent = $false
    try { if ((Get-Item -LiteralPath $Path).Length -gt 0) { $HasContent = $true } } catch {}
    if ($HasContent) {
        $Array | Export-Csv -LiteralPath $Path -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Append
    } else {
        $Array | Export-Csv -LiteralPath $Path -Delimiter ";" -Encoding UTF8 -NoTypeInformation
    }
}

function Flush-Buffers {
    Write-CsvBuffer -Rows $MatrixBuffer      -Path $MatrixCsv
    Write-CsvBuffer -Rows $NtfsBuffer        -Path $NtfsCsv
    Write-CsvBuffer -Rows $SmbBuffer         -Path $SmbCsv
    Write-CsvBuffer -Rows $GroupsBuffer      -Path $GroupsCsv
    Write-CsvBuffer -Rows $InheritanceBuffer -Path $InheritanceCsv
    Write-CsvBuffer -Rows $OrphanSidBuffer   -Path $OrphanSidCsv
    Write-CsvBuffer -Rows $ErrorBuffer       -Path $ErrorsCsv
    Write-CsvBuffer -Rows $FolderBuffer      -Path $FoldersCsv
    Write-CsvBuffer -Rows $PrincipalsBuffer  -Path $PrincipalsCsv
    $MatrixBuffer.Clear(); $NtfsBuffer.Clear(); $SmbBuffer.Clear(); $GroupsBuffer.Clear()
    $InheritanceBuffer.Clear(); $OrphanSidBuffer.Clear(); $ErrorBuffer.Clear(); $FolderBuffer.Clear(); $PrincipalsBuffer.Clear()
}

function Get-Prop {
    param($Object,[string]$Name)
    if ($null -eq $Object) { return $null }
    $P = $Object.PSObject.Properties[$Name]
    if ($null -eq $P) { return $null }
    return $P.Value
}

function Copy-Ordered {
    param([Parameter(Mandatory)]$Source)
    $Copy = [ordered]@{}
    foreach ($K in $Source.Keys) { $Copy[$K] = $Source[$K] }
    return $Copy
}

function Test-IdentityExcluded {
    param([string]$Identity)
    foreach ($Pattern in $ExcludedIdentityPatterns) { if ($Identity -match $Pattern) { return $true } }
    return $false
}

function Get-UncParts {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$') { throw "Ungültiger UNC-Pfad: $Path" }
    return [PSCustomObject]@{
        Server       = $Matches[1]
        Share        = $Matches[2]
        RelativePath = if ($Matches[3]) { $Matches[3] } else { "" }
        ShareRoot    = "\\$($Matches[1])\$($Matches[2])"
    }
}

function Test-IsLocalServer {
    param([Parameter(Mandatory)][string]$ServerName)
    $ShortName = ($ServerName -split '\.')[0]
    return ($ShortName -ieq $env:COMPUTERNAME -or $ServerName -ieq "localhost" -or $ServerName -eq "127.0.0.1")
}

function Get-ShareInformation {
    param([Parameter(Mandatory)][string]$FileServer,[Parameter(Mandatory)][string]$ShareName)
    $Key = "$FileServer|$ShareName"
    if ($ShareInfoCache.ContainsKey($Key)) { return $ShareInfoCache[$Key] }
    $Session = $null
    try {
        if (Test-IsLocalServer -ServerName $FileServer) {
            $Share = Get-SmbShare -Name $ShareName -ErrorAction Stop
        } else {
            $Session = New-CimSession -ComputerName $FileServer -ErrorAction Stop
            $Share = Get-SmbShare -Name $ShareName -CimSession $Session -ErrorAction Stop
        }
        $Result = [PSCustomObject]@{
            Server                = $FileServer
            ShareName             = $ShareName
            LocalPath             = [string]$Share.Path
            Description           = [string]$Share.Description
            IsLocal               = (Test-IsLocalServer -ServerName $FileServer)
            FolderEnumerationMode = [string]$Share.FolderEnumerationMode   # AccessBased = ABE aktiv
            EncryptData           = [bool]$Share.EncryptData
            CachingMode           = [string]$Share.CachingMode
            ConcurrentUserLimit   = [string]$Share.ConcurrentUserLimit
            ShareType             = [string]$Share.ShareType
        }
        $ShareInfoCache[$Key] = $Result
        return $Result
    }
    finally {
        if ($null -ne $Session) { Remove-CimSession -CimSession $Session -ErrorAction SilentlyContinue }
    }
}

function Get-ScanRoot {
    param([Parameter(Mandatory)][string]$AuditRoot,[Parameter(Mandatory)]$Unc)
    if ($DisableLocalPathOptimization -or -not (Test-IsLocalServer -ServerName $Unc.Server)) {
        return [PSCustomObject]@{ ScanRoot = $AuditRoot; LocalMode = $false }
    }
    try {
        $ShareInfo = Get-ShareInformation -FileServer $Unc.Server -ShareName $Unc.Share
        $LocalRoot = $ShareInfo.LocalPath
        if (-not [string]::IsNullOrWhiteSpace($Unc.RelativePath)) { $LocalRoot = Join-Path $LocalRoot $Unc.RelativePath }
        if (Test-Path -LiteralPath $LocalRoot) { return [PSCustomObject]@{ ScanRoot = $LocalRoot; LocalMode = $true } }
    }
    catch { Add-AuditError -Target $AuditRoot -Operation "LocalPathOptimization" -Message $_.Exception.Message -Severity "Warning" }
    return [PSCustomObject]@{ ScanRoot = $AuditRoot; LocalMode = $false }
}

function Get-RelativePathText {
    param([Parameter(Mandatory)][string]$Root,[Parameter(Mandatory)][string]$Current)
    $CleanRoot = $Root.TrimEnd('\'); $CleanCurrent = $Current.TrimEnd('\')
    if ($CleanCurrent -ieq $CleanRoot) { return "." }
    if ($CleanCurrent.StartsWith($CleanRoot,[System.StringComparison]::OrdinalIgnoreCase)) {
        return $CleanCurrent.Substring($CleanRoot.Length).TrimStart('\')
    }
    return $Current
}

function Get-DisplayPath {
    param([Parameter(Mandatory)][string]$ScanRoot,[Parameter(Mandatory)][string]$AuditRoot,[Parameter(Mandatory)][string]$CurrentScanPath)
    $Relative = Get-RelativePathText -Root $ScanRoot -Current $CurrentScanPath
    if ($Relative -eq ".") { return $AuditRoot }
    return ($AuditRoot.TrimEnd('\') + "\" + $Relative)
}

# Long-Path-Form für .NET-Aufrufe (\\?\ bzw. \\?\UNC\)
function Get-LongPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path.StartsWith('\\?\')) { return $Path }
    if ($Path.StartsWith('\\')) { return '\\?\UNC\' + $Path.Substring(2) }
    return '\\?\' + $Path
}

# Erst normal versuchen; bei Fehler und langem Pfad mit \\?\-Prefix wiederholen
# (funktioniert je nach .NET-Version/LongPathsEnabled – Fehler landen sonst in 07_Errors mit Hinweis "LongPath").
function Invoke-LongPathAware {
    param([Parameter(Mandatory)][scriptblock]$Action,[Parameter(Mandatory)][string]$Path)
    try { return (& $Action $Path) }
    catch {
        if ($Path.Length -ge 248 -and -not $Path.StartsWith('\\?\')) { return (& $Action (Get-LongPath -Path $Path)) }
        throw
    }
}

function ConvertFrom-LongPath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path.StartsWith('\\?\UNC\')) { return '\\' + $Path.Substring(8) }
    if ($Path.StartsWith('\\?\')) { return $Path.Substring(4) }
    return $Path
}

# ============================================================================
# RECHTE-KLASSIFIKATION
# ============================================================================

# Generic Rights -> spezifische Dateisystemrechte
$GENERIC_READ    = [int64]0x80000000
$GENERIC_WRITE   = [int64]0x40000000
$GENERIC_EXECUTE = [int64]0x20000000
$GENERIC_ALL     = [int64]0x10000000
$FILE_GENERIC_READ    = 0x120089
$FILE_GENERIC_WRITE   = 0x120116
$FILE_GENERIC_EXECUTE = 0x1200A0
$FILE_ALL_ACCESS      = 0x1F01FF
$RIGHT_MODIFY         = 0x301BF
$RIGHT_READ_EXECUTE   = 0x200A9
$RIGHT_READ           = 0x20089
$RIGHT_WRITE          = 0x116
$RIGHT_WRITE_DAC      = 0x40000
$RIGHT_WRITE_OWNER    = 0x80000
$RIGHT_DELETE         = 0x10000
$RIGHT_DELETE_CHILD   = 0x40
$SMB_RIGHTS = @{ "Read" = $RIGHT_READ_EXECUTE; "Change" = $RIGHT_MODIFY; "Full" = $FILE_ALL_ACCESS }

function ConvertTo-RightsMask {
    param([Parameter(Mandatory)]$FileSystemRights)
    # FileSystemRights kann negative int32-Werte enthalten (Generic Bits)
    $Raw = [int64]([int32]$FileSystemRights)
    if ($Raw -lt 0) { $Raw = $Raw -band 0xFFFFFFFF }
    $Mask = $Raw -band 0x0FFFFFFF
    if ($Raw -band $GENERIC_READ)    { $Mask = $Mask -bor $FILE_GENERIC_READ }
    if ($Raw -band $GENERIC_WRITE)   { $Mask = $Mask -bor $FILE_GENERIC_WRITE }
    if ($Raw -band $GENERIC_EXECUTE) { $Mask = $Mask -bor $FILE_GENERIC_EXECUTE }
    if ($Raw -band $GENERIC_ALL)     { $Mask = $Mask -bor $FILE_ALL_ACCESS }
    return [int64]$Mask
}

function Get-RightsClass {
    param([Parameter(Mandatory)][int64]$Mask)
    $M = $Mask -band 0x1F01FF
    if (($M -band $FILE_ALL_ACCESS) -eq $FILE_ALL_ACCESS) { return "FullControl" }
    if (($M -band $RIGHT_MODIFY) -eq $RIGHT_MODIFY)       { return "Modify" }
    $HasWrite = ($M -band ($RIGHT_WRITE -bor $RIGHT_DELETE -bor $RIGHT_DELETE_CHILD)) -ne 0
    $HasRead  = ($M -band $RIGHT_READ) -eq $RIGHT_READ
    if ($HasWrite -and $HasRead) { return "ReadWrite" }
    if ($HasWrite)               { return "WriteOnly" }
    if (($M -band $RIGHT_READ_EXECUTE) -eq $RIGHT_READ_EXECUTE) { return "ReadExecute" }
    if ($HasRead)                { return "Read" }
    if ($M -band ($RIGHT_WRITE_DAC -bor $RIGHT_WRITE_OWNER)) { return "SpecialAclControl" }
    if ($M -eq 0) { return "None" }
    return "Special"
}

function Get-RightsText {
    param([Parameter(Mandatory)][int64]$Mask)
    try { return ([System.Security.AccessControl.FileSystemRights]([int]$Mask)).ToString() } catch { return "0x{0:X}" -f $Mask }
}

function Get-AppliesTo {
    param([string]$InheritanceFlags,[string]$PropagationFlags,[bool]$IsContainer = $true)
    if (-not $IsContainer) { return "Datei" }
    $CI = $InheritanceFlags -match "ContainerInherit"
    $OI = $InheritanceFlags -match "ObjectInherit"
    $IO = $PropagationFlags -match "InheritOnly"
    $NP = $PropagationFlags -match "NoPropagateInherit"
    $Parts = @()
    if (-not $IO) { $Parts += "Dieser Ordner" }
    if ($CI) { $Parts += "Unterordner" }
    if ($OI) { $Parts += "Dateien" }
    $Text = $Parts -join ", "
    if ($NP -and ($CI -or $OI)) { $Text += " (nur eine Ebene)" }
    if (-not $Text) { $Text = "Dieser Ordner" }
    return $Text
}

# ============================================================================
# IDENTITÄTS-KLASSIFIKATION
# ============================================================================

function Get-IdentityClass {
    param([string]$Identity,[string]$SID,[string]$PrincipalType)
    $Id = [string]$Identity
    $S  = [string]$SID
    $Rid = ""
    if ($S -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') { $Rid = $Matches[1] }

    # Sehr breite Identitäten – faktisch "jeder"
    if ($S -in @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546','S-1-5-4','S-1-5-2','S-1-5-7','S-1-2-0','S-1-2-1')) { return "Broad" }
    if ($Rid -in @('513','514','515','545')) { return "Broad" }   # Domain Users, Domain Guests, Domain Computers
    if ($Id -match '^(Everyone|Jeder)$' -or $Id -match '\\(Everyone|Jeder|Authenticated Users|Authentifizierte Benutzer|Users|Benutzer|Domain Users|Domänen-Benutzer|Domain Computers|Domänencomputer|Guests|Gäste|INTERACTIVE|INTERAKTIV|NETWORK|NETZWERK)$') { return "Broad" }

    # Administrative Identitäten
    if ($S -in @('S-1-5-32-544','S-1-5-32-548','S-1-5-32-549','S-1-5-32-550','S-1-5-32-551')) { return "Admin" }
    if ($Rid -in @('500','512','518','519','520','544')) { return "Admin" }
    if ($Id -match '\\(Administrators|Administratoren|Administrator|Domain Admins|Domänen-Admins|Enterprise Admins|Organisations-Admins|Schema Admins|Schema-Admins|Backup Operators|Sicherungs-Operatoren|Server Operators|Server-Operatoren)$') { return "Admin" }

    # System / Betriebssystem
    if ($S -in @('S-1-5-18','S-1-5-19','S-1-5-20','S-1-3-0','S-1-3-1','S-1-3-4','S-1-5-32-559','S-1-5-32-568')) { return "System" }
    if ($S -match '^S-1-5-80-') { return "Service" }
    if ($Id -match '^(NT AUTHORITY|NT-AUTORITÄT)\\(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|LOKALER DIENST|NETZWERKDIENST)$' -or $Id -match '^(CREATOR OWNER|ERSTELLER-BESITZER)$' -or $Id -match '\\(CREATOR OWNER|ERSTELLER-BESITZER|TrustedInstaller)$') { return "System" }
    if ($Id -match '^NT SERVICE\\') { return "Service" }
    if ($PrincipalType -eq "ServiceAccount") { return "Service" }
    return "Standard"
}

# ============================================================================
# AD / PRINCIPAL AUFLÖSUNG
# ============================================================================

function New-PrincipalRecord {
    param([string]$Identity)
    return [ordered]@{
        Identity          = $Identity
        SID               = ""
        SamAccountName    = ""
        Name              = ""
        PrincipalType     = "Unknown"      # Group, User, Computer, ServiceAccount, BuiltIn, LocalGroup, LocalUser, ForeignSecurityPrincipal, OrphanedSID, UnknownSID, LocalOrUnknown
        IdentityClass     = "Standard"
        DistinguishedName = ""
        Domain            = ""
        Enabled           = $null
        LastLogonDate     = $null
        InactiveDays      = $null
        PasswordLastSet   = $null
        AccountExpires    = $null
        AdminCount        = $null
        GroupScope        = ""
        GroupCategory     = ""
        OrphanedSID       = $false
        IsLocal           = $false
        Source            = ""
    }
}

function Convert-FileTime {
    param($Value)
    try {
        if ($null -eq $Value) { return $null }
        $V = [int64]$Value
        if ($V -le 0 -or $V -eq 9223372036854775807) { return $null }
        return [DateTime]::FromFileTime($V)
    } catch { return $null }
}

function ConvertTo-LdapEscaped {
    param([string]$Value)
    return $Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace("`0",'\00')
}

function Resolve-AdObjectByFilter {
    param([Parameter(Mandatory)][string]$LdapFilter)
    $Props = @("objectClass","sAMAccountName","name","displayName","distinguishedName","userAccountControl","lastLogonTimestamp","pwdLastSet","accountExpires","adminCount","groupType","objectSid","primaryGroupID","msDS-PrincipalName")
    $AdP = $script:AdParams
    return @(Get-ADObject -LDAPFilter $LdapFilter -Properties $Props -ResultSetSize 2 @AdP -ErrorAction Stop)
}

function Complete-PrincipalFromAdObject {
    param([Parameter(Mandatory)]$Result,[Parameter(Mandatory)]$Obj)
    $Class = [string](Get-Prop $Obj "objectClass")
    $Result.SamAccountName    = [string](Get-Prop $Obj "sAMAccountName")
    $Dn = [string](Get-Prop $Obj "displayName")
    $Result.Name              = if ($Dn) { $Dn } else { [string](Get-Prop $Obj "name") }
    $Result.DistinguishedName = [string](Get-Prop $Obj "distinguishedName")
    $Sid = Get-Prop $Obj "objectSid"
    if ($null -ne $Sid) { $Result.SID = [string]$Sid.Value }
    $Pn = [string](Get-Prop $Obj "msDS-PrincipalName")
    if ($Pn) { $Result.Identity = $Pn }
    elseif ($script:DomainNetBIOS -and $Result.SamAccountName) { $Result.Identity = "$($script:DomainNetBIOS)\$($Result.SamAccountName)" }
    if ($Result.Identity -match '^([^\\]+)\\') { $Result.Domain = $Matches[1] }
    $Result.Source = "AD"
    $UAC = [int64](Get-Prop $Obj "userAccountControl")

    switch -Regex ($Class) {
        '^group$' {
            $Result.PrincipalType = "Group"
            $GT = [int64](Get-Prop $Obj "groupType")
            $Result.GroupCategory = if ($GT -band 0x80000000) { "Security" } else { "Distribution" }
            $Result.GroupScope = if ($GT -band 2) { "Global" } elseif ($GT -band 4) { "DomainLocal" } elseif ($GT -band 8) { "Universal" } elseif ($GT -band 1) { "BuiltinLocal" } else { "Unknown" }
            break
        }
        '^user$' {
            $Result.PrincipalType = "User"
            $Result.Enabled = -not ($UAC -band 2)
            $Result.LastLogonDate = Convert-FileTime (Get-Prop $Obj "lastLogonTimestamp")
            $Result.PasswordLastSet = Convert-FileTime (Get-Prop $Obj "pwdLastSet")
            $Result.AccountExpires = Convert-FileTime (Get-Prop $Obj "accountExpires")
            $Ac = Get-Prop $Obj "adminCount"
            $Result.AdminCount = if ($null -ne $Ac) { [int]$Ac } else { 0 }
            if ($Result.LastLogonDate) { $Result.InactiveDays = [int]((Get-Date) - $Result.LastLogonDate).TotalDays }
            break
        }
        '^computer$' {
            $Result.PrincipalType = "Computer"
            $Result.Enabled = -not ($UAC -band 2)
            $Result.LastLogonDate = Convert-FileTime (Get-Prop $Obj "lastLogonTimestamp")
            if ($Result.LastLogonDate) { $Result.InactiveDays = [int]((Get-Date) - $Result.LastLogonDate).TotalDays }
            break
        }
        'msDS-(Group)?ManagedServiceAccount' {
            $Result.PrincipalType = "ServiceAccount"
            $Result.Enabled = -not ($UAC -band 2)
            $Result.LastLogonDate = Convert-FileTime (Get-Prop $Obj "lastLogonTimestamp")
            break
        }
        '^foreignSecurityPrincipal$' {
            $Result.PrincipalType = "ForeignSecurityPrincipal"
            break
        }
        default { $Result.PrincipalType = "AdObject:$Class" }
    }
}

function Get-PrincipalFromIdentity {
    param([Parameter(Mandatory)][string]$Identity)

    if ($AdCache.ContainsKey($Identity)) { return $AdCache[$Identity] }

    $OriginalIdentity = $Identity
    $Result = New-PrincipalRecord -Identity $Identity
    $AccountName = $Identity
    if ($Identity -match '\\') { $AccountName = ($Identity -split '\\',2)[1] }

    # ---- SID <-> NTAccount ----
    try {
        if ($Identity -match '^S-\d-\d+') {
            $SidObject = New-Object System.Security.Principal.SecurityIdentifier($Identity)
            $Result.SID = $SidObject.Value
            try {
                $Translated = $SidObject.Translate([System.Security.Principal.NTAccount])
                $Result.Identity = $Translated.Value
                $Identity = $Translated.Value
                if ($Identity -match '\\') { $AccountName = ($Identity -split '\\',2)[1] }
            }
            catch { $Result.OrphanedSID = $true }
        }
        else {
            $NtAccount = New-Object System.Security.Principal.NTAccount($Identity)
            $Result.SID = $NtAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
    }
    catch {}

    if ($Result.Identity -match '^([^\\]+)\\') { $Result.Domain = $Matches[1] }

    # ---- Builtin / Well-Known ----
    $IsWellKnown = (
        $Result.SID -match '^S-1-5-32-' -or $Result.SID -match '^S-1-(1|2|3)-' -or $Result.SID -match '^S-1-5-(1|2|4|6|7|9|11|18|19|20)$' -or $Result.SID -match '^S-1-5-80-' -or
        $Identity -match '^(BUILTIN|VORDEFINIERT|NT AUTHORITY|NT-AUTORITÄT|NT SERVICE)\\' -or $Identity -in @('Everyone','Jeder','CREATOR OWNER','ERSTELLER-BESITZER')
    )
    if ($IsWellKnown) {
        $Result.PrincipalType = if ($Result.SID -match '^S-1-5-32-') { "LocalGroup" } else { "BuiltIn" }
        $Result.Name = $Identity
        $Result.Source = "WellKnown"
        $Result.IsLocal = ($Result.SID -match '^S-1-5-32-')
        $Result.IdentityClass = Get-IdentityClass -Identity $Result.Identity -SID $Result.SID -PrincipalType $Result.PrincipalType
        $Object = [PSCustomObject]$Result; $AdCache[$OriginalIdentity] = $Object; return $Object
    }

    # ---- Lokales Konto des Fileservers? (Maschinen-SID) ----
    foreach ($MachineSid in $script:MachineSids.Values) {
        if ($MachineSid -and $Result.SID.StartsWith("$MachineSid-")) {
            $Result.IsLocal = $true
            $Result.Source = "LocalSAM"
            $Result.PrincipalType = "LocalOrUnknown"
            try {
                $Srv = ($script:MachineSids.GetEnumerator() | Where-Object { $_.Value -eq $MachineSid } | Select-Object -First 1).Key
                $Adsi = [ADSI]"WinNT://$Srv/$AccountName"
                $Cls = [string]$Adsi.psbase.SchemaClassName
                if ($Cls -eq "Group") { $Result.PrincipalType = "LocalGroup" }
                elseif ($Cls -eq "User") {
                    $Result.PrincipalType = "LocalUser"
                    $Flags = [int]$Adsi.UserFlags.Value
                    $Result.Enabled = -not ($Flags -band 2)
                    try { $Result.LastLogonDate = [DateTime]$Adsi.LastLogin.Value } catch {}
                }
                $Result.SamAccountName = $AccountName
                $Result.Name = $AccountName
            } catch {}
            $Result.IdentityClass = Get-IdentityClass -Identity $Result.Identity -SID $Result.SID -PrincipalType $Result.PrincipalType
            $Object = [PSCustomObject]$Result; $AdCache[$OriginalIdentity] = $Object; return $Object
        }
    }

    # ---- Active Directory (LDAP, ein Lookup, dann Klassifizierung nach objectClass) ----
    if ($script:AdAvailable) {
        $Objs = @()
        try {
            if ($Result.SID) { $Objs = @(Resolve-AdObjectByFilter -LdapFilter "(objectSid=$($Result.SID))") }
            if ($Objs.Count -eq 0 -and $AccountName) { $Objs = @(Resolve-AdObjectByFilter -LdapFilter "(sAMAccountName=$(ConvertTo-LdapEscaped $AccountName))") }
        }
        catch { Add-AuditError -Target $OriginalIdentity -Operation "AD Lookup" -Identity $OriginalIdentity -Message $_.Exception.Message -Severity "Warning" }

        if ($Objs.Count -gt 0) {
            Complete-PrincipalFromAdObject -Result $Result -Obj $Objs[0]
            $Result.IdentityClass = Get-IdentityClass -Identity $Result.Identity -SID $Result.SID -PrincipalType $Result.PrincipalType
            $Object = [PSCustomObject]$Result; $AdCache[$OriginalIdentity] = $Object; return $Object
        }
    }

    if ($OriginalIdentity -match '^S-\d-\d+' -and $Result.OrphanedSID) { $Result.PrincipalType = "OrphanedSID" }
    elseif ($OriginalIdentity -match '^S-\d-\d+') { $Result.PrincipalType = "UnknownSID" }
    elseif ($Result.SID -match '^S-1-5-21-' -and $Result.Domain -and $Result.Domain -ne $script:DomainNetBIOS) { $Result.PrincipalType = "ForeignDomain" }
    else { $Result.PrincipalType = "LocalOrUnknown" }
    $Result.Name = $Result.Identity
    $Result.IdentityClass = Get-IdentityClass -Identity $Result.Identity -SID $Result.SID -PrincipalType $Result.PrincipalType
    $Object = [PSCustomObject]$Result; $AdCache[$OriginalIdentity] = $Object; return $Object
}

function Register-Principal {
    param([Parameter(Mandatory)]$Principal)
    $Key = if ($Principal.SID) { $Principal.SID } else { $Principal.Identity }
    if ($PrincipalsWritten.ContainsKey($Key)) { return }
    $PrincipalsWritten[$Key] = $true
    $Row = [PSCustomObject]@{
        Identity          = $Principal.Identity
        SID               = $Principal.SID
        SamAccountName    = $Principal.SamAccountName
        Name              = $Principal.Name
        PrincipalType     = $Principal.PrincipalType
        IdentityClass     = $Principal.IdentityClass
        Domain            = $Principal.Domain
        IsLocal           = $Principal.IsLocal
        Enabled           = $Principal.Enabled
        LastLogonDate     = $Principal.LastLogonDate
        InactiveDays      = $Principal.InactiveDays
        PasswordLastSet   = $Principal.PasswordLastSet
        AccountExpires    = $Principal.AccountExpires
        AdminCount        = $Principal.AdminCount
        GroupScope        = $Principal.GroupScope
        GroupCategory     = $Principal.GroupCategory
        OrphanedSID       = $Principal.OrphanedSID
        DistinguishedName = $Principal.DistinguishedName
        Source            = $Principal.Source
    }
    $PrincipalsBuffer.Add($Row)
}

function New-MemberRecord {
    param($Resolved,[string]$GroupPath,[string]$TypeOverride = "")
    return [PSCustomObject]@{
        GroupPath            = $GroupPath
        MemberIdentity       = $Resolved.Identity
        MemberSamAccountName = $Resolved.SamAccountName
        MemberName           = $Resolved.Name
        MemberType           = if ($TypeOverride) { $TypeOverride } else { $Resolved.PrincipalType }
        MemberClass          = $Resolved.IdentityClass
        MemberEnabled        = $Resolved.Enabled
        MemberSID            = $Resolved.SID
        MemberLastLogon      = $Resolved.LastLogonDate
        MemberInactiveDays   = $Resolved.InactiveDays
        MemberAdminCount     = $Resolved.AdminCount
    }
}

function Add-GroupRow {
    param($Group,[string]$GroupPath,$Resolved,[string]$TypeOverride = "")
    $GroupsBuffer.Add([PSCustomObject]@{
        RootGroup     = $Group.SamAccountName
        RootGroupSID  = $Group.SID
        ParentGroup   = if ($Group.SamAccountName) { $Group.SamAccountName } else { $Group.Identity }
        GroupPath     = $GroupPath
        GroupScope    = $Group.GroupScope
        GroupCategory = $Group.GroupCategory
        Member        = if ($Resolved.SamAccountName) { $Resolved.SamAccountName } else { $Resolved.Identity }
        MemberName    = $Resolved.Name
        MemberType    = if ($TypeOverride) { $TypeOverride } else { $Resolved.PrincipalType }
        MemberClass   = $Resolved.IdentityClass
        Enabled       = $Resolved.Enabled
        LastLogonDate = $Resolved.LastLogonDate
        InactiveDays  = $Resolved.InactiveDays
        SID           = $Resolved.SID
    })
}

# --- Direkte Mitglieder einer AD-Gruppe per LDAP (inkl. primaryGroupID, ohne 5000er-Limit) ---
function Get-AdGroupDirectMembers {
    param([Parameter(Mandatory)]$Group)
    $Dn = ConvertTo-LdapEscaped $Group.DistinguishedName
    $Filter = "(memberOf=$Dn)"
    if ($Group.SID -match '-(\d+)$') { $Filter = "(|(memberOf=$Dn)(primaryGroupID=$($Matches[1])))" }
    $Props = @("objectClass","sAMAccountName","name","displayName","distinguishedName","userAccountControl","lastLogonTimestamp","pwdLastSet","accountExpires","adminCount","groupType","objectSid","msDS-PrincipalName")
    $AdP = $script:AdParams
    return @(Get-ADObject -LDAPFilter $Filter -Properties $Props -ResultPageSize 500 @AdP -ErrorAction Stop)
}

function Expand-AdGroup {
    param([Parameter(Mandatory)]$Group,[string[]]$VisitedGroups = @(),[string]$CurrentPath = "")

    if ($Group.PrincipalType -ne "Group") { return @() }
    $GroupKey = if ($Group.SID) { [string]$Group.SID } else { [string]$Group.SamAccountName }
    $ThisPath = if ([string]::IsNullOrWhiteSpace($CurrentPath)) { [string]$Group.SamAccountName } else { "$CurrentPath -> $($Group.SamAccountName)" }

    if ($VisitedGroups -contains $GroupKey) {
        return @(New-MemberRecord -Resolved $Group -GroupPath "$CurrentPath -> [CIRCULAR:$($Group.SamAccountName)]" -TypeOverride "CircularGroupReference")
    }

    # Cache je Gruppe (flache Mitgliederliste); GroupPath wird beim Abruf umgeschrieben
    if ($GroupExpansionCache.ContainsKey($GroupKey)) {
        $Cached = $GroupExpansionCache[$GroupKey]
        return @($Cached | ForEach-Object {
            $Copy = $_.PSObject.Copy()
            $Copy.GroupPath = if ($_.GroupPath) { "$ThisPath -> $($_.GroupPath)" } else { $ThisPath }
            $Copy
        })
    }

    $VisitedNow = @($VisitedGroups + $GroupKey)
    $Output = [System.Collections.Generic.List[object]]::new()

    try {
        $Members = @()
        if ($script:AdAvailable -and $Group.DistinguishedName) { $Members = @(Get-AdGroupDirectMembers -Group $Group) }

        if ($Members.Count -eq 0) {
            $Empty = New-PrincipalRecord -Identity ""
            $Empty.PrincipalType = "EmptyGroup"
            $Output.Add((New-MemberRecord -Resolved ([PSCustomObject]$Empty) -GroupPath "" -TypeOverride "EmptyGroup"))
        }

        foreach ($Member in $Members) {
            $SidObj = Get-Prop $Member "objectSid"
            $MemberSid = if ($null -ne $SidObj) { [string]$SidObj.Value } else { "" }
            $Pn = [string](Get-Prop $Member "msDS-PrincipalName")
            $Lookup = if ($MemberSid) { $MemberSid } elseif ($Pn) { $Pn } else { [string](Get-Prop $Member "sAMAccountName") }
            if (-not $Lookup) { continue }
            $Resolved = Get-PrincipalFromIdentity -Identity $Lookup
            Register-Principal -Principal $Resolved
            Add-GroupRow -Group $Group -GroupPath $ThisPath -Resolved $Resolved

            if ($Resolved.PrincipalType -eq "Group") {
                $Nested = @(Expand-AdGroup -Group $Resolved -VisitedGroups $VisitedNow -CurrentPath $ThisPath)
                foreach ($N in $Nested) { $Output.Add($N) }
            }
            else {
                $Output.Add((New-MemberRecord -Resolved $Resolved -GroupPath ""))
            }
        }
    }
    catch {
        Add-AuditError -Target $Group.Identity -Operation "Expand-AdGroup" -Identity $Group.Identity -Message $_.Exception.Message
        $Err = New-PrincipalRecord -Identity $Group.Identity
        $Err.PrincipalType = "ExpansionError"
        $Output.Add((New-MemberRecord -Resolved ([PSCustomObject]$Err) -GroupPath "" -TypeOverride "ExpansionError"))
    }

    # Cache mit relativen Pfaden speichern (Pfad unterhalb dieser Gruppe)
    $Relative = @($Output | ForEach-Object {
        $Copy = $_.PSObject.Copy()
        $GP = [string]$_.GroupPath
        if ($GP.StartsWith("$ThisPath -> ")) { $Copy.GroupPath = $GP.Substring($ThisPath.Length + 4) }
        elseif ($GP -eq $ThisPath) { $Copy.GroupPath = "" }
        $Copy
    })
    $GroupExpansionCache[$GroupKey] = $Relative

    return @($Relative | ForEach-Object {
        $Copy = $_.PSObject.Copy()
        $Copy.GroupPath = if ($_.GroupPath) { "$ThisPath -> $($_.GroupPath)" } else { $ThisPath }
        $Copy
    })
}

# --- Lokale Gruppe des Fileservers (BUILTIN\Users, BUILTIN\Administrators, SERVER\Gruppe) ---
function Expand-LocalGroup {
    param([Parameter(Mandatory)][string]$Server,[Parameter(Mandatory)]$Group,[string[]]$VisitedGroups = @(),[string]$CurrentPath = "")

    $GroupName = if ($Group.Identity -match '\\') { ($Group.Identity -split '\\',2)[1] } else { $Group.Identity }
    $Key = "$Server|$($Group.SID)|$GroupName"
    $ThisPath = if ([string]::IsNullOrWhiteSpace($CurrentPath)) { "$Server\$GroupName" } else { "$CurrentPath -> $Server\$GroupName" }
    if ($VisitedGroups -contains $Key) { return @() }
    $VisitedNow = @($VisitedGroups + $Key)

    if ($LocalGroupCache.ContainsKey($Key)) {
        return @($LocalGroupCache[$Key] | ForEach-Object { $c = $_.PSObject.Copy(); $c.GroupPath = if ($_.GroupPath) { "$ThisPath -> $($_.GroupPath)" } else { $ThisPath }; $c })
    }

    $Output = [System.Collections.Generic.List[object]]::new()
    try {
        $Adsi = [ADSI]"WinNT://$Server/$GroupName,group"
        $Members = @($Adsi.psbase.Invoke("Members"))
        if ($Members.Count -eq 0) {
            $Empty = New-PrincipalRecord -Identity ""; $Empty.PrincipalType = "EmptyGroup"
            $Output.Add((New-MemberRecord -Resolved ([PSCustomObject]$Empty) -GroupPath "" -TypeOverride "EmptyGroup"))
        }
        foreach ($M in $Members) {
            $MName = [string]$M.GetType().InvokeMember("Name","GetProperty",$null,$M,$null)
            $MPath = [string]$M.GetType().InvokeMember("ADsPath","GetProperty",$null,$M,$null)
            $MSid  = ""
            try {
                $Bytes = $M.GetType().InvokeMember("objectSid","GetProperty",$null,$M,$null)
                $MSid = (New-Object System.Security.Principal.SecurityIdentifier($Bytes,0)).Value
            } catch {}
            # WinNT://DOMAIN/name  bzw. WinNT://SERVER/name  bzw. WinNT://NT AUTHORITY/...
            $Domain = ""
            if ($MPath -match '^WinNT://([^/]+)/([^/]+)$') { $Domain = $Matches[1] }
            $Lookup = if ($MSid) { $MSid } elseif ($Domain) { "$Domain\$MName" } else { $MName }
            $Resolved = Get-PrincipalFromIdentity -Identity $Lookup
            Register-Principal -Principal $Resolved
            Add-GroupRow -Group $Group -GroupPath $ThisPath -Resolved $Resolved

            if ($Resolved.PrincipalType -eq "Group" -and -not $SkipGroupExpansion) {
                foreach ($N in @(Expand-AdGroup -Group $Resolved -CurrentPath $ThisPath)) { $Output.Add($N) }
            }
            elseif ($Resolved.PrincipalType -eq "LocalGroup" -and $Resolved.SID -ne $Group.SID) {
                foreach ($N in @(Expand-LocalGroup -Server $Server -Group $Resolved -VisitedGroups $VisitedNow -CurrentPath $ThisPath)) { $Output.Add($N) }
            }
            else {
                $Output.Add((New-MemberRecord -Resolved $Resolved -GroupPath ""))
            }
        }
    }
    catch {
        Add-AuditError -Target "$Server\$GroupName" -Operation "Expand-LocalGroup" -Identity $Group.Identity -Message $_.Exception.Message
        $Err = New-PrincipalRecord -Identity $Group.Identity; $Err.PrincipalType = "ExpansionError"
        $Output.Add((New-MemberRecord -Resolved ([PSCustomObject]$Err) -GroupPath "" -TypeOverride "ExpansionError"))
    }

    $Relative = @($Output | ForEach-Object {
        $c = $_.PSObject.Copy(); $GP = [string]$_.GroupPath
        if ($GP.StartsWith("$ThisPath -> ")) { $c.GroupPath = $GP.Substring($ThisPath.Length + 4) } elseif ($GP -eq $ThisPath) { $c.GroupPath = "" }
        $c
    })
    $LocalGroupCache[$Key] = $Relative
    return @($Relative | ForEach-Object { $c = $_.PSObject.Copy(); $c.GroupPath = if ($_.GroupPath) { "$ThisPath -> $($_.GroupPath)" } else { $ThisPath }; $c })
}

function Get-MachineSid {
    param([Parameter(Mandatory)][string]$Server)
    if ($script:MachineSids.ContainsKey($Server)) { return $script:MachineSids[$Server] }
    $Sid = ""
    try {
        $Adm = [ADSI]"WinNT://$Server/Administrator,user"
        $Bytes = $Adm.psbase.InvokeGet("objectSid")
        $Full = (New-Object System.Security.Principal.SecurityIdentifier($Bytes,0)).Value
        if ($Full -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') { $Sid = $Matches[1] }
    }
    catch {
        try {
            $Acct = New-Object System.Security.Principal.NTAccount("$Server\Administrator")
            $Full = $Acct.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if ($Full -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') { $Sid = $Matches[1] }
        }
        catch {
            try {
                $Computer = [ADSI]"WinNT://$Server"
                foreach ($Child in $Computer.psbase.Children) {
                    if ($Child.psbase.SchemaClassName -ne "User") { continue }
                    $Bytes = $Child.psbase.InvokeGet("objectSid")
                    $Full = (New-Object System.Security.Principal.SecurityIdentifier($Bytes,0)).Value
                    if ($Full -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') { $Sid = $Matches[1]; break }
                }
            }
            catch { Add-AuditError -Target $Server -Operation "MachineSID" -Message $_.Exception.Message -Severity "Warning" }
        }
    }
    $script:MachineSids[$Server] = $Sid
    return $Sid
}

# ============================================================================
# MATRIX
# ============================================================================

function Add-MatrixRowsForPrincipal {
    param(
        [Parameter(Mandatory)][string]$Drive,[Parameter(Mandatory)][string]$FileServer,[Parameter(Mandatory)][string]$ShareName,
        [Parameter(Mandatory)][string]$ShareRoot,[Parameter(Mandatory)][string]$FolderPath,[Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][ValidateSet("SMB","NTFS")][string]$Layer,[Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][int64]$RightsMask,[Parameter(Mandatory)][string]$RightsText,[Parameter(Mandatory)][string]$AccessType,
        [bool]$IsInherited = $false,[bool]$InheritanceBroken = $false,[string]$InheritanceFlags = "",[string]$PropagationFlags = "",
        [string]$AppliesTo = "Dieser Ordner",[string]$ItemType = "Folder"
    )

    if (Test-IdentityExcluded -Identity $Identity) { return }

    $Principal = Get-PrincipalFromIdentity -Identity $Identity
    Register-Principal -Principal $Principal

    if ($Principal.OrphanedSID) {
        $OrphanSidBuffer.Add([PSCustomObject]@{
            Drive = $Drive; FileServer = $FileServer; ShareName = $ShareName; Path = $FolderPath; Layer = $Layer
            Identity = $Identity; SID = $Principal.SID; Rights = $RightsText; RightsClass = (Get-RightsClass -Mask $RightsMask); AccessType = $AccessType
        })
    }

    $Role = if ($Principal.SamAccountName) { [string]$Principal.SamAccountName } else { [string]$Principal.Identity }
    $RightsClass = Get-RightsClass -Mask $RightsMask
    $CanChangeAcl = (($RightsMask -band ($RIGHT_WRITE_DAC -bor $RIGHT_WRITE_OWNER)) -ne 0)

    $Base = [ordered]@{
        Drive = $Drive; FileServer = $FileServer; ShareName = $ShareName; ShareRoot = $ShareRoot
        FolderPath = $FolderPath; RelativePath = $RelativePath; ItemType = $ItemType; PermissionLayer = $Layer
        Role = $Role; RoleIdentity = $Principal.Identity; RoleType = $Principal.PrincipalType; RoleSID = $Principal.SID
        RoleClass = $Principal.IdentityClass; RoleScope = $Principal.GroupScope; RoleCategory = $Principal.GroupCategory
        GroupPath = ""; UserOrMember = ""; MemberName = ""; MemberType = ""; MemberSID = ""; MemberClass = ""
        MemberEnabled = $null; MemberLastLogon = $null; MemberInactiveDays = $null; MemberAdminCount = $null
        Rights = $RightsText; RightsMask = $RightsMask; RightsClass = $RightsClass; CanChangePermissions = $CanChangeAcl
        AppliesTo = $AppliesTo; AccessType = $AccessType; IsInherited = $IsInherited; InheritanceBroken = $InheritanceBroken
        InheritanceFlags = $InheritanceFlags; PropagationFlags = $PropagationFlags
        OrphanedSID = $Principal.OrphanedSID; DirectAssignment = $false
    }

    $Members = @()
    if (-not $SkipGroupExpansion -and $Principal.PrincipalType -eq "Group") {
        $Members = @(Expand-AdGroup -Group $Principal)
    }
    elseif (-not $SkipLocalGroupExpansion -and $Principal.PrincipalType -eq "LocalGroup") {
        $Members = @(Expand-LocalGroup -Server $FileServer -Group $Principal)
    }

    if ($Members.Count -gt 0) {
        foreach ($Member in $Members) {
            $Row = Copy-Ordered -Source $Base
            $Row.GroupPath          = $Member.GroupPath
            $Row.UserOrMember       = if ($Member.MemberSamAccountName) { $Member.MemberSamAccountName } else { $Member.MemberIdentity }
            $Row.MemberName         = $Member.MemberName
            $Row.MemberType         = $Member.MemberType
            $Row.MemberSID          = $Member.MemberSID
            $Row.MemberClass        = $Member.MemberClass
            $Row.MemberEnabled      = $Member.MemberEnabled
            $Row.MemberLastLogon    = $Member.MemberLastLogon
            $Row.MemberInactiveDays = $Member.MemberInactiveDays
            $Row.MemberAdminCount   = $Member.MemberAdminCount
            $MatrixBuffer.Add([PSCustomObject]$Row)
        }
        return
    }

    $Row = Copy-Ordered -Source $Base
    $Row.UserOrMember       = if ($Principal.SamAccountName) { $Principal.SamAccountName } else { $Principal.Identity }
    $Row.MemberName         = $Principal.Name
    $Row.MemberType         = $Principal.PrincipalType
    $Row.MemberSID          = $Principal.SID
    $Row.MemberClass        = $Principal.IdentityClass
    $Row.MemberEnabled      = $Principal.Enabled
    $Row.MemberLastLogon    = $Principal.LastLogonDate
    $Row.MemberInactiveDays = $Principal.InactiveDays
    $Row.MemberAdminCount   = $Principal.AdminCount
    $Row.DirectAssignment   = ($Principal.PrincipalType -in @("User","Computer","ServiceAccount","LocalUser"))
    $MatrixBuffer.Add([PSCustomObject]$Row)
}

# ============================================================================
# SMB AUDIT
# ============================================================================

function Get-SmbPermissions {
    param([Parameter(Mandatory)][string]$Drive,[Parameter(Mandatory)][string]$FileServer,[Parameter(Mandatory)][string]$ShareName,[Parameter(Mandatory)][string]$ShareRoot)

    if ($SkipSmbAudit) { return }
    $Key = "$FileServer|$ShareName"
    if ($SmbAudited.ContainsKey($Key)) { return }
    $SmbAudited[$Key] = $true

    Write-LiveStatus -Type "INFO" -Message "SMB-Berechtigungen: \\$FileServer\$ShareName"
    $Session = $null
    try {
        $ShareInfo = Get-ShareInformation -FileServer $FileServer -ShareName $ShareName
        if (Test-IsLocalServer -ServerName $FileServer) {
            $ShareAcl = @(Get-SmbShareAccess -Name $ShareName -ErrorAction Stop)
        } else {
            $Session = New-CimSession -ComputerName $FileServer -ErrorAction Stop
            $ShareAcl = @(Get-SmbShareAccess -Name $ShareName -CimSession $Session -ErrorAction Stop)
        }

        foreach ($Ace in $ShareAcl) {
            $Identity = [string]$Ace.AccountName
            $Right = [string]$Ace.AccessRight
            $Mask = if ($SMB_RIGHTS.ContainsKey($Right)) { [int64]$SMB_RIGHTS[$Right] } else { [int64]0 }
            $Principal = Get-PrincipalFromIdentity -Identity $Identity

            $SmbBuffer.Add([PSCustomObject]@{
                Drive = $Drive; FileServer = $FileServer; ShareName = $ShareName; ShareRoot = $ShareRoot
                SharePath = $ShareInfo.LocalPath; Identity = $Identity; PrincipalType = $Principal.PrincipalType; IdentityClass = $Principal.IdentityClass
                SID = $Principal.SID; AccessRight = $Right; RightsMask = $Mask; RightsClass = (Get-RightsClass -Mask $Mask)
                AccessType = [string]$Ace.AccessControlType
                FolderEnumerationMode = $ShareInfo.FolderEnumerationMode; AccessBasedEnumeration = ($ShareInfo.FolderEnumerationMode -eq "AccessBased")
                EncryptData = $ShareInfo.EncryptData; CachingMode = $ShareInfo.CachingMode; ConcurrentUserLimit = $ShareInfo.ConcurrentUserLimit
            })

            Add-MatrixRowsForPrincipal -Drive $Drive -FileServer $FileServer -ShareName $ShareName -ShareRoot $ShareRoot `
                -FolderPath $ShareRoot -RelativePath "." -Layer "SMB" -Identity $Identity -RightsMask $Mask -RightsText $Right `
                -AccessType ([string]$Ace.AccessControlType) -AppliesTo "Gesamte Freigabe"
        }
        Flush-Buffers
    }
    catch {
        Add-AuditError -Target "\\$FileServer\$ShareName" -Operation "SMB Audit" -Message $_.Exception.Message
        Write-LiveStatus -Type "WARN" -Message "SMB-Abfrage fehlgeschlagen: $($_.Exception.Message)"
    }
    finally {
        if ($null -ne $Session) { Remove-CimSession -CimSession $Session -ErrorAction SilentlyContinue }
    }
}

# ============================================================================
# NTFS AUDIT
# ============================================================================

function Get-ItemSecurity {
    param([Parameter(Mandatory)][string]$Path,[bool]$IsContainer = $true)
    $Sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner
    try {
        if ($IsContainer) {
            return (Invoke-LongPathAware -Path $Path -Action { param($P) New-Object System.Security.AccessControl.DirectorySecurity($P,$Sections) })
        }
        return (Invoke-LongPathAware -Path $Path -Action { param($P) New-Object System.Security.AccessControl.FileSecurity($P,$Sections) })
    }
    catch {
        if ($Path.Length -ge 248) { throw }
        # Zweiter Versuch über den Provider (z. B. bei Sonderzeichen)
        return (Get-Acl -LiteralPath $Path -ErrorAction Stop)
    }
}

function Get-NtfsPermissions {
    param(
        [Parameter(Mandatory)][string]$Drive,[Parameter(Mandatory)][string]$FileServer,[Parameter(Mandatory)][string]$ShareName,
        [Parameter(Mandatory)][string]$ShareRoot,[Parameter(Mandatory)][string]$AuditRoot,[Parameter(Mandatory)][string]$ScanRoot,
        [Parameter(Mandatory)][string]$ScanPath,[Parameter(Mandatory)][bool]$IsRoot,[int]$Depth = 0,[bool]$IsContainer = $true,[bool]$IsReparsePoint = $false
    )

    $DisplayPath  = Get-DisplayPath -ScanRoot $ScanRoot -AuditRoot $AuditRoot -CurrentScanPath $ScanPath
    $RelativePath = Get-RelativePathText -Root $AuditRoot -Current $DisplayPath
    $ItemType     = if ($IsContainer) { "Folder" } else { "File" }

    try {
        $Sec = Get-ItemSecurity -Path $ScanPath -IsContainer $IsContainer
        $InheritanceBroken = [bool]$Sec.AreAccessRulesProtected

        # Owner (SID-basiert, dann auflösen)
        $OwnerSid = ""; $OwnerIdentity = ""
        try { $OwnerSid = $Sec.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch {}
        $Owner = $null
        if ($OwnerSid) { $Owner = Get-PrincipalFromIdentity -Identity $OwnerSid; Register-Principal -Principal $Owner; $OwnerIdentity = $Owner.Identity }

        $Rules = @($Sec.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
        $ExplicitCount = 0; $InheritedCount = 0
        foreach ($R in $Rules) { if ($R.IsInherited) { $InheritedCount++ } else { $ExplicitCount++ } }

        if ($InheritanceBroken) {
            $InheritanceBuffer.Add([PSCustomObject]@{
                Drive = $Drive; FileServer = $FileServer; ShareName = $ShareName; FolderPath = $DisplayPath; RelativePath = $RelativePath
                ItemType = $ItemType; Owner = $OwnerIdentity; OwnerSID = $OwnerSid; ExplicitAceCount = $ExplicitCount
            })
        }

        $OwnerRisk = ""
        if ($null -ne $Owner) {
            if ($Owner.OrphanedSID) { $OwnerRisk = "OrphanedOwner" }
            elseif ($Owner.PrincipalType -in @("User","LocalUser") -and $Owner.IdentityClass -notin @("Admin","System")) { $OwnerRisk = "UserOwner" }
            elseif ($Owner.IdentityClass -eq "Broad") { $OwnerRisk = "BroadOwner" }
        }

        # Ordnerindex: jeder geprüfte Ordner, auch ohne explizite ACEs (für Vollständigkeit + Owner + wirksame Rechte in der GUI)
        if ($IsContainer -or $ExplicitCount -gt 0 -or $InheritanceBroken) {
            $FolderBuffer.Add([PSCustomObject]@{
                Drive = $Drive; FileServer = $FileServer; ShareName = $ShareName; FolderPath = $DisplayPath; RelativePath = $RelativePath
                Depth = $Depth; ItemType = $ItemType; Owner = $OwnerIdentity; OwnerSID = $OwnerSid
                OwnerType = if ($Owner) { $Owner.PrincipalType } else { "" }; OwnerClass = if ($Owner) { $Owner.IdentityClass } else { "" }
                OwnerRisk = $OwnerRisk; InheritanceBroken = $InheritanceBroken; ExplicitAceCount = $ExplicitCount; InheritedAceCount = $InheritedCount
                IsReparsePoint = $IsReparsePoint; AclStatus = "OK"
            })
        }

        foreach ($Ace in $Rules) {
            if ($AclMode -eq "ChangesOnly" -and -not $IsRoot -and [bool]$Ace.IsInherited) { continue }

            $Identity = [string]$Ace.IdentityReference.Value
            if (Test-IdentityExcluded -Identity $Identity) { continue }

            $Principal  = Get-PrincipalFromIdentity -Identity $Identity
            $Mask       = ConvertTo-RightsMask -FileSystemRights $Ace.FileSystemRights
            $RightsText = Get-RightsText -Mask $Mask
            $RightsClass = Get-RightsClass -Mask $Mask
            $InhFlags   = [string]$Ace.InheritanceFlags
            $PropFlags  = [string]$Ace.PropagationFlags
            $AppliesTo  = Get-AppliesTo -InheritanceFlags $InhFlags -PropagationFlags $PropFlags -IsContainer $IsContainer

            $NtfsBuffer.Add([PSCustomObject]@{
                Drive = $Drive; FileServer = $FileServer; ShareName = $ShareName; ShareRoot = $ShareRoot; AuditRoot = $AuditRoot
                FolderPath = $DisplayPath; RelativePath = $RelativePath; ItemType = $ItemType; Owner = $OwnerIdentity
                Identity = $Principal.Identity; PrincipalType = $Principal.PrincipalType; IdentityClass = $Principal.IdentityClass; SID = $Principal.SID
                Rights = $RightsText; RightsMask = $Mask; RightsClass = $RightsClass
                CanChangePermissions = (($Mask -band ($RIGHT_WRITE_DAC -bor $RIGHT_WRITE_OWNER)) -ne 0)
                AppliesTo = $AppliesTo; AccessType = [string]$Ace.AccessControlType; IsInherited = [bool]$Ace.IsInherited
                InheritanceBroken = $InheritanceBroken; InheritanceFlags = $InhFlags; PropagationFlags = $PropFlags
                OrphanedSID = [bool]$Principal.OrphanedSID
            })

            Add-MatrixRowsForPrincipal -Drive $Drive -FileServer $FileServer -ShareName $ShareName -ShareRoot $ShareRoot `
                -FolderPath $DisplayPath -RelativePath $RelativePath -Layer "NTFS" -Identity $Identity `
                -RightsMask $Mask -RightsText $RightsText -AccessType ([string]$Ace.AccessControlType) `
                -IsInherited ([bool]$Ace.IsInherited) -InheritanceBroken $InheritanceBroken `
                -InheritanceFlags $InhFlags -PropagationFlags $PropFlags -AppliesTo $AppliesTo -ItemType $ItemType
        }
        return $true
    }
    catch {
        $Op = if ($ScanPath.Length -ge 248) { "Get-Acl (LongPath)" } else { "Get-Acl" }
        Add-AuditError -Target $DisplayPath -Operation $Op -Message $_.Exception.Message
        $FolderBuffer.Add([PSCustomObject]@{
            Drive = $Drive; FileServer = $FileServer; ShareName = $ShareName; FolderPath = $DisplayPath; RelativePath = $RelativePath
            Depth = $Depth; ItemType = $ItemType; Owner = ""; OwnerSID = ""; OwnerType = ""; OwnerClass = ""; OwnerRisk = ""
            InheritanceBroken = $null; ExplicitAceCount = $null; InheritedAceCount = $null; IsReparsePoint = $IsReparsePoint; AclStatus = "Error"
        })
        return $false
    }
}

# ============================================================================
# ACTIVE DIRECTORY
# ============================================================================

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $script:AdAvailable = $true
    if ($AdServer) { $script:AdParams = @{ Server = $AdServer } }
    try {
        $AdP = $script:AdParams
        $Domain = Get-ADDomain @AdP -ErrorAction Stop
        $script:DomainNetBIOS = [string]$Domain.NetBIOSName
        $script:DomainSID = [string]$Domain.DomainSID.Value
    } catch {}
    Write-LiveStatus -Type "OK" -Message "ActiveDirectory-Modul geladen."
    if ($script:DomainNetBIOS) { Write-LiveStatus -Type "INFO" -Message "AD-Domäne erkannt: $($script:DomainNetBIOS) ($($script:DomainSID))" }
}
catch {
    Write-LiveStatus -Type "WARN" -Message "ActiveDirectory-Modul nicht verfügbar. Gruppenauflösung eingeschränkt."
    Add-AuditError -Target "ActiveDirectory" -Operation "Import-Module" -Message $_.Exception.Message -Severity "Warning"
}

# ============================================================================
# HAUPTAUSWERTUNG
# ============================================================================

$SummaryRows  = [System.Collections.Generic.List[object]]::new()
$TargetNumber = 0

Write-LiveStatus -Type "INFO" -Message "Audit v$ScriptVersion gestartet. ACL-Modus: $AclMode, ausführendes Konto: $env:USERDOMAIN\$env:USERNAME auf $env:COMPUTERNAME"
Write-LiveStatus -Type "INFO" -Message "Ergebnisse werden alle $FlushEvery geprüften Objekte in CSV geschrieben."

foreach ($Target in $Targets) {
    $TargetNumber++
    $Drive = [string]$Target.Drive
    $AuditRoot = [string]$Target.Path
    $TargetStart = Get-Date

    $Scanned = 0; $FilesScanned = 0; $AclSuccess = 0; $AclErrors = 0; $EnumErrors = 0; $ReparseSkipped = 0; $LongPaths = 0; $MaxDepthSeen = 0
    $TargetNtfsCount = 0; $TargetMatrixCount = 0; $TargetInheritanceCount = 0; $TargetOrphanCount = 0

    Write-Host ""
    Write-Host "====================================================================" -ForegroundColor DarkCyan
    Write-Host "[$TargetNumber/$($Targets.Count)] $Drive -> $AuditRoot" -ForegroundColor Cyan
    Write-Host "====================================================================" -ForegroundColor DarkCyan

    try { $Unc = Get-UncParts -Path $AuditRoot }
    catch {
        Add-AuditError -Target $AuditRoot -Operation "Parse UNC" -Message $_.Exception.Message
        Write-LiveStatus -Type "ERR" -Message $_.Exception.Message
        Flush-Buffers; continue
    }

    Write-LiveStatus -Type "INFO" -Message "Server: $($Unc.Server), Share: $($Unc.Share)"
    if ($Unc.RelativePath) { Write-LiveStatus -Type "INFO" -Message "Unterpfad: $($Unc.RelativePath)" }

    if (-not (Test-Path -LiteralPath $AuditRoot)) {
        Add-AuditError -Target $AuditRoot -Operation "Test-Path" -Message "UNC-Pfad nicht erreichbar oder keine Leseberechtigung."
        Write-LiveStatus -Type "ERR" -Message "UNC-Pfad nicht erreichbar: $AuditRoot"
        Flush-Buffers; continue
    }

    $MachineSid = Get-MachineSid -Server $Unc.Server
    if ($MachineSid) { Write-LiveStatus -Type "INFO" -Message "Maschinen-SID $($Unc.Server): $MachineSid (lokale Konten werden erkannt)" }

    Get-SmbPermissions -Drive $Drive -FileServer $Unc.Server -ShareName $Unc.Share -ShareRoot $Unc.ShareRoot

    $ScanInfo = Get-ScanRoot -AuditRoot $AuditRoot -Unc $Unc
    $ScanRoot = [string]$ScanInfo.ScanRoot
    if ($ScanInfo.LocalMode) { Write-LiveStatus -Type "OK" -Message "Lokale Pfadoptimierung aktiv: $AuditRoot -> $ScanRoot" }
    else { Write-LiveStatus -Type "INFO" -Message "Audit erfolgt über UNC: $ScanRoot" }

    # ---- Root ----
    $B1 = $NtfsBuffer.Count; $B2 = $MatrixBuffer.Count; $B3 = $InheritanceBuffer.Count; $B4 = $OrphanSidBuffer.Count
    $RootOk = Get-NtfsPermissions -Drive $Drive -FileServer $Unc.Server -ShareName $Unc.Share -ShareRoot $Unc.ShareRoot `
        -AuditRoot $AuditRoot -ScanRoot $ScanRoot -ScanPath $ScanRoot -IsRoot $true -Depth 0
    if ($RootOk) { $AclSuccess++ } else { $AclErrors++ }
    $TargetNtfsCount += ($NtfsBuffer.Count - $B1); $TargetMatrixCount += ($MatrixBuffer.Count - $B2)
    $TargetInheritanceCount += ($InheritanceBuffer.Count - $B3); $TargetOrphanCount += ($OrphanSidBuffer.Count - $B4)

    Write-LiveStatus -Type "INFO" -Message "Iterative Ordner-Enumeration beginnt (Streaming, Enumerationsfehler werden protokolliert)."

    # ---- Echte Streaming-Enumeration: iterativer Stack, kein Get-ChildItem -Recurse ----
    $Stack = [System.Collections.Generic.Stack[object]]::new()
    $Stack.Push([PSCustomObject]@{ Path = $ScanRoot; Depth = 0 })
    $ReparseAttr = [System.IO.FileAttributes]::ReparsePoint

    while ($Stack.Count -gt 0) {
        $Current = $Stack.Pop()
        $CurPath = [string]$Current.Path
        $CurDepth = [int]$Current.Depth
        if ($MaxDepth -gt 0 -and $CurDepth -ge $MaxDepth) { continue }

        # Unterordner
        $Children = @()
        try {
            $Children = @(Invoke-LongPathAware -Path $CurPath -Action { param($P) [System.IO.Directory]::EnumerateDirectories($P) })
        }
        catch {
            $EnumErrors++
            Add-AuditError -Target (Get-DisplayPath -ScanRoot $ScanRoot -AuditRoot $AuditRoot -CurrentScanPath $CurPath) -Operation "Enumerate" -Message $_.Exception.Message
            Write-LiveStatus -Type "WARN" -Message "Enumeration fehlgeschlagen (Teilbaum fehlt!): $CurPath – $($_.Exception.Message)"
            continue
        }

        foreach ($ChildRaw in $Children) {
            $Child = ConvertFrom-LongPath -Path ([string]$ChildRaw)
            $Depth = $CurDepth + 1
            if ($Depth -gt $MaxDepthSeen) { $MaxDepthSeen = $Depth }
            if ($Child.Length -ge 248) { $LongPaths++ }

            $IsReparse = $false
            try { $IsReparse = ((Invoke-LongPathAware -Path $Child -Action { param($P) [System.IO.File]::GetAttributes($P) }) -band $ReparseAttr) -ne 0 } catch {}

            $Scanned++
            $B1 = $NtfsBuffer.Count; $B2 = $MatrixBuffer.Count; $B3 = $InheritanceBuffer.Count; $B4 = $OrphanSidBuffer.Count
            $Ok = Get-NtfsPermissions -Drive $Drive -FileServer $Unc.Server -ShareName $Unc.Share -ShareRoot $Unc.ShareRoot `
                -AuditRoot $AuditRoot -ScanRoot $ScanRoot -ScanPath $Child -IsRoot $false -Depth $Depth -IsReparsePoint $IsReparse
            if ($Ok) { $AclSuccess++ } else { $AclErrors++ }
            $TargetNtfsCount += ($NtfsBuffer.Count - $B1); $TargetMatrixCount += ($MatrixBuffer.Count - $B2)
            $TargetInheritanceCount += ($InheritanceBuffer.Count - $B3); $TargetOrphanCount += ($OrphanSidBuffer.Count - $B4)

            if ($IsReparse -and -not $FollowReparsePoints) {
                $ReparseSkipped++
                Add-AuditError -Target (Get-DisplayPath -ScanRoot $ScanRoot -AuditRoot $AuditRoot -CurrentScanPath $Child) -Operation "ReparsePoint" -Message "Junction/Symlink/DFS-Verweis – Inhalt nicht rekursiv geprüft (FollowReparsePoints nicht gesetzt)." -Severity "Info"
            }
            else {
                $Stack.Push([PSCustomObject]@{ Path = $Child; Depth = $Depth })
            }

            if (($Scanned % $StatusEvery) -eq 0) {
                $Elapsed = (Get-Date) - $TargetStart
                $Rate = if ($Elapsed.TotalSeconds -gt 0) { [math]::Round($Scanned / $Elapsed.TotalSeconds,1) } else { 0 }
                Write-LiveStatus -Type "PROGRESS" -Message ("$Drive | Ordner: $Scanned | ACL OK: $AclSuccess | ACL-Fehler: $AclErrors | Enum-Fehler: $EnumErrors | " +
                    "NTFS-Zeilen: $TargetNtfsCount | Matrix-Zeilen: $TargetMatrixCount | Tempo: $Rate Ordner/s | aktuell: $Child")
            }
            if (($Scanned % $FlushEvery) -eq 0) { Flush-Buffers }
        }

        # Dateien (optional)
        if ($IncludeFiles) {
            try {
                foreach ($FileRaw in @(Invoke-LongPathAware -Path $CurPath -Action { param($P) [System.IO.Directory]::EnumerateFiles($P) })) {
                    $File = ConvertFrom-LongPath -Path ([string]$FileRaw)
                    $FilesScanned++
                    $B1 = $NtfsBuffer.Count; $B2 = $MatrixBuffer.Count; $B3 = $InheritanceBuffer.Count; $B4 = $OrphanSidBuffer.Count
                    $Ok = Get-NtfsPermissions -Drive $Drive -FileServer $Unc.Server -ShareName $Unc.Share -ShareRoot $Unc.ShareRoot `
                        -AuditRoot $AuditRoot -ScanRoot $ScanRoot -ScanPath $File -IsRoot $false -Depth ($CurDepth + 1) -IsContainer $false
                    if ($Ok) { $AclSuccess++ } else { $AclErrors++ }
                    $TargetNtfsCount += ($NtfsBuffer.Count - $B1); $TargetMatrixCount += ($MatrixBuffer.Count - $B2)
                    $TargetInheritanceCount += ($InheritanceBuffer.Count - $B3); $TargetOrphanCount += ($OrphanSidBuffer.Count - $B4)
                    if (($FilesScanned % $FlushEvery) -eq 0) { Flush-Buffers }
                }
            }
            catch {
                $EnumErrors++
                Add-AuditError -Target (Get-DisplayPath -ScanRoot $ScanRoot -AuditRoot $AuditRoot -CurrentScanPath $CurPath) -Operation "EnumerateFiles" -Message $_.Exception.Message
            }
        }
    }

    Flush-Buffers
    $TargetElapsed = (Get-Date) - $TargetStart

    $SummaryRows.Add([PSCustomObject]@{
        Drive = $Drive; RootPath = $AuditRoot; ScanPath = $ScanRoot; FileServer = $Unc.Server; ShareName = $Unc.Share
        LocalOptimization = [bool]$ScanInfo.LocalMode; AclMode = $AclMode; IncludeFiles = [bool]$IncludeFiles
        FoldersScanned = $Scanned; FilesScanned = $FilesScanned; MaxDepth = $MaxDepthSeen
        AclSuccess = $AclSuccess; AclErrors = $AclErrors; EnumerationErrors = $EnumErrors; ReparsePointsSkipped = $ReparseSkipped; LongPaths = $LongPaths
        NTFSRows = $TargetNtfsCount; MatrixRows = $TargetMatrixCount; InheritanceBreaks = $TargetInheritanceCount; OrphanedSIDRows = $TargetOrphanCount
        Complete = ($EnumErrors -eq 0 -and $AclErrors -eq 0)
        Start = $TargetStart.ToString("yyyy-MM-dd HH:mm:ss"); End = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"); Duration = $TargetElapsed.ToString()
    })

    $Verdict = if ($EnumErrors -eq 0 -and $AclErrors -eq 0) { "VOLLSTÄNDIG" } else { "UNVOLLSTÄNDIG ($EnumErrors Enumerationsfehler, $AclErrors ACL-Fehler – siehe 07_Errors.csv)" }
    Write-LiveStatus -Type $(if ($EnumErrors -eq 0 -and $AclErrors -eq 0) { "OK" } else { "WARN" }) -Message ("$Drive abgeschlossen: $Scanned Ordner, $FilesScanned Dateien, $TargetNtfsCount NTFS-Zeilen, $TargetMatrixCount Matrix-Zeilen, Dauer $($TargetElapsed.ToString()). Abdeckung: $Verdict")
}

# ============================================================================
# SUMMARY / RUNINFO / MANIFEST
# ============================================================================

Write-CsvBuffer -Rows $SummaryRows -Path $SummaryCsv
Flush-Buffers

$OverallElapsed = (Get-Date) - $OverallStart
$ScriptHash = ""
try { if ($PSCommandPath) { $ScriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash } } catch {}

$ParamText = ($PSBoundParameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
$RunInfo = @(
    [PSCustomObject]@{ Key = "ScriptVersion";     Value = $ScriptVersion }
    [PSCustomObject]@{ Key = "ScriptPath";        Value = [string]$PSCommandPath }
    [PSCustomObject]@{ Key = "ScriptSHA256";      Value = $ScriptHash }
    [PSCustomObject]@{ Key = "RunId";             Value = $Timestamp }
    [PSCustomObject]@{ Key = "RunDirectory";      Value = $RunDirectory }
    [PSCustomObject]@{ Key = "ExecutedBy";        Value = "$env:USERDOMAIN\$env:USERNAME" }
    [PSCustomObject]@{ Key = "ExecutedOn";        Value = $env:COMPUTERNAME }
    [PSCustomObject]@{ Key = "ExecutedOnFQDN";    Value = $(try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $env:COMPUTERNAME }) }
    [PSCustomObject]@{ Key = "PowerShellVersion"; Value = $PSVersionTable.PSVersion.ToString() }
    [PSCustomObject]@{ Key = "OSVersion";         Value = [System.Environment]::OSVersion.VersionString }
    [PSCustomObject]@{ Key = "AdAvailable";       Value = $script:AdAvailable }
    [PSCustomObject]@{ Key = "AdDomainNetBIOS";   Value = $script:DomainNetBIOS }
    [PSCustomObject]@{ Key = "AdDomainSID";       Value = $script:DomainSID }
    [PSCustomObject]@{ Key = "AdServer";          Value = $AdServer }
    [PSCustomObject]@{ Key = "AclMode";           Value = $AclMode }
    [PSCustomObject]@{ Key = "IncludeFiles";      Value = [bool]$IncludeFiles }
    [PSCustomObject]@{ Key = "SkipGroupExpansion";      Value = [bool]$SkipGroupExpansion }
    [PSCustomObject]@{ Key = "SkipLocalGroupExpansion"; Value = [bool]$SkipLocalGroupExpansion }
    [PSCustomObject]@{ Key = "SkipSmbAudit";      Value = [bool]$SkipSmbAudit }
    [PSCustomObject]@{ Key = "FollowReparsePoints"; Value = [bool]$FollowReparsePoints }
    [PSCustomObject]@{ Key = "InactiveDays";      Value = $InactiveDays }
    [PSCustomObject]@{ Key = "MaxDepth";          Value = $MaxDepth }
    [PSCustomObject]@{ Key = "Parameters";        Value = $ParamText }
    [PSCustomObject]@{ Key = "Targets";           Value = (($Targets | ForEach-Object { "$($_.Drive)=$($_.Path)" }) -join " | ") }
    [PSCustomObject]@{ Key = "ExcludedIdentityPatterns"; Value = ($ExcludedIdentityPatterns -join " | ") }
    [PSCustomObject]@{ Key = "Start";             Value = $OverallStart.ToString("yyyy-MM-dd HH:mm:ss") }
    [PSCustomObject]@{ Key = "End";               Value = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }
    [PSCustomObject]@{ Key = "Duration";          Value = $OverallElapsed.ToString() }
    [PSCustomObject]@{ Key = "PrincipalsResolved"; Value = $PrincipalsWritten.Count }
    [PSCustomObject]@{ Key = "Complete";          Value = (@($SummaryRows | Where-Object { -not $_.Complete }).Count -eq 0) }
)
$RunInfo | Export-Csv -LiteralPath $RunInfoCsv -Delimiter ";" -Encoding UTF8 -NoTypeInformation

# ---- Optional Excel ----
$ExcelCreated = $false
if ($ExportExcel) {
    if (Get-Module -ListAvailable -Name ImportExcel) {
        try {
            Import-Module ImportExcel -ErrorAction Stop
            if (Test-Path -LiteralPath $ExcelPath) { Remove-Item -LiteralPath $ExcelPath -Force }
            $Sheets = @(
                @{ Csv = $RunInfoCsv; Sheet = "RunInfo" }, @{ Csv = $SummaryCsv; Sheet = "Summary" }, @{ Csv = $MatrixCsv; Sheet = "Permission Matrix" },
                @{ Csv = $NtfsCsv; Sheet = "NTFS ACL" }, @{ Csv = $SmbCsv; Sheet = "SMB ACL" }, @{ Csv = $GroupsCsv; Sheet = "AD Groups" },
                @{ Csv = $InheritanceCsv; Sheet = "Inheritance Breaks" }, @{ Csv = $OrphanSidCsv; Sheet = "Orphaned SIDs" },
                @{ Csv = $FoldersCsv; Sheet = "Folder Index" }, @{ Csv = $PrincipalsCsv; Sheet = "Principals" }, @{ Csv = $ErrorsCsv; Sheet = "Errors" }
            )
            $First = $true
            foreach ($Sheet in $Sheets) {
                if ((Test-Path -LiteralPath $Sheet.Csv) -and (Get-Item -LiteralPath $Sheet.Csv).Length -gt 0) {
                    $Data = Import-Csv -LiteralPath $Sheet.Csv -Delimiter ";"
                    if ($First) { $Data | Export-Excel -Path $ExcelPath -WorksheetName $Sheet.Sheet -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow; $First = $false }
                    else { $Data | Export-Excel -Path $ExcelPath -WorksheetName $Sheet.Sheet -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow -Append }
                }
            }
            $ExcelCreated = $true
            Write-LiveStatus -Type "OK" -Message "Excel-Arbeitsmappe erstellt: $ExcelPath"
        }
        catch {
            Add-AuditError -Target $ExcelPath -Operation "Excel Export" -Message $_.Exception.Message -Severity "Warning"
            Flush-Buffers
            Write-LiveStatus -Type "WARN" -Message "Excel-Export fehlgeschlagen: $($_.Exception.Message)"
        }
    }
    else { Write-LiveStatus -Type "WARN" -Message "ImportExcel ist nicht installiert. CSV-Ausgabe ist vollständig vorhanden." }
}

Write-LiveStatus -Type "OK" -Message "Audit vollständig abgeschlossen. Manifest wird geschrieben."

# ---- Manifest (SHA-256 aller Ausgabedateien) – immer als letztes ----
$ManifestLines = [System.Collections.Generic.List[string]]::new()
Get-ChildItem -LiteralPath $RunDirectory -File | Where-Object { $_.Name -ne (Split-Path $ManifestFile -Leaf) } | Sort-Object Name | ForEach-Object {
    $H = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
    $ManifestLines.Add("$H  $($_.Name)")
}
[System.IO.File]::WriteAllLines($ManifestFile,$ManifestLines,(New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Green
Write-Host " FILESERVER PERMISSION AUDIT v$ScriptVersion ABGESCHLOSSEN" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Ausgabe:        $RunDirectory" -ForegroundColor Yellow
Write-Host "Live-Log:       $StatusLog" -ForegroundColor Yellow
Write-Host "Matrix:         $MatrixCsv" -ForegroundColor Yellow
Write-Host "RunInfo:        $RunInfoCsv" -ForegroundColor Yellow
Write-Host "Manifest:       $ManifestFile" -ForegroundColor Yellow
Write-Host "Gesamtdauer:    $($OverallElapsed.ToString())" -ForegroundColor Yellow
if ($ExcelCreated) { Write-Host "Excel:          $ExcelPath" -ForegroundColor Yellow }
foreach ($S in $SummaryRows) {
    $C = if ($S.Complete) { "Green" } else { "Yellow" }
    Write-Host ("Abdeckung {0}: {1}" -f $S.Drive, $(if ($S.Complete) { "vollständig" } else { "UNVOLLSTÄNDIG – $($S.EnumerationErrors) Enum-Fehler, $($S.AclErrors) ACL-Fehler" })) -ForegroundColor $C
}
Write-Host ""
Write-Host "Zur Auswertung den gesamten Ordner (inkl. 99_Manifest.sha256) in die WebGUI laden." -ForegroundColor Gray
