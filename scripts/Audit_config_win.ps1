#Requires -Version 5.1
<#
Windows Configuration Audit Toolkit (offline) - ISO 27001 aligned (technical configuration checks)
- Supports: Desktop + Server profile
- Output: HTML report (EN or FR full translation)
- No manual checkpoints
- No WIN-15 auditpol verification
- Improved AV/EDR detection (Kaspersky + others) with multiple fallbacks

Tip: Run PowerShell as Administrator for best coverage.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = (Join-Path $PSScriptRoot "reports"),
    [ValidateSet('EN','FR')]
    [string]$Language,
    [ValidateSet('Desktop','Server')]
    [string]$Profile,
    [switch]$Redact
)

# -----------------------------
# Helpers: localization, safety
# -----------------------------
function Get-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function L {
    param([string]$EN, [string]$FR)
    if ($script:Language -eq 'FR') { return $FR } else { return $EN }
}

function Sev {
    param([ValidateSet('High','Medium','Low','NA')]$Level)
    switch ($Level) {
        'High'   { return (L 'High'   'Elevee') }
        'Medium' { return (L 'Medium' 'Moyenne') }
        'Low'    { return (L 'Low'    'Faible') }
        default  { return 'NA' }
    }
}

function ResLabel {
    param([ValidateSet('Pass','Fail','Error','Info','NA')]$Result)
    switch ($Result) {
        'Pass'  { return (L 'Pass'        'Conforme') }
        'Fail'  { return (L 'Fail'        'Non conforme') }
        'Error' { return (L 'Error'       'Erreur') }
        'Info'  { return (L 'Information' 'Information') }
        default { return 'NA' }
    }
}

function SafeText {
    param([string]$Text)
    if (-not $Text) { return "" }
    $t = $Text
    # Basic HTML escape
    $t = $t.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
    return $t
}

function Redact-Text {
    param([string]$Text)
    if (-not $script:Redact) { return $Text }
    if (-not $Text) { return $Text }
    $t = $Text

    # Redact host/domain if present
    if ($script:HostName)   { $t = $t -replace [regex]::Escape($script:HostName), "<REDACTED_HOST>" }
    if ($script:DomainName) { $t = $t -replace [regex]::Escape($script:DomainName), "<REDACTED_DOMAIN>" }

    # Redact common "COMPUTER\user" patterns
    $t = $t -replace '([A-Za-z0-9\-\_\.]+)\\([A-Za-z0-9\-\_\.]+)', '<REDACTED_ACCOUNT>'
    return $t
}

function Add-Result {
    param(
        [string]$Id,
        [string]$CheckNameEN,
        [string]$CheckNameFR,
        [string]$ISO27001,
        [ValidateSet('High','Medium','Low','NA')]$Severity,
        [ValidateSet('Pass','Fail','Error','Info','NA')]$Result,
        [string]$Evidence,
        [string]$RecoEN,
        [string]$RecoFR,
        [bool]$Applicable = $true
    )

    if (-not $Applicable) { return }

    $obj = [PSCustomObject]@{
        ID         = $Id
        Check      = (L $CheckNameEN $CheckNameFR)
        ISO27001   = $ISO27001
        Severity   = (Sev $Severity)
        ResultRaw  = $Result
        Result     = (ResLabel $Result)
        Evidence   = (Redact-Text $Evidence)
        Reco       = (L $RecoEN $RecoFR)
    }
    $script:Results.Add($obj) | Out-Null
}

function Get-RegDword {
    param([string]$Path, [string]$Name)
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name
        if ($v -is [int] -or $v -is [long]) { return [int64]$v }
        return $null
    } catch { return $null }
}

function Get-RegString {
    param([string]$Path, [string]$Name)
    try {
        return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop | Select-Object -ExpandProperty $Name)
    } catch { return $null }
}

function Ensure-Folder {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# --------------------------------
# Collect basic system information
# --------------------------------
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Now = Get-Date
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue

$script:HostName  = $env:COMPUTERNAME
$script:DomainName = try { (Get-CimInstance Win32_ComputerSystem).Domain } catch { "" }
$osCaption = if ($os) { $os.Caption } else { "Windows" }
$osVersion = if ($os) { $os.Version } else { "" }

# Language choice
if (-not $Language) {
    Write-Host ""
    Write-Host "Select report language / Choisir la langue du rapport:" -ForegroundColor Cyan
    Write-Host "  [1] English"
    Write-Host "  [2] Francais"
    $c = Read-Host "Choice (1/2)"
    $Language = if ($c -eq '2') { 'FR' } else { 'EN' }
}
$script:Language = $Language

# Profile choice (Desktop/Server)
if (-not $Profile) {
    $detected = 'Desktop'
    try {
        $pt = (Get-CimInstance Win32_OperatingSystem).ProductType
        if ($pt -ne 1) { $detected = 'Server' }
    } catch {}
    Write-Host ""
    Write-Host (L "Select audit profile:" "Choisir le profil d audit:") -ForegroundColor Cyan
    Write-Host "  [1] Desktop (Workstation)"
    Write-Host "  [2] Server"
    $c2 = Read-Host (L "Choice (default $detected):" "Choix (defaut $detected):")
    if ($c2 -eq '2') { $Profile = 'Server' }
    elseif ($c2 -eq '1') { $Profile = 'Desktop' }
    else { $Profile = $detected }
}
$script:Profile = $Profile

Ensure-Folder -Path $OutputFolder

# -------------------------
# Info: admin execution
# -------------------------
$isAdmin = Get-IsAdmin
Add-Result -Id "INF-00" `
  -CheckNameEN "Execution context (Administrator rights)" `
  -CheckNameFR "Contexte d execution (droits Administrateur)" `
  -ISO27001 "A.8.9" -Severity NA -Result Info `
  -Evidence ("Running as Administrator: {0}" -f $isAdmin) `
  -RecoEN "If some checks return Error, re-run PowerShell as Administrator." `
  -RecoFR "Si certains controles sont en Erreur, relancer PowerShell en Administrateur."

# -------------------------
# Cache: secedit export
# -------------------------
$script:Secedit = @{}
function Load-SeceditCfg {
    if ($script:Secedit.Count -gt 0) { return }

    $tmp = Join-Path $env:TEMP ("secpol_{0}.cfg" -f ([Guid]::NewGuid().ToString("N")))
    try {
        & secedit /export /cfg $tmp /quiet | Out-Null
        $lines = Get-Content -Path $tmp -ErrorAction Stop
        foreach ($ln in $lines) {
            if ($ln -match '^\s*([^;].*?)\s*=\s*(.*?)\s*$') {
                $k = $matches[1].Trim()
                $v = $matches[2].Trim()
                if (-not $script:Secedit.ContainsKey($k)) {
                    $script:Secedit[$k] = $v
                }
            }
        }
    } catch {
        # keep empty, handled by checks
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Get-SeceditValue {
    param([string]$Key)
    Load-SeceditCfg
    if ($script:Secedit.ContainsKey($Key)) { return $script:Secedit[$Key] }
    return $null
}

# -------------------------
# Check: Password policies
# -------------------------
function Test-PasswordMinimumLength {
    $min = 10
    try {
        $v = Get-SeceditValue "MinimumPasswordLength"
        if ($null -eq $v) { throw "MinimumPasswordLength not found in secedit export." }
        $cur = [int]$v
        $res = if ($cur -ge $min) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-01" "Minimum password length" "Longueur minimale du mot de passe" `
          "A.5.15, A.8.5, A.8.9" High $res `
          ("MinimumPasswordLength = {0}" -f $cur) `
          ("Increase minimum password length to at least {0} characters." -f $min) `
          ("Augmenter la longueur minimale a au moins {0} caracteres." -f $min)
    } catch {
        Add-Result "WIN-01" "Minimum password length" "Longueur minimale du mot de passe" `
          "A.5.15, A.8.5, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Collect the local security policy and verify password baseline via GPO/local policy." `
          "Verifier la baseline mot de passe via GPO/politique locale et collecter la preuve."
    }
}

function Test-PasswordComplexity {
    try {
        $v = Get-SeceditValue "PasswordComplexity"
        if ($null -eq $v) { throw "PasswordComplexity not found in secedit export." }
        $cur = [int]$v
        $res = if ($cur -eq 1) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-02" "Password complexity requirements" "Exigences de complexite du mot de passe" `
          "A.5.15, A.8.5, A.8.9" High $res `
          ("PasswordComplexity = {0} (1=enabled)" -f $cur) `
          "Enable password complexity to reduce guessing/brute-force risk." `
          "Activer la complexite pour reduire le risque de devinette/force brute."
    } catch {
        Add-Result "WIN-02" "Password complexity requirements" "Exigences de complexite du mot de passe" `
          "A.5.15, A.8.5, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify password complexity configuration via local policy/GPO baseline." `
          "Verifier la configuration complexite via politique locale/GPO."
    }
}

function Test-PasswordHistory {
    $min = 5
    try {
        $v = Get-SeceditValue "PasswordHistorySize"
        if ($null -eq $v) { throw "PasswordHistorySize not found in secedit export." }
        $cur = [int]$v
        $res = if ($cur -ge $min) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-03" "Password history size" "Historique des mots de passe" `
          "A.5.15, A.8.5, A.8.9" Medium $res `
          ("PasswordHistorySize = {0}" -f $cur) `
          ("Set password history to at least {0} remembered passwords." -f $min) `
          ("Fixer l historique a au moins {0} mots de passe memorises." -f $min)
    } catch {
        Add-Result "WIN-03" "Password history size" "Historique des mots de passe" `
          "A.5.15, A.8.5, A.8.9" Medium Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify password history configuration via local policy/GPO baseline." `
          "Verifier l historique via politique locale/GPO."
    }
}

function Test-MaxPasswordAge {
    $maxDays = 90
    try {
        $v = Get-SeceditValue "MaximumPasswordAge"
        if ($null -eq $v) { throw "MaximumPasswordAge not found in secedit export." }
        $cur = [int]$v
        # 0 means "never expires" in many contexts
        $res = if ($cur -gt 0 -and $cur -le $maxDays) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-04" "Maximum password age" "Age maximal du mot de passe" `
          "A.5.15, A.8.5, A.8.9" Medium $res `
          ("MaximumPasswordAge = {0} day(s)" -f $cur) `
          ("Set maximum password age to {0} days or less (and avoid 'never expires')." -f $maxDays) `
          ("Fixer l age maximal a {0} jours ou moins (eviter 'n expire jamais')." -f $maxDays)
    } catch {
        Add-Result "WIN-04" "Maximum password age" "Age maximal du mot de passe" `
          "A.5.15, A.8.5, A.8.9" Medium Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify maximum password age via local policy/GPO baseline." `
          "Verifier l age maximal via politique locale/GPO."
    }
}

# -------------------------
# Check: Account lockout
# -------------------------
function Test-AccountLockoutThreshold {
    $min = 3; $max = 5
    try {
        $v = Get-SeceditValue "LockoutBadCount"
        if ($null -eq $v) { throw "LockoutBadCount not found in secedit export." }
        $cur = [int]$v
        $res = if ($cur -ge $min -and $cur -le $max) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-05" "Account lockout threshold" "Seuil de verrouillage de compte" `
          "A.5.15, A.8.5, A.8.9" High $res `
          ("LockoutBadCount = {0}" -f $cur) `
          ("Set account lockout threshold to {0}-{1} invalid attempts (avoid 0)." -f $min,$max) `
          ("Fixer le seuil a {0}-{1} tentatives invalides (eviter 0)." -f $min,$max)
    } catch {
        Add-Result "WIN-05" "Account lockout threshold" "Seuil de verrouillage de compte" `
          "A.5.15, A.8.5, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify account lockout policy via local policy/GPO baseline." `
          "Verifier la politique verrouillage via politique locale/GPO."
    }
}

function Test-AccountLockoutDuration {
    # LockoutDuration is in minutes in secedit export for many systems (can vary). We'll treat 15+ as acceptable.
    $minMinutes = 15
    try {
        $v = Get-SeceditValue "LockoutDuration"
        if ($null -eq $v) { throw "LockoutDuration not found in secedit export." }
        $cur = [int]$v
        # Some exports use negative values (in minutes) depending on policy representation.
        $abs = [Math]::Abs($cur)
        $res = if ($abs -ge $minMinutes) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-06" "Account lockout duration" "Duree de verrouillage de compte" `
          "A.5.15, A.8.5, A.8.9" Medium $res `
          ("LockoutDuration = {0} (abs={1}) minute(s)" -f $cur,$abs) `
          ("Set lockout duration to at least {0} minutes to slow down brute-force attempts." -f $minMinutes) `
          ("Fixer la duree a au moins {0} minutes pour ralentir les attaques force-brute." -f $minMinutes)
    } catch {
        Add-Result "WIN-06" "Account lockout duration" "Duree de verrouillage de compte" `
          "A.5.15, A.8.5, A.8.9" Medium Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify lockout duration via local policy/GPO baseline." `
          "Verifier la duree via politique locale/GPO."
    }
}

# -------------------------
# Check: Firewall
# -------------------------
function Test-FirewallEnabledAllProfiles {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $map = @{}
        foreach ($p in $profiles) { $map[$p.Name] = $p.Enabled }
        $all = ($map.Values | Where-Object { $_ -ne $true }).Count -eq 0
        $res = if ($all) { 'Pass' } else { 'Fail' }
        $ev = "Domain=$($map['Domain']); Private=$($map['Private']); Public=$($map['Public'])"
        Add-Result "WIN-07" "Windows Firewall enabled on all profiles" "Pare-feu Windows actif sur tous les profils" `
          "A.8.20, A.8.9, A.8.1" High $res `
          $ev `
          "Enable Windows Firewall on Domain/Private/Public profiles." `
          "Activer le Pare-feu Windows sur les profils Domaine/Prive/Public."
    } catch {
        Add-Result "WIN-07" "Windows Firewall enabled on all profiles" "Pare-feu Windows actif sur tous les profils" `
          "A.8.20, A.8.9, A.8.1" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify firewall status using Get-NetFirewallProfile or netsh advfirewall." `
          "Verifier le pare-feu via Get-NetFirewallProfile ou netsh advfirewall."
    }
}

function Test-FirewallDefaultInboundBlock {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $bad = @()
        $evParts = @()
        foreach ($p in $profiles) {
            $evParts += ("{0}={1}" -f $p.Name, $p.DefaultInboundAction)
            if ($p.DefaultInboundAction -ne 'Block') { $bad += $p.Name }
        }
        $res = if ($bad.Count -eq 0) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-08" "Firewall default inbound action = Block" "Politique pare-feu par defaut (entrant) = Bloquer" `
          "A.8.20, A.8.9" Medium $res `
          ($evParts -join '; ') `
          "Set default inbound action to Block on all profiles (allow only required rules)." `
          "Mettre l action entrante par defaut sur Bloquer sur tous les profils (autoriser seulement le necessaire)."
    } catch {
        Add-Result "WIN-08" "Firewall default inbound action = Block" "Politique pare-feu par defaut (entrant) = Bloquer" `
          "A.8.20, A.8.9" Medium Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify firewall policy baseline (default inbound should be Block)." `
          "Verifier la baseline pare-feu (entrant par defaut doit etre Bloquer)."
    }
}

# -------------------------
# Check: RDP + Remote Assistance
# -------------------------
function Test-RDP {
    try {
        $deny = Get-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections"
        if ($null -eq $deny) { throw "Cannot read fDenyTSConnections." }
        $enabled = ($deny -eq 0)
        $nla = Get-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
        $nlaRequired = ($nla -eq 1)

        if (-not $enabled) {
            Add-Result "WIN-09" "Remote Desktop (RDP) configuration" "Configuration du Bureau a distance (RDP)" `
              "A.8.20, A.5.15, A.8.5, A.8.9" High Pass `
              ("RDP Enabled=False; NLA Required={0}" -f $nlaRequired) `
              "No action required. RDP is disabled." `
              "Aucune action requise. RDP est desactive."
            return
        }

        # Enabled: require NLA at minimum
        $res = if ($nlaRequired) { 'Pass' } else { 'Fail' }

        $recoEN = if ($script:Profile -eq 'Desktop') {
            "Disable RDP unless strictly needed. If needed, enforce NLA, restrict access (firewall/allowlist), and monitor logs."
        } else {
            "If RDP is required on servers, enforce NLA, restrict access (jump host/VPN/allowlist), and monitor logs."
        }
        $recoFR = if ($script:Profile -eq 'Desktop') {
            "Desactiver RDP sauf besoin strict. Si necessaire, imposer NLA, restreindre l acces (pare-feu/allowlist) et surveiller les logs."
        } else {
            "Si RDP est necessaire sur serveurs, imposer NLA, restreindre l acces (bastion/VPN/allowlist) et surveiller les logs."
        }

        Add-Result "WIN-09" "Remote Desktop (RDP) configuration" "Configuration du Bureau a distance (RDP)" `
          "A.8.20, A.5.15, A.8.5, A.8.9" High $res `
          ("RDP Enabled=True; NLA Required={0}" -f $nlaRequired) `
          $recoEN `
          $recoFR
    } catch {
        Add-Result "WIN-09" "Remote Desktop (RDP) configuration" "Configuration du Bureau a distance (RDP)" `
          "A.8.20, A.5.15, A.8.5, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify RDP settings via registry/GPO and ensure NLA is enforced." `
          "Verifier les parametres RDP via registre/GPO et imposer NLA."
    }
}

function Test-RemoteAssistanceDisabled {
    try {
        $v = Get-RegDword "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp"
        if ($null -eq $v) { throw "Cannot read fAllowToGetHelp." }
        $res = if ($v -eq 0) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-10" "Remote Assistance disabled" "Assistance a distance desactivee" `
          "A.8.20, A.8.9" Medium $res `
          ("fAllowToGetHelp={0} (0=disabled,1=enabled)" -f $v) `
          "Disable Remote Assistance unless explicitly needed and controlled." `
          "Desactiver l assistance a distance sauf besoin explicite et controle."
    } catch {
        Add-Result "WIN-10" "Remote Assistance disabled" "Assistance a distance desactivee" `
          "A.8.20, A.8.9" Medium Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify Remote Assistance policy via registry/GPO baseline." `
          "Verifier la politique assistance a distance via registre/GPO."
    }
}

# -------------------------
# Check: Antivirus / EDR
# -------------------------
function Parse-ProductState {
    param([int]$State)
    # Heuristic decoding for WSC productState
    try {
        $hex = "{0:x6}" -f $State
        $rtByte  = $hex.Substring(2,2)
        $defByte = $hex.Substring(4,2)

        $rt = switch ($rtByte.ToLower()) {
            '10' { 'On' }
            '11' { 'On' }
            '00' { 'Off' }
            default { 'Unknown' }
        }
        $def = switch ($defByte.ToLower()) {
            '00' { 'UpToDate' }
            '10' { 'Outdated' }
            default { 'Unknown' }
        }
        return [PSCustomObject]@{ Realtime=$rt; Definitions=$def; Hex=$hex }
    } catch {
        return [PSCustomObject]@{ Realtime='Unknown'; Definitions='Unknown'; Hex='' }
    }
}

function Get-AntivirusEvidence {
    $products = @()
    $activeCount = 0

    # 1) Windows Security Center (best on Desktop)
    try {
        $av = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
        foreach ($p in $av) {
            $ps = Parse-ProductState -State ([int]$p.productState)
            $products += [PSCustomObject]@{
                Name = $p.displayName
                Realtime = $ps.Realtime
                Definitions = $ps.Definitions
                StateHex = $ps.Hex
                Path = $p.pathToSignedProductExe
            }
            if ($ps.Realtime -eq 'On') { $activeCount++ }
        }
    } catch {
        # ignore, fallback
    }

    # 2) Defender status (works on many systems)
    $defenderInfo = $null
    try {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            $st = Get-MpComputerStatus -ErrorAction Stop
            $defenderInfo = [PSCustomObject]@{
                RealTime = $st.RealTimeProtectionEnabled
                SigAge   = $st.AntivirusSignatureAge
                AMServiceEnabled = $st.AMServiceEnabled
            }
        }
    } catch {}

    # 3) Service-based fallback (broad vendor support)
    $vendorKeywords = @(
        "kaspersky","eset","sophos","mcafee","symantec","norton","trend","crowdstrike","sentinel",
        "withsecure","f-secure","bitdefender","avast","avg","cylance","carbon","palo alto","cortex",
        "malwarebytes","defender","microsoft defender","forticlient","check point","checkpoint"
    )

    $runningSecurityServices = @()
    try {
        $svcs = Get-Service -ErrorAction Stop
        foreach ($s in $svcs) {
            if ($s.Status -ne 'Running') { continue }
            $dn = ($s.DisplayName + " " + $s.Name).ToLower()
            foreach ($kw in $vendorKeywords) {
                if ($dn -like "*$kw*") {
                    $runningSecurityServices += $s.DisplayName
                    break
                }
            }
        }
        $runningSecurityServices = $runningSecurityServices | Select-Object -Unique
    } catch {}

    # Decide pass/fail:
    # - Pass if at least one WSC product reports Realtime=On
    # - Or if we have clear evidence of a 3rd-party security service running
    # - Or Defender real-time is enabled
    $hasWsc = ($products.Count -gt 0)
    $wscActive = ($activeCount -gt 0)
    $svcActive = ($runningSecurityServices.Count -gt 0)
    $defActive = ($defenderInfo -and $defenderInfo.RealTime -eq $true)

    $pass = ($wscActive -or $svcActive -or $defActive)

    # Evidence string
    $parts = @()
    if ($hasWsc) {
        $pNames = ($products | Select-Object -ExpandProperty Name) -join ", "
        $parts += ("WSC products: {0}" -f $pNames)
        $details = ($products | ForEach-Object { "$($_.Name){rt=$($_.Realtime),def=$($_.Definitions),hex=$($_.StateHex)}" }) -join " | "
        $parts += ("WSC detail: {0}" -f $details)
    } else {
        $parts += "WSC products: not available"
    }
    if ($defenderInfo) {
        $parts += ("Defender: RealTime={0}; SigAge={1} day(s); AMServiceEnabled={2}" -f $defenderInfo.RealTime, $defenderInfo.SigAge, $defenderInfo.AMServiceEnabled)
    } else {
        $parts += "Defender: status not available"
    }
    if ($svcActive) {
        $parts += ("Running security services: {0}" -f (($runningSecurityServices | Select-Object -First 10) -join ", "))
    } else {
        $parts += "Running security services: none detected"
    }

    return [PSCustomObject]@{
        Pass = $pass
        Evidence = ($parts -join " | ")
    }
}

function Test-AntivirusPresence {
    try {
        $av = Get-AntivirusEvidence
        $res = if ($av.Pass) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-11" "Antivirus / EDR protection detected" "Protection antivirus / EDR detectee" `
          "A.8.7, A.8.9, A.5.34" High $res `
          $av.Evidence `
          "Ensure an AV/EDR solution is installed and actively protecting the system (real-time on, updates enabled)." `
          "Assurer une solution antivirus/EDR installee et active (temps reel actif, mises a jour actives)."
    } catch {
        Add-Result "WIN-11" "Antivirus / EDR protection detected" "Protection antivirus / EDR detectee" `
          "A.8.7, A.8.9, A.5.34" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify endpoint protection status via Windows Security Center and running services." `
          "Verifier la protection via Centre de securite Windows et services en cours."
    }
}

# -------------------------
# Check: BitLocker
# -------------------------
function Test-BitLockerOSDrive {
    try {
        $osDrive = $env:SystemDrive
        $ev = ""
        $protOn = $false

        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            $bl = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction Stop
            $protOn = ($bl.ProtectionStatus -eq 'On')
            $ev = ("{0}: Protection={1}, Encryption={2}%, Method={3}" -f $osDrive, $bl.ProtectionStatus, $bl.EncryptionPercentage, $bl.EncryptionMethod)
        } else {
            $out = & manage-bde -status $osDrive 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $out) { throw "manage-bde returned no data." }
            $t = ($out | Out-String)
            $protOn = ($t -match 'Protection Status:\s+Protection On')
            $ev = "manage-bde output parsed. ProtectionOn=$protOn"
        }

        $res = if ($protOn) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-12" "Disk encryption (BitLocker) on OS drive" "Chiffrement disque (BitLocker) sur disque systeme" `
          "A.8.12, A.8.9, A.5.34" High $res `
          $ev `
          "Enable BitLocker (or equivalent) on the OS drive to protect data at rest." `
          "Activer BitLocker (ou equivalent) sur le disque systeme pour proteger les donnees au repos."
    } catch {
        Add-Result "WIN-12" "Disk encryption (BitLocker) on OS drive" "Chiffrement disque (BitLocker) sur disque systeme" `
          "A.8.12, A.8.9, A.5.34" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify disk encryption status using BitLocker tools and policy baseline." `
          "Verifier le statut de chiffrement via outils BitLocker et baseline."
    }
}

# -------------------------
# Check: Windows Update
# -------------------------
function Test-WindowsUpdate {
    try {
        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

        $noAU = Get-RegDword $auPath "NoAutoUpdate"
        $useWUServer = Get-RegDword $auPath "UseWUServer"
        $wus = Get-RegString $wuPath "WUServer"

        # Last detection success time
        $last = $null
        try {
            $lastStr = Get-RegString "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" "LastSuccessTime"
            if ($lastStr) { $last = [datetime]$lastStr }
        } catch {}

        $autoUpdateEnabled = ($noAU -ne 1)
        $daysSince = $null
        if ($last) { $daysSince = (New-TimeSpan -Start $last -End (Get-Date)).Days }

        $pass = $autoUpdateEnabled -and (($daysSince -eq $null) -or ($daysSince -le 14))
        $res = if ($pass) { 'Pass' } else { 'Fail' }

        $evParts = @()
        $evParts += ("AutoUpdateEnabled={0}" -f $autoUpdateEnabled)
        if ($useWUServer -eq 1 -and $wus) { $evParts += ("WSUS={0}" -f $wus) } else { $evParts += "WSUS=(not configured)" }
        if ($last) { $evParts += ("LastDetectionSuccess={0}; DaysSince={1}" -f $last, $daysSince) } else { $evParts += "LastDetectionSuccess=(unknown)" }

        Add-Result "WIN-13" "Windows Update / patch configuration" "Configuration Windows Update / correctifs" `
          "A.8.8, A.8.9, A.8.19" High $res `
          ($evParts -join "; ") `
          "Enable automatic updates and ensure patch detection happens regularly (e.g., within the last 14 days) via WSUS or Microsoft Update." `
          "Activer les mises a jour automatiques et assurer une detection reguliere (ex: <= 14 jours) via WSUS ou Microsoft Update."
    } catch {
        Add-Result "WIN-13" "Windows Update / patch configuration" "Configuration Windows Update / correctifs" `
          "A.8.8, A.8.9, A.8.19" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify Windows Update policy and evidence of recent detection/patching." `
          "Verifier la politique Windows Update et la preuve de detection/correction recente."
    }
}

# -------------------------
# Check: Local Administrators group
# -------------------------
function Get-LocalAdminsSafe {
    # Returns objects with Name, Source (Local/Domain/Other)
    $members = @()

    # Method 1: Get-LocalGroupMember (not available everywhere)
    try {
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $raw = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            foreach ($m in $raw) {
                $n = $m.Name
                $src = "Other"
                if ($n -match '^[^\\]+\\[^\\]+$') {
                    $left = $n.Split('\')[0]
                    if ($left -ieq $env:COMPUTERNAME) { $src = "Local" } else { $src = "Domain" }
                }
                $members += [PSCustomObject]@{ Name=$n; Source=$src }
            }
            return $members
        }
    } catch {}

    # Method 2: ADSI WinNT provider
    try {
        $grp = [ADSI]"WinNT://./Administrators,group"
        $raw = @($grp.psbase.Invoke("Members"))
        foreach ($r in $raw) {
            $name = $r.GetType().InvokeMember("Name",'GetProperty',$null,$r,$null)
            $adspath = $r.GetType().InvokeMember("ADsPath",'GetProperty',$null,$r,$null)
            $src = "Other"
            if ($adspath -match '^WinNT://([^/]+)/') {
                $left = $matches[1]
                if ($left -ieq $env:COMPUTERNAME) { $src = "Local" } else { $src = "Domain" }
            }
            $members += [PSCustomObject]@{ Name=$name; Source=$src }
        }
        return $members
    } catch {}

    throw "Unable to enumerate local Administrators group members."
}

function Test-LocalAdminsReview {
    try {
        $m = Get-LocalAdminsSafe
        $localCount  = ($m | Where-Object { $_.Source -eq 'Local' }).Count
        $domainCount = ($m | Where-Object { $_.Source -eq 'Domain' }).Count
        $total       = $m.Count

        # Baseline by profile
        $maxLocal = if ($script:Profile -eq 'Server') { 2 } else { 1 }

        $res = if ($localCount -le $maxLocal) { 'Pass' } else { 'Fail' }
        $ev = "MembersTotal=$total; LocalMembers=$localCount; DomainMembers=$domainCount"

        Add-Result "WIN-14" "Local Administrators group membership" "Revue du groupe Administrateurs locaux" `
          "A.5.15, A.8.2, A.8.5, A.8.9" High $res `
          $ev `
          ("Reduce local admin users to <= {0}. Use dedicated admin accounts and justifications for exceptions." -f $maxLocal) `
          ("Reduire les admins locaux a <= {0}. Utiliser des comptes admin dedies et justifier les exceptions." -f $maxLocal)
    } catch {
        Add-Result "WIN-14" "Local Administrators group membership" "Revue du groupe Administrateurs locaux" `
          "A.5.15, A.8.2, A.8.5, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Run as Administrator and verify the local Administrators group membership." `
          "Executer en Administrateur et verifier les membres du groupe Administrateurs."
    }
}

# -------------------------
# Check: Guest account disabled
# -------------------------
function Test-GuestAccountDisabled {
    try {
        $enabled = $null

        # Method 1: Get-LocalUser (not on DC)
        try {
            if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
                $u = Get-LocalUser -Name "Guest" -ErrorAction Stop
                $enabled = $u.Enabled
            }
        } catch {}

        # Method 2: net user
        if ($null -eq $enabled) {
            $out = & net user Guest 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $out) { throw "Cannot query Guest via net user." }
            $txt = ($out | Out-String)
            if ($txt -match 'Account active\s+(\w+)' ) {
                $enabled = ($matches[1].ToLower() -eq 'yes')
            } elseif ($txt -match 'Compte actif\s+(\w+)' ) {
                $enabled = ($matches[1].ToLower() -eq 'oui')
            } else {
                throw "Cannot parse Guest status from net user output."
            }
        }

        $res = if ($enabled -eq $false) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-15" "Guest account disabled" "Compte Invite desactive" `
          "A.5.15, A.8.2, A.8.9" Medium $res `
          ("Guest enabled={0}" -f $enabled) `
          "Disable the Guest account to reduce unauthorized access risk." `
          "Desactiver le compte Invite pour reduire le risque d acces non autorise."
    } catch {
        Add-Result "WIN-15" "Guest account disabled" "Compte Invite desactive" `
          "A.5.15, A.8.2, A.8.9" Medium Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify Guest account status locally or via policy baseline." `
          "Verifier le statut du compte Invite localement ou via baseline."
    }
}

# -------------------------
# Check: UAC
# -------------------------
function Test-UACEnabled {
    try {
        $v = Get-RegDword "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
        if ($null -eq $v) { throw "EnableLUA not found." }
        $res = if ($v -eq 1) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-16" "User Account Control (UAC) enabled" "Controle de compte utilisateur (UAC) actif" `
          "A.8.3, A.8.9" High $res `
          ("EnableLUA={0} (1=enabled)" -f $v) `
          "Enable UAC to reduce privilege abuse and improve security boundaries." `
          "Activer UAC pour reduire l abus de privileges et renforcer les frontieres de securite."
    } catch {
        Add-Result "WIN-16" "User Account Control (UAC) enabled" "Controle de compte utilisateur (UAC) actif" `
          "A.8.3, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify UAC policy and enforce baseline." `
          "Verifier la politique UAC et appliquer la baseline."
    }
}

# -------------------------
# Check: Screen lock (Desktop only)
# -------------------------
function Test-ScreenLock {
    $applicable = ($script:Profile -eq 'Desktop')
    if (-not $applicable) { return }

    $maxSeconds = 900
    try {
        $policyHKLM = "HKLM:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        $policyHKCU = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
        $userHKCU   = "HKCU:\Control Panel\Desktop"

        $src = $null
        $active = $null
        $secure = $null
        $timeout = $null

        foreach ($p in @($policyHKLM,$policyHKCU,$userHKCU)) {
            $a = Get-RegString $p "ScreenSaveActive"
            $s = Get-RegString $p "ScreenSaverIsSecure"
            $t = Get-RegString $p "ScreenSaveTimeOut"
            if ($a -or $s -or $t) {
                $src = $p
                $active = $a
                $secure = $s
                $timeout = $t
                break
            }
        }

        if (-not $src) { throw "Screen saver settings not found in policy/user keys." }

        $activeOk = ($active -eq '1')
        $secureOk = ($secure -eq '1')
        $toInt = $null
        if ($timeout -and ($timeout -match '^\d+$')) { $toInt = [int]$timeout }
        $timeoutOk = ($toInt -ne $null -and $toInt -le $maxSeconds)

        $res = if ($activeOk -and $secureOk -and $timeoutOk) { 'Pass' } else { 'Fail' }
        $ev = "Source=$src; ScreenSaveActive=$active; ScreenSaverIsSecure=$secure; ScreenSaveTimeOut=$timeout"

        Add-Result "WIN-17" "Screen lock (<= 15 minutes)" "Verrouillage ecran (<= 15 minutes)" `
          "A.8.11, A.8.9, A.8.1" Medium $res `
          $ev `
          "Configure screen lock with password and timeout <= 15 minutes." `
          "Configurer le verrouillage ecran avec mot de passe et delai <= 15 minutes."
    } catch {
        Add-Result "WIN-17" "Screen lock (<= 15 minutes)" "Verrouillage ecran (<= 15 minutes)" `
          "A.8.11, A.8.9, A.8.1" Medium Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify screen lock policy via GPO/local policy (Desktop baseline)." `
          "Verifier la politique verrouillage ecran via GPO/politique locale (baseline Desktop)."
    }
}

# -------------------------
# Check: SMB settings
# -------------------------
function Test-SMBv1Disabled {
    try {
        $state = $null

        # Feature check (best)
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
            $state = $f.State
        } catch {}

        # Registry fallback (not always present)
        $reg = Get-RegDword "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"

        if ($state) {
            $res = if ($state -eq 'Disabled') { 'Pass' } else { 'Fail' }
            Add-Result "WIN-18" "SMBv1 disabled" "SMBv1 desactive" `
              "A.8.20, A.8.9" High $res `
              ("Feature SMB1Protocol State={0}; RegSMB1={1}" -f $state, $reg) `
              "Disable/Remove SMBv1 to reduce exposure to legacy vulnerabilities." `
              "Desactiver/Supprimer SMBv1 pour reduire les risques lies aux protocoles obsoletes."
        } else {
            # If no feature state, rely on registry (0=disabled)
            if ($null -eq $reg) {
                Add-Result "WIN-18" "SMBv1 disabled" "SMBv1 desactive" `
                  "A.8.20, A.8.9" High Info `
                  "SMB1 feature state unknown and SMB1 registry value not found (could still be removed)." `
                  "Confirm SMBv1 is removed/disabled." `
                  "Confirmer que SMBv1 est supprime/desactive."
            } else {
                $res = if ($reg -eq 0) { 'Pass' } else { 'Fail' }
                Add-Result "WIN-18" "SMBv1 disabled" "SMBv1 desactive" `
                  "A.8.20, A.8.9" High $res `
                  ("Reg SMB1={0} (0=disabled)" -f $reg) `
                  "Disable/Remove SMBv1 to reduce exposure to legacy vulnerabilities." `
                  "Desactiver/Supprimer SMBv1 pour reduire les risques lies aux protocoles obsoletes."
            }
        }
    } catch {
        Add-Result "WIN-18" "SMBv1 disabled" "SMBv1 desactive" `
          "A.8.20, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify SMBv1 removal via Windows features and baseline policy." `
          "Verifier la suppression SMBv1 via fonctionnalites Windows et baseline."
    }
}

function Test-SMBSigningRequired {
    try {
        $srvReq = Get-RegDword "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
        $cliReq = Get-RegDword "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"

        # Treat missing as not enforced
        $srvOk = ($srvReq -eq 1)
        $cliOk = ($cliReq -eq 1)

        $res = if ($srvOk -and $cliOk) { 'Pass' } else { 'Fail' }
        $ev = "Server RequireSecuritySignature=$srvReq; Client RequireSecuritySignature=$cliReq"

        Add-Result "WIN-19" "SMB signing required (client & server)" "Signature SMB requise (client & serveur)" `
          "A.8.20, A.8.9" High $res `
          $ev `
          "Require SMB signing on both client and server to reduce MITM risk." `
          "Exiger la signature SMB cote client et serveur pour reduire le risque MITM."
    } catch {
        Add-Result "WIN-19" "SMB signing required (client & server)" "Signature SMB requise (client & serveur)" `
          "A.8.20, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify SMB signing policy via registry/GPO baseline." `
          "Verifier la signature SMB via registre/GPO baseline."
    }
}

function Test-InsecureGuestAuthDisabled {
    try {
        $v = Get-RegDword "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "AllowInsecureGuestAuth"
        # If missing, default on modern Windows is disabled (0). We'll treat missing as Pass but note it.
        if ($null -eq $v) {
            Add-Result "WIN-20" "Insecure guest logons (SMB) disabled" "Connexions invites non securisees (SMB) desactivees" `
              "A.8.20, A.8.9" High Pass `
              "AllowInsecureGuestAuth not set (default is disabled on modern Windows)." `
              "Ensure insecure guest SMB logons remain disabled." `
              "Assurer que les connexions invites SMB restent desactivees."
        } else {
            $res = if ($v -eq 0) { 'Pass' } else { 'Fail' }
            Add-Result "WIN-20" "Insecure guest logons (SMB) disabled" "Connexions invites non securisees (SMB) desactivees" `
              "A.8.20, A.8.9" High $res `
              ("AllowInsecureGuestAuth={0} (0=disabled)" -f $v) `
              "Disable insecure guest SMB logons to prevent unauthorized access." `
              "Desactiver les connexions invites SMB non securisees pour eviter l acces non autorise."
        }
    } catch {
        Add-Result "WIN-20" "Insecure guest logons (SMB) disabled" "Connexions invites non securisees (SMB) desactivees" `
          "A.8.20, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify SMB guest logon policy via registry/GPO baseline." `
          "Verifier la politique SMB guest via registre/GPO baseline."
    }
}

# -------------------------
# Check: LLMNR
# -------------------------
function Test-LLMNRDisabled {
    try {
        $v = Get-RegDword "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
        # If not configured -> Fail (recommended to disable)
        if ($null -eq $v) {
            Add-Result "WIN-21" "LLMNR disabled" "LLMNR desactive" `
              "A.8.20, A.8.9" High Fail `
              "EnableMulticast not configured (policy missing)." `
              "Disable LLMNR via GPO (EnableMulticast=0) to reduce spoofing risk." `
              "Desactiver LLMNR via GPO (EnableMulticast=0) pour reduire le risque de spoofing."
        } else {
            $res = if ($v -eq 0) { 'Pass' } else { 'Fail' }
            Add-Result "WIN-21" "LLMNR disabled" "LLMNR desactive" `
              "A.8.20, A.8.9" High $res `
              ("EnableMulticast={0} (0=disabled)" -f $v) `
              "Disable LLMNR via GPO (EnableMulticast=0) to reduce spoofing risk." `
              "Desactiver LLMNR via GPO (EnableMulticast=0) pour reduire le risque de spoofing."
        }
    } catch {
        Add-Result "WIN-21" "LLMNR disabled" "LLMNR desactive" `
          "A.8.20, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify LLMNR policy baseline and enforce disablement where applicable." `
          "Verifier la baseline LLMNR et imposer la desactivation si applicable."
    }
}

# -------------------------
# Check: WinRM hardening
# -------------------------
function Test-WinRMHardening {
    try {
        $winrmSvc = Get-Service -Name "WinRM" -ErrorAction Stop
        if ($winrmSvc.Status -ne 'Running') {
            Add-Result "WIN-22" "WinRM hardening (if enabled)" "Durcissement WinRM (si active)" `
              "A.8.20, A.8.9" High Info `
              "WinRM service is not running." `
              "No action required. If WinRM is enabled later, harden it (no Basic, no unencrypted, restrict access)." `
              "Aucune action requise. Si WinRM est active plus tard, la durcir (pas de Basic, pas de non-chiffre, restreindre acces)."
            return
        }

        $clientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
        $svcPath    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"

        $allowUnencC = Get-RegDword $clientPath "AllowUnencryptedTraffic"
        $basicC      = Get-RegDword $clientPath "AllowBasic"
        $allowUnencS = Get-RegDword $svcPath "AllowUnencryptedTraffic"
        $basicS      = Get-RegDword $svcPath "AllowBasic"

        $ok = $true
        if ($allowUnencC -eq 1 -or $allowUnencS -eq 1) { $ok = $false }
        if ($basicC -eq 1 -or $basicS -eq 1) { $ok = $false }

        $res = if ($ok) { 'Pass' } else { 'Fail' }
        $ev = "WinRM=Running; Client(AllowUnenc=$allowUnencC,Basic=$basicC); Service(AllowUnenc=$allowUnencS,Basic=$basicS)"

        Add-Result "WIN-22" "WinRM hardening (if enabled)" "Durcissement WinRM (si active)" `
          "A.8.20, A.8.9" High $res `
          $ev `
          "If WinRM is used, disable Basic auth and unencrypted traffic, enforce HTTPS where possible, and restrict access." `
          "Si WinRM est utilise, desactiver Basic et trafic non chiffre, imposer HTTPS si possible et restreindre l acces."
    } catch {
        Add-Result "WIN-22" "WinRM hardening (if enabled)" "Durcissement WinRM (si active)" `
          "A.8.20, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify WinRM configuration and hardening baseline." `
          "Verifier la configuration WinRM et baseline de durcissement."
    }
}

# -------------------------
# Check: TLS legacy protocols
# -------------------------
function Test-TLSLegacyDisabled {
    try {
        $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
        $targets = @(
            @{Name="TLS 1.0"; Path="$base\TLS 1.0\Server"},
            @{Name="TLS 1.1"; Path="$base\TLS 1.1\Server"}
        )

        $bad = @()
        $evParts = @()
        foreach ($t in $targets) {
            $en = Get-RegDword $t.Path "Enabled"
            $def = Get-RegDword $t.Path "DisabledByDefault"
            $evParts += ("{0}: Enabled={1}, DisabledByDefault={2}" -f $t.Name,$en,$def)

            # Consider disabled if Enabled=0 OR DisabledByDefault=1 (or keys missing might mean default enabled in older OS)
            $disabled = $false
            if ($en -eq 0) { $disabled = $true }
            if ($def -eq 1) { $disabled = $true }
            if (-not $disabled) { $bad += $t.Name }
        }

        $res = if ($bad.Count -eq 0) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-23" "TLS 1.0/1.1 disabled (server)" "TLS 1.0/1.1 desactives (serveur)" `
          "A.8.20, A.8.9" High $res `
          ($evParts -join "; ") `
          "Disable legacy TLS (1.0/1.1) and enforce TLS 1.2+ to reduce cryptographic risk." `
          "Desactiver TLS obsoletes (1.0/1.1) et imposer TLS 1.2+ pour reduire le risque cryptographique."
    } catch {
        Add-Result "WIN-23" "TLS 1.0/1.1 disabled (server)" "TLS 1.0/1.1 desactives (serveur)" `
          "A.8.20, A.8.9" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify SCHANNEL TLS protocol settings and enforce baseline." `
          "Verifier SCHANNEL (protocoles TLS) et imposer la baseline."
    }
}

# -------------------------
# Check: Event log size
# -------------------------
function Get-LogMaxSizeBytes {
    param([string]$LogName)
    $out = & wevtutil gl $LogName 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    foreach ($ln in $out) {
        if ($ln -match '^\s*maxSize:\s*(\d+)\s*$') {
            return [int64]$matches[1]
        }
    }
    return $null
}

function Test-EventLogSize {
    try {
        $minBytes = 67108864 # 64 MB
        $logs = @("Security","System","Application")
        $evParts = @()
        $bad = @()

        foreach ($l in $logs) {
            $b = Get-LogMaxSizeBytes -LogName $l
            if ($null -eq $b) {
                $evParts += ("{0}=(unknown)" -f $l)
                $bad += $l
                continue
            }
            $mb = [Math]::Round($b/1MB,2)
            $evParts += ("{0}={1}MB" -f $l,$mb)
            if ($b -lt $minBytes) { $bad += $l }
        }

        $res = if ($bad.Count -eq 0) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-24" "Event log max size (>= 64 MB)" "Taille max des journaux (>= 64 MB)" `
          "A.8.15, A.8.16, A.8.9" Medium $res `
          ("Min=64MB; " + ($evParts -join "; ")) `
          "Increase Security/System/Application log maximum size (>= 64 MB) to reduce evidence loss risk." `
          "Augmenter la taille max des logs Securite/Systeme/Application (>= 64 MB) pour reduire le risque de perte."
    } catch {
        Add-Result "WIN-24" "Event log max size (>= 64 MB)" "Taille max des journaux (>= 64 MB)" `
          "A.8.15, A.8.16, A.8.9" Medium Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify event log sizing via wevtutil and enforce baseline." `
          "Verifier la taille des logs via wevtutil et imposer la baseline."
    }
}

# -------------------------
# Info: Secure Boot
# -------------------------
function Info-SecureBoot {
    try {
        if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
            $sb = Confirm-SecureBootUEFI -ErrorAction Stop
            Add-Result "INF-01" "Secure Boot status (evidence)" "Statut Secure Boot (preuve)" `
              "A.8.9, A.8.12" NA Info `
              ("SecureBoot={0}" -f $sb) `
              "Secure Boot is enabled." `
              "Secure Boot est active."
        } else {
            Add-Result "INF-01" "Secure Boot status (evidence)" "Statut Secure Boot (preuve)" `
              "A.8.9, A.8.12" NA Info `
              "Confirm-SecureBootUEFI not available (non-UEFI or unsupported)." `
              "Verify Secure Boot via BIOS/UEFI settings if applicable." `
              "Verifier Secure Boot via BIOS/UEFI si applicable."
        }
    } catch {
        Add-Result "INF-01" "Secure Boot status (evidence)" "Statut Secure Boot (preuve)" `
          "A.8.9, A.8.12" NA Info `
          ("Unable to query Secure Boot: {0}" -f $_.Exception.Message) `
          "Verify Secure Boot via BIOS/UEFI settings if applicable." `
          "Verifier Secure Boot via BIOS/UEFI si applicable."
    }
}

# -------------------------
# Info: Installed software inventory
# -------------------------
function Info-InstalledSoftware {
    try {
        $paths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $items = @()
        foreach ($p in $paths) {
            $items += Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion |
                ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion)" }
        }
        $items = $items | Sort-Object -Unique
        $count = $items.Count
        $sample = ($items | Select-Object -First 25) -join " | "
        Add-Result "INF-02" "Installed software inventory (evidence)" "Inventaire des logiciels installes (preuve)" `
          "A.8.19, A.8.9, A.8.1, A.5.9, A.5.10" NA Info `
          ("Total={0}; Sample: {1}" -f $count,$sample) `
          "Validate installed software against an approved list and restrict installation where needed." `
          "Valider les logiciels vs liste approuvee et restreindre l installation si necessaire."
    } catch {
        Add-Result "INF-02" "Installed software inventory (evidence)" "Inventaire des logiciels installes (preuve)" `
          "A.8.19, A.8.9, A.8.1, A.5.9, A.5.10" NA Info `
          ("Unable to enumerate software: {0}" -f $_.Exception.Message) `
          "Collect software inventory via registry uninstall keys or endpoint management tools." `
          "Collecter l inventaire via cles uninstall registre ou outils de gestion endpoint."
    }
}

# -------------------------
# Run all checks
# -------------------------
Test-PasswordMinimumLength
Test-PasswordComplexity
Test-PasswordHistory
Test-MaxPasswordAge
Test-AccountLockoutThreshold
Test-AccountLockoutDuration
Test-FirewallEnabledAllProfiles
Test-FirewallDefaultInboundBlock
Test-RDP
Test-RemoteAssistanceDisabled
Test-AntivirusPresence
Test-BitLockerOSDrive
Test-WindowsUpdate
Test-LocalAdminsReview
Test-GuestAccountDisabled
Test-UACEnabled
Test-ScreenLock
Test-SMBv1Disabled
Test-SMBSigningRequired
Test-InsecureGuestAuthDisabled
Test-LLMNRDisabled
Test-WinRMHardening
Test-TLSLegacyDisabled
Test-EventLogSize
Info-SecureBoot
Info-InstalledSoftware

# -------------------------
# Compute compliance
# - Only Pass/Fail count toward score
# - Info/Error shown but not included in score
# -------------------------
$passCount = ($Results | Where-Object { $_.ResultRaw -eq 'Pass' }).Count
$failCount = ($Results | Where-Object { $_.ResultRaw -eq 'Fail' }).Count
$errorCount = ($Results | Where-Object { $_.ResultRaw -eq 'Error' }).Count
$infoCount = ($Results | Where-Object { $_.ResultRaw -eq 'Info' }).Count

$applicable = $passCount + $failCount
$compliance = if ($applicable -gt 0) { [Math]::Round(($passCount / $applicable) * 100, 1) } else { 0 }

$isoRefs = ($Results | ForEach-Object { $_.ISO27001.Split(',') } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Sort-Object -Unique) -join ", "

# -------------------------
# Report labels (full doc)
# -------------------------
$title = L "Windows Configuration Audit - ISO 27001" "Audit de configuration Windows - ISO 27001"
$labelHost = L "Host" "Hote"
$labelProfile = L "Profile" "Profil"
$labelOS = L "Operating System" "Systeme d exploitation"
$labelDate = L "Date" "Date"
$labelOverallComp = L "Overall compliance (automatic)" "Conformite globale (automatique)"
$labelDetails = L "Detailed checks" "Details des controles"
$labelContext = L "Context and scope" "Contexte et portee"
$labelScoreNote = L "Score is calculated from Pass/Fail checks only. Info/Error do not impact the score." `
                    "Le score est calcule uniquement a partir des controles Conforme/Non conforme. Information/Erreur n impactent pas le score."

$ctx = if ($Language -eq 'FR') {
@"
Ce rapport presente un audit de configuration hors ligne sur un systeme Windows (profil: $Profile).
Il se base sur des controles techniques et des recommandations de durcissement alignees sur les controles technologiques pertinents de la norme ISO/IEC 27001 (Annexe A).
$labelScoreNote
"@
} else {
@"
This report presents an offline configuration audit on a Windows system (profile: $Profile).
It is based on technical configuration checks and hardening recommendations aligned with relevant ISO/IEC 27001 Annex A technology controls.
$labelScoreNote
"@
}

# -------------------------
# Build HTML
# -------------------------
$rowsHtml = ""
foreach ($r in $Results) {
    $rowColor = switch ($r.ResultRaw) {
        'Pass'  { '#d4edda' }
        'Fail'  { '#f8d7da' }
        'Error' { '#fff3cd' }
        'Info'  { '#d1ecf1' }
        default { '#ffffff' }
    }
    $rowsHtml += "<tr style='background-color:$rowColor'>"
    $rowsHtml += "<td>$(SafeText $r.ID)</td>"
    $rowsHtml += "<td>$(SafeText $r.Check)</td>"
    $rowsHtml += "<td>$(SafeText $r.ISO27001)</td>"
    $rowsHtml += "<td>$(SafeText $r.Severity)</td>"
    $rowsHtml += "<td><strong>$(SafeText $r.Result)</strong></td>"
    $rowsHtml += "<td class='wrap'>$(SafeText $r.Evidence)</td>"
    $rowsHtml += "<td class='wrap'>$(SafeText $r.Reco)</td>"
    $rowsHtml += "</tr>`n"
}

$css = @"
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { max-width: 1500px; margin: 0 auto; background-color: white; padding: 28px; border-radius: 10px; box-shadow: 0 2px 6px rgba(0,0,0,0.12); }
h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
h2 { color: #34495e; margin-top: 28px; border-left: 4px solid #3498db; padding-left: 10px; }
.summary { border: 2px solid #3498db; padding: 18px; margin: 18px 0; background-color: #ecf0f1; border-radius: 10px; }
.summary p { margin: 6px 0; }
.score { font-size: 2em; color: #3498db; font-weight: 800; }
.badge { display: inline-block; padding: 6px 12px; border-radius: 6px; font-size: 0.9em; font-weight: 700; margin: 2px; }
.b-pass { background-color: #d4edda; color: #155724; }
.b-fail { background-color: #f8d7da; color: #721c24; }
.b-err  { background-color: #fff3cd; color: #856404; }
.b-info { background-color: #d1ecf1; color: #0c5460; }
table { border-collapse: collapse; width: 100%; margin-top: 14px; font-size: 14px; }
th, td { border: 1px solid #ddd; padding: 10px; vertical-align: top; text-align: left; }
th { background-color: #34495e; color: white; font-weight: 700; }
tr:hover { background-color: #f8f9fa; }
.small { color: #6c757d; font-size: 0.9em; }
.wrap { word-break: break-word; }
pre { white-space: pre-wrap; }
"@

$html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>$($title) - $($script:HostName) ($($Profile))</title>
  <style>$css</style>
</head>
<body>
  <div class="container">
    <h1>$($title)</h1>

    <div class="summary">
      <p><strong>${labelHost}:</strong> $(SafeText $script:HostName)</p>
      <p><strong>${labelProfile}:</strong> $(SafeText $Profile)</p>
      <p><strong>${labelOS}:</strong> $(SafeText "$osCaption ($osVersion)")</p>
      <p><strong>${labelDate}:</strong> $(SafeText ($script:Now.ToString("yyyy-MM-dd HH:mm:ss")))</p>
      <p><strong>${labelOverallComp}:</strong> <span class="score">$compliance %</span></p>
      <p>
        <span class="badge b-pass">$(SafeText (ResLabel 'Pass')): $passCount</span>
        <span class="badge b-fail">$(SafeText (ResLabel 'Fail')): $failCount</span>
        <span class="badge b-err">$(SafeText (ResLabel 'Error')): $errorCount</span>
        <span class="badge b-info">$(SafeText (ResLabel 'Info')): $infoCount</span>
        <span class="badge b-info">$(SafeText (L 'Total checks' 'Nombre total de controles')): $($Results.Count)</span>
      </p>
      <p class="small">ISO refs covered: $(SafeText $isoRefs)</p>
    </div>

    <h2>$($labelContext)</h2>
    <pre class="wrap">$(SafeText $ctx)</pre>

    <h2>$($labelDetails)</h2>
    <table>
      <thead>
        <tr>
          <th style="width: 90px;">ID</th>
          <th style="width: 260px;">$(SafeText (L 'Check' 'Controle'))</th>
          <th style="width: 170px;">ISO 27001</th>
          <th style="width: 110px;">$(SafeText (L 'Severity' 'Criticite'))</th>
          <th style="width: 130px;">$(SafeText (L 'Result' 'Resultat'))</th>
          <th style="width: 360px;">$(SafeText (L 'Current configuration (evidence)' 'Configuration actuelle (preuve)'))</th>
          <th>$(SafeText (L 'Recommendation' 'Recommandation'))</th>
        </tr>
      </thead>
      <tbody>
        $rowsHtml
      </tbody>
    </table>

    <p class="small" style="margin-top:18px;">Generated by Windows Config Audit Toolkit (offline) - v4.0</p>
  </div>
</body>
</html>
"@

# Write report in UTF-8 (no BOM) to avoid encoding issues in browsers
$reportFileName = ("WinAudit_{0}_{1}_{2}.html" -f $script:HostName, $Profile, $script:Now.ToString('yyyyMMdd_HHmmss'))
$reportPath = Join-Path $OutputFolder $reportFileName
[System.IO.File]::WriteAllText($reportPath, $html, New-Object System.Text.UTF8Encoding($false))

Write-Host ""
Write-Host (L "Report generated:" "Rapport genere:") -ForegroundColor Green
Write-Host $reportPath -ForegroundColor Yellow
Write-Host (L "Compliance score:" "Score de conformite:") -NoNewline
Write-Host (" $compliance% ($passCount/$applicable Pass/Fail checks)" ) -ForegroundColor Cyan
