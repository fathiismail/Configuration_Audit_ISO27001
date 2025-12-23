#Requires -Version 5.1
<#
Windows Configuration Audit Toolkit - ISO 27001 aligned (technical configuration checks)
- Supports: Desktop + Server profile
- Output: Excel report (EN or FR full translation)
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

function Escape-XmlText {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Security.SecurityElement]::Escape($Text)
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

function Get-LocalizedAdminGroupName {
    try {
        $sid = New-Object Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $translated = $sid.Translate([Security.Principal.NTAccount])
        $parts = $translated.Value.Split('\')
        return $parts[-1]
    } catch {
        return "Administrators"
    }
}

# --------------------------------
# Collect basic system information
# --------------------------------
$script:Results = New-Object System.Collections.Generic.List[object]
$script:Now = Get-Date
$script:ToolVersion = "4.1.0"
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

function Get-LockoutDurationMinutes {
    $v = Get-SeceditValue "LockoutDuration"
    if ($null -ne $v) {
        return [Math]::Abs([int]$v)
    }

    $out = & net accounts 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) {
        $txt = ($out | Out-String)
        $patterns = @(
            'Lockout duration[^0-9]*(\d+)',
            'Dur[eé]e du verrouillage[^0-9]*(\d+)'
        )
        foreach ($p in $patterns) {
            if ($txt -match $p) {
                return [int]$matches[1]
            }
        }
        $neverPatterns = @(
            'Lockout duration[^:]*:\s*Never',
            'Dur[eé]e du verrouillage[^:]*:\s*Jamais'
        )
        foreach ($p in $neverPatterns) {
            if ($txt -match $p) {
                return 0
            }
        }
    }

    throw "Lockout duration not found in policy export or net accounts output."
}

function Test-AccountLockoutDuration {
    # LockoutDuration is in minutes in secedit export for many systems (can vary). We'll treat 15+ as acceptable.
    $minMinutes = 15
    try {
        $cur = Get-LockoutDurationMinutes
        $res = if ($cur -ge $minMinutes) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-06" "Account lockout duration" "Duree de verrouillage de compte" `
          "A.5.15, A.8.5, A.8.9" Medium $res `
          ("LockoutDuration = {0} minute(s)" -f $cur) `
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
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
        $v = Get-RegDword $path "fAllowToGetHelp"

        $missingValue = ($null -eq $v)
        $disabled = ($v -eq 0 -or $missingValue)
        $res = if ($disabled) { 'Pass' } else { 'Fail' }
        $evidence = if ($missingValue) {
            "fAllowToGetHelp not set under $path (treated as disabled by default)."
        } else {
            "fAllowToGetHelp={0} (0=disabled,1=enabled)" -f $v
        }
        Add-Result "WIN-10" "Remote Assistance disabled" "Assistance a distance desactivee" `
          "A.8.20, A.8.9" Medium $res `
          $evidence `
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
        $checked = $false

        if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
            try {
                $bl = Get-BitLockerVolume -MountPoint $osDrive -ErrorAction Stop
                $protOn = ($bl.ProtectionStatus -eq 'On')
                $ev = ("{0}: Protection={1}, Encryption={2}%, Method={3}" -f $osDrive, $bl.ProtectionStatus, $bl.EncryptionPercentage, $bl.EncryptionMethod)
                $checked = $true
            } catch {
                $ev = "Get-BitLockerVolume failed: {0}" -f $_.Exception.Message
            }
        }

        if (-not $checked -and (Get-Command manage-bde -ErrorAction SilentlyContinue)) {
            $out = & manage-bde -status $osDrive 2>$null
            $checked = $true
            if ($LASTEXITCODE -eq 0 -and $out) {
                $t = ($out | Out-String)
                $protOn = ($t -match 'Protection Status:\s+Protection On')
                $ev = "manage-bde output parsed. ProtectionOn=$protOn"
            } else {
                $ev = "manage-bde returned exit code $LASTEXITCODE or no output when checking $osDrive."
            }
        }

        if (-not $checked) {
            $ev = "BitLocker cmdlets and manage-bde are unavailable on this system (feature not installed?)."
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

function Get-WindowsFamily {
    param([string]$ProductName, [string]$Build)

    # Some preview/dev builds report a legacy product name (e.g., "Windows 10 Pro") even
    # though the build number clearly belongs to Windows 11 (26000+). To avoid false
    # downgrades, sanitize the build string and prefer build-based detection when reliable.
    $buildNum = $null
    if ($Build) {
        $buildCore = $Build -replace "[^0-9].*$", ""  # keep the leading numeric portion (e.g., 26200.7462 -> 26200)
        [int]::TryParse($buildCore, [ref]$buildNum) | Out-Null
    }

    if ($buildNum) {
        # Desktop/workstation builds: Windows 11 uses build 22000+, while Windows 10 stops at 19045
        if ($buildNum -ge 26000) { return 'Windows 11' }
        if ($buildNum -ge 22000) { return 'Windows 11' }
        if ($buildNum -ge 19000 -and $buildNum -lt 22000) { return 'Windows 10' }

        # Server builds (best-effort fallback when product name is ambiguous)
        if ($buildNum -ge 20348 -and $buildNum -lt 22000) { return 'Windows Server 2022' }
        if ($buildNum -ge 17763 -and $buildNum -lt 19000) { return 'Windows Server 2019' }
        if ($buildNum -ge 14393 -and $buildNum -lt 17763) { return 'Windows Server 2016' }
    }

    if ($ProductName -match 'Windows 11') { return 'Windows 11' }
    if ($ProductName -match 'Windows 10') { return 'Windows 10' }
    if ($ProductName -match 'Windows Server 2022') { return 'Windows Server 2022' }
    if ($ProductName -match 'Windows Server 2019') { return 'Windows Server 2019' }
    if ($ProductName -match 'Windows Server 2016') { return 'Windows Server 2016' }

    return 'Unknown'
}

function Get-WindowsLifecycleRecord {
    param([string]$Family, [string]$Build, [string]$VersionLabel)
    $table = @(
        @{Family='Windows 11'; Release='24H2'; BuildPrefix=@('26100','26200'); SupportEnd=[datetime]'2027-10-14'},
        @{Family='Windows 11'; Release='23H2'; BuildPrefix=@('22631'); SupportEnd=[datetime]'2025-11-11'},
        @{Family='Windows 11'; Release='22H2'; BuildPrefix=@('22621'); SupportEnd=[datetime]'2024-10-08'},
        @{Family='Windows 10'; Release='22H2'; BuildPrefix=@('19045'); SupportEnd=[datetime]'2025-10-14'},
        @{Family='Windows Server 2022'; Release='21H2'; BuildPrefix=@('20348'); SupportEnd=[datetime]'2031-10-14'},
        @{Family='Windows Server 2019'; Release='1809'; BuildPrefix=@('17763'); SupportEnd=[datetime]'2029-01-09'},
        @{Family='Windows Server 2016'; Release='1607'; BuildPrefix=@('14393'); SupportEnd=[datetime]'2027-01-12'}
    )

    $candidates = $table | Where-Object { $_.Family -eq $Family }
    foreach ($c in $candidates) {
        $buildMatch = $false
        foreach ($prefix in $c.BuildPrefix) {
            if ($Build -and ($Build -like "$prefix*")) { $buildMatch = $true; break }
        }
        if ($buildMatch -or ($VersionLabel -and ($VersionLabel -eq $c.Release))) {
            return $c
        }
    }
    return $null
}

function Get-LatestSecurityUpdateInfo {
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop
        if (-not $hotfixes) { return $null }
        $preferred = $hotfixes | Where-Object { $_.Description -match 'Security|S[eé]curit[eé]' } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if (-not $preferred) {
            $preferred = $hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1
        }
        if (-not $preferred) { return $null }

        $installedOn = $preferred.InstalledOn
        if ($installedOn -is [string] -and $installedOn) {
            try { $installedOn = [datetime]$installedOn } catch {}
        }

        return [PSCustomObject]@{
            HotFixID    = $preferred.HotFixID
            Description = $preferred.Description
            InstalledOn = $installedOn
        }
    } catch { return $null }
}

# -------------------------
# Check: Windows support lifecycle and patch currency
# -------------------------
function Test-WindowsVersionSupport {
    try {
        $cvPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $productName = Get-RegString $cvPath "ProductName"
        if (-not $productName) { $productName = $osCaption }

        $displayVersion = Get-RegString $cvPath "DisplayVersion"
        $releaseId = Get-RegString $cvPath "ReleaseId"
        $build = Get-RegString $cvPath "CurrentBuild"
        $ubr = Get-RegDword $cvPath "UBR"
        $buildFull = if ($ubr -ne $null -and $build) { "$build.$ubr" } else { $build }
        $versionLabel = $displayVersion
        if (-not $versionLabel) { $versionLabel = $releaseId }
        if (-not $versionLabel) { $versionLabel = $osVersion }

        $family = Get-WindowsFamily -ProductName $productName -Build $build
        $productDisplay = $productName
        if ($family -and $family -ne 'Unknown' -and ($productDisplay -notmatch [regex]::Escape($family))) {
            if ($osCaption -and ($osCaption -match $family)) {
                # Use the CIM caption (e.g., "Microsoft Windows 11 Pro (10.0.26200)") when it already reflects the detected family
                $productDisplay = $osCaption
            } elseif ($family -eq 'Windows 11' -and ($productDisplay -match 'Windows 10')) {
                # Align legacy product names (Windows 10 Pro) with Windows 11 detection when build numbers prove it
                $productDisplay = $productDisplay -replace 'Windows 10', 'Windows 11'
            } elseif ($family -eq 'Windows 10' -and ($productDisplay -match 'Windows 11')) {
                $productDisplay = $productDisplay -replace 'Windows 11', 'Windows 10'
            } else {
                $productDisplay = "$family ($productDisplay)"
            }
        }
        $lifecycle = Get-WindowsLifecycleRecord -Family $family -Build $build -VersionLabel $versionLabel

        $supportEnd = $null
        $supportOk = $false
        if ($lifecycle) {
            $supportEnd = $lifecycle.SupportEnd
            $supportOk = ($supportEnd -gt (Get-Date))
        }

        $latestUpdate = Get-LatestSecurityUpdateInfo
        $updateInfo = "LatestSecurityUpdate=(not found)"
        if ($latestUpdate) {
            $dateText = "(unknown)"
            if ($latestUpdate.InstalledOn) {
                try { $dateText = ([datetime]$latestUpdate.InstalledOn).ToString('yyyy-MM-dd') } catch { $dateText = "$($latestUpdate.InstalledOn)" }
            }
            $updateInfo = "LatestSecurityUpdate={0} ({1})" -f $latestUpdate.HotFixID, $dateText
        }

        $supportEndText = if ($supportEnd) { $supportEnd.ToString('yyyy-MM-dd') } else { "(unknown)" }
        $ev = "Family=$family; Product=$productDisplay; Version=$versionLabel; Build=$buildFull; SupportEnd=$supportEndText; $updateInfo"

        $res = if ($supportOk) { 'Pass' } else { 'Fail' }
        $recoEN = if ($supportOk) {
            "OS release is supported; continue applying the latest cumulative security updates and monitor the lifecycle end date ($supportEndText)."
        } else {
            "Upgrade to a Windows release still under support per Microsoft lifecycle and keep applying the latest security updates."
        }
        $recoFR = if ($supportOk) {
            "La version est supportee; continuer a appliquer les mises a jour de securite les plus recentes et surveiller la date de fin de support ($supportEndText)."
        } else {
            "Mettre a niveau vers une version de Windows encore supportee selon le cycle de vie Microsoft et appliquer les dernieres mises a jour de securite."
        }
        Add-Result "WIN-24" "Windows version support status" "Statut de support de la version Windows" `
          "A.8.8, A.8.9, A.8.19" High $res `
          $ev `
          $recoEN `
          $recoFR
    } catch {
        Add-Result "WIN-24" "Windows version support status" "Statut de support de la version Windows" `
          "A.8.8, A.8.9, A.8.19" High Error `
          ("Error: {0}" -f $_.Exception.Message) `
          "Verify the Windows version against Microsoft lifecycle and ensure security updates are current." `
          "Verifier la version de Windows vs le cycle de vie Microsoft et s assurer que les mises a jour de securite sont a jour."
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
    $adminGroup = Get-LocalizedAdminGroupName

    # Method 1: Get-LocalGroupMember (not available everywhere)
    try {
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $raw = Get-LocalGroupMember -Group $adminGroup -ErrorAction Stop
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
        $grp = [ADSI]("WinNT://./{0},group" -f $adminGroup)
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

function Get-GuestAccountInfo {
    try {
        $accounts = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction Stop
        $guest = $accounts | Where-Object { $_.SID -match '-501$' }
        if (-not $guest) {
            $guest = $accounts | Where-Object { $_.Name -in @('Guest','Invite','Invité') }
        }
        if (-not $guest) { throw "Guest account not found." }
        return ($guest | Select-Object -First 1)
    } catch {
        throw $_
    }
}

# -------------------------
# Check: Guest account disabled
# -------------------------
function Test-GuestAccountDisabled {
    try {
        $guest = Get-GuestAccountInfo
        $enabled = -not $guest.Disabled

        $res = if ($enabled -eq $false) { 'Pass' } else { 'Fail' }
        Add-Result "WIN-15" "Guest account disabled" "Compte Invite desactive" `
          "A.5.15, A.8.2, A.8.9" Medium $res `
          ("Guest enabled={0}; AccountName={1}" -f $enabled, $guest.Name) `
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
    if ($script:Profile -ne 'Server') { return }
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
Test-WindowsVersionSupport
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
Info-SecureBoot
Info-InstalledSoftware

# -------------------------
# Excel export helper
# -------------------------
function New-AuditExcelReport {
    param(
        [string]$Path,
        [hashtable]$Metadata,
        $Results,
        [string]$Language
    )

    Add-Type -AssemblyName 'System.IO.Compression.FileSystem' -ErrorAction SilentlyContinue

    $statusOptions = @(
        (ResLabel 'Pass'),
        (ResLabel 'Fail'),
        (ResLabel 'Error'),
        (ResLabel 'Info'),
        (L 'Not applicable' 'Non applicable')
    )

    $title          = L "Windows Configuration Audit - ISO 27001" "Audit de configuration Windows - ISO 27001"
    $labelHost      = L "Host" "Hote"
    $labelProfile   = L "Profile" "Profil"
    $labelOS        = L "Operating System" "Systeme d exploitation"
    $labelVersion   = L "Toolkit version" "Version de l outil"
    $labelDate      = L "Date" "Date"
    $labelOverall   = L "Automatic compliance (%)" "Conformite automatique (%)"
    $labelPassCt    = L "Pass" "Conforme"
    $labelFailCt    = L "Fail" "Non conforme"
    $labelErrorCt   = L "Error" "Erreur"
    $labelInfoCt    = L "Info" "Information"
    $labelIsoRefs   = L "ISO refs covered" "References ISO couvertes"
    $labelManual    = L "Use the Status dropdown to update findings; the compliance formula will refresh automatically." `
                         "Utilisez la liste Statut pour mettre a jour les constats ; la formule de conformite se recalculera automatiquement."
    $labelGlobal    = L "To build a global report, copy/paste the table rows into a consolidated workbook; compliance will update on paste." `
                         "Pour un rapport global, copiez/collez les lignes du tableau dans un classeur consolide ; la conformite se mettra a jour lors du collage."
    $labelStatusOpt = L "Status options" "Options de statut"
    $labelHeaderId  = "ID"
    $labelHeaderChk = L "Check" "Controle"
    $labelHeaderIso = "ISO 27001"
    $labelHeaderSev = L "Severity" "Criticite"
    $labelHeaderRes = L "Status" "Statut"
    $labelHeaderEv  = L "Current configuration (evidence)" "Configuration actuelle (preuve)"
    $labelHeaderRec = L "Recommendation" "Recommandation"

    $passLabel = (ResLabel 'Pass')
    $failLabel = (ResLabel 'Fail')

    $dataStartRow = 14
    $dataEndRow = if ($Results.Count -gt 0) { $dataStartRow + $Results.Count - 1 } else { $dataStartRow }
    $statusRange = "E${dataStartRow}:E${dataEndRow}"
    $statusFormulaEnd = 1 + $statusOptions.Count
    $complianceFormula = "IFERROR(ROUND(COUNTIF($statusRange,""=$passLabel"")/(COUNTIF($statusRange,""=$passLabel"")+COUNTIF($statusRange,""=$failLabel""))*100,1),0)"
    $complianceValue = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $Metadata.Compliance)

    function New-InlineCell {
        param([string]$Ref, [string]$Text)
        return "<c r=""$Ref"" t=""inlineStr""><is><t xml:space=""preserve"">$(Escape-XmlText $Text)</t></is></c>"
    }

    function Add-RowXml {
        param([System.Text.StringBuilder]$Sb, [int]$RowIndex, [string[]]$Cells)
        $Sb.Append("  <row r=""$RowIndex"">") | Out-Null
        foreach ($c in $Cells) { $Sb.Append($c) | Out-Null }
        $Sb.Append("</row>`n") | Out-Null
    }

    $sheetSb = New-Object System.Text.StringBuilder
    $sheetSb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>') | Out-Null
    $sheetSb.AppendLine('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">') | Out-Null
    $sheetSb.AppendLine('  <sheetData>') | Out-Null

    Add-RowXml -Sb $sheetSb -RowIndex 1  -Cells @((New-InlineCell -Ref "A1" -Text $title))
    Add-RowXml -Sb $sheetSb -RowIndex 2  -Cells @((New-InlineCell -Ref "A2" -Text $labelHost),    (New-InlineCell -Ref "B2" -Text $Metadata.Host))
    Add-RowXml -Sb $sheetSb -RowIndex 3  -Cells @((New-InlineCell -Ref "A3" -Text $labelProfile), (New-InlineCell -Ref "B3" -Text $Metadata.Profile))
    Add-RowXml -Sb $sheetSb -RowIndex 4  -Cells @((New-InlineCell -Ref "A4" -Text $labelOS),      (New-InlineCell -Ref "B4" -Text $Metadata.OS))
    Add-RowXml -Sb $sheetSb -RowIndex 5  -Cells @((New-InlineCell -Ref "A5" -Text $labelVersion), (New-InlineCell -Ref "B5" -Text $Metadata.ToolkitVersion))
    Add-RowXml -Sb $sheetSb -RowIndex 6  -Cells @((New-InlineCell -Ref "A6" -Text $labelDate),    (New-InlineCell -Ref "B6" -Text $Metadata.Date))
    Add-RowXml -Sb $sheetSb -RowIndex 7  -Cells @((New-InlineCell -Ref "A7" -Text $labelOverall), "<c r=""B7""><f>$complianceFormula</f><v>$complianceValue</v></c>", (New-InlineCell -Ref "D7" -Text (L "Total checks" "Nombre total de controles")), (New-InlineCell -Ref "E7" -Text $Metadata.TotalChecks))
    Add-RowXml -Sb $sheetSb -RowIndex 8  -Cells @((New-InlineCell -Ref "A8" -Text $labelPassCt),  (New-InlineCell -Ref "B8" -Text $Metadata.PassCount.ToString()), (New-InlineCell -Ref "C8" -Text $labelFailCt), (New-InlineCell -Ref "D8" -Text $Metadata.FailCount.ToString()), (New-InlineCell -Ref "E8" -Text $labelErrorCt), (New-InlineCell -Ref "F8" -Text $Metadata.ErrorCount.ToString()), (New-InlineCell -Ref "G8" -Text $labelInfoCt), (New-InlineCell -Ref "H8" -Text $Metadata.InfoCount.ToString()))
    Add-RowXml -Sb $sheetSb -RowIndex 9  -Cells @((New-InlineCell -Ref "A9" -Text $labelIsoRefs), (New-InlineCell -Ref "B9" -Text $Metadata.IsoRefs))
    Add-RowXml -Sb $sheetSb -RowIndex 10 -Cells @((New-InlineCell -Ref "A10" -Text (L "Context and scope" "Contexte et portee")), (New-InlineCell -Ref "B10" -Text $Metadata.Context))
    Add-RowXml -Sb $sheetSb -RowIndex 11 -Cells @((New-InlineCell -Ref "A11" -Text $labelManual))
    Add-RowXml -Sb $sheetSb -RowIndex 12 -Cells @((New-InlineCell -Ref "A12" -Text $labelGlobal))

    # Header row
    Add-RowXml -Sb $sheetSb -RowIndex ($dataStartRow - 1) -Cells @(
        (New-InlineCell -Ref "A$($dataStartRow - 1)" -Text $labelHeaderId),
        (New-InlineCell -Ref "B$($dataStartRow - 1)" -Text $labelHeaderChk),
        (New-InlineCell -Ref "C$($dataStartRow - 1)" -Text $labelHeaderIso),
        (New-InlineCell -Ref "D$($dataStartRow - 1)" -Text $labelHeaderSev),
        (New-InlineCell -Ref "E$($dataStartRow - 1)" -Text $labelHeaderRes),
        (New-InlineCell -Ref "F$($dataStartRow - 1)" -Text $labelHeaderEv),
        (New-InlineCell -Ref "G$($dataStartRow - 1)" -Text $labelHeaderRec)
    )

    $rowIndex = $dataStartRow
    foreach ($r in $Results) {
        Add-RowXml -Sb $sheetSb -RowIndex $rowIndex -Cells @(
            (New-InlineCell -Ref ("A$rowIndex") -Text $r.ID),
            (New-InlineCell -Ref ("B$rowIndex") -Text $r.Check),
            (New-InlineCell -Ref ("C$rowIndex") -Text $r.ISO27001),
            (New-InlineCell -Ref ("D$rowIndex") -Text $r.Severity),
            (New-InlineCell -Ref ("E$rowIndex") -Text $r.Result),
            (New-InlineCell -Ref ("F$rowIndex") -Text $r.Evidence),
            (New-InlineCell -Ref ("G$rowIndex") -Text $r.Reco)
        )
        $rowIndex++
    }

    $sheetSb.AppendLine('  </sheetData>') | Out-Null
    $sheetSb.AppendLine("  <dataValidations count=""1"">") | Out-Null
    $sheetSb.AppendLine("    <dataValidation type=""list"" allowBlank=""1"" showInputMessage=""1"" showErrorMessage=""1"" sqref=""$statusRange"">") | Out-Null
    $sheetSb.AppendLine("      <formula1>'Lookups'!$A$2:$A$$statusFormulaEnd</formula1>") | Out-Null
    $sheetSb.AppendLine("    </dataValidation>") | Out-Null
    $sheetSb.AppendLine("  </dataValidations>") | Out-Null
    $sheetSb.AppendLine('</worksheet>') | Out-Null

    $lookupSb = New-Object System.Text.StringBuilder
    $lookupSb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>') | Out-Null
    $lookupSb.AppendLine('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">') | Out-Null
    $lookupSb.AppendLine('  <sheetData>') | Out-Null
    Add-RowXml -Sb $lookupSb -RowIndex 1 -Cells @((New-InlineCell -Ref "A1" -Text $labelStatusOpt))
    $lr = 2
    foreach ($opt in $statusOptions) {
        Add-RowXml -Sb $lookupSb -RowIndex $lr -Cells @((New-InlineCell -Ref ("A$lr") -Text $opt))
        $lr++
    }
    $lookupSb.AppendLine('  </sheetData>') | Out-Null
    $lookupSb.AppendLine('</worksheet>') | Out-Null

    $styles = @"
<?xml version="1.0" encoding="UTF-8"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="1">
    <font>
      <sz val="11"/>
      <color theme="1"/>
      <name val="Calibri"/>
      <family val="2"/>
    </font>
  </fonts>
  <fills count="1"><fill><patternFill patternType="none"/></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" applyNumberFormat="0"/></cellXfs>
</styleSheet>
"@

    $workbook = @"
<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Audit" sheetId="1" r:id="rId1"/>
    <sheet name="Lookups" sheetId="2" state="hidden" r:id="rId2"/>
  </sheets>
</workbook>
"@

    $workbookRels = @"
<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>
"@

    $rootRels = @"
<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>
"@

    $contentTypes = @"
<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>
"@

    $tmpRoot = Join-Path $env:TEMP ("audit_excel_{0}" -f ([Guid]::NewGuid().ToString("N")))
    New-Item -ItemType Directory -Path $tmpRoot -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tmpRoot "_rels") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tmpRoot "xl") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tmpRoot "xl/_rels") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $tmpRoot "xl/worksheets") -Force | Out-Null

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $tmpRoot "[Content_Types].xml"), $contentTypes, $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $tmpRoot "_rels/.rels"), $rootRels, $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $tmpRoot "xl/workbook.xml"), $workbook, $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $tmpRoot "xl/_rels/workbook.xml.rels"), $workbookRels, $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $tmpRoot "xl/styles.xml"), $styles, $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $tmpRoot "xl/worksheets/sheet1.xml"), $sheetSb.ToString(), $utf8NoBom)
    [System.IO.File]::WriteAllText((Join-Path $tmpRoot "xl/worksheets/sheet2.xml"), $lookupSb.ToString(), $utf8NoBom)

    $parentDir = Split-Path -Path $Path -Parent
    if ($parentDir) { Ensure-Folder -Path $parentDir }
    if (Test-Path $Path) { Remove-Item $Path -Force -ErrorAction SilentlyContinue }
    [System.IO.Compression.ZipFile]::CreateFromDirectory($tmpRoot, $Path)

    Remove-Item $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

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

$ctx = if ($Language -eq 'FR') {
@"
Ce rapport presente un audit de configuration sur un systeme Windows (profil: $Profile).
Il se base sur des controles techniques et des recommandations de durcissement alignees sur les exigences pertinentes de la norme ISO/IEC 27001 (Annexe A).
Le score est calcule uniquement a partir des controles Conforme/Non conforme. Information/Erreur n impactent pas le score.
"@
} else {
@"
This report presents a Windows configuration audit (profile: $Profile).
It is based on technical configuration checks and hardening recommendations aligned with relevant ISO/IEC 27001 requirements.
The score is calculated from Pass/Fail checks only. Info/Error do not impact the score.
"@
}

$reportFileName = ("WinAudit_{0}_{1}_{2}.xlsx" -f $script:HostName, $Profile, $script:Now.ToString('yyyyMMdd_HHmmss'))
$reportPath = Join-Path $OutputFolder $reportFileName

New-AuditExcelReport -Path $reportPath -Metadata @{
    Host           = $script:HostName
    Profile        = $Profile
    OS             = "$osCaption ($osVersion)"
    ToolkitVersion = $script:ToolVersion
    Date           = $script:Now.ToString("yyyy-MM-dd HH:mm:ss")
    Compliance     = $compliance
    TotalChecks    = $Results.Count
    PassCount      = $passCount
    FailCount      = $failCount
    ErrorCount     = $errorCount
    InfoCount      = $infoCount
    IsoRefs        = $isoRefs
    Context        = $ctx.Trim()
} -Results $Results -Language $Language

Write-Host ""
Write-Host (L "Report generated (Excel):" "Rapport genere (Excel):") -ForegroundColor Green
Write-Host $reportPath -ForegroundColor Yellow
Write-Host (L "Compliance score (automatic):" "Score de conformite (automatique):") -NoNewline
Write-Host (" $compliance% ($passCount/$applicable Pass/Fail checks)" ) -ForegroundColor Cyan
