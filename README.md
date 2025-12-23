# Configuration Audit ISO27001

## Description
PowerShell script for auditing system configurations against ISO27001 compliance requirements.

## Usage
```powershell
.\scripts\Audit_config_win.ps1 -Language EN -Profile Desktop -Redact
```

## Requirements
- PowerShell 5.1 or higher
- Administrative privileges

### Parameters
- `-OutputFolder`: Path where HTML reports are saved. Defaults to `scripts\reports`.
- `-Language`: Report language. `EN` or `FR`. Defaults to interactive prompt.
- `-Profile`: Audit profile. `Desktop` or `Server`. Defaults to detected role with prompt override.
- `-Redact`: Switch to mask host/domain/account strings in evidence.
