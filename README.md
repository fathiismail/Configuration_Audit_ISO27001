# Configuration Audit ISO27001

## Description
PowerShell and Python scripts for auditing system configurations against ISO27001 compliance requirements on Windows and Linux.

## Usage
```powershell
.\scripts\Audit_config_win.ps1 -Language EN -Profile Desktop -Redact
```

```bash
python3 scripts/audit_config_linux.py --language EN --profile Server --output-folder scripts/reports
```

## Requirements
- PowerShell 5.1 or higher
- Administrative privileges

### Parameters
- `-OutputFolder`: Path where HTML reports are saved. Defaults to `scripts\reports`.
- `-Language`: Report language. `EN` or `FR`. Defaults to interactive prompt.
- `-Profile`: Audit profile. `Desktop` or `Server`. Defaults to detected role with prompt override.
- `-Redact`: Switch to mask host/domain/account strings in evidence.

Linux script parameters:
- `--output-folder`: Path where Excel reports are saved. Defaults to `scripts/reports`.
- `--language`: Report language. `EN` or `FR`. Defaults to `EN`.
- `--profile`: Audit profile. `Desktop` or `Server`. Defaults to `Server`.
