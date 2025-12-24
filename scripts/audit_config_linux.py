#!/usr/bin/env python3
"""
Linux Configuration Audit Toolkit - ISO 27001 aligned
- Supports: Desktop + Server profile
- Output: Excel report (EN or FR full translation)
- No manual checkpoints

This script mirrors the behavior of the Windows PowerShell audit by
collecting common Linux hardening signals and exporting an Excel report
with bilingual labels.
"""

import argparse
import datetime
import os
import platform
import re
import subprocess
import sys
import tempfile
import textwrap
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

TOOL_VERSION = "1.0.0"


# -----------------------------
# Helpers: localization, safety
# -----------------------------
def l(en: str, fr: str, language: str) -> str:
    """Return the localized string based on requested language."""

    return fr if language.upper() == "FR" else en


def sev_label(level: str, language: str) -> str:
    mapping = {
        "High": l("High", "Elevee", language),
        "Medium": l("Medium", "Moyenne", language),
        "Low": l("Low", "Faible", language),
        "NA": "NA",
    }
    return mapping.get(level, "NA")


def res_label(result: str, language: str) -> str:
    mapping = {
        "Pass": l("Pass", "Conforme", language),
        "Fail": l("Fail", "Non conforme", language),
        "Error": l("Error", "Erreur", language),
        "Info": l("Information", "Information", language),
        "NA": "NA",
    }
    return mapping.get(result, "NA")


def escape_xml(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


@dataclass
class AuditResult:
    ID: str
    Check: str
    ISO27001: str
    Severity: str
    ResultRaw: str
    Evidence: str
    Reco: str

    def localized(self, language: str) -> Dict[str, str]:
        return {
            "ID": self.ID,
            "Check": self.Check,
            "ISO27001": self.ISO27001,
            "Severity": sev_label(self.Severity, language),
            "Result": res_label(self.ResultRaw, language),
            "ResultRaw": self.ResultRaw,
            "Evidence": self.Evidence,
            "Reco": self.Reco,
        }


# -----------------------------
# Core helpers
# -----------------------------
def ensure_folder(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def read_file(path: Path) -> str:
    try:
        return path.read_text()
    except Exception:
        return ""


def detect_os_info() -> str:
    try:
        os_release = Path("/etc/os-release")
        if os_release.exists():
            data = {}
            for line in os_release.read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k] = v.strip().strip('"')
            name = data.get("PRETTY_NAME") or data.get("NAME")
            if name:
                return name
    except Exception:
        pass
    return platform.platform()


# -----------------------------
# Audit logic
# -----------------------------
def add_result(
    results: List[AuditResult],
    language: str,
    *,
    _id: str,
    check_en: str,
    check_fr: str,
    iso: str,
    severity: str,
    result: str,
    evidence: str,
    reco_en: str,
    reco_fr: str,
    applicable: bool = True,
) -> None:
    if not applicable:
        return
    results.append(
        AuditResult(
            ID=_id,
            Check=l(check_en, check_fr, language),
            ISO27001=iso,
            Severity=severity,
            ResultRaw=result,
            Evidence=evidence,
            Reco=l(reco_en, reco_fr, language),
        )
    )


def check_root_context(results: List[AuditResult], language: str) -> None:
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    add_result(
        results,
        language,
        _id="INF-00",
        check_en="Execution context (root privileges)",
        check_fr="Contexte d'execution (droits root)",
        iso="A.8.9",
        severity="NA",
        result="Info",
        evidence=f"Running as root: {is_root}",
        reco_en="Run with sudo/root to collect all evidence.",
        reco_fr="Executer avec sudo/root pour collecter toutes les preuves.",
    )


def check_password_policy(results: List[AuditResult], language: str) -> None:
    try:
        content = read_file(Path("/etc/login.defs"))
        match = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", content, re.MULTILINE)
        cur = int(match.group(1)) if match else 0
        min_len = 12
        res = "Pass" if cur >= min_len else "Fail"
        evidence = f"PASS_MIN_LEN = {cur}" if match else "PASS_MIN_LEN not found"
        add_result(
            results,
            language,
            _id="LIN-01",
            check_en="Minimum password length",
            check_fr="Longueur minimale du mot de passe",
            iso="A.5.15, A.8.5, A.8.9",
            severity="High",
            result=res,
            evidence=evidence,
            reco_en=f"Set PASS_MIN_LEN to at least {min_len} in /etc/login.defs.",
            reco_fr=f"Definir PASS_MIN_LEN a au moins {min_len} dans /etc/login.defs.",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-01",
            check_en="Minimum password length",
            check_fr="Longueur minimale du mot de passe",
            iso="A.5.15, A.8.5, A.8.9",
            severity="High",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Collect /etc/login.defs to verify password policy.",
            reco_fr="Collecter /etc/login.defs pour verifier la politique de mot de passe.",
        )


def check_pwquality(results: List[AuditResult], language: str) -> None:
    try:
        paths = [
            Path("/etc/security/pwquality.conf"),
            Path("/etc/pam.d/common-password"),
            Path("/etc/pam.d/system-auth"),
        ]
        found = False
        minlen_value = None
        for p in paths:
            if not p.exists():
                continue
            text = read_file(p)
            if "pam_pwquality" in text or "pwquality" in text:
                found = True
            if p.name == "pwquality.conf":
                m = re.search(r"^\s*minlen\s*=\s*(\d+)", text, re.MULTILINE)
                if m:
                    minlen_value = int(m.group(1))
        res = "Pass" if found and (minlen_value is None or minlen_value >= 12) else "Fail"
        evidence_parts: List[str] = []
        evidence_parts.append("pam_pwquality present" if found else "pam_pwquality not found")
        if minlen_value is not None:
            evidence_parts.append(f"minlen={minlen_value}")
        evidence = "; ".join(evidence_parts)
        add_result(
            results,
            language,
            _id="LIN-02",
            check_en="Password complexity (pwquality)",
            check_fr="Complexite des mots de passe (pwquality)",
            iso="A.5.15, A.8.5, A.8.9",
            severity="High",
            result=res,
            evidence=evidence,
            reco_en="Enable pam_pwquality with strong parameters (minlen>=12, character class requirements).",
            reco_fr="Activer pam_pwquality avec des parametres forts (minlen>=12, exigences de classes de caracteres).",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-02",
            check_en="Password complexity (pwquality)",
            check_fr="Complexite des mots de passe (pwquality)",
            iso="A.5.15, A.8.5, A.8.9",
            severity="High",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Review PAM configuration to enforce password complexity.",
            reco_fr="Verifier la configuration PAM pour imposer la complexite des mots de passe.",
        )


def check_account_lockout(results: List[AuditResult], language: str) -> None:
    try:
        paths = [Path("/etc/security/faillock.conf"), Path("/etc/pam.d/system-auth"), Path("/etc/pam.d/password-auth")]
        deny_value = None
        text = "".join(read_file(p) for p in paths if p.exists())
        m = re.search(r"deny\s*=\s*(\d+)", text)
        if m:
            deny_value = int(m.group(1))
        if deny_value is None:
            result = "Fail"
            evidence = "No deny= parameter found in faillock configuration."
        else:
            result = "Pass" if 3 <= deny_value <= 5 else "Fail"
            evidence = f"deny={deny_value}"
        add_result(
            results,
            language,
            _id="LIN-03",
            check_en="Account lockout (faillock)",
            check_fr="Verrouillage de compte (faillock)",
            iso="A.5.15, A.8.5, A.8.9",
            severity="High",
            result=result,
            evidence=evidence,
            reco_en="Configure pam_faillock deny between 3 and 5 attempts to slow brute force.",
            reco_fr="Configurer pam_faillock deny entre 3 et 5 tentatives pour freiner la force brute.",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-03",
            check_en="Account lockout (faillock)",
            check_fr="Verrouillage de compte (faillock)",
            iso="A.5.15, A.8.5, A.8.9",
            severity="High",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Review pam_faillock configuration for account lockout.",
            reco_fr="Verifier la configuration pam_faillock pour le verrouillage des comptes.",
        )


def check_firewall(results: List[AuditResult], language: str) -> None:
    try:
        ufw = run_cmd(["sh", "-c", "command -v ufw && ufw status"])
        firewalld = run_cmd(["sh", "-c", "command -v firewall-cmd && firewall-cmd --state"])
        active = False
        evidence_parts: List[str] = []

        if ufw.returncode == 0 and "Status: active" in ufw.stdout:
            active = True
            evidence_parts.append("ufw active")
        elif ufw.returncode == 0:
            evidence_parts.append(ufw.stdout.strip() or "ufw available but inactive")
        if firewalld.returncode == 0:
            if firewalld.stdout.strip().lower() == "running":
                active = True
            evidence_parts.append(f"firewalld: {firewalld.stdout.strip()}")

        result = "Pass" if active else "Fail"
        evidence = "; ".join([p for p in evidence_parts if p]) or "No firewall detected"
        add_result(
            results,
            language,
            _id="LIN-04",
            check_en="Host firewall enabled",
            check_fr="Pare-feu hote active",
            iso="A.8.20, A.8.23",
            severity="High",
            result=result,
            evidence=evidence,
            reco_en="Enable ufw or firewalld with default deny inbound.",
            reco_fr="Activer ufw ou firewalld avec refus entrant par defaut.",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-04",
            check_en="Host firewall enabled",
            check_fr="Pare-feu hote active",
            iso="A.8.20, A.8.23",
            severity="High",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Verify host firewall status (ufw/firewalld) manually.",
            reco_fr="Verifier manuellement l'etat du pare-feu hote (ufw/firewalld).",
        )


def check_sshd_root_login(results: List[AuditResult], language: str) -> None:
    try:
        config = read_file(Path("/etc/ssh/sshd_config"))
        match = re.search(r"^\s*PermitRootLogin\s+(\S+)", config, re.MULTILINE)
        value = match.group(1).lower() if match else ""
        disallowed = value in {"no", "prohibit-password", "without-password"}
        result = "Pass" if disallowed else "Fail"
        evidence = f"PermitRootLogin={value or 'not set'}"
        add_result(
            results,
            language,
            _id="LIN-05",
            check_en="SSH root login disabled",
            check_fr="Connexion root SSH desactivee",
            iso="A.8.2, A.8.23",
            severity="High",
            result=result,
            evidence=evidence,
            reco_en="Set PermitRootLogin to 'no' or 'prohibit-password' in sshd_config.",
            reco_fr="Definir PermitRootLogin a 'no' ou 'prohibit-password' dans sshd_config.",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-05",
            check_en="SSH root login disabled",
            check_fr="Connexion root SSH desactivee",
            iso="A.8.2, A.8.23",
            severity="High",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Review /etc/ssh/sshd_config for PermitRootLogin setting.",
            reco_fr="Verifier /etc/ssh/sshd_config pour le parametre PermitRootLogin.",
        )


def check_sshd_password_auth(results: List[AuditResult], language: str) -> None:
    try:
        config = read_file(Path("/etc/ssh/sshd_config"))
        match = re.search(r"^\s*PasswordAuthentication\s+(\S+)", config, re.MULTILINE)
        value = match.group(1).lower() if match else ""
        disabled = value == "no"
        result = "Pass" if disabled else "Fail"
        evidence = f"PasswordAuthentication={value or 'not set'}"
        add_result(
            results,
            language,
            _id="LIN-06",
            check_en="SSH password authentication disabled",
            check_fr="Authentification par mot de passe SSH desactivee",
            iso="A.8.2, A.8.23",
            severity="Medium",
            result=result,
            evidence=evidence,
            reco_en="Disable PasswordAuthentication to enforce SSH keys.",
            reco_fr="Desactiver PasswordAuthentication pour imposer les cles SSH.",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-06",
            check_en="SSH password authentication disabled",
            check_fr="Authentification par mot de passe SSH desactivee",
            iso="A.8.2, A.8.23",
            severity="Medium",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Review PasswordAuthentication in sshd_config.",
            reco_fr="Verifier PasswordAuthentication dans sshd_config.",
        )


def check_auto_updates(results: List[AuditResult], language: str) -> None:
    try:
        enabled = False
        evidence_parts: List[str] = []
        unattended_path = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        if unattended_path.exists():
            content = read_file(unattended_path)
            if "APT::Periodic::Unattended-Upgrade \"1\";" in content:
                enabled = True
            evidence_parts.append("unattended-upgrades file present")
        timer = run_cmd(["systemctl", "is-enabled", "--quiet", "unattended-upgrades.service"])
        timer_timer = run_cmd(["systemctl", "is-enabled", "--quiet", "unattended-upgrades.timer"])
        if timer.returncode == 0 or timer_timer.returncode == 0:
            enabled = True
            evidence_parts.append("unattended-upgrades systemd enabled")
        dnf_conf = Path("/etc/dnf/automatic.conf")
        if dnf_conf.exists():
            content = read_file(dnf_conf)
            if re.search(r"^apply_updates\s*=\s*yes", content, re.MULTILINE | re.IGNORECASE):
                enabled = True
            evidence_parts.append("dnf-automatic configuration present")
        result = "Pass" if enabled else "Fail"
        evidence = "; ".join(evidence_parts) or "No automatic update service detected"
        add_result(
            results,
            language,
            _id="LIN-07",
            check_en="Automatic security updates",
            check_fr="Mises a jour de securite automatiques",
            iso="A.8.8",
            severity="Medium",
            result=result,
            evidence=evidence,
            reco_en="Enable unattended-upgrades or distro equivalent for security patches.",
            reco_fr="Activer unattended-upgrades ou equivalent distribution pour les correctifs de securite.",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-07",
            check_en="Automatic security updates",
            check_fr="Mises a jour de securite automatiques",
            iso="A.8.8",
            severity="Medium",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Verify automatic update service status.",
            reco_fr="Verifier l'etat du service de mises a jour automatiques.",
        )


def check_disk_encryption(results: List[AuditResult], language: str) -> None:
    try:
        crypttab = Path("/etc/crypttab")
        luks_present = crypttab.exists() and bool(crypttab.read_text().strip())
        lsblk = run_cmd(["lsblk", "-o", "NAME,TYPE,MOUNTPOINT"])
        luks_devices = "luks" in lsblk.stdout.lower()
        encrypted = luks_present or luks_devices
        evidence_parts: List[str] = []
        if luks_present:
            evidence_parts.append("/etc/crypttab entries present")
        if luks_devices:
            evidence_parts.append("lsblk reports luks devices")
        evidence = "; ".join(evidence_parts) or "No LUKS entries detected"
        result = "Pass" if encrypted else "Fail"
        add_result(
            results,
            language,
            _id="LIN-08",
            check_en="Disk encryption (LUKS)",
            check_fr="Chiffrement du disque (LUKS)",
            iso="A.8.12, A.8.24",
            severity="High",
            result=result,
            evidence=evidence,
            reco_en="Configure LUKS full-disk or partition encryption for sensitive systems.",
            reco_fr="Configurer le chiffrement LUKS du disque ou des partitions pour les systemes sensibles.",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-08",
            check_en="Disk encryption (LUKS)",
            check_fr="Chiffrement du disque (LUKS)",
            iso="A.8.12, A.8.24",
            severity="High",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Verify disk encryption status manually (lsblk/crypttab).",
            reco_fr="Verifier manuellement l'etat du chiffrement disque (lsblk/crypttab).",
        )


def check_antivirus(results: List[AuditResult], language: str) -> None:
    try:
        clamav = run_cmd(["sh", "-c", "command -v clamscan && clamscan --version"])
        installed = clamav.returncode == 0
        evidence = clamav.stdout.strip() if installed else "No ClamAV detected"
        result = "Pass" if installed else "Info"
        add_result(
            results,
            language,
            _id="LIN-09",
            check_en="Antivirus/anti-malware presence",
            check_fr="Presence d'un antivirus/anti-malware",
            iso="A.8.16",
            severity="Low",
            result=result,
            evidence=evidence,
            reco_en="Install and regularly update anti-malware tooling where applicable.",
            reco_fr="Installer et mettre a jour regulierement un outil anti-malware si applicable.",
        )
    except Exception as exc:
        add_result(
            results,
            language,
            _id="LIN-09",
            check_en="Antivirus/anti-malware presence",
            check_fr="Presence d'un antivirus/anti-malware",
            iso="A.8.16",
            severity="Low",
            result="Error",
            evidence=f"Error: {exc}",
            reco_en="Assess need for anti-malware and deploy accordingly.",
            reco_fr="Evaluer le besoin d'anti-malware et deploiement en consequence.",
        )


def run_checks(language: str) -> List[AuditResult]:
    results: List[AuditResult] = []
    check_root_context(results, language)
    check_password_policy(results, language)
    check_pwquality(results, language)
    check_account_lockout(results, language)
    check_firewall(results, language)
    check_sshd_root_login(results, language)
    check_sshd_password_auth(results, language)
    check_auto_updates(results, language)
    check_disk_encryption(results, language)
    check_antivirus(results, language)
    return results


# -----------------------------
# Excel export helper
# -----------------------------
def create_excel_report(path: Path, metadata: Dict[str, str], results: Iterable[AuditResult], language: str) -> None:
    status_options = [res_label(x, language) for x in ["Pass", "Fail", "Error", "Info"]]
    status_options.append(l("Not applicable", "Non applicable", language))

    title = l("Linux Configuration Audit - ISO 27001", "Audit de configuration Linux - ISO 27001", language)
    labels = {
        "host": l("Host", "Hote", language),
        "profile": l("Profile", "Profil", language),
        "os": l("Operating System", "Systeme d'exploitation", language),
        "version": l("Toolkit version", "Version de l'outil", language),
        "date": l("Date", "Date", language),
        "overall": l("Automatic compliance (%)", "Conformite automatique (%)", language),
        "pass": l("Pass", "Conforme", language),
        "fail": l("Fail", "Non conforme", language),
        "error": l("Error", "Erreur", language),
        "info": l("Info", "Information", language),
        "iso": l("ISO refs covered", "References ISO couvertes", language),
        "manual": l(
            "Use the Status dropdown to update findings; the compliance formula will refresh automatically.",
            "Utilisez la liste Statut pour mettre a jour les constats ; la formule de conformite se recalculera automatiquement.",
            language,
        ),
        "global": l(
            "To build a global report, copy/paste the table rows into a consolidated workbook; compliance will update on paste.",
            "Pour un rapport global, copiez/collez les lignes du tableau dans un classeur consolide ; la conformite se mettra a jour lors du collage.",
            language,
        ),
        "status_opt": l("Status options", "Options de statut", language),
        "header_check": l("Check", "Controle", language),
        "header_sev": l("Severity", "Criticite", language),
        "header_res": l("Status", "Statut", language),
        "header_ev": l("Current configuration (evidence)", "Configuration actuelle (preuve)", language),
        "header_rec": l("Recommendation", "Recommandation", language),
        "header_id": "ID",
        "header_iso": "ISO 27001",
    }

    pass_label = res_label("Pass", language)
    fail_label = res_label("Fail", language)
    results_list = [r.localized(language) for r in results]

    data_start_row = 14
    data_end_row = data_start_row + len(results_list) - 1 if results_list else data_start_row
    status_range = f"E{data_start_row}:E{data_end_row}"
    status_formula_end = 1 + len(status_options)
    compliance_formula = (
        f'IFERROR(ROUND(COUNTIF({status_range},"={pass_label}")/(COUNTIF({status_range},"={pass_label}")'
        f'+COUNTIF({status_range},"={fail_label}"))*100,1),0)'
    )

    def inline_cell(ref: str, text: str) -> str:
        return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escape_xml(text)}</t></is></c>'

    def add_row(sb: List[str], row_index: int, cells: List[str]) -> None:
        sb.append(f'  <row r="{row_index}">' + "".join(cells) + "</row>\n")

    sheet_lines: List[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">\n',
        '  <sheetData>\n',
    ]

    add_row(sheet_lines, 1, [inline_cell("A1", title)])
    add_row(sheet_lines, 2, [inline_cell("A2", labels["host"]), inline_cell("B2", metadata["Host"])])
    add_row(sheet_lines, 3, [inline_cell("A3", labels["profile"]), inline_cell("B3", metadata["Profile"])])
    add_row(sheet_lines, 4, [inline_cell("A4", labels["os"]), inline_cell("B4", metadata["OS"])])
    add_row(sheet_lines, 5, [inline_cell("A5", labels["version"]), inline_cell("B5", metadata["ToolkitVersion"])])
    add_row(sheet_lines, 6, [inline_cell("A6", labels["date"]), inline_cell("B6", metadata["Date"])])
    add_row(
        sheet_lines,
        7,
        [
            inline_cell("A7", labels["overall"]),
            f'<c r="B7"><f>{compliance_formula}</f><v>{metadata["Compliance"]}</v></c>',
            inline_cell("D7", l("Total checks", "Nombre total de controles", language)),
            inline_cell("E7", str(metadata["TotalChecks"])),
        ],
    )
    add_row(
        sheet_lines,
        8,
        [
            inline_cell("A8", labels["pass"]),
            inline_cell("B8", str(metadata["PassCount"])),
            inline_cell("C8", labels["fail"]),
            inline_cell("D8", str(metadata["FailCount"])),
            inline_cell("E8", labels["error"]),
            inline_cell("F8", str(metadata["ErrorCount"])),
            inline_cell("G8", labels["info"]),
            inline_cell("H8", str(metadata["InfoCount"])),
        ],
    )
    add_row(sheet_lines, 9, [inline_cell("A9", labels["iso"]), inline_cell("B9", metadata["IsoRefs"])])
    add_row(
        sheet_lines,
        10,
        [inline_cell("A10", l("Context and scope", "Contexte et portee", language)), inline_cell("B10", metadata["Context"])],
    )
    add_row(sheet_lines, 11, [inline_cell("A11", labels["manual"])])
    add_row(sheet_lines, 12, [inline_cell("A12", labels["global"])])

    header_row = data_start_row - 1
    add_row(
        sheet_lines,
        header_row,
        [
            inline_cell(f"A{header_row}", labels["header_id"]),
            inline_cell(f"B{header_row}", labels["header_check"]),
            inline_cell(f"C{header_row}", labels["header_iso"]),
            inline_cell(f"D{header_row}", labels["header_sev"]),
            inline_cell(f"E{header_row}", labels["header_res"]),
            inline_cell(f"F{header_row}", labels["header_ev"]),
            inline_cell(f"G{header_row}", labels["header_rec"]),
        ],
    )

    row_index = data_start_row
    for r in results_list:
        add_row(
            sheet_lines,
            row_index,
            [
                inline_cell(f"A{row_index}", r["ID"]),
                inline_cell(f"B{row_index}", r["Check"]),
                inline_cell(f"C{row_index}", r["ISO27001"]),
                inline_cell(f"D{row_index}", r["Severity"]),
                inline_cell(f"E{row_index}", r["Result"]),
                inline_cell(f"F{row_index}", r["Evidence"]),
                inline_cell(f"G{row_index}", r["Reco"]),
            ],
        )
        row_index += 1

    sheet_lines.append("  </sheetData>\n")
    sheet_lines.append("  <dataValidations count=\"1\">\n")
    sheet_lines.append(
        f"    <dataValidation type=\"list\" allowBlank=\"1\" showInputMessage=\"1\" showErrorMessage=\"1\" sqref=\"{status_range}\">\n"
    )
    sheet_lines.append(f"      <formula1>'Lookups'!$A$2:$A${status_formula_end}</formula1>\n")
    sheet_lines.append("    </dataValidation>\n")
    sheet_lines.append("  </dataValidations>\n")
    sheet_lines.append('</worksheet>\n')

    lookup_lines: List[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n',
        '  <sheetData>\n',
    ]
    add_row(lookup_lines, 1, [inline_cell("A1", labels["status_opt"])])
    for idx, opt in enumerate(status_options, start=2):
        add_row(lookup_lines, idx, [inline_cell(f"A{idx}", opt)])
    lookup_lines.append("  </sheetData>\n")
    lookup_lines.append('</worksheet>\n')

    styles = textwrap.dedent(
        """
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
        """
    ).strip() + "\n"

    workbook = textwrap.dedent(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
          <sheets>
            <sheet name="Audit" sheetId="1" r:id="rId1"/>
            <sheet name="Lookups" sheetId="2" state="hidden" r:id="rId2"/>
          </sheets>
        </workbook>
        """
    ).strip() + "\n"

    workbook_rels = textwrap.dedent(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
          <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
          <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
        </Relationships>
        """
    ).strip() + "\n"

    root_rels = textwrap.dedent(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
        </Relationships>
        """
    ).strip() + "\n"

    content_types = textwrap.dedent(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
          <Default Extension="xml" ContentType="application/xml"/>
          <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
          <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
          <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
          <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
        </Types>
        """
    ).strip() + "\n"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_root = Path(tmpdir)
        (tmp_root / "_rels").mkdir()
        (tmp_root / "xl" / "_rels").mkdir(parents=True)
        (tmp_root / "xl" / "worksheets").mkdir()

        (tmp_root / "[Content_Types].xml").write_text(content_types, encoding="utf-8")
        (tmp_root / "_rels" / ".rels").write_text(root_rels, encoding="utf-8")
        (tmp_root / "xl" / "workbook.xml").write_text(workbook, encoding="utf-8")
        (tmp_root / "xl" / "_rels" / "workbook.xml.rels").write_text(workbook_rels, encoding="utf-8")
        (tmp_root / "xl" / "styles.xml").write_text(styles, encoding="utf-8")
        (tmp_root / "xl" / "worksheets" / "sheet1.xml").write_text("".join(sheet_lines), encoding="utf-8")
        (tmp_root / "xl" / "worksheets" / "sheet2.xml").write_text("".join(lookup_lines), encoding="utf-8")

        ensure_folder(path.parent)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for file_path in tmp_root.rglob("*"):
                arcname = file_path.relative_to(tmp_root)
                zf.write(file_path, arcname)


# -----------------------------
# Main
# -----------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Linux configuration audit (ISO 27001)")
    parser.add_argument(
        "--output-folder",
        dest="output_folder",
        default=Path(__file__).parent / "reports",
        type=Path,
        help="Folder where Excel reports are saved",
    )
    parser.add_argument("--language", dest="language", choices=["EN", "FR"], default="EN", help="Report language")
    parser.add_argument("--profile", dest="profile", choices=["Desktop", "Server"], default="Server", help="Audit profile")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    language = args.language

    results = run_checks(language)

    pass_count = sum(1 for r in results if r.ResultRaw == "Pass")
    fail_count = sum(1 for r in results if r.ResultRaw == "Fail")
    error_count = sum(1 for r in results if r.ResultRaw == "Error")
    info_count = sum(1 for r in results if r.ResultRaw == "Info")

    applicable = pass_count + fail_count
    compliance = round((pass_count / applicable) * 100, 1) if applicable else 0

    iso_refs = sorted({iso.strip() for r in results for iso in r.ISO27001.split(",") if iso.strip()})
    iso_refs_str = ", ".join(iso_refs)

    context = l(
        f"This report presents a Linux configuration audit (profile: {args.profile}).\n"
        "It is based on technical configuration checks and hardening recommendations aligned with relevant ISO/IEC 27001 requirements.\n"
        "The score is calculated from Pass/Fail checks only. Info/Error do not impact the score.",
        f"Ce rapport presente un audit de configuration Linux (profil : {args.profile}).\n"
        "Il se base sur des controles techniques et des recommandations de durcissement alignees sur les exigences pertinentes de la norme ISO/IEC 27001 (Annexe A).\n"
        "Le score est calcule uniquement a partir des controles Conforme/Non conforme. Information/Erreur n'impactent pas le score.",
        language,
    )

    now = datetime.datetime.now()
    metadata = {
        "Host": platform.node(),
        "Profile": args.profile,
        "OS": detect_os_info(),
        "ToolkitVersion": TOOL_VERSION,
        "Date": now.strftime("%Y-%m-%d %H:%M:%S"),
        "Compliance": f"{compliance}",
        "TotalChecks": len(results),
        "PassCount": pass_count,
        "FailCount": fail_count,
        "ErrorCount": error_count,
        "InfoCount": info_count,
        "IsoRefs": iso_refs_str,
        "Context": context.strip(),
    }

    filename = f"LinuxAudit_{metadata['Host']}_{args.profile}_{now.strftime('%Y%m%d_%H%M%S')}.xlsx"
    report_path = args.output_folder / filename

    create_excel_report(report_path, metadata, results, language)

    print(l("Report generated (Excel):", "Rapport genere (Excel):", language))
    print(report_path)
    print(
        l("Compliance score (automatic):", "Score de conformite (automatique):", language),
        f"{compliance}% ({pass_count}/{applicable} Pass/Fail checks)",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
