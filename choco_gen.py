#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


TEMPLATE_INSTALL = Path("chocolateyinstall.txt")
TEMPLATE_UNINSTALL = Path("chocolateyuninstall.txt")
TEMPLATE_NUSPEC = Path("nuspec.txt")


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def sanitize_id(name: str) -> str:
    # Chocolatey package id: lowercase letters, numbers, and . or -
    s = name.strip().lower()
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"[^a-z0-9\.-]", "", s)
    s = re.sub(r"-+", "-", s)
    s = s.strip("-.")
    return s or "package"


def guess_name_and_version_from_filename(filename: str) -> Tuple[str, Optional[str]]:
    base = Path(filename).stem
    # try to parse version like 1.2.3.4 or 2024.09
    m = re.search(r"(?<!\d)(\d{1,4}(?:[\._-]\d{1,4}){1,3})(?!\d)", base)
    version = None
    if m:
        version = m.group(1).replace("_", ".").replace("-", ".")
        name = base[: m.start()] + base[m.end() :]
    else:
        name = base
    # cleanup name
    name = re.sub(r"[\._-]+$", "", name)
    name = name.replace("64bit", "").replace("x64", "").replace("x86", "")
    name = re.sub(r"[\._-]+$", "", name)
    name = re.sub(r"[\._-]+", " ", name).strip()
    if not name:
        name = base
    return name, version


def run_powershell_json(script: str) -> Optional[dict]:
    try:
        # Use PowerShell if available (Windows), otherwise return None
        exe = "powershell" if os.name == "nt" else shutil.which("pwsh") or shutil.which("powershell")
        if not exe:
            return None
        cmd = [exe, "-NoProfile", "-NonInteractive", "-Command", script]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return None
        out = proc.stdout.strip()
        return json.loads(out) if out else None
    except Exception:
        return None


def get_file_metadata_windows(path: Path) -> Dict[str, Optional[str]]:
    script = (
        f"$f = Get-Item -LiteralPath '{str(path)}'; "
        "$o = [ordered]@{"
        "FullName=$f.FullName;"
        "Name=$f.Name;"
        "Extension=$f.Extension;"
        "Length=$f.Length;"
        "ProductName=$f.VersionInfo.ProductName;"
        "FileDescription=$f.VersionInfo.FileDescription;"
        "CompanyName=$f.VersionInfo.CompanyName;"
        "ProductVersion=$f.VersionInfo.ProductVersion;"
        "FileVersion=$f.VersionInfo.FileVersion;"
        "}; $o | ConvertTo-Json -Depth 4 -Compress"
    )
    data = run_powershell_json(script)
    if not data:
        return {}
    return data


def ensure_openai() -> "OpenAI":  # type: ignore[name-defined]
    try:
        from openai import OpenAI  # type: ignore
    except Exception as e:
        print(
            "[ERROR] The 'openai' package is required. Install with: pip install openai",
            file=sys.stderr,
        )
        raise
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("[ERROR] OPENAI_API_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(2)
    base_url = os.environ.get("OPENAI_BASE_URL")
    if base_url:
        client = OpenAI(api_key=api_key, base_url=base_url)
    else:
        client = OpenAI(api_key=api_key)
    return client


def call_llm_generate(
    client,
    model: str,
    file_info: Dict[str, Optional[str]],
    inferred_name: str,
    inferred_version: Optional[str],
    install_template: str,
    uninstall_template: str,
    nuspec_template: str,
) -> Dict[str, str]:
    system = (
        "You are a senior Windows packaging engineer generating Chocolatey package files.\n"
        "Follow the provided templates' structure, variable names, and approach.\n"
        "Return only strict JSON matching the schema. No extra keys or commentary.\n"
        "Prefer safe, enterprise-ready silent install/uninstall arguments.\n"
        "When in doubt, choose MSI defaults: /qn /norestart.\n"
        "PowerShell must be compatible with Windows PowerShell 5.1.\n"
        "For uninstall, use Get-UninstallRegistryKey and Uninstall-ChocolateyPackage as in template.\n"
        "Ensure scripts use $env:ChocolateyPackageName for packageName.\n"
        "Assume the installer is embedded under tools and referenced via $toolsDir.\n"
    )

    # Minimal schema that includes fully rendered files. We'll render ourselves if needed.
    schema_hint = {
        "type": "object",
        "properties": {
            "package_id": {"type": "string"},
            "version": {"type": "string"},
            "title": {"type": "string"},
            "authors": {"type": "string"},
            "project_url": {"type": "string"},
            "tags": {"type": "string"},
            "summary": {"type": "string"},
            "description": {"type": "string"},
            "software_name_pattern": {"type": "string"},
            "installer_base_name": {"type": "string"},
            "install_ps1": {"type": "string"},
            "uninstall_ps1": {"type": "string"},
            "nuspec_xml": {"type": "string"}
        },
        "required": [
            "package_id",
            "version",
            "title",
            "authors",
            "project_url",
            "tags",
            "summary",
            "description",
            "software_name_pattern",
            "installer_base_name",
            "install_ps1",
            "uninstall_ps1",
            "nuspec_xml"
        ]
    }

    user = {
        "instruction": (
            "Generate Chocolatey package scripts and nuspec strictly based on these templates.\n"
            "- Templates are examples; match structure and function calls.\n"
            "- Use @packageArgs with keys: packageName, fileType, file, softwareName, silentArgs, validExitCodes.\n"
            "- For installers, set $fileLocation = Join-Path $toolsDir '<installer_base_name>' and detect .msi vs .exe exactly like the template.\n"
            "- For uninstall, follow the template flow with Get-UninstallRegistryKey and Uninstall-ChocolateyPackage.\n"
            "- Use enterprise-safe silent args by installer type (MSI/EXE).\n"
            "- Tailor softwareName to product (e.g., 'Acme App*').\n"
            "- nuspec should include <files> entry for tools/** and realistic metadata.\n"
        ),
        "file_info": file_info,
        "inferred_name": inferred_name,
        "inferred_version": inferred_version or "",
        "templates": {
            "install": install_template,
            "uninstall": uninstall_template,
            "nuspec": nuspec_template,
        },
        "json_schema_hint": schema_hint,
    }

    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.2,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user)},
            ],
        )
        content = resp.choices[0].message.content
        data = json.loads(content)
        return data
    except Exception as e:
        print(f"[ERROR] OpenAI API call failed: {e}", file=sys.stderr)
        raise


def write_if_changed(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        old = path.read_text(encoding="utf-8")
        if old == content:
            return
    path.write_text(content, encoding="utf-8")


def generate_pester_tests(
    package_dir: Path,
    package_id: str,
    software_name_pattern: str,
    installer_base_name: str,
) -> None:
    tests_dir = package_dir / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)

    install_test = f"""
Describe '{package_id} install script' {{
  BeforeAll {{
    $env:ChocolateyPackageName = '{package_id}'
    $script:toolsDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools'
    # Ensure dummy files exist so Test-Path succeeds if needed
    New-Item -ItemType Directory -Force -Path $script:toolsDir | Out-Null
    if (-not (Test-Path (Join-Path $script:toolsDir '{installer_base_name}'))) {{ New-Item -ItemType File -Path (Join-Path $script:toolsDir '{installer_base_name}') | Out-Null }}
    if (-not (Test-Path (Join-Path $script:toolsDir '{installer_base_name}.exe'))) {{ New-Item -ItemType File -Path (Join-Path $script:toolsDir '{installer_base_name}.exe') | Out-Null }}
    if (-not (Test-Path (Join-Path $script:toolsDir '{installer_base_name}.msi'))) {{ New-Item -ItemType File -Path (Join-Path $script:toolsDir '{installer_base_name}.msi') | Out-Null }}
    Mock Install-ChocolateyInstallPackage {{ return }} -Verifiable
  }}

  It 'invokes Install-ChocolateyInstallPackage with required parameters' {{
    . (Join-Path $script:toolsDir 'chocolateyinstall.ps1')
    Assert-MockCalled Install-ChocolateyInstallPackage -Times 1 -ParameterFilter {{
      $packageName -eq $env:ChocolateyPackageName -and
      $softwareName -like '{software_name_pattern}' -and
      $fileType -in @('MSI','EXE') -and
      $silentArgs -is [string] -and
      $validExitCodes.Count -ge 1
    }}
  }}
}}
""".strip()

    _display_name = software_name_pattern.replace("*", "").strip() or package_id
    uninstall_test = f"""
Describe '{package_id} uninstall script' {{
  BeforeAll {{
    $env:ChocolateyPackageName = '{package_id}'
    Mock Get-UninstallRegistryKey {{
      # Return one fake match
      [pscustomobject]@{{
        DisplayName = '{_display_name}';
        UninstallString = 'msiexec.exe /x {{00000000-0000-0000-0000-000000000000}}';
        PSChildName = '{{00000000-0000-0000-0000-000000000000}}';
      }}
    }} -Verifiable
    Mock Uninstall-ChocolateyPackage {{ return }} -Verifiable
  }}

  It 'invokes Uninstall-ChocolateyPackage appropriately' {{
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools' 'chocolateyuninstall.ps1')
    Assert-MockCalled Get-UninstallRegistryKey -Times 1 -ParameterFilter {{ $SoftwareName -like '{software_name_pattern}' }}
    Assert-MockCalled Uninstall-ChocolateyPackage -Times 1 -ParameterFilter {{
      $packageName -eq $env:ChocolateyPackageName -and $silentArgs -is [string]
    }}
  }}
}}
""".strip()

    write_if_changed(tests_dir / "Install.Tests.ps1", install_test)
    write_if_changed(tests_dir / "Uninstall.Tests.ps1", uninstall_test)

    # Test runner
    runner = f"""
param(
  [switch]$InstallPester
)

if ($InstallPester) {{
  try {{
    if (-not (Get-Module -ListAvailable -Name Pester)) {{
      Write-Host 'Installing Pester for CurrentUser...' -ForegroundColor Yellow
      Install-Module Pester -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop
    }}
  }} catch {{ Write-Warning $_ }}
}}

Import-Module Pester -ErrorAction SilentlyContinue
if (-not (Get-Module -Name Pester)) {{
  Write-Error 'Pester module not available. Install it or pass -InstallPester.'
  exit 2
}}

Invoke-Pester -Path '{tests_dir}' -CI
""".strip()
    write_if_changed(package_dir / "Run-Pester.ps1", runner)


def run_pester(package_dir: Path) -> int:
    exe = shutil.which("pwsh") or shutil.which("powershell")
    if not exe:
        print("[WARN] PowerShell not found; skipping Pester run.")
        return 0
    cmd = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(package_dir / "Run-Pester.ps1")]
    proc = subprocess.run(cmd)
    return proc.returncode


@dataclass
class GenerationResult:
    package_id: str
    version: str
    title: str
    authors: str
    project_url: str
    tags: str
    summary: str
    description: str
    software_name_pattern: str
    installer_base_name: str
    install_ps1: str
    uninstall_ps1: str
    nuspec_xml: str


def process_installer(
    installer: Path,
    out_dir: Path,
    model: str,
    skip_tests: bool,
) -> GenerationResult:
    install_template = read_text(TEMPLATE_INSTALL)
    uninstall_template = read_text(TEMPLATE_UNINSTALL)
    nuspec_template = read_text(TEMPLATE_NUSPEC)

    meta = get_file_metadata_windows(installer) if os.name == "nt" else {}
    inferred_name, inferred_version = guess_name_and_version_from_filename(installer.name)
    file_info = {
        "full_path": str(installer.resolve()),
        "file_name": installer.name,
        "extension": installer.suffix,
        "product_name": meta.get("ProductName"),
        "file_description": meta.get("FileDescription"),
        "company_name": meta.get("CompanyName"),
        "product_version": meta.get("ProductVersion"),
        "file_version": meta.get("FileVersion"),
        "length": meta.get("Length"),
    }

    client = ensure_openai()
    data = call_llm_generate(
        client,
        model,
        file_info,
        inferred_name,
        inferred_version,
        install_template,
        uninstall_template,
        nuspec_template,
    )

    # Fallbacks if model omits
    package_id = sanitize_id(data.get("package_id") or inferred_name)
    version = data.get("version") or inferred_version or (meta.get("ProductVersion") or meta.get("FileVersion") or "1.0.0")
    installer_base = data.get("installer_base_name") or Path(installer.name).stem

    result = GenerationResult(
        package_id=package_id,
        version=str(version),
        title=data.get("title") or inferred_name,
        authors=data.get("authors") or (file_info.get("company_name") or "Unknown"),
        project_url=data.get("project_url") or "",
        tags=data.get("tags") or "",
        summary=data.get("summary") or inferred_name,
        description=data.get("description") or inferred_name,
        software_name_pattern=data.get("software_name_pattern") or f"{inferred_name}*",
        installer_base_name=installer_base,
        install_ps1=data.get("install_ps1") or install_template,
        uninstall_ps1=data.get("uninstall_ps1") or uninstall_template,
        nuspec_xml=data.get("nuspec_xml") or nuspec_template,
    )

    # Create output structure
    package_dir = out_dir / result.package_id
    tools_dir = package_dir / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)

    # Copy installer into tools, ensuring the base name matches what scripts expect
    expected_name = f"{result.installer_base_name}{installer.suffix}"
    dest_installer = tools_dir / expected_name
    shutil.copy2(str(installer), str(dest_installer))

    # Write files
    write_if_changed(tools_dir / "chocolateyinstall.ps1", result.install_ps1)
    write_if_changed(tools_dir / "chocolateyuninstall.ps1", result.uninstall_ps1)

    # Ensure nuspec id, version, title align; if nuspec_xml seems generic, patch it
    nuspec_path = package_dir / f"{result.package_id}.nuspec"
    nuspec_xml = result.nuspec_xml
    # Best-effort replacements for id and version from template
    nuspec_xml = re.sub(r"<id>.*?</id>", f"<id>{result.package_id}</id>", nuspec_xml)
    nuspec_xml = re.sub(r"<version>.*?</version>", f"<version>{result.version}</version>", nuspec_xml)
    nuspec_xml = re.sub(r"<title>.*?</title>", f"<title>{result.title}</title>", nuspec_xml)
    nuspec_xml = re.sub(r"<authors>.*?</authors>", f"<authors>{result.authors}</authors>", nuspec_xml)
    if "<files>" not in nuspec_xml:
        # append standard files section
        nuspec_xml = nuspec_xml.replace(
            "</metadata>",
            "    <files>\n      <file src=\"tools\\**\" target=\"tools\" />\n    </files>\n  </metadata>",
        )
    write_if_changed(nuspec_path, nuspec_xml)

    # Generate Pester tests and runner
    generate_pester_tests(package_dir, result.package_id, result.software_name_pattern, result.installer_base_name)

    # Optionally run Pester
    if not skip_tests:
        code = run_pester(package_dir)
        if code != 0:
            print(f"[ERROR] Pester tests failed for {result.package_id} (exit {code})", file=sys.stderr)
            sys.exit(code)

    return result


def discover_installers(path: Path, recursive: bool) -> List[Path]:
    if path.is_file():
        return [path]
    files: List[Path] = []
    pattern = "**/*" if recursive else "*"
    for p in path.glob(pattern):
        if p.is_file() and p.suffix.lower() in {".msi", ".exe"}:
            files.append(p)
    return files


def main():
    parser = argparse.ArgumentParser(description="Generate Chocolatey package files using OpenAI and templates, with Pester validation.")
    parser.add_argument("path", type=str, help="Path to installer file or directory containing .msi/.exe")
    parser.add_argument("--out", dest="out_dir", default="out", help="Output directory (default: out)")
    parser.add_argument("--model", dest="model", default=os.environ.get("OPENAI_MODEL", "gpt-4.1-mini"), help="OpenAI model name")
    parser.add_argument("--recursive", action="store_true", help="Recurse into subdirectories when scanning a folder")
    parser.add_argument("--skip-tests", action="store_true", help="Skip running Pester tests after generation")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"[ERROR] Path not found: {target}", file=sys.stderr)
        sys.exit(2)

    installers = discover_installers(target, args.recursive)
    if not installers:
        print("[ERROR] No .msi or .exe files found.", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[GenerationResult] = []
    for inst in installers:
        print(f"[INFO] Processing {inst}")
        res = process_installer(inst, out_dir, args.model, args.skip_tests)
        results.append(res)

    print("\n[OK] Generated packages:")
    for r in results:
        print(f" - {r.package_id} {r.version}")


if __name__ == "__main__":
    main()
