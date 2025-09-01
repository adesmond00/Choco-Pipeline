# Choco-Pipeline

Python CLI to generate Chocolatey package files from a given .msi or .exe using your templates and the OpenAI API. The tool also scaffolds and runs Pester tests to validate the generated PowerShell scripts.

Quick start
- Requirements: Python 3.12+, PowerShell (Windows), Pester (PowerShell module), OpenAI API key.
- Install Python deps: `pip install openai`
- Set env var: `setx OPENAI_API_KEY "<your-key>"` (Windows) or `export OPENAI_API_KEY=<your-key>`

Usage
- Single file: `python choco_gen.py C:\path\to\installer.exe`
- Folder scan: `python choco_gen.py C:\path\to\folder --recursive`
- Custom output folder: `python choco_gen.py C:\path\to\installer.msi --out dist`
- Choose model: `python choco_gen.py . --model gpt-4.1-mini`
- Skip Pester run: `python choco_gen.py . --skip-tests`

What it does
- Reads your templates from `chocolateyinstall.txt`, `chocolateyuninstall.txt`, and `nuspec.txt`.
- Uses the OpenAI API to propose fully formed `chocolateyinstall.ps1`, `chocolateyuninstall.ps1`, and `.nuspec` tailored to each installer.
- Creates a Chocolatey package folder layout under `out/<packageId>/` and copies the installer into `tools/`.
- Generates Pester tests and a `Run-Pester.ps1` runner per package, and runs them (unless `--skip-tests`).

Notes
- The tool attempts to extract product metadata on Windows via PowerShell for better defaults; otherwise it falls back to filename heuristics.
- Pester is installed if already available; you can run the generated `Run-Pester.ps1 -InstallPester` to install for CurrentUser.
- Configure `OPENAI_MODEL` via env var or `--model` flag. Default: `gpt-4.1-mini`.
