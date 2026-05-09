import re
import os
import yaml
import math
from pathlib import Path
from models import RawFinding, SourceType
from tqdm import tqdm

class PatternEngine:
    def __init__(self, patterns_path):
        """Initialise le moteur avec les signatures YAML."""
        with open(patterns_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            self.patterns = data.get("patterns", {})

        self.allowed_extensions = {".java", ".kt", ".xml", ".json", ".txt", ".smali", ".gradle"}
        # Blacklist renforcée pour éviter les bibliothèques Google/Android
        self.blacklist = ["android.support", "androidx.", "com.google", "java.io", "xmlns.android", "google_ad_id"]

    def calculate_entropy(self, data: str):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def scan_directory(self, root_path: Path):
        all_findings = []
        files_to_scan = []
        for root, _, files in os.walk(root_path):
            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in self.allowed_extensions:
                    files_to_scan.append(file_path)

        if not files_to_scan: return []

        with tqdm(total=len(files_to_scan), desc="Scan Statique", unit="file", colour="green", leave=False) as pbar:
            for file_path in files_to_scan:
                try:
                    # Détection type de source
                    if file_path.suffix in [".java", ".kt", ".smali"]: stype = SourceType.CODE
                    elif file_path.name == "AndroidManifest.xml": stype = SourceType.MANIFEST
                    else: stype = SourceType.RESOURCE

                    findings = self._scan_file(file_path, stype)
                    all_findings.extend(findings)
                except: pass
                finally: pbar.update(1)

        return all_findings

    def _scan_file(self, file_path: Path, source_type: SourceType):
        findings = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            lines = content.splitlines()
        except: return []

        for name, details in self.patterns.items():
            regex = details.get("pattern") if isinstance(details, dict) else details
            if not regex: continue

            try:
                compiled = re.compile(regex)
                for i, line in enumerate(lines):
                    for match in compiled.finditer(line):
                        # Extraction
                        val = match.group(1) if match.groups() else match.group(0)
                        val = val.strip().strip('"\'').strip()

                        # --- FILTRAGE DE PRÉCISION (Niveau Ingénieur) ---
                        if len(val) < 10: continue
                        
                        # 1. Ignorer les certificats et données binaires hexadécimales
                        if "\\u" in val or "0x" in val or len(val) > 500: continue
                        
                        # 2. Ignorer les constantes Java Long (ex: 315576000000L)
                        if val.upper().endswith('L') and val[:-1].isdigit(): continue
                        
                        # 3. Ignorer le code dynamique et les variables internes
                        if "+" in val or "this." in val or val.startswith("com.android"): continue
                        
                        # 4. Vérifier la blacklist
                        if any(b in val.lower() for b in self.blacklist): continue

                        findings.append(RawFinding(
                            file_path=str(file_path),
                            line_number=i + 1,
                            matched_value=val,
                            context_lines=lines[max(0, i-2):min(len(lines), i+3)],
                            pattern_name=name,
                            category=details.get("service", name) if isinstance(details, dict) else name,
                            source_type=source_type,
                            entropy=round(self.calculate_entropy(val), 2),
                            confidence=0.85
                        ))
            except: continue
        return findings