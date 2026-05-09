import sys
import time
import shutil
import os
import json
from pathlib import Path
from tqdm import tqdm
from report_generator import generate_pdf
import asyncio

# Imports de tes modules
from apk_extractor import APKExtractor
from pattern_engine import PatternEngine
from ai_classifier import AIClassifier
from config import PATTERNS_FILE, TEMP_DIR, OUTPUT_DIR, AI_CONFIG

class Color:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    CYAN = '\033[96m'

def print_banner():
    banner = f"""
    {Color.CYAN}{Color.BOLD}
                                        ╔════════════════════════════════════════════════════════════╗
                                        ║                S E C R E T   H U N T E R                   ║
                                        ║           Advanced Mobile Security Scanner                 ║
                                        ╚════════════════════════════════════════════════════════════╝
    {Color.END}"""
    print(banner)

def setup_workspace():
    if TEMP_DIR.exists(): shutil.rmtree(TEMP_DIR, ignore_errors=True)
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

async def run_web_scan(apk_path_str, websocket=None):
    """Version asynchrone pour l'interface Web avec progression en temps réel."""
    
    async def update_progress(text, percent):
        if websocket:
            await websocket.send_json({"status": text, "progress": percent})

    apk_path = Path(apk_path_str)
    setup_workspace()
    
    # Étape 1
    await update_progress("Extraction du code source (JADX)...", 15)
    extractor = APKExtractor(apk_path)
    extracted_folder = extractor.decompile()
    if not extracted_folder: return []

    # Étape 2
    await update_progress("Analyse statique des patterns...", 40)
    engine = PatternEngine(PATTERNS_FILE)
    raw_findings = engine.scan_directory(extracted_folder)

    final_findings = []
    seen_secrets = set()
    
    # Étape 3
    if raw_findings:
        total = len(raw_findings)
        await update_progress(f"Expertise cognitive IA (0/{total})...", 60)
        classifier = AIClassifier()
        
        for i, f in enumerate(raw_findings):
            if f.matched_value in seen_secrets: continue
            
            analysis = classifier.analyze_finding(f)
            if analysis.get("is_secret"):
                seen_secrets.add(f.matched_value)
                f.explanation = analysis.get("explanation", "N/A")
                f.masvs = analysis.get("masvs_id", "N/A")
                f.severity = analysis.get("severity", "MEDIUM")
                final_findings.append(f.__dict__)
            
            # Mise à jour de la barre pendant l'IA
            prog = 60 + int((i+1)/total * 30)
            await update_progress(f"Expertise cognitive IA ({i+1}/{total})...", prog)
    
    # Étape 4
    await update_progress("Génération du rapport PDF final...", 95)
    if final_findings:
        pdf_path = OUTPUT_DIR / f"Audit_Report_{apk_path.stem}.pdf"
        generate_pdf(final_findings, pdf_path)
        
    await update_progress("Scan terminé avec succès.", 100)
    return final_findings

def main(apk_path_str):
    start_time = time.time()
    apk_path = Path(apk_path_str)
    if not apk_path.exists():
        print(f"{Color.RED}[!] Erreur : Fichier introuvable{Color.END}")
        return

    print_banner()
    setup_workspace()

    print(f"{Color.BLUE}[1/4]{Color.END} Extraction du code source (JADX)...")
    extractor = APKExtractor(apk_path)
    extracted_folder = extractor.decompile()
    if not extracted_folder: return

    print(f"\n{Color.BLUE}[2/4]{Color.END} Analyse des patterns et calcul d'entropie...")
    engine = PatternEngine(PATTERNS_FILE)
    raw_findings = engine.scan_directory(extracted_folder)

    final_findings_objects = []
    seen_secrets = set()

    if raw_findings:
        print(f"\n{Color.BLUE}[3/4]{Color.END} Validation par le moteur d'expertise (Phi-3)...")
        classifier = AIClassifier()
        with tqdm(total=len(raw_findings), desc="AI Audit", unit="find", colour="cyan", leave=False) as pbar:
            for f in raw_findings:
                if f.matched_value in seen_secrets:
                    pbar.update(1)
                    continue
                analysis = classifier.analyze_finding(f)
                if analysis.get("is_secret"):
                    seen_secrets.add(f.matched_value)
                    f.explanation = analysis.get("explanation", "N/A")
                    f.masvs = analysis.get("masvs_id", "N/A")
                    f.severity = analysis.get("severity", "MEDIUM")
                    final_findings_objects.append(f)
                    tqdm.write(f"{Color.YELLOW}[VULN]{Color.END} {f.pattern_name} | {f.severity} | {f.masvs}")
                pbar.update(1)

    print(f"\n{Color.BLUE}[4/4]{Color.END} Génération des livrables d'audit...")
    if final_findings_objects:
        structured_data = [f.__dict__ for f in final_findings_objects]
        pdf_path = OUTPUT_DIR / f"Audit_Report_{apk_path.stem}.pdf"
        generate_pdf(structured_data, pdf_path)
        print(f"{Color.GREEN}[+] Rapport PDF généré : {pdf_path}{Color.END}")
    else:
        print(f"{Color.GREEN}[+] Aucune menace détectée.{Color.END}")

    print(f"\n{Color.CYAN}=== Scan terminé en {time.time() - start_time:.1f}s ==={Color.END}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <chemin_apk>")
    else:
        main(os.path.abspath(sys.argv[1]))