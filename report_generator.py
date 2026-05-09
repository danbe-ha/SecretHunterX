from fpdf import FPDF
from datetime import datetime
from pathlib import Path

class SecretHunterReport(FPDF):
    def header(self):
        # Bandeau de titre stylisé
        self.set_fill_color(41, 128, 185) # Bleu Professionnel
        self.rect(0, 0, 210, 30, 'F')
        self.set_font("Arial", "B", 18)
        self.set_text_color(255, 255, 255)
        self.cell(0, 20, "SECRETHUNTER | AUDIT REPORT", 0, 1, "C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(127, 140, 141)
        self.cell(0, 10, f"Confidential - SecretHunter v2.0 - Page {self.page_no()}", 0, 0, "C")

    def chapter_header(self, title):
        self.set_font("Arial", "B", 14)
        self.set_text_color(44, 62, 80)
        self.set_draw_color(41, 128, 185)
        self.cell(0, 10, title, "B", 1, "L")
        self.ln(5)

    def safe_text(self, text):
        """Nettoie le texte pour éviter les erreurs d'encodage FPDF."""
        if isinstance(text, list):
            text = ", ".join(map(str, text))
        text = str(text)
        # Remplace les caractères problématiques pour latin-1
        return text.encode('latin-1', 'replace').decode('latin-1')

    def add_finding(self, finding):
        # 1. Gestion de la sévérité et des couleurs
        sev = str(finding.get('severity', 'LOW')).upper()
        colors = {
            'CRITICAL': (192, 57, 43), # Rouge
            'HIGH': (211, 84, 0),     # Orange
            'MEDIUM': (243, 156, 18), # Jaune
            'LOW': (41, 128, 185)      # Bleu
        }
        accent = colors.get(sev, (127, 140, 141))

        # 2. En-tête de la vulnérabilité (Carte)
        self.set_fill_color(*accent)
        self.set_font("Arial", "B", 10)
        self.set_text_color(255, 255, 255)
        pattern_name = self.safe_text(finding.get('pattern_name', 'Unknown'))
        self.cell(0, 8, f"  VULNERABILITY: {pattern_name} [{sev}]", 0, 1, 'L', True)
        
        # 3. Détails techniques
        self.set_text_color(0, 0, 0)
        self.ln(2)
        
        # Standard MASVS
        self.set_font("Arial", "B", 9)
        self.cell(40, 6, "  Standard:", 0, 0)
        self.set_font("Arial", "", 9)
        masvs_text = self.safe_text(finding.get('masvs', 'OWASP MASVS'))
        self.cell(0, 6, masvs_text, 0, 1)

        # Fichier Source
        self.set_font("Arial", "B", 9)
        self.cell(40, 6, "  Source File:", 0, 0)
        self.set_font("Arial", "I", 9)
        file_name = Path(str(finding.get('file_path', 'unknown'))).name
        self.cell(0, 6, self.safe_text(file_name), 0, 1)

        # Analyse de l'IA
        self.ln(2)
        self.set_font("Arial", "B", 9)
        self.cell(0, 6, "  Expert Analysis:", 0, 1)
        self.set_font("Arial", "", 9)
        explanation = self.safe_text(finding.get('explanation', 'No details available.'))
        self.multi_cell(0, 5, explanation)
        
        # 4. Bloc de code (Style Terminal)
        self.ln(3)
        self.set_fill_color(30, 30, 30) # Fond noir
        self.set_text_color(46, 204, 113) # Texte vert Matrix
        self.set_font("Courier", "", 8)
        
        context_lines = finding.get('context_lines', [])
        if context_lines:
            code_snippet = self.safe_text("\n".join(context_lines))
            # On tronque si le code est trop long pour une page
            if len(code_snippet) > 1000:
                code_snippet = code_snippet[:1000] + "\n[... Truncated for Report ...]"
            self.multi_cell(0, 4, code_snippet, 0, "L", True)
        
        self.ln(10)
        # Reset couleur texte pour la suite
        self.set_text_color(0, 0, 0)

def generate_pdf(json_data, output_path):
    """Fonction principale pour générer le document PDF."""
    pdf = SecretHunterReport()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Section 1 : Résumé
    pdf.chapter_header("1. EXECUTIVE SUMMARY")
    pdf.set_font("Arial", "", 10)
    summary = (f"Analysis of the application revealed {len(json_data)} security finding(s). "
               "This document provides technical evidence and remediation steps based on international "
               "security standards (OWASP MASVS).")
    pdf.multi_cell(0, 5, summary)
    pdf.ln(5)

    # Section 2 : Détails
    pdf.chapter_header("2. FINDINGS DETAILS")
    for finding in json_data:
        # Vérification si on a assez de place pour un nouveau finding, sinon nouvelle page
        if pdf.get_y() > 230:
            pdf.add_page()
        pdf.add_finding(finding)
        
    # Export final
    pdf.output(str(output_path))