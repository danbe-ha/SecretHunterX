import os
from pathlib import Path

# --- Chemins de base ---
BASE_DIR = Path(__file__).parent
TEMP_DIR = BASE_DIR / ".tmp"
OUTPUT_DIR = BASE_DIR / "output"

# LA VARIABLE QUI MANQUAIT :
PATTERNS_FILE = BASE_DIR / "patterns" / "secrets_patterns.yaml"

# Création automatique des dossiers
TEMP_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# --- JADX CONFIG ---
# Utilise bien le 'r' pour éviter les erreurs de caractères Windows
JADX_PATH = r"C:\jadx\bin\jadx.bat" 

# --- CONFIGURATION IA (OLLAMA) ---
AI_CONFIG = {
    "url": "http://localhost:11434/api/generate",
    "model": "phi3"
}

# --- FILTRAGE ---
IGNORE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.mp4', '.wav', '.ttf', '.woff'}

# Mapping de sévérité pour le rapport final
SEVERITY_MAP = {
    "private_key": "CRITICAL",
    "api_key": "HIGH",
    "oauth_token": "HIGH",
    "jwt": "HIGH",
    "secret": "MEDIUM",
    "endpoint": "LOW",
}