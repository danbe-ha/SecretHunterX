import subprocess
import shutil
import os
from pathlib import Path
from config import JADX_PATH, TEMP_DIR, IGNORE_EXTENSIONS

class APKExtractor:
    def __init__(self, apk_path: Path):
        """Initialise l'extracteur avec le chemin de l'APK cible."""
        self.apk_path = apk_path
        self.app_name = apk_path.stem
        self.extraction_root = TEMP_DIR / self.app_name

    def decompile(self):
        """Lance la décompilation via JADX avec optimisation du bruit."""
        if self.extraction_root.exists():
            shutil.rmtree(self.extraction_root)
        self.extraction_root.mkdir(parents=True, exist_ok=True)

        # Commande JADX optimisée (pas d'infos de debug pour la rapidité)
        cmd = f'"{JADX_PATH}" -d "{self.extraction_root}" "{self.apk_path}" --no-debug-info'

        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True)

            if (self.extraction_root / "sources").exists():
                self._cleanup_multimedia()
                return self.extraction_root
            return None
        except Exception as e:
            print(f"[!] Erreur d'extraction : {str(e)}")
            return None

    def _cleanup_multimedia(self):
        """Supprime les fichiers non textuels pour accélérer le scan ultérieur."""
        for root, _, files in os.walk(self.extraction_root):
            for file in files:
                if Path(file).suffix.lower() in IGNORE_EXTENSIONS:
                    try: os.remove(os.path.join(root, file))
                    except: continue