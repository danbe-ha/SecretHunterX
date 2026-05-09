import requests
import json
from config import AI_CONFIG

class AIClassifier:
    def __init__(self):
        """Initialise le moteur d'expertise basé sur l'IA locale."""
        self.url = AI_CONFIG["url"]
        self.model = AI_CONFIG["model"]

    def analyze_finding(self, finding):
        """
        Analyse une découverte via le modèle LLM pour validation MASVS v2.
        """
        # On limite chaque ligne de contexte à 150 caractères pour éviter de saturer Phi-3
        context_str = "\n".join([line[:150] for line in finding.context_lines])
        
        # Prompt optimisé pour Phi-3 avec les vraies catégories MASVS
        prompt = f"""
        Système: Tu es un expert en cybersécurité mobile. Utilise le référentiel OWASP MASVS v2.
        Vérifie si cette découverte est un SECRET RÉEL ou un code technique inoffensif.

        DÉTAILS :
        - Type : {finding.pattern_name}
        - Valeur : {finding.matched_value}
        - Code contextuel : 
        {context_str}

        INSTRUCTIONS :
        1. "is_secret" : true si c'est une clé API, token ou credential hardcodé.
        2. "explanation" : Justification courte en FRANÇAIS.
        3. "masvs_id" : Utilise uniquement ces catégories : 
           (MASVS-STORAGE, MASVS-CRYPTO, MASVS-NETWORK, MASVS-PLATFORM, MASVS-CODE, MASVS-RESILIENCE).
        4. "severity" : CRITICAL/HIGH/MEDIUM/LOW.

        Réponds UNIQUEMENT au format JSON.
        """

        try:
            response = requests.post(
                self.url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                },
                timeout=90 # Augmenté pour éviter le "Read timed out"
            )
            
            if response.status_code == 200:
                result = response.json()
                return json.loads(result['response'])
            return {"is_secret": True, "explanation": "Validation par défaut", "masvs_id": "MASVS-STORAGE", "severity": "MEDIUM"}

        except Exception as e:
            # En cas de timeout ou erreur, on garde par sécurité
            return {"is_secret": True, "explanation": f"Analyse manuelle requise (Timeout)", "masvs_id": "N/A", "severity": "LOW"}