import json
import os
import sys

# Add parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ghost.clone_factory import GhostCloneFactory

class DynamicLure:
    def __init__(self, workspace_root):
        self.workspace_root = workspace_root

    def analyze_attacker_intent(self, attacker_ip, events):
        """Devine ce que l'attaquant cherche (Web, SSH, DB...)"""
        intent = "generic"
        for e in events:
            if "port_scan" in e['type']: intent = "recon"
            if "sql" in e['description'].lower(): intent = "database"
            if "http" in e['description'].lower(): intent = "web"
        return intent

    def create_targeted_lure(self, attacker_ip, intent):
        """Ordonne à Ghost de créer un leurre spécifique"""
        print(f"[🧠 ORACLE] Création d'un leurre dynamique pour {attacker_ip} (Intention: {intent})")
        factory = GhostCloneFactory()
        
        if intent == "database":
            factory.deploy_dionaea() # Dionaea est excellent pour le SQL
        elif intent == "web":
            # On pourrait ici choisir un clone web spécifique
            pass
        else:
            factory.deploy_pro_suite()
