import os
import sys
from datetime import datetime
import logging
import math

# Add parent directory for database_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from state_manager import MirageState
try:
    from database_manager import MongoAtlasManager
except ImportError:
    MongoAtlasManager = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Oracle.Correlator")

class OracleCorrelator:
    """
    Système de corrélation avancé utilisant un scoring de risque logarithmique
    et une analyse de chaine d'attaque (Kill Chain).
    """
    def __init__(self):
        self.workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.state = MirageState(self.workspace_root)
        self.db = MongoAtlasManager() if MongoAtlasManager else None
        self.incidents = {} # {attacker_ip: data}
        
        # Poids des événements pour le calcul du risque
        self.weights = {
            "discovery": 5,      # Simple ping/ARP scan
            "port_scan": 15,     # Scan agressif
            "vulnerability": 40,  # Service vulnérable touché
            "bruteforce": 50,    # Tentative d'accès
            "threat": 60,        # Alerte IDS (Suricata/Zeek)
            "lateral_movement": 80, # Mouvement interne suspect
            "data_exfiltration": 100 # Vol de données (CRITIQUE)
        }

    def fetch_recent_events(self, limit=200):
        if self.db and self.db.db is not None:
            return self.db.get_latest_events(limit)
        return []

    def calculate_risk_score(self, events):
        """
        Calcule un score de risque pondéré.
        Utilise une fonction logarithmique pour éviter l'explosion des scores 
        tout en restant très sensible aux répétitions.
        """
        base_score = 0
        event_types = {}
        
        for e in events:
            etype = e.get('type', 'unknown')
            weight = self.weights.get(etype, 10)
            
            # Plus un type d'attaque se répète, plus le score monte (mais de façon amortie)
            event_types[etype] = event_types.get(etype, 0) + 1
            occurrence_multiplier = 1 + (math.log10(event_types[etype]) * 0.5)
            
            base_score += weight * occurrence_multiplier

        # Capé à 100 pour une lecture facile du pourcentage de danger
        return min(100, base_score)

    def correlate(self):
        logger.info("Démarrage du cycle de corrélation intelligente...")
        events = self.fetch_recent_events()
        self.incidents = {}

        for e in events:
            ip = e.get('ip') or e.get('target', {}).get('ip') or e.get('attacker', {}).get('ip')
            if not ip: continue

            if ip not in self.incidents:
                self.incidents[ip] = {
                    "first_seen": e.get('timestamp'),
                    "last_seen": e.get('timestamp'),
                    "raw_events": [],
                    "chain": []
                }
            
            self.incidents[ip]["raw_events"].append(e)
            if e.get('type') not in self.incidents[ip]["chain"]:
                self.incidents[ip]["chain"].append(e.get('type'))

        return self.analyze_incidents()

    def analyze_incidents(self):
        reports = []
        for ip, data in self.incidents.items():
            risk_score = self.calculate_risk_score(data["raw_events"])
            
            # Détermination du niveau de menace
            if risk_score > 85:
                threat_level = "CRITICAL"
                action = "GHOST_TRAP + ISOLATION"
            elif risk_score > 60:
                threat_level = "HIGH"
                action = "SENTINELLE_THROTTLING"
            elif risk_score > 30:
                threat_level = "MEDIUM"
                action = "ENHANCED_LOGGING"
            else:
                threat_level = "LOW"
                action = "MONITORING"

            report = {
                "attacker": ip,
                "risk_score": round(risk_score, 2),
                "threat_level": threat_level,
                "recommended_action": action,
                "attack_path": " -> ".join(data["chain"]),
                "summary": f"Analyse proactive : {ip} présente un risque de {risk_score}%."
            }
            
            reports.append(report)
            self.push_decision(report)
            
        return reports

    def push_decision(self, report):
        """Transmet la décision aux modules d'exécution (Active Defense)"""
        if not self.db: return

        # Log l'incident corrélé
        self.db.insert_event({
            "component": "oracle",
            "type": "incident_report",
            "severity": report["threat_level"].lower(),
            "target": {"ip": report["attacker"]},
            "data": report
        })

        # Actions automatiques
        if report["threat_level"] == "CRITICAL":
            logger.critical(f"AUTONOMOUS RESPONSE: Deploying GHOST for {report['attacker']}")
            self.db.push_command("ghost", "trap_attacker", target_ip=report["attacker"])
            self.db.push_command("sentinelle", "full_block", target_ip=report["attacker"])
        
        elif report["threat_level"] == "HIGH":
            logger.warning(f"AUTONOMOUS RESPONSE: Escalating monitoring for {report['attacker']}")
            self.db.push_command("sentinelle", "throttle_traffic", target_ip=report["attacker"])

if __name__ == "__main__":
    correlator = OracleCorrelator()
    correlator.correlate()
