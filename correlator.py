import os
import sys
from datetime import datetime
import logging

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
    def __init__(self):
        self.workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.state = MirageState(self.workspace_root)
        self.db = MongoAtlasManager() if MongoAtlasManager else None
        self.incidents = {} # {attacker_ip: [list_of_events]}

    def fetch_recent_events(self, limit=100):
        """Récupère les derniers événements de MongoDB Atlas"""
        if self.db and self.db.db is not None:
            return self.db.get_latest_events(limit)
        return []
# ...

    def correlate(self):
        """Analyse et regroupe les événements par attaquant"""
        events = self.fetch_recent_events()
        self.incidents = {}

        for e in events:
            # Essayer de trouver l'IP de l'attaquant ou de la cible
            ip = e.get('ip') or e.get('target', {}).get('ip') or e.get('attacker', {}).get('ip')
            if not ip: continue

            if ip not in self.incidents:
                self.incidents[ip] = {
                    "first_seen": e.get('timestamp'),
                    "last_seen": e.get('timestamp'),
                    "severity_sum": 0,
                    "event_types": set(),
                    "raw_events": []
                }
            
            self.incidents[ip]["raw_events"].append(e)
            self.incidents[ip]["event_types"].add(e.get('type', 'unknown'))
            
            # Calcul de score de menace (simplifié)
            severity_weights = {"info": 1, "low": 10, "medium": 30, "high": 70, "critical": 100}
            self.incidents[ip]["severity_sum"] += severity_weights.get(str(e.get('severity', 'info')).lower(), 0)

        return self.generate_incident_reports()

    def generate_incident_reports(self):
        reports = []
        for ip, data in self.incidents.items():
            if data["severity_sum"] > 50:
                threat_level = "CRITICAL" if data["severity_sum"] > 150 else "HIGH" if data["severity_sum"] > 80 else "MEDIUM"
                report = {
                    "attacker": ip,
                    "threat_level": threat_level,
                    "attack_chain": " -> ".join(list(data["event_types"])),
                    "summary": f"L'IP {ip} montre un comportement agressif avec {len(data['raw_events'])} alertes.",
                    "timestamp": datetime.now().isoformat()
                }
                reports.append(report)
                
                # Push back to cloud as a "CORRELATION" event
                if self.db and self.db.db is not None:
                    self.db.insert_event({
                        "component": "oracle",
                        "type": "incident_report",
                        "severity": threat_level.lower(),
                        "target": {"ip": ip},
                        "message": report["summary"],
                        "data": report
                    })
                    
        return reports

    def run_brain_cycle(self):
        print(f"[*] {datetime.now().strftime('%H:%M:%S')} [ORACLE] Analyse de corrélation en cours...")
        reports = self.correlate()
        if reports:
            for r in reports:
                print(f"[🧠 ORACLE] INCIDENT DÉTECTÉ : {r['attacker']} | Niveau: {r['threat_level']}")
                print(f"    Chaîne d'attaque : {r['attack_chain']}")
        else:
            print("    [.] RAS : Aucun pattern d'attaque complexe détecté.")

if __name__ == "__main__":
    correlator = OracleCorrelator()
    correlator.run_brain_cycle()
