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
                    
                    # --- DÉCISION AUTONOME (DÉFENSE ACTIVE) ---
                    if threat_level == "CRITICAL":
                        logger.warning(f"Menace CRITIQUE détectée pour {ip}. Déclenchement GHOST.")
                        self.db.push_command("ghost", "trap_attacker", target_ip=ip)
                    elif threat_level == "HIGH":
                        logger.warning(f"Menace ÉLEVÉE détectée pour {ip}. Demande d'isolation SENTINELLE.")
                        self.db.push_command("sentinelle", "isolate_ip", target_ip=ip)
                    
        return reports

    def run_brain_cycle(self):
        """Lance un cycle d'analyse et signale que le cerveau est actif"""
        logger.info("Cycle de corrélation en cours...")
        if self.db:
            self.db.send_heartbeat("oracle")
            
        reports = self.correlate()
        if reports:
            for r in reports:
                logger.warning(f"INCIDENT DÉTECTÉ : {r['attacker']} | Niveau: {r['threat_level']}")
        else:
            logger.info("Aucun incident complexe détecté.")

    def start_daemon(self, interval=30):
        """Lance Oracle en mode continu"""
        logger.info(f"Démon Oracle lancé (Intervalle: {interval}s)")
        try:
            while True:
                self.run_brain_cycle()
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Arrêt du cerveau Oracle.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Mirage Oracle - The Autonomous Brain")
    parser.add_argument("--daemon", action="store_true", help="Run in continuous mode")
    parser.add_argument("--interval", type=int, default=30, help="Check interval in seconds")
    args = parser.parse_args()

    correlator = OracleCorrelator()
    if args.daemon:
        correlator.start_daemon(args.interval)
    else:
        correlator.run_brain_cycle()
