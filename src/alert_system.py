import json
import logging
from datetime import datetime
import os

class AlertSystem:
    def __init__(self, log_file='logs/alerts.log'):
        self.log_file = log_file
        self.alerts_count = 0
        
        # Set up logging
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        logging.basicConfig(
            level=logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()  # Also print to console
            ]
        )
        self.logger = logging.getLogger('IDS')
        
    def alert(self, alert_data):
        """Log an alert"""
        self.alerts_count += 1
        
        # Add timestamp and ID
        alert_data['timestamp'] = datetime.now().isoformat()
        alert_data['alert_id'] = self.alerts_count
        
        # Format for logging
        severity = alert_data.get('severity', 'medium').upper()
        alert_type = alert_data.get('type', 'Unknown')
        source = alert_data.get('source', 'Unknown')
        confidence = alert_data.get('confidence', 0)
        
        # Log to file and console
        log_message = f"[ALERT] {alert_type} from {source} (Confidence: {confidence}%)"
        if severity == 'CRITICAL':
            self.logger.critical(log_message)
        elif severity == 'HIGH':
            self.logger.error(log_message)
        elif severity == 'MEDIUM':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
        
        # Also save full JSON to a separate file for analysis
        with open('logs/alerts.jsonl', 'a') as f:
            f.write(json.dumps(alert_data) + '\n')
        
        # Print colorful alert to console
        self.print_alert(alert_data)
        
        return alert_data['alert_id']
    
    def print_alert(self, alert_data):
        """Print a colorful alert to console"""
        severity = alert_data.get('severity', 'medium')
        # Windows doesn't support ANSI colors by default, so we'll use plain text
        print(f"\n{'='*50}")
        print(f" ALERT: {alert_data.get('type', 'Unknown')}")
        print(f"Severity: {severity.upper()}")
        print(f"Source: {alert_data.get('source', 'Unknown')}")
        print(f"Confidence: {alert_data.get('confidence', 0)}%")
        print(f"Details: {alert_data.get('details', '')}")
        print(f"{'='*50}\n")
