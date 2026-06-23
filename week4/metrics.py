import json
from datetime import datetime

class MetricsCollector:
    def __init__(self, scenario_name):
        self.scenario_name = scenario_name
        self.start_time = datetime.now()
        self.alerts = []
        self.attack_events = []
        self.metrics = {}

    def add_alert(self, alert, timestamp):
        self.alerts.append({"alert": alert, "timestamp": timestamp})

    def add_attack_event(self, event_type, description, timestamp):
        self.attack_events.append({
            "type": event_type,
            "description": description,
            "timestamp": timestamp
        })

    def compute_metrics(self):
        """Compute TP, FP, FN, Precision, Recall"""
        tp = len([a for a in self.alerts if self._is_real_attack(a)])
        fp = len([a for a in self.alerts if not self._is_real_attack(a)])
        fn = len([e for e in self.attack_events if not self._detected(e)])
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        return {
            "scenario": self.scenario_name,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "total_alerts": len(self.alerts),
            "total_attack_events": len(self.attack_events),
        }

    def _is_real_attack(self, alert):
        return "T105" in alert.get("alert", {}).get("rule", "")

    def _detected(self, event):
        return any(event["type"] in str(a) for a in self.alerts)

    def print_report(self):
        metrics = self.compute_metrics()
        print("\n" + "="*60)
        print(f"SCENARIO: {metrics['scenario']}")
        print("="*60)
        print(f"True Positives:  {metrics['true_positives']}")
        print(f"False Positives: {metrics['false_positives']}")
        print(f"False Negatives: {metrics['false_negatives']}")
        print(f"Precision:       {metrics['precision']}")
        print(f"Recall:          {metrics['recall']}")
        print("="*60 + "\n")
        return metrics
