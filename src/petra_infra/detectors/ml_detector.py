from typing import List
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
from collections import defaultdict
from petra_domain.entities.log_entry import LogEntry
from petra_domain.entities.anomaly import Anomaly, AnomalyLevel

class MLDetector:
    """Improved ML for timing & fail anomalies."""

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination  # Lower for sensitivity

    def detect_outliers(self, entries: List[LogEntry]) -> List[Anomaly]:
        if len(entries) < 10:
            return []

        # Feature engineering: [hour, fail_rate per IP]
        features = []
        fail_rates = defaultdict(int)
        for entry in entries:
            hour = entry.timestamp.hour + entry.timestamp.minute / 60.0
            fail = 1 if not entry.success and "failed" in entry.details.lower() else 0  # Simple fail check
            if entry.ip:
                fail_rates[entry.ip] += fail
            features.append([hour, fail_rates[entry.ip or "unknown"] / max(1, len(entries))])  # Normalized fail rate

        X = np.array(features)

        # Normalize
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # IsolationForest
        model = IsolationForest(contamination=self.contamination, random_state=42)
        labels = model.fit_predict(X_scaled)  # -1 = outlier
        scores = -model.decision_function(X_scaled)  # Positive, higher = anomalous

        # Collect anomalies
        anomalies = []
        outlier_indices = np.where(labels == -1)[0]
        if len(outlier_indices) > 0:
            evidence = [entries[i] for i in outlier_indices]
            avg_score = np.mean(scores[outlier_indices])
            level = AnomalyLevel.MEDIUM if avg_score < 0.5 else AnomalyLevel.HIGH
            anomalies.append(
                Anomaly(
                    level=level,
                    score=avg_score,
                    type="unusual_timing",
                    evidence=evidence,
                    description=f"Detected {len(evidence)} outliers in timing/fail patterns. Ref: NIST SP 800-61"
                )
            )

        return anomalies