from typing import List
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import numpy as np
from petra_domain.entities.log_entry import LogEntry
from petra_domain.entities.anomaly import Anomaly, AnomalyLevel

class MLDetector:
    """basic ml"""

    def __init__(self, clusters: int = 3):
        self.clusters = clusters

    def detect_outliers(self, entries: List[LogEntry]) -> List[Anomaly]:
        """kmeans for clusters"""
        if len(entries) < self.clusters:
            return []  # too few data

        # takes timestamps as seconds from epoch
        timestamps = np.array([entry.timestamp.timestamp() for entry in entries]).reshape(-1, 1)

        # normalizes
        scaler = StandardScaler()
        scaled_ts = scaler.fit_transform(timestamps)

        # creates cluster
        kmeans = KMeans(n_clusters=self.clusters, random_state=42, n_init=10)
        labels = kmeans.fit_predict(scaled_ts)

        # finds outliers e.g <10%
        cluster_sizes = np.bincount(labels)
        outlier_labels = np.where(cluster_sizes < len(entries) * 0.15)[0]

        anomalies = []
        for label in outlier_labels:
            outlier_indices = np.where(labels == label)[0]
            evidence = [entries[i] for i in outlier_indices]
            if evidence:
                anomalies.append(
                    Anomaly(
                        level=AnomalyLevel.MEDIUM,
                        score=0.7,  # heuristic
                        type="unusual_timing",
                        evidence=evidence,
                        description=f"Outlier cluster of {len(evidence)} entries at unusual times. Ref: NIST SP 800-61"
                    )
                )

        return anomalies