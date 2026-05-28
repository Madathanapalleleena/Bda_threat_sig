"""
ml_engine.py — Pure PySpark Threat Intelligence Engine

Pipelines (All PySpark Big Data Concepts):
  1. Anomaly Detection — Distance from PySpark KMeans cluster center
  2. Random Forest     — PySpark MLlib classification on synthetic labelled data
  3. KMeans            — PySpark MLlib clustering (Attacker / Scanner / Spammer / Clean)
  4. Linear regression — PySpark MLlib trend projection
  5. Feature Assembly  — PySpark VectorAssembler & StandardScaler
"""

import threading
import random
import math
from datetime import datetime, timezone
import warnings
warnings.filterwarnings("ignore")

import sys
import os

import pandas as pd

os.environ["PYSPARK_PYTHON"] = sys.executable
os.environ["PYSPARK_DRIVER_PYTHON"] = sys.executable
os.environ.setdefault("JAVA_HOME", r"C:\Java\jdk1.8.0_202")

from pyspark.sql import SparkSession
from pyspark.ml.feature import VectorAssembler, StandardScaler, StringIndexer, IndexToString
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.clustering import KMeans
from pyspark.ml.regression import LinearRegression

# ── PySpark ──────────────────────────────────────────────────────────────────
_spark = None
_spark_lock = threading.Lock()

def get_spark():
    global _spark
    if _spark is not None:
        return _spark
    with _spark_lock:
        if _spark is not None:
            return _spark
        try:
            _spark = (
                SparkSession.builder
                .appName("ThreatSig-PurePySpark")
                .master("local[1]")
                .config("spark.driver.memory", "512m")
                .config("spark.sql.shuffle.partitions", "2")
                .config("spark.default.parallelism", "2")
                .config("spark.ui.enabled", "false")
                .config("spark.driver.extraJavaOptions", "-XX:+UseG1GC -XX:MaxGCPauseMillis=200")
                .config("spark.sql.execution.arrow.pyspark.enabled", "true")
                .getOrCreate()
            )
            _spark.sparkContext.setLogLevel("ERROR")
            print("[ML] Pure PySpark session started [OK]")
            return _spark
        except Exception as e:
            print(f"[ML] PySpark unavailable: {e}")
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Feature Engineering
# ─────────────────────────────────────────────────────────────────────────────
THREAT_CATEGORIES = [
    "Port Scan", "SSH Brute-Force", "Web App Attack", "DDoS Attack",
    "Phishing", "SQL Injection", "Credential Stuffing", "TOR Exit Node",
    "Botnet", "Ransomware C2"
]

HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "UA", "SY", "LY", "IQ"}
MED_RISK_COUNTRIES  = {"BR", "IN", "NG", "RO", "PK", "BD"}

def _country_risk_score(code: str) -> float:
    if code in HIGH_RISK_COUNTRIES: return 1.0
    if code in MED_RISK_COUNTRIES:  return 0.5
    return 0.1

def extract_ip_features(record: dict) -> list:
    """Convert raw IP scan data into a float list for PySpark DataFrame."""
    score           = record.get("threat_score", 0)
    total_reports   = min(record.get("total_reports", 0), 10000)
    distinct_users  = min(record.get("distinct_users", 0), 500)
    is_tor          = int(record.get("is_tor", False))
    is_vpn          = int(record.get("is_vpn", False))
    cats            = record.get("recent_categories", [])
    cat_count       = min(len(cats), 10)
    is_brute_force  = int(any("brute" in c.lower() or "ssh" in c.lower() for c in cats))
    is_ddos         = int(any("ddos" in c.lower() for c in cats))
    is_scan         = int(any("scan" in c.lower() for c in cats))
    is_inject       = int(any("inject" in c.lower() or "sqli" in c.lower() for c in cats))
    country_risk    = _country_risk_score(record.get("country", ""))

    return [
        float(score / 100), float(total_reports / 10000), float(distinct_users / 500),
        float(is_tor), float(is_vpn), float(cat_count / 10), float(is_brute_force),
        float(is_ddos), float(is_scan), float(is_inject), float(country_risk),
    ]


def extract_email_features(record: dict) -> list:
    """Convert raw email breach data into a float list."""
    score        = record.get("threat_score", 0)
    breach_count = min(record.get("breach_count", 0), 30)
    analytics    = record.get("analytics", {})
    passwords    = int(analytics.get("passwords", 0) > 0)
    cc           = int(analytics.get("credit_cards", 0) > 0)
    ssn          = int(analytics.get("ssn", 0) > 0)

    return [
        float(score / 100), float(breach_count / 30), float(passwords), float(cc),
        float(ssn), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    ]

FEATURE_NAMES = [
    "f_score", "f_vol", "f_dist", "f_tor", "f_vpn", "f_cat",
    "f_brute", "f_ddos", "f_scan", "f_sqli", "f_country"
]


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic training data via Pandas → Spark Arrow (avoids Python worker issues)
# ─────────────────────────────────────────────────────────────────────────────
def _make_training_data_pyspark(spark, n: int = 500):
    records = []
    for _ in range(n):
        r = random.random()
        if r < 0.15:
            label = "critical"
            feats = [random.uniform(0.85,1), random.uniform(0.5,1), random.uniform(0.4,1),
                     float(random.choices([0,1],weights=[3,7])[0]), float(random.choices([0,1],weights=[4,6])[0]),
                     random.uniform(0.4,1)] + [float(random.randint(0,1)) for _ in range(5)]
        elif r < 0.40:
            label = "high"
            feats = [random.uniform(0.60,0.85), random.uniform(0.2,0.6), random.uniform(0.1,0.4),
                     float(random.choices([0,1],weights=[7,3])[0]), float(random.choices([0,1],weights=[5,5])[0]),
                     random.uniform(0.2,0.5)] + [float(random.randint(0,1)) for _ in range(5)]
        elif r < 0.70:
            label = "medium"
            feats = [random.uniform(0.35,0.60), random.uniform(0.05,0.2), random.uniform(0.0,0.1),
                     0.0, float(random.choices([0,1],weights=[8,2])[0]),
                     random.uniform(0.05,0.25)] + [float(random.randint(0,1)) for _ in range(5)]
        else:
            label = "low"
            feats = [random.uniform(0,0.35), random.uniform(0,0.05), 0.0, 0.0, 0.0,
                     random.uniform(0,0.1)] + [0.0]*5

        row = {name: val for name, val in zip(FEATURE_NAMES, feats)}
        row["label_str"] = label
        records.append(row)

    # Use Pandas → Arrow path: avoids Python worker serialization issues on Windows
    pdf = pd.DataFrame(records)
    return spark.createDataFrame(pdf)


def _pandas_to_spark(spark, feat_list: list, extra_cols: dict = None):
    """Create a single-row Spark DataFrame from feature list via Pandas/Arrow."""
    row = {name: val for name, val in zip(FEATURE_NAMES, feat_list)}
    if extra_cols:
        row.update(extra_cols)
    return spark.createDataFrame(pd.DataFrame([row]))


# ─────────────────────────────────────────────────────────────────────────────
# Pure PySpark Engine
# ─────────────────────────────────────────────────────────────────────────────
class ThreatMLEngine:
    CLUSTER_NAMES = {0: "Botnet Node", 1: "Port Scanner", 2: "Spammer", 3: "Clean"}

    def __init__(self):
        self._spark = get_spark()
        self._trained = False
        self._history = []
        self._lock = threading.Lock()

        # PySpark Models
        self.assembler = None
        self.scaler_model = None
        self.label_indexer_model = None
        self.label_converter = None
        self.rf_model = None
        self.kmeans_model = None
        self.cluster_centers = []

        if self._spark:
            try:
                self._train()
            except Exception as e:
                print(f"[ML] Training failed: {e}")
                self._trained = False

    def _train(self):
        print("[ML] Training Pure PySpark models...")
        df = _make_training_data_pyspark(self._spark, 500)

        # 1. Feature Assembly
        self.assembler = VectorAssembler(inputCols=FEATURE_NAMES, outputCol="raw_features")
        df_assembled = self.assembler.transform(df)

        # 2. Scaling
        scaler = StandardScaler(inputCol="raw_features", outputCol="features", withStd=True, withMean=True)
        self.scaler_model = scaler.fit(df_assembled)
        df_scaled = self.scaler_model.transform(df_assembled)

        # 3. Label Indexing for Classification
        label_indexer = StringIndexer(inputCol="label_str", outputCol="label")
        self.label_indexer_model = label_indexer.fit(df_scaled)
        df_indexed = self.label_indexer_model.transform(df_scaled)

        self.label_converter = IndexToString(
            inputCol="prediction", outputCol="predicted_label",
            labels=self.label_indexer_model.labels
        )

        # 4. PySpark Random Forest
        rf = RandomForestClassifier(featuresCol="features", labelCol="label", numTrees=20, maxDepth=4, seed=42)
        self.rf_model = rf.fit(df_indexed)

        # 5. PySpark KMeans
        kmeans = KMeans(featuresCol="features", k=4, seed=42)
        self.kmeans_model = kmeans.fit(df_scaled)
        self.cluster_centers = self.kmeans_model.clusterCenters()

        self._trained = True
        print("[ML] Pure PySpark Models ready [OK]")

    def _add_to_history(self, score: float):
        """Maintain a rolling window for PySpark trend analysis."""
        with self._lock:
            ts = datetime.now(timezone.utc).timestamp()
            self._history.append((ts, score))
            if len(self._history) > 500:
                self._history.pop(0)

    def score_trend(self) -> dict:
        """PySpark Linear Regression over recent event scores."""
        with self._lock:
            hist = list(self._history)
        if len(hist) < 10 or not self._spark:
            return {"slope": 0, "intercept": 0, "next_predicted": None, "trend": "stable"}

        t0 = hist[0][0]
        records = [{"time_hr": float((h[0]-t0)/3600.0), "score": float(h[1])} for h in hist]
        df = self._spark.createDataFrame(pd.DataFrame(records))

        assembler = VectorAssembler(inputCols=["time_hr"], outputCol="features")
        df_vec = assembler.transform(df)

        lr = LinearRegression(featuresCol="features", labelCol="score", maxIter=10)
        try:
            lr_model = lr.fit(df_vec)
            slope = float(lr_model.coefficients[0])
            intercept = float(lr_model.intercept)

            t_next = (datetime.now(timezone.utc).timestamp() - t0) / 3600.0 + 1
            predicted = max(0.0, min(100.0, slope * t_next + intercept))
            trend = "rising" if slope > 2 else "falling" if slope < -2 else "stable"

            return {
                "slope": round(slope, 3),
                "intercept": round(intercept, 2),
                "next_predicted": round(predicted, 1),
                "trend": trend,
                "data_points": len(hist),
            }
        except Exception:
            return {"slope": 0, "intercept": 0, "next_predicted": None, "trend": "stable"}

    def analyze(self, record: dict, record_type: str = "ip") -> dict:
        """Full ML inference using PySpark DataFrames."""
        if not self._trained or not self._spark:
            return {"ml_ready": False, "reason": "PySpark models not initialized"}

        feat_fn = extract_ip_features if record_type == "ip" else extract_email_features
        feat_list = feat_fn(record)

        df = _pandas_to_spark(self._spark, feat_list)

        df_assembled = self.assembler.transform(df)
        df_scaled = self.scaler_model.transform(df_assembled)

        # PySpark Random Forest
        df_rf = self.rf_model.transform(df_scaled)
        df_final = self.label_converter.transform(df_rf)

        # PySpark KMeans
        df_km = self.kmeans_model.transform(df_scaled)

        # Collect results
        row_rf = df_final.select("predicted_label", "probability").first()
        rf_label = row_rf["predicted_label"]
        prob_vec = row_rf["probability"].toArray()
        rf_conf = float(max(prob_vec)) * 100

        rf_proba = {}
        for i, label in enumerate(self.label_indexer_model.labels):
            if i < len(prob_vec):
                rf_proba[label] = round(float(prob_vec[i]) * 100, 1)

        row_km = df_km.select("prediction", "features").first()
        cluster_id = int(row_km["prediction"])
        cluster_name = self.CLUSTER_NAMES.get(cluster_id, "Unknown")

        # Anomaly Detection (Euclidean distance to cluster center)
        features_vec = row_km["features"].toArray()
        center_vec = self.cluster_centers[cluster_id]
        distance = float(math.sqrt(sum((a - b) ** 2 for a, b in zip(features_vec, center_vec))))
        is_anomaly = bool(distance > 3.5)

        # PySpark Feature importances
        importances = self.rf_model.featureImportances.toArray()
        top_drivers = sorted(
            zip(FEATURE_NAMES, importances),
            key=lambda x: x[1], reverse=True
        )[:3]
        risk_drivers = [{"factor": k, "weight": round(float(v)*100, 1)} for k,v in top_drivers]

        # ML-adjusted threat score
        raw_score = record.get("threat_score", 0)
        level_weights = {"critical": 100, "high": 70, "medium": 45, "low": 10}
        ml_score = int(0.6 * raw_score + 0.4 * level_weights.get(rf_label, raw_score))
        ml_score = min(100, max(0, ml_score))

        self._add_to_history(float(ml_score))

        return {
            "ml_ready":          True,
            "anomaly":           is_anomaly,
            "anomaly_score":     round(distance, 4),
            "rf_prediction":     rf_label,
            "rf_confidence":     round(rf_conf, 1),
            "rf_probabilities":  rf_proba,
            "cluster_id":        cluster_id,
            "cluster_name":      cluster_name,
            "risk_drivers":      risk_drivers,
            "ml_adjusted_score": ml_score,
            "spark": {
                "available": True,
                "pipeline": "Pure PySpark MLlib Pipeline",
                "feature_dim": len(FEATURE_NAMES),
                "spark_risk_tier": rf_label,
                "enriched_score": ml_score,
            },
        }

# Global singleton
engine = ThreatMLEngine()
