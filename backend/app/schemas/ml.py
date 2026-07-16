from pydantic import BaseModel


class ModelMetrics(BaseModel):
    model: str
    precision: float
    recall: float
    f1_score: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int


class TrainResult(BaseModel):
    isolation_forest: ModelMetrics
    random_forest: ModelMetrics
    train_samples: int
    test_samples: int
    contamination_estimate: float


class MLScoreResult(BaseModel):
    ips_scanned: int
    alerts_created: int
