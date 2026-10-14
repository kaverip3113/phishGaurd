"""Print Random Forest evaluation metrics and confusion matrices."""
import json
from ml_model import evaluate_models

if __name__ == "__main__":
    print(json.dumps(evaluate_models(), indent=2))
