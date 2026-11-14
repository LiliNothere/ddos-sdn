"""
Train ML models for DDoS detection
"""

import argparse
import logging
import sys
from pathlib import Path

import pandas as pd

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ml_service.config import settings, MODEL_PARAMS
from ml_service.model import ModelManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def train_all_models(dataset_path: str = None, model_dir: str = None):
    """Train all available models"""
    dataset_path = dataset_path or settings.dataset_path
    model_dir = model_dir or settings.model_dir

    logger.info(f"Loading dataset from {dataset_path}")
    try:
        df = pd.read_csv(dataset_path)
        logger.info(f"Dataset loaded: {len(df)} samples, {len(df.columns)} columns")
    except FileNotFoundError:
        logger.error(f"Dataset not found: {dataset_path}")
        return

    model_manager = ModelManager(Path(model_dir))

    # Train each model type
    results = {}
    for model_type in MODEL_PARAMS.keys():
        logger.info(f"\n{'='*50}")
        logger.info(f"Training {model_type}...")
        logger.info(f"{'='*50}")

        try:
            metadata = model_manager.train_model(model_type, df)
            results[model_type] = metadata
            logger.info(f"{model_type} Accuracy: {metadata['accuracy']:.4f}")
            logger.info(f"Training time: {metadata['training_time']:.2f}s")
        except Exception as e:
            logger.error(f"Failed to train {model_type}: {e}")
            results[model_type] = {"error": str(e)}

    # Print summary
    logger.info(f"\n{'='*50}")
    logger.info("TRAINING SUMMARY")
    logger.info(f"{'='*50}")

    for model_type, metadata in results.items():
        if "error" in metadata:
            logger.info(f"{model_type}: FAILED - {metadata['error']}")
        else:
            logger.info(f"{model_type}: Accuracy={metadata['accuracy']:.4f}, Time={metadata['training_time']:.2f}s")

    # Find best model
    best_model = max(
        [(k, v) for k, v in results.items() if "error" not in v],
        key=lambda x: x[1]['accuracy'],
        default=(None, None)
    )

    if best_model[0]:
        logger.info(f"\nBest model: {best_model[0]} (Accuracy: {best_model[1]['accuracy']:.4f})")
        model_manager.set_current(best_model[0])

    logger.info("Training complete!")


def train_specific_model(model_type: str, dataset_path: str = None, model_dir: str = None):
    """Train a specific model only"""
    dataset_path = dataset_path or settings.dataset_path
    model_dir = model_dir or settings.model_dir

    logger.info(f"Loading dataset from {dataset_path}")
    try:
        df = pd.read_csv(dataset_path)
        logger.info(f"Dataset loaded: {len(df)} samples, {len(df.columns)} columns")
    except FileNotFoundError:
        logger.error(f"Dataset not found: {dataset_path}")
        sys.exit(1)

    if model_type not in MODEL_PARAMS:
        logger.error(f"Unknown model type: {model_type}. Available: {list(MODEL_PARAMS.keys())}")
        sys.exit(1)

    model_manager = ModelManager(Path(model_dir))

    logger.info(f"\n{'='*50}")
    logger.info(f"Training {model_type}...")
    logger.info(f"{'='*50}")

    try:
        metadata = model_manager.train_model(model_type, df)
        logger.info(f"{model_type} Accuracy: {metadata['accuracy']:.4f}")
        logger.info(f"Training time: {metadata['training_time']:.2f}s")
    except Exception as e:
        logger.error(f"Failed to train {model_type}: {e}")
        sys.exit(1)

    logger.info("Training complete!")


def evaluate_model(model_type: str, dataset_path: str = None, model_dir: str = None):
    """Evaluate a specific model"""
    dataset_path = dataset_path or settings.dataset_path
    model_dir = model_dir or settings.model_dir

    logger.info(f"Evaluating {model_type}...")
    df = pd.read_csv(dataset_path)

    model_manager = ModelManager(Path(model_dir))
    model = model_manager.get_model(model_type)

    if not model.is_trained:
        logger.error(f"Model {model_type} not trained")
        return

    # Split data
    from sklearn.model_selection import train_test_split
    from ml_service.config import FEATURE_COLUMNS, TARGET_COLUMN

    # Use same preprocessing as model - pass raw DataFrame to predict()
    # predict() will call _preprocess() internally
    _, df_test, _, y_test = train_test_split(
        df, df[TARGET_COLUMN], test_size=settings.test_size, random_state=settings.random_state, stratify=df[TARGET_COLUMN]
    )

    # Predict using raw DataFrame (predict calls _preprocess internally)
    labels, confidences = model.predict(df_test)

    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    acc = accuracy_score(y_test, labels)
    logger.info(f"Accuracy: {acc:.4f}")
    logger.info(f"\nClassification Report:\n{classification_report(y_test, labels)}")
    logger.info(f"\nConfusion Matrix:\n{confusion_matrix(y_test, labels)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train DDoS detection models")
    parser.add_argument("--dataset", type=str, help="Path to dataset CSV")
    parser.add_argument("--model-dir", type=str, help="Model directory")
    parser.add_argument("--model", type=str, help="Specific model to train/evaluate (default: train all)")
    parser.add_argument("--evaluate", action="store_true", help="Evaluate instead of train")
    parser.add_argument("--all", action="store_true", help="Train all models (default if no --model)")

    args = parser.parse_args()

    if args.evaluate and args.model:
        evaluate_model(args.model, args.dataset, args.model_dir)
    elif args.model:
        # Train specific model only
        train_specific_model(args.model, args.dataset, args.model_dir)
    else:
        # Train all models (default)
        train_all_models(args.dataset, args.model_dir)