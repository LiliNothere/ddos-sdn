"""
ML Model Training and Inference for DDoS Detection
"""

import os
import time
import logging
import pickle
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

from .config import settings, MODEL_PARAMS, NUMERIC_FEATURE_COLUMNS, TARGET_COLUMN

logger = logging.getLogger(__name__)

# Feature columns are now defined in config.py as NUMERIC_FEATURE_COLUMNS
# to ensure single source of truth across model, training, and data generation

# Columns that need special handling
ID_COLUMNS = ['flow_id']
# IP_COLUMNS removed - IP features dropped to prevent data leakage


class DDoSModel:
    """Wrapper for ML model with preprocessing"""

    MODEL_VERSION = "1.0.0"
    SCHEMA_VERSION = "1.0"

    def __init__(self, model_type: str = "RandomForest"):
        self.model_type = model_type
        self.model: Optional[Pipeline] = None
        self.feature_columns = NUMERIC_FEATURE_COLUMNS.copy()
        self.is_trained = False
        self.training_time = 0.0
        self.accuracy = 0.0
        self.metadata = {}

    def _get_model(self):
        """Get model instance based on type"""
        params = MODEL_PARAMS.get(self.model_type, MODEL_PARAMS["RandomForest"])

        models = {
            "RandomForest": RandomForestClassifier,
            "KNN": KNeighborsClassifier,
            "DecisionTree": DecisionTreeClassifier,
            "LogisticRegression": LogisticRegression,
            "NaiveBayes": GaussianNB,
            "SVM": SVC
        }

        model_class = models.get(self.model_type, RandomForestClassifier)
        return model_class(**params)

    def _preprocess(self, df: pd.DataFrame) -> np.ndarray:
        """Preprocess features: handle missing values, select numeric features only.

        Note: IP columns (ip_src, ip_dst) are deliberately excluded to prevent data leakage.
        Scaling is handled by the Pipeline during train/predict.
        """
        df = df.copy()

        # Ensure all numeric feature columns exist
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0

        # Select only numeric features (no IP columns)
        X = df[self.feature_columns].values.astype(np.float64)

        # Handle NaN/inf
        X = np.nan_to_num(X, nan=0.0, posinf=1e10, neginf=-1e10)

        return X

    def _preprocess_labels(self, df: pd.DataFrame) -> np.ndarray:
        """Extract and preprocess labels"""
        if TARGET_COLUMN in df.columns:
            y = df[TARGET_COLUMN].values.astype(np.int32)
        else:
            # For prediction without labels
            y = np.zeros(len(df), dtype=np.int32)
        return y

    def train(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Train the model with proper train/test split BEFORE scaling.

        Pipeline handles scaling internally - fit only on training data.
        """
        start_time = time.time()

        logger.info(f"Training {self.model_type} model on {len(df)} samples")

        # Preprocess features (no scaling here - Pipeline will handle it)
        X = self._preprocess(df)
        y = self._preprocess_labels(df)

        # Check label distribution
        unique_labels = np.unique(y)
        logger.info(f"Labels found: {unique_labels}, distribution: {np.bincount(y)}")

        if len(unique_labels) < 2:
            logger.warning("Only one class in training data, model may not generalize")

        # Split FIRST, before any scaling (Pipeline will fit scaler on train only)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=settings.test_size,
            random_state=settings.random_state,
            stratify=y if len(unique_labels) > 1 else None
        )

        # Train using Pipeline (scaler fit only on training data)
        base_model = self._get_model()
        self.model = Pipeline([
            ('scaler', StandardScaler()),
            ('classifier', base_model)
        ])

        self.model.fit(X_train, y_train)

        # Evaluate on test set
        y_pred = self.model.predict(X_test)
        self.accuracy = accuracy_score(y_test, y_pred)

        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        if cm.size == 4:
            tn, fp, fn, tp = cm.ravel()
        else:
            tn, fp, fn, tp = 0, 0, 0, 0

        self.training_time = time.time() - start_time
        self.is_trained = True

        self.metadata = {
            "model_type": self.model_type,
            "model_version": self.MODEL_VERSION,
            "schema_version": self.SCHEMA_VERSION,
            "accuracy": float(self.accuracy),
            "training_time": self.training_time,
            "n_samples": len(df),
            "n_features": X.shape[1],
            "feature_names": self.feature_columns,
            "confusion_matrix": {
                "tn": int(tn), "fp": int(fp),
                "fn": int(fn), "tp": int(tp)
            },
            "classification_report": classification_report(y_test, y_pred, output_dict=True, zero_division=0),
            "trained_at": datetime.now().isoformat(),
            "params": MODEL_PARAMS.get(self.model_type, {}),
            "dataset_hash": str(hash(df.to_json()))[:16]  # Simple dataset fingerprint
        }

        logger.info(f"Training completed in {self.training_time:.2f}s, Accuracy: {self.accuracy:.4f}")

        return self.metadata

    def predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict labels and probabilities"""
        if not self.is_trained or self.model is None:
            raise ValueError("Model not trained")

        X = self._preprocess(df)

        # Predict
        labels = self.model.predict(X)

        # Get probabilities if available
        try:
            probas = self.model.predict_proba(X)
            confidence = np.max(probas, axis=1)
        except AttributeError:
            # For SVM without probability or other models
            confidence = np.ones(len(labels))

        return labels, confidence

    def save(self, path: Path) -> None:
        """Save model to disk atomically"""
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write to temp file first, then rename for atomicity
        temp_path = path.with_suffix('.tmp')

        model_data = {
            "model_type": self.model_type,
            "model": self.model,
            "feature_columns": self.feature_columns,
            "is_trained": self.is_trained,
            "training_time": self.training_time,
            "accuracy": self.accuracy,
            "metadata": self.metadata,
            "model_version": self.MODEL_VERSION,
            "schema_version": self.SCHEMA_VERSION
        }

        joblib.dump(model_data, temp_path)
        temp_path.replace(path)  # Atomic rename
        logger.info(f"Model saved to {path}")

    @classmethod
    def load(cls, path: Path) -> 'DDoSModel':
        """Load model from disk"""
        model_data = joblib.load(path)

        instance = cls(model_data["model_type"])
        instance.model = model_data["model"]
        instance.feature_columns = model_data["feature_columns"]
        instance.is_trained = model_data["is_trained"]
        instance.training_time = model_data["training_time"]
        instance.accuracy = model_data["accuracy"]
        instance.metadata = model_data["metadata"]

        logger.info(f"Model loaded from {path}")
        return instance


class ModelManager:
    """Manage multiple models"""

    def __init__(self, model_dir: Path):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.models: Dict[str, DDoSModel] = {}
        self.current_model: Optional[DDoSModel] = None

    def get_model(self, model_type: str) -> DDoSModel:
        """Get or create model"""
        if model_type not in self.models:
            model_path = self.model_dir / f"{model_type.lower()}_model.joblib"

            if model_path.exists():
                self.models[model_type] = DDoSModel.load(model_path)
            else:
                self.models[model_type] = DDoSModel(model_type)

        return self.models[model_type]

    def set_current(self, model_type: str) -> None:
        """Set current active model"""
        self.current_model = self.get_model(model_type)

    def train_model(self, model_type: str, df: pd.DataFrame) -> Dict[str, Any]:
        """Train specific model"""
        model = self.get_model(model_type)
        metadata = model.train(df)

        # Save
        model_path = self.model_dir / f"{model_type.lower()}_model.joblib"
        model.save(model_path)

        # Set as current
        self.current_model = model

        return metadata

    def predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict using current model"""
        if self.current_model is None:
            raise ValueError("No model loaded")
        return self.current_model.predict(df)

    def list_models(self) -> List[Dict[str, Any]]:
        """List available models"""
        result = []
        for model_type, model in self.models.items():
            result.append({
                "type": model_type,
                "trained": model.is_trained,
                "accuracy": model.accuracy,
                "training_time": model.training_time,
                "metadata": model.metadata
            })
        return result

    def load_all(self) -> None:
        """Load all saved models"""
        for model_file in self.model_dir.glob("*_model.joblib"):
            # Extract model type from filename (e.g., "randomforest_model.joblib" -> "RandomForest")
            stem = model_file.stem
            if stem.endswith("_model"):
                model_type = stem[:-6]  # Remove "_model"
                # Capitalize properly: randomforest -> RandomForest, knn -> KNN
                if model_type.lower() == "knn":
                    model_type = "KNN"
                elif model_type.lower() == "dt" or model_type.lower() == "decisiontree":
                    model_type = "DecisionTree"
                elif model_type.lower() == "lr" or model_type.lower() == "logisticregression":
                    model_type = "LogisticRegression"
                elif model_type.lower() == "nb" or model_type.lower() == "naivebayes":
                    model_type = "NaiveBayes"
                elif model_type.lower() == "svm":
                    model_type = "SVM"
                else:
                    model_type = model_type.capitalize()  # Randomforest -> Randomforest, but we handle below

                # Special case for RandomForest
                if model_type.lower() == "randomforest":
                    model_type = "RandomForest"

                try:
                    self.models[model_type] = DDoSModel.load(model_file)
                    logger.info(f"Loaded {model_type} model")
                except Exception as e:
                    logger.error(f"Failed to load {model_type}: {e}")

        # Set default
        if self.models and not self.current_model:
            default = self.models.get(settings.default_model) or list(self.models.values())[0]
            self.current_model = default