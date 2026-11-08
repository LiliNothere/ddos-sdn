#!/bin/bash
# Train ML models for DDoS detection

set -e

cd "$(dirname "$0")/.."

echo "======================================"
echo "Training DDoS Detection Models"
echo "======================================"

# Check if dataset exists
if [ ! -f "data/FlowStatsfile.csv" ]; then
    echo "Dataset not found! Generating first..."
    bash scripts/generate_data.sh
fi

# Activate virtual environment if exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Train all models or specific model
if [ -n "$1" ]; then
    MODEL_TYPE="$1"
    echo "Training specific model: $MODEL_TYPE"
    python -c "
import sys
sys.path.insert(0, '.')
from ml_service.train import train_specific_model
from ml_service.config import settings
train_specific_model('$MODEL_TYPE', settings.dataset_path, settings.model_dir)
"
else
    echo "Training all models (RandomForest, KNN, DT, LR, NB, SVM)..."
    python -c "
import sys
sys.path.insert(0, '.')
from ml_service.train import train_all_models
from ml_service.config import settings
train_all_models(settings.dataset_path, settings.model_dir)
"
fi

echo ""
echo "======================================"
echo "Training complete!"
echo "======================================"
echo ""
echo "Models saved to: ./models/"
echo "To evaluate a model:"
echo "  python -m ml_service.train --model RandomForest --evaluate"
echo ""