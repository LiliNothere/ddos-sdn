#!/bin/bash
# Generate training dataset for DDoS detection

set -e

cd "$(dirname "$0")/.."

# Activate virtual environment if exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Install dependencies if needed
pip install -q pandas numpy

echo "======================================"
echo "Generating DDoS Training Dataset"
echo "======================================"

# Default sizes (can be overridden with env vars)
BENIGN=${BENIGN:-50000}
DDOS=${DDOS:-50000}
OUTPUT=${OUTPUT:-data/FlowStatsfile.csv}

echo "Configuration:"
echo "  Benign flows:  $BENIGN"
echo "  DDoS flows:    $DDOS"
echo "  Output:        $OUTPUT"
echo ""

# Generate dataset
python scripts/generate_dataset.py \
    --benign $BENIGN \
    --ddos $DDOS \
    --output $OUTPUT \
    --seed 42

echo ""
echo "======================================"
echo "Dataset generated successfully!"
echo "======================================"
echo ""
echo "Next steps:"
echo "  1. Train models:  bash train_model.sh"
echo "  2. Or via Docker: docker-compose exec ml-service python -m ml_service.train --all"
echo ""