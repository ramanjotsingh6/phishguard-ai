#!/usr/bin/env bash
# build.sh — runs during Render deployment
set -e

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Training phishing detection model..."
python3 model/train_model.py

echo "Build complete."
