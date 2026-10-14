"""
CLI script to execute training and evaluation of the PHISHGUARD ML module.
Run via: python ml/train.py
"""

import sys
import os

# Add parent directory to path so relative imports work when run as script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ml.model import train_and_evaluate_model, save_evaluation_metrics

def main():
    print("=" * 65)
    print(" PHISHGUARD - Machine Learning Evaluation & Benchmark Runner")
    print("=" * 65)
    print("[*] Extracting features from curated benchmark dataset...")
    
    metrics = train_and_evaluate_model()
    
    print(f"[*] Engine: {metrics['engine']}")
    print(f"[*] Total Samples: {metrics['total_samples']} (Train: {metrics['train_samples']}, Test: {metrics['test_samples']})")
    print("-" * 65)
    print(f"[*] EVALUATION METRICS (Actual Test Data):")
    print(f"    - Accuracy:  {metrics['accuracy'] * 100:.2f}%")
    print(f"    - Precision: {metrics['precision'] * 100:.2f}%")
    print(f"    - Recall:    {metrics['recall'] * 100:.2f}%")
    print(f"    - F1-Score:  {metrics['f1_score'] * 100:.2f}%")
    print("-" * 65)
    cm = metrics["confusion_matrix"]
    print("[*] CONFUSION MATRIX:")
    print(f"    [True Negative : {cm['true_negative']:>3}]  [False Positive: {cm['false_positive']:>3}]")
    print(f"    [False Negative: {cm['false_negative']:>3}]  [True Positive : {cm['true_positive']:>3}]")
    print("-" * 65)
    print("[*] TOP DISCRIMINATIVE FEATURES:")
    for i, item in enumerate(metrics.get("top_features", []), 1):
        print(f"    {i}. {item['feature']:<30} (Weight: {item['importance']:.4f})")
    
    out_file = save_evaluation_metrics(metrics)
    print("-" * 65)
    print(f"[+] Evaluation metrics saved to: {out_file}")
    print("=" * 65)

if __name__ == "__main__":
    main()
