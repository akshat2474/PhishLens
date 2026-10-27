# PhishLens

Explainable phishing detection using URL feature analysis and machine learning.

PhishLens classifies website URLs as legitimate or phishing and explains the factors influencing each prediction. The system implements a dual path architecture: an offline lexical model for real time URL scanning without network risk, and a full thirty feature model for deep evaluation on the UCI Phishing Websites benchmark. Predictions are explained using game theoretic Shapley values (TreeSHAP) and counterfactual recourse.

## Model Benchmarks

Evaluated on the held out test partition (1,659 records, 15% stratified split):

| Model | Features | Accuracy | Precision | Recall | F1 Score | ROC AUC | MCC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| XGBoost | 30 | 96.87% | 96.34% | 96.60% | 0.9645 | 0.9944 | 0.9366 |
| Random Forest | 30 | 96.50% | 96.06% | 96.05% | 0.9600 | 0.9936 | 0.9292 |
| Logistic Regression | 30 | 93.49% | 92.54% | 92.93% | 0.9254 | 0.9818 | 0.8681 |
| XGBoost Live Subset | 8 | 75.89% | 72.16% | 76.05% | 0.7593 | 0.8329 | 0.5147 |

## Quick Start

```bash
git clone https://github.com/akshat2474/PhishLens.git
cd PhishLens

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

streamlit run app.py
```

## Running Tests

```bash
PYTHONPATH=. pytest tests/
```

## License

MIT
