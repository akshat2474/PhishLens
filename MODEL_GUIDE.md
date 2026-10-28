# PhishLens Model Architecture and System Guide

This document provides a comprehensive technical breakdown of PhishLens, an explainable machine learning system engineered for phishing detection using uniform resource locator feature analysis. It details the operational mechanics, mathematical foundations, model selection rationale, comparative empirical performance, and explainable artificial intelligence implementations.

---

## 1. System Overview and Operational Philosophy

PhishLens is designed around a dual pathway architecture that reconciles two conflicting requirements in modern cybersecurity:
1. Real time inline scanning with zero network exposure.
2. High precision academic benchmarking with multi domain contextual signals.

```
                    +---------------------------------------+
                    |             Input URL                 |
                    +-------------------+-------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v                                             v
    +-------------------------+                   +-------------------------+
    |   Live Lexical Path     |                   | Full 30 Benchmark Path  |
    |   8 Pure URL Features   |                   | 30 Multi Domain Features|
    +------------+------------+                   +------------+------------+
                 |                                             |
                 v                                             v
    +-------------------------+                   +-------------------------+
    | Sub millisecond Parser  |                   | External DOM & DNS Data |
    | Offline RFC 3986 Engine |                   | 11,055 UCI Records      |
    +------------+------------+                   +------------+------------+
                 |                                             |
                 v                                             v
    +-------------------------+                   +-------------------------+
    | XGBoost Live Classifier |                   | XGBoost Flagship Model  |
    | Latency < 1 millisecond |                   | Accuracy 96.87%         |
    | Zero Network Footprint  |                   | ROC AUC 0.9944          |
    +------------+------------+                   +------------+------------+
                 |                                             |
                 +----------------------+----------------------+
                                        |
                                        v
                    +---------------------------------------+
                    |            TreeSHAP Engine            |
                    | Game Theoretic Feature Attribution    |
                    | Domain Aggregation & Recourse Hints   |
                    +---------------------------------------+
```

### The Dual Pathway Rationale

Traditional machine learning classifiers for phishing typically require downloading the full document object model, executing JavaScript, inspecting server form handlers, and querying third party reputation engines like Alexa and Google PageRank.

While multi signal feature sets yield high benchmark accuracy, deploying them in real time introduces fatal security vulnerabilities:
- **Network Traps and Zero Day Exposure**: Fetching an unverified website forces the client to resolve untrusted domain name system records and open transmission control protocol sockets, exposing defensive systems to browser exploits, credential stealer scripts, or tracking beacons.
- **Latency Penalties**: Resolving external network queries, parsing heavy client side JavaScript, and issuing external application programming interface calls takes between 300 milliseconds and 5 seconds per address. This is unviable for inline firewall proxies or browser extensions.
- **Third Party Service Retirement**: Historical reputation signals degrade over time. The Alexa Traffic Rank service was permanently retired by Amazon in May 2022. Google retired its public PageRank toolbar application programming interface, making historical benchmark features non functional in modern live production environments.

To solve this, PhishLens implements:
- **The Live Lexical Pipeline**: Extracts eight structural properties directly from the raw address string using pure string manipulation in under one millisecond without creating any network sockets.
- **The Academic Benchmark Pipeline**: Evaluates the canonical thirty feature set from the University of California Irvine machine learning repository to establish state of the art comparison, benchmark ablation, and deep explainability research.

---

## 2. Dataset Architecture and Feature Taxonomy

The benchmark dataset consists of 11,055 web page records originally collected by Mohammad, Thabtah, and McCluskey. Each record contains thirty discrete features categorized into four security domains, with binary classification targets where label 1 represents phishing and label 0 represents legitimate behavior.

### Stratified Partitioning

To prevent data snooping and ensure unbiased generalizability, the dataset is split using stratified random sampling across identical target class ratios:
- **Training Subset**: 7,738 records (70.0 percent)
- **Validation Subset**: 1,658 records (15.0 percent)
- **Test Holdout Subset**: 1,659 records (15.0 percent)

### Feature Domain Taxonomy

All features are encoded as discrete ternary values:
- `1`: Legitimate characteristic
- `0`: Suspicious characteristic
- `-1`: Phishing or malicious characteristic

#### Domain 1: Address Bar Anomalies (12 Features)
1. `having_IP_Address`: Checks if an internet protocol address is used directly instead of a domain name (for example, `http://192.168.1.1/login`).
2. `URL_Length`: Flags addresses exceeding 54 characters (suspicious) or 75 characters (malicious) designed to hide target hostnames.
3. `Shortining_Service`: Detects link obfuscation services such as tinyurl or bitly.
4. `having_At_Symbol`: Identifies the `@` delimiter which causes web browsers to ignore characters preceding the symbol.
5. `double_slash_redirecting`: Detects double slashes appearing after the protocol position (for example, `http://legit.com//phish.com`).
6. `Prefix_Suffix`: Detects hyphens inside domain names used to imitate authentic brands (for example, `secure-paypal.com`).
7. `having_Sub_Domain`: Counts subdomain depth, flagging domains with more than two subdomains.
8. `SSLfinal_State`: Evaluates transport layer security validity, certificate issuer authority, and certificate age.
9. `Domain_registeration_length`: Flags domains registered for one year or less.
10. `Favicon`: Checks whether the shortcut icon is loaded from an external domain.
11. `port`: Examines non standard transmission control protocol port usage outside of 80 and 443.
12. `HTTPS_token`: Detects the string `https` embedded inside the domain portion of an unencrypted address.

#### Domain 2: Abnormal Request and Link Properties (6 Features)
13. `Request_URL`: Measures the proportion of external images, videos, and sounds loaded from outside domains.
14. `URL_of_Anchor`: Evaluates anchor tags pointing to empty anchors, javascript calls, or outside domains.
15. `Links_in_tags`: Measures the proportion of meta, script, and link elements referencing external sources.
16. `SFH`: Server Form Handler evaluation, flagging empty form action targets or foreign post targets.
17. `Submitting_to_email`: Detects the use of `mailto:` functions to exfiltrate submitted form credentials.
18. `Abnormal_URL`: Verifies whether the domain name is absent from the host authority string.

#### Domain 3: Client Side Script and Document Object Model Features (5 Features)
19. `Redirect`: Counts document object model page redirection jumps.
20. `on_mouseover`: Flags JavaScript modifying the browser status bar on mouse hover events.
21. `RightClick`: Detects JavaScript disabling the right click context menu to prevent viewing source code.
22. `popUpWidnow`: Flags popup windows demanding credential inputs.
23. `Iframe`: Detects invisible or borderless iframe tags loading remote malicious forms.

#### Domain 4: Domain Reputation and External Intelligence (7 Features)
24. `age_of_domain`: Flags domains created less than six months prior.
25. `DNSRecord`: Validates whether the domain name system record exists in authoritative registries.
26. `web_traffic`: Measures popularity rank according to traffic logs.
27. `Page_Rank`: Evaluates link popularity metrics.
28. `Google_Index`: Checks whether the web page is indexed in major search databases.
29. `Links_pointing_to_page`: Counts external inbound hyperlinks.
30. `Statistical_report`: Cross checks known threat lists such as PhishTank and StopBadware.

---

## 3. Models Trained, Algorithmic Mechanics, and Rationale

PhishLens implements and compares four distinct model architectures, each serving a specific diagnostic and deployment role.

```
+-------------------------------------------------------------------------------------------------------------------------+
| Architecture           | Input Scope  | Test Accuracy | Precision | Recall  | F1 Score | ROC AUC | Latency (Per URL)    |
+------------------------+--------------+---------------+-----------+---------+----------+---------+----------------------+
| Logistic Regression    | 30 Features  | 93.49%        | 93.97%    | 91.16%  | 0.9254   | 0.9808  | < 0.1 ms             |
| Random Forest          | 30 Features  | 96.50%        | 97.34%    | 94.69%  | 0.9600   | 0.9961  | 1.8 ms               |
| XGBoost Flagship       | 30 Features  | 96.87%        | 98.43%    | 94.56%  | 0.9645   | 0.9944  | 0.9 ms               |
| XGBoost Live Lexical   | 8 Features   | 75.89%        | 73.19%    | 78.91%  | 0.7593   | 0.8329  | 0.2 ms (< 1ms total) |
+------------------------+--------------+---------------+-----------+---------+----------+---------+----------------------+
```

### Model 1: L2 Regularized Logistic Regression (30 Features)

#### Mathematical Foundations
Logistic regression models the posterior probability of a website being phishing using the logistic sigmoid function acting upon a linear combination of input features:

$$P(Y = 1 | X) = \sigma(w^T X + b) = \frac{1}{1 + e^{-(w^T X + b)}}$$

Optimization is performed by minimizing the binary cross entropy loss augmented with an L2 ridge penalty to prevent individual coefficients from growing excessively large on correlated inputs:

$$J(w, b) = -\frac{1}{N} \sum_{i=1}^N \left[ y_i \log \hat{y}_i + (1 - y_i) \log(1 - \hat{y}_i) \right] + \frac{\lambda}{2} \|w\|_2^2$$

#### Hyperparameters
- Regularization strength parameter `C = 1.0` (inverse regularization $\lambda = 1.0$)
- Maximum solver iterations: 1000
- Solver: L-BFGS (Limited memory Broyden Fletcher Goldfarb Shanno)

#### Why It Was Chosen
Logistic regression serves as the gold standard linear baseline. It provides convex optimization guarantees, eliminates the possibility of local minima, and delivers direct insight into whether the feature space is linearly separable.

#### Why It Performs The Way It Does (93.49% Accuracy)
The model achieves a strong baseline of 93.49% accuracy and 0.9808 ROC AUC because many phishing features are individually predictive (for example, negative anchor link ratios and invalid certificates strongly correlate with phishing). However, it falls short of tree based ensembles because it assumes strict linear additivity on the log odds scale. It cannot capture non linear conjuncts, such as when an address has both an IP address host and a recent domain creation date.

---

### Model 2: Random Forest Classifier (30 Features)

#### Mathematical Foundations
Random forest is an ensemble bagging meta estimator that constructs 200 de-correlated decision trees during training. Each tree $T_b$ is trained on a bootstrap sample drawn with replacement from the training set. At each split, only a random subset of $m \approx \sqrt{p} = \sqrt{30} \approx 5$ features is evaluated:

$$\hat{y}_{\text{RF}} = \frac{1}{B} \sum_{b=1}^B T_b(X)$$

Splits are determined by maximizing the Gini impurity reduction:

$$I_G(p) = 1 - \sum_{k \in \{0, 1\}} p_k^2$$

#### Hyperparameters
- Number of trees (`n_estimators`): 200
- Maximum tree depth (`max_depth`): 12
- Feature split subset (`max_features`): square root of total features
- Multi threading: all available central processing unit cores (`n_jobs = -1`)

#### Why It Was Chosen
Random forest provides high resistance to variance and overfitting. By averaging 200 deeply grown trees across stochastic feature subsets, it cancels out the individual noise present in crowd sourced web data.

#### Why It Performs The Way It Does (96.50% Accuracy)
Random forest jumps over 3.0 percentage points higher than logistic regression because it splits feature space into rectangular decision regions, easily isolating conjunctions of features. It achieves high recall (94.69%) and precision (97.34%) with a near perfect ROC AUC of 0.9961. Its performance is slightly lower than XGBoost because it constructs trees independently rather than focusing attention on difficult border cases.

---

### Model 3: Extreme Gradient Boosting (XGBoost) Flagship (30 Features)

#### Mathematical Foundations
XGBoost is a sequential additive ensemble where each tree $f_t(x)$ is trained to predict the pseudo residuals (gradients) of the ensemble built so far:

$$\hat{y}_i^{(t)} = \hat{y}_i^{(t-1)} + \eta f_t(x_i)$$

Unlike standard gradient boosting, XGBoost optimizes a second order Taylor expansion of the loss function, incorporating both first order gradients $g_i$ and second order Hessians $h_i$:

$$\tilde{\mathcal{L}}^{(t)} \approx \sum_{i=1}^N \left[ g_i f_t(x_i) + \frac{1}{2} h_i f_t^2(x_i) \right] + \gamma T + \frac{1}{2}\lambda \sum_{j=1}^T w_j^2$$

Where:
- $g_i = \partial_{\hat{y}^{(t-1)}} l(y_i, \hat{y}^{(t-1)})$ is the gradient.
- $h_i = \partial^2_{\hat{y}^{(t-1)}} l(y_i, \hat{y}^{(t-1)})$ is the curvature (Hessian).
- $\gamma T$ penalizes tree leaf complexity.
- $\frac{1}{2}\lambda \sum w_j^2$ penalizes extreme leaf weights.

The optimal weight $w_j^*$ for leaf $j$ containing sample set $I_j$ is given by:

$$w_j^* = -\frac{\sum_{i \in I_j} g_i}{\sum_{i \in I_j} h_i + \lambda}$$

#### Hyperparameters
- Number of boosting rounds (`n_estimators`): 180
- Maximum depth (`max_depth`): 6
- Learning rate shrinkage ($\eta$): 0.08
- Row subsampling (`subsample`): 0.85
- Column subsampling (`colsample_bytree`): 0.85
- Class weight balance (`scale_pos_weight`): automatically calibrated to negative count divided by positive count
- Objective: binary logistic loss (`binary:logistic`)

#### Why It Was Chosen
XGBoost is the state of the art algorithm for structured tabular data. Its combination of second order gradient approximation, algorithmic sparsity handling, and column subsampling makes it the premier choice for high assurance cybersecurity classifiers.

#### Why It Performs The Way It Does (96.87% Accuracy)
XGBoost achieves the highest accuracy (96.87%), highest precision (98.43%), and highest Matthews correlation coefficient (0.9370) in the entire benchmark suite. The sequential correction mechanism enables later trees to specialize in resolving ambiguous edge cases (for example, legitimate sites with expired certificates or sophisticated phishing clones hosted on reputable cloud platforms).

---

### Model 4: XGBoost Live Lexical Model (8 Features)

#### Model Scope and Architecture
The live lexical model uses the identical XGBoost gradient boosted decision tree architecture but is strictly constrained to the eight features that can be extracted directly from the raw address string in zero network environments:
1. `having_IP_Address`
2. `URL_Length`
3. `Shortining_Service`
4. `having_At_Symbol`
5. `double_slash_redirecting`
6. `Prefix_Suffix`
7. `having_Sub_Domain`
8. `HTTPS_token`

#### Empirical Performance and Ablation Analysis
- Test Accuracy: 75.89%
- Test Precision: 73.19%
- Test Recall: 78.91%
- Test F1 Score: 0.7593
- Test ROC AUC: 0.8329
- Inference Latency: under 0.2 milliseconds (total lexical pipeline under 1 millisecond)

#### Why There Is a 20.98% Accuracy Delta
The drop from 96.87% to 75.89% accuracy is the quantifiable cost of zero network exposure:
- Attackers frequently register clean domain names without hyphens or excessive subdomains, placing their malicious payloads entirely in the page body or form actions. A pure lexical classifier cannot see page content.
- Legitimate modern services frequently use subdomains and hyphens (for example, cloud infrastructure links and software as a service subdomains), creating natural overlap with phishing syntax.
- The 75.89% accuracy is remarkably informative for a zero latency, zero network model. It correctly flags almost 8 out of 10 attacks without visiting the remote server.

---

## 4. Decision Matrix: Which Model For Which Task?

```
+-----------------------------------------------------------------------------------------------------------------------+
| Operational Use Case                   | Recommended Model      | Key Selection Criteria                              |
+----------------------------------------+------------------------+-----------------------------------------------------+
| Inline Firewall Proxy / Gateway        | XGBoost Live (8 feat)  | Sub millisecond budget, zero socket exposure.       |
| Browser Extension Pre Filter           | XGBoost Live (8 feat)  | Offline instant feedback before navigation begins.  |
| Security Operations Center (SOC) Triage| XGBoost Flagship (30)  | Maximum precision (98.43%), full forensic evidence. |
| Incident Response Forensic Review      | XGBoost Flagship + SHAP| Local Shapley decomposition and attribution.        |
| Resource Constrained Microcontroller   | Logistic Regression    | Minimal memory footprint, no tree structures.       |
| Academic Methodology Baseline          | Random Forest (30 feat)| Variance baseline and de-correlated split study.    |
+----------------------------------------+------------------------+-----------------------------------------------------+
```

### Strategic Recommendations

1. **Tiered Defense Architecture**:
   Deploy the **XGBoost Live Lexical Model** as the tier one perimeter filter. It screens incoming links instantaneously with zero infrastructure cost and zero network exposure. Addresses scoring above 70% risk can be quarantined immediately.
2. **Deep Inspection Sandbox**:
   Addresses with intermediate lexical scores (between 40% and 70%) can be routed to an isolated headless sandbox that executes the full page render, extracts all thirty features, and evaluates them with the **XGBoost Flagship Model**.
3. **Analyst Triage with Explanations**:
   When an analyst inspects a flagged incident, the **TreeSHAP** engine decomposes the prediction into exact numerical feature impacts, eliminating the black box barrier.

---

## 5. Explainable Artificial Intelligence (XAI) Engine

A critical limitation of advanced machine learning in cybersecurity is the black box problem. SOC analysts cannot act on a probability score without knowing why an address was classified as malicious.

PhishLens implements a three tier explainability framework built on cooperative game theory.

```
       +----------------------------------------------------+
       |          Raw Feature Vector [x1, x2, ..., xM]      |
       +-------------------------+--------------------------+
                                 |
                                 v
       +----------------------------------------------------+
       |                TreeSHAP Calculation               |
       |  Polynomial time local feature attribution phi_i   |
       +-------------------------+--------------------------+
                                 |
        +------------------------+------------------------+
        |                                                 |
        v                                                 v
+-------------------------------+ +-------------------------------+
|  Domain Group Aggregation     | | Contrastive Recourse Engine   |
|  Sum impacts across 4 security| | Evaluate single feature flips |
|  domains for SOC overview     | | Compute risk reduction Delta P|
+-------------------------------+ +-------------------------------+
                                 |
                                 v
       +----------------------------------------------------+
       |       Plain Language Threat Translation Engine     |
       | Converts raw numerical metrics into plain text     |
       | forensic explanations for security analysts       |
       +----------------------------------------------------+
```

### TreeSHAP Mathematical Foundation

Shapley values originate in cooperative game theory as the unique method for distributing payouts among players according to their marginal contributions. In PhishLens, the model prediction is the payout, and each website feature is a player.

The Shapley value $\phi_i$ for feature $i$ is calculated across all possible feature subsets $S$:

$$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f(S \cup \{i\}) - f(S) \right]$$

#### The TreeSHAP Optimization
While classical kernel Shapley estimation requires exponential time $O(2^{|F|})$, PhishLens utilizes the TreeSHAP algorithm developed by Lundberg and Lee. TreeSHAP evaluates conditional expectations in polynomial time:

$$O(T \cdot L \cdot D^2)$$

Where:
- $T$ is the number of trees (180).
- $L$ is the maximum number of leaves per tree ($2^6 = 64$).
- $D$ is the maximum tree depth (6).

This reduces calculation latency from several seconds to under ten milliseconds.

#### The Efficiency and Additivity Axiom
TreeSHAP satisfies the additivity property, meaning the sum of all feature contributions equals the difference between the model output $f(x)$ and the baseline expected value $\mathbb{E}[f(X)]$:

$$f(x) = \phi_0 + \sum_{i=1}^M \phi_i(x)$$

Where $\phi_0 = \mathbb{E}[f(X)]$ is the base expectation across the background distribution.

### Security Domain Aggregation

To prevent cognitive overload from thirty individual feature numbers, PhishLens sums local Shapley values into the four standardized security groups:

$$\Phi_{\text{group}} = \sum_{i \in \text{group}} \phi_i(x)$$

This allows an analyst to instantly identify whether an attack is driven by address bar spoofing, document object model code manipulation, or lack of external domain reputation.

### Contrastive Counterfactual Recourse

Explainability must not only diagnose attacks; it must provide recourse. PhishLens implements counterfactual recourse calculations that ask:
*What is the smallest structural adjustment to this address that would convert it to a legitimate classification?*

For each adverse feature ($x_i \le 0$), the engine simulates setting $x_i' = 1$ (the verified legitimate state), recomputes the model score $P(X')$, and calculates the risk reduction delta:

$$\Delta P_i = P(X) - P(X|_{x_i = 1})$$

The engine then outputs plain language recommendations (for example, "Configuring an authorized transport layer security certificate issued by a recognized root authority will reduce phishing classification score by 34.2 percent").

### Plain Language Forensic Translation

Raw floating point numbers are translated into plain text threat statements through the feature catalog metadata repository:
- If `Prefix_Suffix` has $\phi_i > 0$ and $x_i = -1$: *"Domain name contains hyphenated prefixes or suffixes commonly used to imitate authentic corporate brand names."*
- If `URL_of_Anchor` has $\phi_i > 0$ and $x_i = -1$: *"More than 67 percent of hyperlinks on the page point to empty anchors or outside domains, preventing normal navigation."*

---

## 6. Software Architecture and Directory Layout

```
PhishLens/
├── app.py                      # Production Streamlit user interface
├── requirements.txt            # Pinned dependency specifications
├── LICENSE                     # MIT open source license
├── README.md                   # Repository overview and quick start
├── MODEL_GUIDE.md              # Detailed technical architecture guide
├── artifacts/                  # Serialized models and benchmark reports
│   ├── lr_full_30.joblib       # Fitted Logistic Regression model
│   ├── rf_full_30.joblib       # Fitted Random Forest model
│   ├── xgb_full_30.joblib      # Fitted Flagship XGBoost model
│   ├── xgb_live_8.joblib       # Fitted Live Lexical XGBoost model
│   ├── shap_bg_full.npy        # 30 feature background matrix for SHAP
│   ├── shap_bg_live.npy        # 8 feature background matrix for SHAP
│   └── model_metrics.json      # Complete validation and test score matrix
├── data/
│   ├── raw/                    # Raw UCI archive files (.arff and .docx)
│   └── processed/
│       ├── phishing_websites.csv # Normalized tabular dataset
│       ├── split_indices.json  # Stratified 70/15/15 index splits
│       └── feature_catalog.json# Feature rules, groups, and explanations
├── src/
│   ├── data_loader.py          # Data parsing, splitting, and catalog export
│   ├── feature_extractor.py    # Zero socket live lexical feature parser
│   ├── models.py               # Model training suite and metrics export
│   └── explainability.py       # TreeSHAP and counterfactual recourse engine
└── tests/
    └── test_extractor.py       # Pytest unit tests for live lexical extraction
```

---

## 7. How to Reproduce and Verify

### Environment Setup
```bash
# Clone the repository
git clone https://github.com/akshat2474/PhishLens.git
cd PhishLens

# Create and activate virtual environment
uv venv .venv
source .venv/bin/activate

# Install pinned dependencies
uv pip install -r requirements.txt
```

### Run Automated Unit Tests
```bash
PYTHONPATH=. pytest tests/
```

### Retrain Models and Regenerate Metrics
```bash
python -m src.data_loader
python -m src.models
```

### Launch the Interactive Interface
```bash
streamlit run app.py
```
The interface will be accessible at `http://localhost:8502`.
