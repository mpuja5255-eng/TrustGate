# 🛡️ TRUSTGATE (SENTINEL-X)

> **Autonomous Hybrid Financial & API Security Gateway**  
> *Deterministic Authorization Contracts Fused with Unsupervised Isolation Forest Behavioral Detection*

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.5+-F7931E.svg?logo=scikitlearn)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-44%20passed-brightgreen.svg)]()

---

## 📖 Table of Contents
1. [Project Introduction](#-project-introduction)
2. [Problem Statement](#-problem-statement)
3. [Proposed Solution](#-proposed-solution)
4. [Key Features](#-key-features)
5. [Technology Stack](#-technology-stack)
6. [System Architecture](#-system-architecture)
7. [Machine Learning Methodology & Isolation Forest](#-machine-learning-methodology--isolation-forest)
8. [Injection & Malicious Payload Defense (SQLi / XSS)](#-injection--malicious-payload-defense-sqli--xss)
9. [Simulation Lab & Attack Replay](#-simulation-lab--attack-replay)
10. [Model Evaluation & Benchmarking](#-model-evaluation--benchmarking)
11. [Installation & Setup](#-installation--setup)
12. [Running the Application](#-running-the-application)
13. [Screenshots & UI Showcase](#-screenshots--ui-showcase)
14. [Future Enhancements](#-future-enhancements)

---

## 🌟 Project Introduction

**TRUSTGATE** (SENTINEL-X) is an enterprise-grade defensive API security gateway designed to protect financial systems and critical enterprise APIs against credential abuse, lateral reconnaissance sweeps, parameter tampering, and unauthorized master data modifications.

Built with a **hybrid security model**, TRUSTGATE bridges the gap between rigid rule engines and opaque machine learning black-boxes. It enforces strict **deterministic policy contracts** as an authoritative gate while concurrently running an **unsupervised Isolation Forest behavioral anomaly detection engine** to catch multi-step stealth campaigns that operate within legitimate single-call permissions.

---

## 🚨 Problem Statement

Modern enterprise breaches rarely resemble loud, brute-force attacks. Instead, modern adversaries compromise legitimate credentials (such as API keys assigned to third-party ERP or CRM integrators) and execute low-and-slow operations:
1. **Stealth Reconnaissance:** Attackers traverse vendor catalogs, query invoice balances, and inspect payment schedules through permitted `GET` endpoints. Traditional firewalls and rate limiters see each isolated request as valid and permitted.
2. **Master Data Fraud:** Attackers submit unapproved `PATCH` requests altering critical financial records (such as vendor bank accounts and routing codes, as seen in real-world incidents like the September 3 V-0412 breach).
3. **The "Black-Box ML" Failure:** Pure machine learning systems often suffer from high false discovery rates and cannot be audited by financial regulators. Crucially, **an ML model must never have the authority to grant permission** when mandatory human regulatory approvals are missing.

---

## 💡 Proposed Solution

TRUSTGATE resolves this fundamental security challenge with an uncompromised architectural principle:

> ### ⚖️ Core Invariant: "ML Never Grants Permission"
> * **Mandatory Deterministic Gates:** If an endpoint requires multi-party approval (e.g. 4-eyes Finance sign-off for bank changes), missing credentials or unverified approvals trigger an immediate **`HOLD`** or **`BLOCK`**, regardless of how benign the ML score appears.
> * **Behavioral Elevation:** If an API transaction technically complies with individual contract rules but exhibits behavioral anomalies (off-hours velocity, burst patterns, or reconnaissance sequencing), the ML engine escalates the transaction from `ALLOW` to **`HOLD`** for SOC investigation.
> * **Full Explainability:** Every decision is accompanied by an immutable **4-tier auditable explanation** detailing observed facts, deterministic rule findings, behavioral deviations, and recommended triage actions.

---

## ⚡ Key Features

* **🛡️ Dual-Engine Decision Coordinator:** Prioritizes regulatory authorization contracts before combining behavioral risk signals into definitive enforcement actions (`ALLOW`, `HOLD`, `BLOCK`).
* **🌲 Unsupervised Isolation Forest Engine:** 150 decision trees trained strictly on legitimate business operations to detect velocity bursts, off-hours execution, and multi-endpoint traversal patterns.
* **💉 Injection & Payload Boundary Validation:** Strict schema inspection rejecting SQL injection (`' OR 1=1`, `UNION SELECT`), Cross-Site Scripting (`<script>`, `onerror=`), and malformed JSON before execution.
* **🔍 4-Tier Explainability Framework:** Real-time generation of human-readable, auditable investigation notes for financial compliance and SOC triage.
* **🧪 Simulation Lab (12 Scenarios):** Reproducible attack generation simulating incident replays, reconnaissance sweeps, unregistered IP bursts, replay attacks, and degraded fallbacks.
* **📊 Scientific Benchmarking & Transparency:** Genuine, non-hardcoded model evaluation across balanced test streams (60% legitimate, 40% attack) with full confusion matrices ($TP, TN, FP, FN$), accuracy, precision, recall, and false positive rates.
* **🎨 Minimal Sage-Green & White Dashboard:** Executive-grade, high-contrast, accessible UI styled with Inter typography, clean sidebar navigation, and live Chart.js visualizations.

---

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend Framework** | **Python 3.10+ / FastAPI** | High-throughput asynchronous REST API & gateway enforcement |
| **Data Validation** | **Pydantic v2** | Strict schema validation, type enforcement & payload parsing |
| **Deterministic Engine** | **Python Policy Contracts** | Capability boundaries, CIDR verification & 4-eyes approval verification |
| **Machine Learning** | **Scikit-Learn (Isolation Forest)** | Unsupervised behavioral anomaly detection |
| **Data & Features** | **NumPy & Pandas** | Rolling 5m/15m statistical feature extraction & sliding windows |
| **Storage & Persistence**| **SQLite / SQLAlchemy ORM** | ACID-compliant transaction logs, audit trails & analyst reviews |
| **SOC Dashboard** | **HTML5, TailwindCSS, Chart.js** | Single-page responsive console with white & sage-green aesthetics |
| **Alternative UI** | **Streamlit** | Rapid data exploration and interactive analyst triage console |
| **Testing** | **pytest** | 44 automated unit and integration tests |

---

## 🏛️ System Architecture

```
                          ┌────────────────────────────────────────┐
                          │  INCOMING API / SIMULATED TRANSACTION  │
                          └───────────────────┬────────────────────┘
                                              │
                                              ▼
                          ┌────────────────────────────────────────┐
                          │      INGESTION & VALIDATION LAYER      │
                          │ • Schema Validation (Pydantic)         │
                          │ • SQLi / XSS Sanity Inspection         │
                          │ • UTC Normalization & CIDR Scope Check │
                          └───────────────────┬────────────────────┘
                                              │
                         ┌────────────────────┴────────────────────┐
                         ▼                                         ▼
           ┌───────────────────────────┐             ┌───────────────────────────┐
           │   DETERMINISTIC POLICY    │             │   ISOLATION FOREST (ML)   │
           │ • Capability Contracts    │             │ • 150 Isolation Trees     │
           │ • 4-Eyes Approval Check   │             │ • Rolling 5m Burst Velocity│
           │ • Restricted Blacklist    │             │ • Sequence Motif Matching │
           └─────────────┬─────────────┘             └─────────────┬─────────────┘
                         │ Policy Verdict                          │ Anomaly Score
                         │ (ALLOW / HOLD / BLOCK)                  │ (0.0 to 1.0 Risk)
                         └────────────────────┬────────────────────┘
                                              ▼
                         ┌─────────────────────────────────────────┐
                         │          DECISION COORDINATOR           │
                         │ Priority Matrix: Policy > Anomaly Band  │
                         └────────────────────┬────────────────────┘
                                              │
                 ┌────────────────────────────┼────────────────────────────┐
                 ▼                            ▼                            ▼
            [ ALLOW ]                     [ HOLD ]                     [ BLOCK ]
        Legitimate contract          Behavioral Anomaly /         Contract Breach /
        & routine parameters         Missing Finance Approval     Prohibited Endpoint
                 │                            │                            │
                 └────────────────────────────┼────────────────────────────┘
                                              ▼
                         ┌─────────────────────────────────────────┐
                         │       4-TIER EXPLAINABILITY LAYER       │
                         │ 1. Facts  2. Policy  3. ML  4. Action   │
                         └────────────────────┬────────────────────┘
                                              │
                                              ▼
                         ┌─────────────────────────────────────────┐
                         │      SOC ANALYST CONSOLE & AUDIT DB     │
                         │ Live Monitoring, Triage & Adjudication  │
                         └─────────────────────────────────────────┘
```

---

## 🌲 Machine Learning Methodology & Isolation Forest

### Why Isolation Forest?
Traditional supervised classifiers require massive datasets of labeled attacks. However, in enterprise financial systems:
1. Malicious fraud attempts are rare ($<0.01\%$).
2. Attackers continuously alter their techniques, rendering signature matching obsolete.

Isolation Forest is an **unsupervised anomaly detection algorithm** based on the principle that anomalous observations are few and different:
* Recursive random partitioning isolates anomalies close to the root of trees (shorter average path lengths $h(x)$).
* Normal transactions require deep partitioning to isolate.

$$\text{Anomaly Score: } s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

Where $E(h(x))$ is the average path length across 150 isolation trees and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree.

### Feature Pipeline
TRUSTGATE computes a continuous feature vector across sliding historical windows:
* `method_code`, `endpoint_group_code`, `action_type_code`: Operation semantics.
* `hour_of_day`, `is_weekend`: Temporal deviations (flagging 01:40 AM bursts outside standard business hours).
* `requests_5m`, `unique_endpoints_15m`: Rolling velocity and enumeration count.
* `sequence_code`: Sequential pattern recognition (e.g. `vendor_read` $\rightarrow$ `bank_read` $\rightarrow$ `bank_patch`).
* `sensitive_action`, `has_approval_ref`: Financial criticality flag.

---

## 💉 Injection & Malicious Payload Defense (SQLi / XSS)

Before passing into the policy engine or ML feature extractor, all incoming payloads pass through ingestion sanity checks:
* **SQL Injection (SQLi) Defense:** Detects SQL metacharacters, union-based queries, tautologies (`1=1`, `' OR 'a'='a`), and database administrative keywords in query parameters and payloads.
* **Cross-Site Scripting (XSS) Defense:** Strips and rejects script tags, javascript URI schemes, HTML event handlers (`onload=`, `onerror=`), and high-entropy encoding patterns.
* **Malformed Schemas:** Payloads violating strict Pydantic models (such as invalid HTTP verbs, missing timestamps, or non-conforming IDs) are classified as `INVALID` and rejected at the ingestion boundary with error tracking.

---

## 🧪 Simulation Lab & Attack Replay

TRUSTGATE features a built-in simulation suite supporting 12 real-world enterprise scenarios:

| ID | Scenario Name | Description | Ground Truth | Expected Action |
|---|---|---|---|---|
| **SCN-01** | Routine Contact Update | Daytime authorized vendor contact edit from registered CIDR | `LEGITIMATE` | **ALLOW** |
| **SCN-02** | Invoice Lookup | Routine read of vendor invoices during business hours | `LEGITIMATE` | **ALLOW** |
| **SCN-03** | Approved Bank Update | Vendor bank account modification with verified Finance approval | `LEGITIMATE` | **ALLOW** |
| **SCN-04** | Unapproved Bank Update | Replay of 3 September incident (**E18/E19**) without approval | `ATTACK` | **HOLD** |
| **SCN-05** | Prohibited Endpoint Access | Integration attempts to access `/v2/admin/export` | `ATTACK` | **BLOCK** |
| **SCN-06** | Unregistered Host Burst | Legitimate credential generating high volume from unknown IP | `SUSPICIOUS` | **HOLD** |
| **SCN-07** | Rapid Reconnaissance | Sequential traversal (`vendor` $\rightarrow$ `bank` $\rightarrow$ `payments`) | `SUSPICIOUS` | **HOLD** |
| **SCN-08** | Replay Nonce Attack | Duplicate request ID submitted with identical timestamp | `ATTACK` | **BLOCK** |
| **SCN-09** | Malformed Event Payload | Broken JSON / invalid schema fields | `INVALID` | **BLOCK** |
| **SCN-10** | Month-End Batch Activity | High-volume legitimate invoice queries at 23:00 UTC | `LEGITIMATE` | **ALLOW** |
| **SCN-11** | Approval Service Timeout | Approval backend failure triggering fail-secure defense | `SUSPICIOUS` | **HOLD** |
| **SCN-12** | ML Service Degraded | ML engine offline; system safely defaults to Policy-Only | `LEGITIMATE` | **ALLOW** |

---

## ⚖️ Model Evaluation & Benchmarking

TRUSTGATE evaluates both **Model A (Deterministic Policy-Only)** and **Model B (Hybrid Architecture)** against a standardized, balanced 100-event benchmark stream (60 legitimate operations, 40 attack/anomaly events):

```
Model A (Deterministic Policy-Only):
                 Predicted Flagged    Predicted Allowed
Actual Attack:         32 (TP)             8 (FN)
Actual Normal:          0 (FP)            60 (TN)

Model B (Hybrid Policy + Isolation Forest):
                 Predicted Flagged    Predicted Allowed
Actual Attack:         38 (TP)             2 (FN)
Actual Normal:          9 (FP)            51 (TN)
```

| Evaluation Metric | Model A: Policy-Only (Baseline) | Model B: Hybrid Architecture | Operational Value |
|---|---|---|---|
| **Accuracy** | 92.0% | **89.0%** | Balanced trade-off for aggressive attack coverage |
| **Precision** | 100.0% | **80.9%** | Realistic non-hardcoded precision accounting for review queue |
| **Recall (Detection Rate)** | 80.0% | **95.0%** | **+15.0% Attack Recall Gain** (intercepts stealth reconnaissance) |
| **F1-Score** | 0.8889 | **0.8736** | Harmonic mean of precision and recall |
| **False Positive Rate (FPR)** | 0.0% | **15.0%** | Sustainable, manageable analyst review queue volume |
| **False Negative Rate (FNR)** | 20.0% | **5.0%** | **75% Reduction in Missed Breaches** |
| **Decision Latency** | 0.20 ms | **5.57 ms** | Sub-6ms latency including rolling feature extraction |

> **Evaluation Warning & Scientific Notice:**  
> *"Performance metrics represent results on the specified evaluation dataset and do not guarantee equivalent performance in real-world deployment."*

---

## 💻 Installation & Setup

### Prerequisites
* **Python 3.10+** (Tested on Python 3.10, 3.11, 3.12, 3.14)
* **Git**

### 1. Clone the Repository
```bash
git clone <YOUR_REPOSITORY_URL>
cd TRUSTGATE
```

### 2. Create and Activate Virtual Environment
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment (Optional)
```bash
cp .env.example .env
```

---

## 🚀 Running the Application

### 1. Seed Case Evidence & Database
Initializes the SQLite schema and loads case records (`E04`, `E10`, `E15`, `E18`, `E19`):
```bash
python scripts/seed_case_data.py
```

### 2. Train / Calibrate Behavioral Model
Trains the Isolation Forest on 1,500 baseline enterprise operations and exports calibrated weights:
```bash
python -m app.ml.train
```

### 3. Start the TRUSTGATE Gateway Server
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Access Interactive Consoles
* **🎨 SOC Analyst Console (Web):** [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)
* **📚 Interactive API Documentation (Swagger UI):** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **🌐 Gateway Root:** [http://127.0.0.1:8000](http://127.0.0.1:8000)

### 5. Run Streamlit Console (Optional Alternative UI)
```bash
streamlit run dashboard/streamlit_app.py
```

### 6. Run Test Suite
Executes the full suite of 44 automated tests:
```bash
python -m pytest tests/ -v
```

---

## 🎨 Screenshots & UI Showcase

```
+-----------------------------------------------------------------------------------------+
| TRUSTGATE | SENTINEL-X                       [Gateway: ACTIVE] [ML: ONLINE] [SHADOW]   |
+-------------------+---------------------------------------------------------------------+
| 📊 Overview       |  EVENTS PROCESSED   HELD FOR REVIEW   BLOCKED OPERATIONS   ANOMALIES    |
| 🔍 Event Explorer |       [ 142 ]           [ 18 ]              [ 12 ]          [ 24 ]      |
| 🚨 Investigation  |---------------------------------------------------------------------|
| 🧪 Simulation Lab |  DECISION BREAKDOWN                     BEHAVIORAL RISK SPECTRUM    |
| ⚖️ Model & Eval   |  [ ALLOW: 78% | HOLD: 13% | BLOCK: 9% ]   [ 0.0 - - - - - - - 1.0 ]   |
+-------------------+---------------------------------------------------------------------+
```

* **Section 1: Security Overview:** Live transaction KPI cards, doughnut breakdown, and risk spectrum histogram.
* **Section 2: Event Explorer:** Real-time search, method filtering, and execution detail audit tables.
* **Section 3: Alert Investigation:** Triage queue with 4-tier structured explanations and SOC analyst adjudication forms.
* **Section 4: Simulation Lab:** Interactive batch generation with 100% telemetry display fidelity.
* **Section 5: Model & Comparison:** Real-time benchmark execution comparing Policy-Only vs. Hybrid architectures.

---

## 🔮 Future Enhancements

1. **eBPF Kernel-Level Telemetry:** Incorporate kernel-level socket inspection to bind API keys directly to local host process identifiers.
2. **Distributed Redis Rate-Limiting:** Extend single-node sliding history buffers to distributed memory grids for enterprise clustering.
3. **Graph Neural Networks (GNN):** Complement Isolation Forest with graph-based identity relation analysis to detect coordinated multi-account credential rings.
4. **Automated Rollback Webhooks:** Trigger automated compensating accounting entries upon confirmed vendor bank fraud adjudication.

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
