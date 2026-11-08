# 🛡️ CyberTrace AI
### From Security Signals to Evidence-Driven Decisions

**An AI-assisted SOC investigation and cyber impact analysis platform.**

`Signal → Evidence → Assessment → Impact`

CyberTrace AI is designed to help security analysts investigate suspicious activity, connect events to known attack techniques, evaluate detection performance, and understand the potential business impact of a hypothetical security incident.

Rather than treating AI as the only source of security decisions, CyberTrace AI combines deterministic detection rules, structured evidence, MITRE ATT&CK mapping, threat intelligence enrichment, and AI-assisted reasoning.

The goal is simple: **make security investigations more explainable, measurable, and actionable.**

---

## ⚡ The Problem

Security teams deal with large volumes of alerts, fragmented evidence, and incidents that can be difficult to interpret.

A suspicious login or command execution may appear harmless in isolation. When connected with other events, however, it may indicate a larger attack.

CyberTrace AI explores how a structured investigation workflow can help answer:

- What suspicious activity occurred?
- Which detection rule identified it?
- What evidence supports the finding?
- Which MITRE ATT&CK technique is associated with it?
- What could the hypothetical business impact be?
- How effectively does the detection system identify simulated attacks without flagging benign activity?

---

## 🧠 What Makes CyberTrace AI Different?

CyberTrace AI is built around an evidence-first investigation philosophy.

| Design Decision | Why It Matters |
|---|---|
| Deterministic detection rules | Produces repeatable findings rather than relying entirely on AI |
| Structured evidence | Makes investigation results easier to inspect and explain |
| MITRE ATT&CK mapping | Connects detections to recognized adversary techniques |
| AI-assisted analysis | Helps interpret findings in an analyst-friendly format |
| Detection evaluation | Measures performance against a defined synthetic test suite |
| Cyber Impact Simulator | Connects technical incident scenarios with potential business consequences |
| No-API mode | Allows core deterministic workflows to operate without an LLM API key |

### The signature feature: Cyber Impact Simulator

CyberTrace AI includes a custom Cyber Impact Simulator that estimates the potential business impact of a hypothetical security incident.

The simulator considers factors such as:

- Incident scenario
- Technical severity
- Asset business criticality
- Exposure
- Data sensitivity

It provides a transparent, rule-based planning estimate.

**This is not a real breach prediction, financial forecast, or substitute for a professional security assessment.**

---

## 🔍 Core Capabilities

### 01 — Incident Investigation

Investigate suspicious activity through a structured workflow.

- Event normalization
- Evidence extraction
- Detection rule evaluation
- Suspicious activity identification
- Investigation findings

### 02 — Detection Engineering

CyberTrace AI includes deterministic detection rules for selected security behaviors.

| Rule ID | Detection Focus | MITRE ATT&CK |
|---|---|---|
| DET-001 | Repeated authentication failures | T1110 — Brute Force |
| DET-002 | Successful authentication following brute-force activity | T1110 — Brute Force |
| DET-003 | Suspicious PowerShell execution | T1059.001 — PowerShell |
| DET-004 | LSASS credential access | T1003.001 — LSASS Memory |
| DET-005 | Lateral movement activity | T1021 — Remote Services |
| DET-006 | Scheduled task persistence | T1053.005 — Scheduled Task |

These rules provide a consistent detection foundation for investigation and evaluation.

### 03 — MITRE ATT&CK Mapping

Detected behaviors are associated with relevant MITRE ATT&CK techniques.

This provides context about the potential adversary behavior and helps analysts understand what a finding represents.

### 04 — Threat Intelligence Enrichment

The application uses local/static threat intelligence enrichment to add context to selected indicators.

This helps connect observed evidence with available threat information.

### 05 — AI Security Analyst

CyberTrace AI integrates Gemini-based analysis through a provider abstraction.

The AI analyst is designed to assist with interpreting structured findings and generating investigation-oriented explanations.

The application also supports a deterministic no-API mode for core workflows.

AI-generated analysis is treated as assistance, not authoritative security evidence.

### 06 — Detection Evaluation

A dedicated evaluation workflow measures detection performance against simulated attack and benign activity cases.

Metrics include:

- Precision
- Recall
- F1 Score
- False Positive Rate
- Attack Detection Coverage
- Rule-Level Coverage
- Case-Level Results
- Confusion Matrix

### 07 — Cyber Impact Simulator

A separate simulation workflow estimates the potential business impact of a hypothetical incident using transparent rules.

This feature bridges the gap between technical security analysis and business-level risk understanding.

---

## 🏗️ System Architecture

```text
                 ┌─────────────────────────────┐
                 │       Streamlit UI         │
                 └──────────────┬──────────────┘
                                │
              ┌─────────────────┼──────────────────┐
              │                 │                  │
              ▼                 ▼                  ▼
     Incident Investigation  Detection          Cyber Impact
                             Evaluation          Simulator
              │                 │                  │
              ▼                 ▼                  ▼
     Event Normalization   Synthetic Cases    Impact Factors
              │                 │                  │
              ▼                 ▼                  ▼
     Evidence Extraction  Detection Rules    Rule-Based Estimate
              │                 │
              ▼                 ▼
     Threat Intelligence   Metrics & Results
              │
              ▼
     MITRE ATT&CK Mapping
              │
              ▼
     AI-Assisted Investigation
              │
              ▼
       Analyst-Oriented Output
```

### Investigation Philosophy

```text
Security Event
      ↓
Normalize the Event
      ↓
Extract Evidence
      ↓
Evaluate Detection Rules
      ↓
Map Relevant ATT&CK Techniques
      ↓
Enrich Available Threat Context
      ↓
Generate AI-Assisted Interpretation
      ↓
Analyst Reviews the Findings
```

The AI component is not intended to replace the deterministic detection layer.

---

## 📊 Detection Evaluation Results

<details>
<summary><strong>View evaluation results</strong></summary>

### Synthetic Test Suite

The current evaluation suite contains:

- 5 simulated attack cases
- 5 benign activity cases

### Metrics

| Metric | Result |
|---|---:|
| Precision | 100.00% |
| Recall | 100.00% |
| F1 Score | 100.00% |
| False Positive Rate | 0.00% |
| Attack Detection Coverage | 100.00% |

### Confusion Matrix

| | Predicted Attack | Predicted Benign |
|---|---:|---:|
| Actual Attack | TP = 5 | FN = 0 |
| Actual Benign | FP = 0 | TN = 5 |

### Interpretation

Within this defined synthetic evaluation set, all five attack cases were detected and all five benign cases were correctly classified.

These results demonstrate the behavior of the current test suite.

**Important:** These metrics do not establish real-world SOC detection accuracy. The evaluation set is small, synthetic, and limited to the scenarios represented in the tests.

</details>

---

## 🛠️ Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Frontend / Dashboard | Streamlit |
| AI Analysis | Gemini API |
| Detection Engineering | Python-based deterministic rules |
| Threat Framework | MITRE ATT&CK |
| Data Processing | JSON, structured event data |
| Evaluation | Precision, Recall, F1, FPR, Confusion Matrix |
| Version Control | Git & GitHub |

---

## 🔐 Security Design Principles

CyberTrace AI follows several practical design principles:

- **Evidence before interpretation:** Findings are grounded in available event data.
- **Deterministic core:** Detection rules provide repeatable outputs.
- **AI as an assistant:** AI-generated reasoning is not treated as guaranteed truth.
- **Human oversight:** Analysts remain responsible for reviewing findings.
- **No automatic containment:** The application does not autonomously isolate systems or disable accounts.
- **Secret management:** API credentials should be stored in environment variables and never committed to GitHub.
- **Defensive purpose:** The project focuses on simulated security investigations and defensive analysis.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or a compatible version supported by the project dependencies
- Git
- Gemini API key (optional, for Gemini-based analysis)

### 1. Clone the repository

```bash
git clone https://github.com/priyadarshini116/CyberTrace-AI.git
```

### 2. Navigate to the project

```bash
cd CyberTrace-AI/AI-SOC-Copilot-main
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure Gemini (Optional)

Set your API key through an environment variable.

PowerShell:

```powershell
$env:GEMINI_API_KEY="YOUR_API_KEY"
$env:LLM_PROVIDER="gemini"
```

Replace `YOUR_API_KEY` with your own key.

Do not hardcode your API key in the source code or commit it to GitHub.

### 6. Run CyberTrace AI

```bash
streamlit run CyberTrace_AI_app.py
```

The application should open in your browser.

---

## 📁 Project Structure

```text
CyberTrace-AI/
│
├── AI-SOC-Copilot-main/
│   │
│   ├── CyberTrace_AI_app.py
│   ├── requirements.txt
│   ├── README.md
│   │
│   ├── detection/
│   ├── evaluation/
│   ├── threat_intelligence/
│   ├── tests/
│   │
│   └── ...
│
└── .gitignore
```

The exact folder organization depends on the files included in the repository.

---

## ⚠️ Limitations

CyberTrace AI is a portfolio and learning project.

Current limitations include:

- Evaluation is based on a limited synthetic test suite.
- It does not connect to a production SIEM or EDR platform.
- It does not ingest live enterprise security telemetry.
- Threat intelligence enrichment is based on local/static data.
- The Cyber Impact Simulator produces hypothetical planning estimates.
- AI-generated interpretations may contain errors.
- The system does not perform autonomous incident containment.

These limitations are intentional to keep the project's scope transparent and defensible.

---

## 🔮 Future Enhancements

Potential extensions include:

- Larger and more diverse evaluation datasets
- Additional detection rules
- More detailed case-level investigation reports
- Expanded MITRE ATT&CK coverage
- Real-time log ingestion through controlled integrations
- Improved threat intelligence enrichment
- Analyst feedback and investigation history
- Enhanced explainability for impact estimates

---

## 🎓 What I Learned

Developing CyberTrace AI helped me explore the intersection of AI/ML and cybersecurity.

Key learning areas:

- Designing deterministic security detection logic
- Structuring evidence-based investigations
- Understanding MITRE ATT&CK technique mapping
- Evaluating detection systems using classification metrics
- Integrating LLM-based analysis into a Python application
- Building interactive applications using Streamlit
- Designing transparent, rule-based impact simulations
- Understanding the importance of evaluation limitations and human oversight

---

## 👩‍💻 Author

**PRIYADARSHINI M N**

B.E. Artificial Intelligence & Machine Learning

BMS Institute of Technology and Management  
Bengaluru, Karnataka, India

🔗 [LinkedIn](https://linkedin.com/in/priyadarshini-m-n-836895335/)  
💻 [GitHub](https://github.com/priyadarshini116)

---

## 🤝 Acknowledgment

CyberTrace AI builds upon the foundational work of [AI-SOC-Copilot by AdityaKGoswami](https://github.com/AdityaKGoswami/AI-SOC-Copilot).

The foundation project provided a starting point for exploring AI-assisted SOC investigation. CyberTrace AI includes additional customization and portfolio-focused enhancements, including its Cyber Impact Simulator and project-specific presentation.

The original repository and its applicable license should be consulted for attribution and usage requirements.

---

## ⚖️ Disclaimer

CyberTrace AI is intended for educational, research, and defensive cybersecurity purposes.

All attack scenarios used for evaluation are simulated. The application is not a production security monitoring solution and should not be used as the sole basis for security decisions.

**CyberTrace AI — Turning Security Signals into Explainable Decisions.**
