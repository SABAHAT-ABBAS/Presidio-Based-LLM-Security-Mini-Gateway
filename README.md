# 🛡️ LLM Security Gateway Pipeline

A standalone, modular security middleware designed to intercept and sanitize user prompts before they are processed by Large Language Models (LLMs). This gateway mitigates risks associated with adversarial prompt injections and PII (Personally Identifiable Information) leakage.

![Gateway Screenshot](gateway%20image.png)
## ⚙️ Technical Infrastructure

The system implements a dual-stage sequential processing pipeline to ensure both security and data privacy:

### 1. Heuristic Injection Detection Engine
* **Mechanism:** Regex-based heuristic pattern matching.
* **Scoring Logic:** Weighted analysis of adversarial keywords (e.g., `bypass`, `ignore`, `root access`, `system prompt`).
* **Decision Policy:** Implements a binary threshold trigger. If the cumulative risk score exceeds **0.35**, the input is flagged as a high-risk injection and blocked immediately.

### 2. NER-Based Privacy Scrubbing Engine
* **Core Engine:** Microsoft Presidio (leveraging spaCy `en_core_web_lg`).
* **Named Entity Recognition (NER):** * **Custom Logic-Based Validators:** Specialized recognizers for structured numerical data (e.g., specific 11-digit identification formats).
    * **Predefined Entity Detection:** Identification of standard PII such as Phone Numbers, API Keys, and Locations.
    * **Static Deny-lists:** String-matching for organizational-specific sensitive terms.
* **Anonymization:** Performs tokenization and replacement of sensitive data with standardized `<ENTITY_TYPE>` placeholders.


## 🛠️ Technology Stack

* **Language:** Python 3.x
* **Anonymization Framework:** [Microsoft Presidio](https://microsoft.github.io/presidio/)
* **NLP Engine:** [spaCy](https://spacy.io/)
* **GUI Library:** Tkinter (Custom event-driven interface)
* **Pattern Matching:** Python `re` module

## 📊 Processing Logic & Evaluation

| Pipeline Stage | Logic Type | Threshold / Condition | Resultant Action |
| :--- | :--- | :--- | :--- |
| **Stage 1: Security** | Heuristic Scoring | Score $\ge 0.35$ | **BLOCK** (Dropped) |
| **Stage 2: Privacy** | NER Detection | Confidence $> 0.40$ | **MASK** (Sanitized) |
| **Stage 3: Validation** | No Match | Default | **ALLOW** (Passed) |



## 🚀 Deployment & Installation

### 1. Install Dependencies
```bash
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg
