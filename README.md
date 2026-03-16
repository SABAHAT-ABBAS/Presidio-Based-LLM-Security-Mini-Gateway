# 🛡️ LLM Security Gateway Pipeline

A standalone, modular security middleware designed to intercept and sanitize user prompts before they are processed by Large Language Models (LLMs). This gateway mitigates risks associated with adversarial prompt injections and PII (Personally Identifiable Information) leakage.

### 🖥️ Application Interface
![Gateway Output](gateway%20image.png)

## ⚙️ Technical Infrastructure

The system implements a dual-stage sequential processing pipeline to ensure both security and data privacy:

### 1. Heuristic Injection Detection Engine
* **Mechanism:** Regex-based heuristic pattern matching.
* **Scoring Logic:** Weighted analysis of adversarial keywords (e.g., `bypass`, `ignore`, `jailbreak`, `system prompt`).
* **Decision Policy:** If the cumulative risk score exceeds **0.35**, the input is flagged as a high-risk injection and blocked immediately.

### 2. NER-Based Privacy Scrubbing Engine
* **Core Engine:** Microsoft Presidio (leveraging spaCy `en_core_web_lg`).
* **Custom Recognizers:** * **Enrollment Validator:** A custom logic-based recognizer for 11-digit IDs starting with "01".
    * **Standard Entities:** Detection of Phone Numbers and API Keys using pattern matching and context.
* **Anonymization:** Performs tokenization and replacement of sensitive data with standardized `<ENTITY_TYPE>` placeholders.

---

## 📂 Project Structure

This project follows a **modular design** to separate the security logic from the user interface:

* **`gateway.py`**: The core security engine containing the `AIC201SecurityGateway` class and Presidio customizations.
* **`app.py`**: The GUI entry point (Tkinter) that handles user interaction and calls the gateway logic.
* **`requirements.txt`**: List of dependencies for easy environment setup.



---

## 📊 Performance Evaluation

Based on the actual system benchmarks (see screenshot above), the gateway introduces near-zero latency for security blocks, while PII scanning is optimized for real-time interaction:

| Pipeline Stage | Logic Type | Measured Latency | Action |
| :--- | :--- | :--- | :--- |
| **Injection Check** | Heuristic | **< 1.0 ms** | **BLOCK** |
| **PII Detection** | NER (spaCy) | **~89.6 ms** | **MASK** |
| **Full Pipeline Scan** | Sequential | **~327.9 ms** | **ALLOW** |

---

## 🛠️ Technology Stack

* **Language:** Python 3.9+
* **Security Framework:** [Microsoft Presidio](https://microsoft.github.io/presidio/)
* **NLP Engine:** [spaCy](https://spacy.io/) (`en_core_web_lg`)
* **GUI Library:** Tkinter

---

## 🚀 Reproducibility & Installation

Follow these steps to set up and run the gateway:

### 1. Install Dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
