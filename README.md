# Presidio-Based-LLM-Security-Mini-Gateway
This repository contains a Standalone Security Gateway. The gateway acts as a "firewall" between a user and an AI model, analyzing incoming prompts in real-time. It utilizes Presidio Analyzer for PII detection and a custom Regex-based Scoring Engine to detect adversarial prompt injections.

---

## 📖 Overview

The **Security Gateway** acts as a protective layer between the user and the AI. It analyzes every incoming prompt using two main engines:
1. **Injection Scorer:** Detects adversarial patterns (Jailbreaks, System Prompt extractions).
2. **Privacy Scrubber:** Identifies and redacts PII (Personally Identifiable Information) using Microsoft Presidio and spaCy.

---

## ✨ Key Features

* **Custom Bahria Logic:**
    * **Enrollment ID Validator:** Custom regex logic that only masks IDs following the `01-XXXXXXXXX` (11-digit) format.
    * **Organizational Protection:** Static deny-list ensures "Bahria University" is always masked.
* **Lilac & Light Grey UI:** A clean, professional Tkinter interface with color-coded results.
* **Detail Viewer:** Double-click any row in the analysis table to see a full comparison of raw vs. filtered text.
* **Performance Tracking:** Real-time latency measurement in milliseconds (ms) for every scan.

---

## 🛠️ Technical Stack

* **Language:** Python 3.x
* **PII Engine:** Microsoft Presidio
* **NLP Model:** spaCy `en_core_web_lg`
* **GUI Framework:** Tkinter



---

## 🚀 Installation & Setup

To run this project locally, follow these steps:

### 1. Install Dependencies
Open your terminal or Spyder console and run:
```bash
pip install presidio-analyzer presidio-anonymizer spacy
