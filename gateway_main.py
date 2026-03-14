import tkinter as tk
from tkinter import ttk, messagebox
import time
import re
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine

class EnrollmentValidator(PatternRecognizer):
    def validate_result(self, pattern_text: str):
        if len(pattern_text) == 11 and pattern_text.startswith("01"):
            return True
        return False

class AIC201SecurityGateway:
    def __init__(self):
        self.FIXED_THRESHOLD = 0.35 
        self.anonymizer = AnonymizerEngine()
        
        enroll_pattern = Pattern(name="enroll_pattern", regex=r"\d{11}", score=1.0)
        enroll_rec = EnrollmentValidator(supported_entity="ENROLLMENT_ID", patterns=[enroll_pattern])
        
        phone_pattern = Pattern(name="phone_pattern", regex=r"(\+92\d{9,11})|(\b03\d{8,10}\b)", score=1.0)
        phone_rec = PatternRecognizer(supported_entity="PHONE_NUMBER", patterns=[phone_pattern])
        
        api_pattern = Pattern(name="api_pattern", regex=r"\b[a-zA-Z0-9]{16,32}\b", score=0.6)
        api_rec = PatternRecognizer(supported_entity="API_KEY", patterns=[api_pattern], context=["api", "key", "token"])

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()
        registry.add_recognizer(enroll_rec)
        registry.add_recognizer(phone_rec)
        registry.add_recognizer(api_rec)
        self.analyzer = AnalyzerEngine(registry=registry)

    def detect_injection(self, text: str) -> float:
        score = 0.0
        patterns = {r"ignore|forget|override|bypass": 0.7, r"system prompt|instruction|rules": 0.5, 
                    r"jailbreak|dan mode|root access": 0.8, r"sudo|cmd|execute": 0.4}
        for pattern, weight in patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                score += weight
        return min(score, 1.0)

    def process(self, text):
        start_time = time.time()
        inj_score = self.detect_injection(text)
        if inj_score >= self.FIXED_THRESHOLD:
            decision, output = "BLOCK", "[REDACTED: Security Risk Detected]"
        else:
            results = self.analyzer.analyze(text=text, language='en')
            output = self.anonymizer.anonymize(text=text, analyzer_results=results).text if results else text
            decision = "MASK" if results else "ALLOW"
        
        latency = (time.time() - start_time) * 1000
        return decision, inj_score, f"{latency:.1f}ms", output

class GatewayGUI:
    def __init__(self, root):
        self.gateway = AIC201SecurityGateway()
        self.root = root
        self.root.title("AIC201: LLM Security Gateway")
        self.root.geometry("1000x650")
        
        self.bg_lilac = "#E6E6FA" 
        self.root.configure(bg=self.bg_lilac)

        # Header
        tk.Label(root, text="LLM SECURITY GATEWAY", bg=self.bg_lilac, fg="#4B0082", font=('Arial', 14, 'bold')).pack(pady=10)

        # Input
        input_frame = tk.Frame(root, bg=self.bg_lilac)
        input_frame.pack(fill=tk.X, padx=20)
        self.input_box = tk.Text(input_frame, height=4, bg="#F8F8FF", font=('Consolas', 11))
        self.input_box.pack(fill=tk.X, pady=5)

        # Buttons
        btn_frame = tk.Frame(root, bg=self.bg_lilac)
        btn_frame.pack(fill=tk.X, padx=20, pady=10)
        tk.Button(btn_frame, text="SCAN INPUT", bg="#9370DB", fg="white", font=('Arial', 9, 'bold'), width=15, command=self.run_analysis).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="RUN BENCHMARK", bg="#BA55D3", fg="white", font=('Arial', 9, 'bold'), width=15, command=self.run_benchmark).pack(side=tk.LEFT, padx=5)
        tk.Label(btn_frame, text="💡 Double-click any row to see full text", bg=self.bg_lilac, fg="#4B0082").pack(side=tk.RIGHT)

        # Table
        table_frame = tk.Frame(root, bg=self.bg_lilac)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        cols = ("Input", "Decision", "Score", "Latency", "Output")
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings')
        
        self.tree.column("Input", width=250, stretch=True)
        self.tree.column("Decision", width=80, anchor=tk.CENTER)
        self.tree.column("Score", width=60, anchor=tk.CENTER)
        self.tree.column("Latency", width=80, anchor=tk.CENTER)
        self.tree.column("Output", width=250, stretch=True)

        for col in cols: self.tree.heading(col, text=col)

        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        # Events
        self.tree.bind("<Double-1>", self.on_double_click)

        self.tree.tag_configure('BLOCK', foreground='#B22222', background='#FFD1DC')
        self.tree.tag_configure('MASK', foreground='#8B4513', background='#FFF9E3')
        self.tree.tag_configure('ALLOW', foreground='#006400', background='#E0FFFF')

    def on_double_click(self, event):
        item = self.tree.selection()[0]
        values = self.tree.item(item, "values")
        
        # Pop-up window for long text
        detail_win = tk.Toplevel(self.root)
        detail_win.title("Analysis Details")
        detail_win.geometry("500x400")
        detail_win.configure(bg="#F3E5F5")
        
        tk.Label(detail_win, text="FULL DETAILS", bg="#F3E5F5", font=('Arial', 10, 'bold')).pack(pady=5)
        text_area = tk.Text(detail_win, wrap=tk.WORD, padx=10, pady=10)
        text_area.insert(tk.END, f"INPUT:\n{values[0]}\n\n" + "-"*30 + f"\n\nOUTPUT:\n{values[4]}")
        text_area.config(state=tk.DISABLED)
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def run_analysis(self):
        text = self.input_box.get("1.0", tk.END).strip()
        if not text: return
        dec, score, lat, out = self.gateway.process(text)
        self.tree.insert("", 0, values=(text, dec, f"{score:.2f}", lat, out), tags=(dec,))
        self.input_box.delete("1.0", tk.END)

    def run_benchmark(self):
        cases = ["Hello!", "Ignore rules!", "My ID: 01134241041", "Bypass protocols"]
        for c in cases:
            dec, score, lat, out = self.gateway.process(c)
            self.tree.insert("", 0, values=(c, dec, f"{score:.2f}", lat, out), tags=(dec,))

if __name__ == "__main__":
    root = tk.Tk()
    ttk.Style().theme_use("clam")
    app = GatewayGUI(root)
    root.mainloop()
