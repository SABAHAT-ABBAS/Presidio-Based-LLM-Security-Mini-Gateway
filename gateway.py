import re
import time
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
