# vulnguard.py - AI-Powered Smart Contract Vulnerability Scanner
import sys
import re
import json
import joblib
import os
from datetime import datetime

# ============================================
# PART 1: FEATURE EXTRACTION
# ============================================

class FeatureExtractor:
    """Extracts features from Solidity code for ML model"""
    
    def __init__(self):
        self.feature_names = [
            'line_count',
            'function_count',
            'has_call',
            'has_tx_origin',
            'has_delegatecall',
            'has_assembly',
            'has_unchecked',
            'has_selfdestruct',
            'has_require',
            'has_revert',
            'has_assert',
            'has_modifier',
            'has_event',
            'has_mapping',
            'has_struct',
            'has_enum',
            'has_interface',
            'has_library'
        ]
    
    def extract(self, code):
        features = {}
        features['line_count'] = len(code.split('\n'))
        features['function_count'] = len(re.findall(r'function\s+\w+', code))
        features['has_call'] = int('call(' in code)
        features['has_tx_origin'] = int('tx.origin' in code)
        features['has_delegatecall'] = int('delegatecall' in code)
        features['has_assembly'] = int('assembly' in code)
        features['has_unchecked'] = int('unchecked{' in code)
        features['has_selfdestruct'] = int('selfdestruct' in code or 'suicide' in code)
        features['has_require'] = int('require(' in code)
        features['has_revert'] = int('revert(' in code)
        features['has_assert'] = int('assert(' in code)
        features['has_modifier'] = int('modifier' in code)
        features['has_event'] = int('event' in code)
        features['has_mapping'] = int('mapping(' in code)
        features['has_struct'] = int('struct' in code)
        features['has_enum'] = int('enum' in code)
        features['has_interface'] = int('interface' in code)
        features['has_library'] = int('library' in code)
        return features


# ============================================
# PART 2: RULE-BASED VULNERABILITY DETECTION
# ============================================

class VulnerabilityDetector:
    """Detects known vulnerability patterns using regex rules"""
    
    PATTERNS = {
        'reentrancy': {
            'pattern': r'\.call\{.*?\}\(.*?\)',
            'description': 'Potential re-entrancy vulnerability. Use Checks-Effects-Interactions pattern.'
        },
        'tx_origin': {
            'pattern': r'tx\.origin',
            'description': 'tx.origin used. Use msg.sender to prevent phishing attacks.'
        },
        'unchecked_transfer': {
            'pattern': r'\.transfer\(|\.send\(',
            'description': 'transfer() and send() can fail. Use .call() with require() instead.'
        },
        'no_visibility': {
            'pattern': r'function\s+\w+\([^)]*\)\s*(?!\b(public|private|internal|external|view|pure|virtual|override|returns|when|modifier)\b)\s*\{',
            'description': 'Function with no visibility specifier. Use public/external/internal/private.'
        },
        'unchecked_return': {
            'pattern': r'\.send\(',
            'description': 'send() returns bool without check. Always check return value.'
        },
        'timestamp_dependence': {
            'pattern': r'block\.timestamp|now\s*',
            'description': 'Block timestamp can be manipulated by miners. Avoid using for critical logic.'
        },
        'blockhash_dependence': {
            'pattern': r'block\.blockhash|block\.number',
            'description': 'Blockhash/number can be manipulated by miners.'
        },
        'uninitialized_storage': {
            'pattern': r'struct.*?;\s*\w+\s*;',
            'description': 'Uninitialized struct may use default values. Initialize properly.'
        }
    }
    
    def scan(self, code):
        vulnerabilities = []
        for vuln_name, config in self.PATTERNS.items():
            matches = re.finditer(config['pattern'], code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    'type': vuln_name,
                    'line': line_num,
                    'description': config['description']
                })
        return vulnerabilities


# ============================================
# PART 3: ML PREDICTOR (Using Pre-trained Model)
# ============================================

class MLPredictor:
    """Uses XGBoost model to predict vulnerability likelihood"""
    
    def __init__(self, model_path='vuln_model.pkl'):
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.feature_names = self.feature_extractor.feature_names
        
        # Try to load pre-trained model
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                print(f"✅ Loaded ML model from {model_path}", file=sys.stderr)
            except Exception as e:
                print(f"⚠️ Could not load model: {e}", file=sys.stderr)
                self.model = None
        else:
            print("⚠️ No pre-trained model found. Using rule-based detection only.", file=sys.stderr)
    
    def predict(self, code):
        if self.model is None:
            return None
        
        features = self.feature_extractor.extract(code)
        feature_values = [features[name] for name in self.feature_names]
        
        prediction = self.model.predict([feature_values])[0]
        confidence = self.model.predict_proba([feature_values])[0]
        
        return {
            'is_vulnerable': bool(prediction),
            'confidence': float(confidence[1]) if prediction else float(confidence[0])
        }


# ============================================
# PART 4: MAIN SCANNER
# ============================================

class VulnGuard:
    """Main scanner combining rule-based and ML detection"""
    
    def __init__(self):
        self.detector = VulnerabilityDetector()
        self.predictor = MLPredictor()
        self.feature_extractor = FeatureExtractor()
    
    def scan(self, code):
        # Step 1: Rule-based detection
        rule_vulns = self.detector.scan(code)
        
        # Step 2: ML prediction
        ml_result = self.predictor.predict(code)
        
        # Step 3: Feature extraction
        features = self.feature_extractor.extract(code)
        
        # Step 4: Calculate risk score
        risk_score = self.calculate_risk_score(rule_vulns, ml_result)
        
        # Step 5: Generate severity levels
        severity_counts = self.count_severity(rule_vulns)
        
        return {
            'risk_score': risk_score,
            'rule_vulnerabilities': rule_vulns,
            'rule_count': len(rule_vulns),
            'ml_prediction': ml_result,
            'features': features,
            'severity_counts': severity_counts,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def calculate_risk_score(self, vulns, ml_result):
        # Base score from rule-based detections
        base_score = len(vulns) * 15
        
        # Add ML confidence if available
        if ml_result and ml_result['is_vulnerable']:
            base_score += 30
        
        # Cap at 100
        return min(base_score, 100)
    
    def count_severity(self, vulns):
        # Categorize vulnerabilities by severity
        severity_map = {
            'reentrancy': 'Critical',
            'tx_origin': 'High',
            'unchecked_transfer': 'High',
            'timestamp_dependence': 'Medium',
            'blockhash_dependence': 'Medium',
            'no_visibility': 'Low',
            'uninitialized_storage': 'Low'
        }
        
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulns:
            severity = severity_map.get(vuln['type'], 'Low')
            counts[severity] += 1
        return counts


# ============================================
# PART 5: CLI ENTRY POINT
# ============================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python vulnguard.py <solidity_file.sol>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        with open(file_path, 'r') as f:
            code = f.read()
    except Exception as e:
        print(json.dumps({'error': f'Error reading file: {str(e)}'}))
        sys.exit(1)
    
    scanner = VulnGuard()
    result = scanner.scan(code)
    
    # Print results as JSON for the backend to parse
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()