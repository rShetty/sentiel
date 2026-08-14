use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::events::DlpViolation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPattern {
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub description: String,
}

pub struct DlpEngine {
    patterns: Vec<(DlpPattern, Regex)>,
    enabled: bool,
}

impl DlpEngine {
    pub fn new(enabled: bool) -> Self {
        let mut engine = DlpEngine {
            patterns: Vec::new(),
            enabled,
        };
        engine.load_default_patterns();
        engine
    }

    fn load_default_patterns(&mut self) {
        let defaults = vec![
            DlpPattern {
                name: "email".to_string(),
                pattern: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".to_string(),
                severity: "medium".to_string(),
                description: "Email address".to_string(),
            },
            DlpPattern {
                name: "ssn".to_string(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".to_string(),
                severity: "critical".to_string(),
                description: "US Social Security Number".to_string(),
            },
            DlpPattern {
                name: "credit_card".to_string(),
                pattern: r"\b(?:\d[ -]*?){13,16}\b".to_string(),
                severity: "critical".to_string(),
                description: "Credit card number".to_string(),
            },
            DlpPattern {
                name: "phone".to_string(),
                pattern: r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b".to_string(),
                severity: "low".to_string(),
                description: "Phone number".to_string(),
            },
            DlpPattern {
                name: "api_key".to_string(),
                pattern: r#"(?i)(?:api[_-]?key|apikey|token|secret|password)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?"#.to_string(),
                severity: "high".to_string(),
                description: "API key or secret".to_string(),
            },
            DlpPattern {
                name: "aws_key".to_string(),
                pattern: r"AKIA[0-9A-Z]{16}".to_string(),
                severity: "critical".to_string(),
                description: "AWS Access Key ID".to_string(),
            },
            DlpPattern {
                name: "github_token".to_string(),
                pattern: r"gh[pousr]_[A-Za-z0-9]{36,}".to_string(),
                severity: "critical".to_string(),
                description: "GitHub token".to_string(),
            },
            DlpPattern {
                name: "slack_token".to_string(),
                pattern: r"xox[baprs]-[A-Za-z0-9-]{10,}".to_string(),
                severity: "critical".to_string(),
                description: "Slack token".to_string(),
            },
            DlpPattern {
                name: "private_key".to_string(),
                pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----".to_string(),
                severity: "critical".to_string(),
                description: "Private key block".to_string(),
            },
            DlpPattern {
                name: "jwt".to_string(),
                pattern: r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}".to_string(),
                severity: "high".to_string(),
                description: "JWT token".to_string(),
            },
        ];

        for p in defaults {
            if let Ok(re) = Regex::new(&p.pattern) {
                self.patterns.push((p, re));
            }
        }
    }

    pub fn add_pattern(&mut self, pattern: DlpPattern) -> Result<(), String> {
        let re = Regex::new(&pattern.pattern).map_err(|e| e.to_string())?;
        self.patterns.push((pattern, re));
        Ok(())
    }

    pub fn inspect(&self, content: &str) -> Vec<DlpViolation> {
        if !self.enabled {
            return Vec::new();
        }

        let mut violations = Vec::new();
        for (pattern, regex) in &self.patterns {
            for m in regex.find_iter(content) {
                violations.push(DlpViolation {
                    pattern_name: pattern.name.clone(),
                    matched_text: redact(m.as_str(), &pattern.name),
                    severity: pattern.severity.clone(),
                    field: "content".to_string(),
                });
            }
        }
        violations
    }

    pub fn inspect_json(&self, data: &serde_json::Value) -> Vec<DlpViolation> {
        if !self.enabled {
            return Vec::new();
        }

        let mut violations = Vec::new();
        match data {
            serde_json::Value::String(s) => {
                violations.extend(self.inspect(s));
            }
            serde_json::Value::Object(obj) => {
                for (key, val) in obj {
                    let mut field_violations = self.inspect_json(val);
                    for v in &mut field_violations {
                        v.field = key.clone();
                    }
                    violations.extend(field_violations);
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    violations.extend(self.inspect_json(item));
                }
            }
            _ => {}
        }
        violations
    }

    pub fn redact_content(&self, content: &str) -> String {
        if !self.enabled {
            return content.to_string();
        }

        let mut redacted = content.to_string();
        for (pattern, regex) in &self.patterns {
            redacted = regex
                .replace_all(
                    &redacted,
                    "[REDACTED:${name}]".replace("${name}", &pattern.name),
                )
                .to_string();
        }
        redacted
    }

    pub fn has_critical_violation(&self, violations: &[DlpViolation]) -> bool {
        violations.iter().any(|v| v.severity == "critical")
    }
}

fn redact(text: &str, pattern_name: &str) -> String {
    if text.len() <= 4 {
        return format!("[REDACTED:{}]", pattern_name);
    }
    format!(
        "{}...[REDACTED:{}]",
        &text[..text.len().min(4)],
        pattern_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_email() {
        let engine = DlpEngine::new(true);
        let violations = engine.inspect("Contact alice@example.com for details");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].pattern_name, "email");
    }

    #[test]
    fn test_detect_ssn() {
        let engine = DlpEngine::new(true);
        let violations = engine.inspect("SSN: 123-45-6789");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].pattern_name, "ssn");
        assert_eq!(violations[0].severity, "critical");
    }

    #[test]
    fn test_detect_github_token() {
        let engine = DlpEngine::new(true);
        let token = "ghp_".to_string() + &"A".repeat(37);
        let violations = engine.inspect(&format!("token: {}", token));
        assert!(violations.iter().any(|v| v.pattern_name == "github_token"));
        assert!(violations.iter().any(|v| v.pattern_name == "api_key"));
    }

    #[test]
    fn test_detect_private_key() {
        let engine = DlpEngine::new(true);
        let violations = engine.inspect("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert_eq!(violations[0].pattern_name, "private_key");
        assert_eq!(violations[0].severity, "critical");
    }

    #[test]
    fn test_redact_content() {
        let engine = DlpEngine::new(true);
        let redacted = engine.redact_content("email: alice@example.com");
        assert!(!redacted.contains("alice@example.com"));
        assert!(redacted.contains("REDACTED"));
    }

    #[test]
    fn test_disabled_engine_returns_empty() {
        let engine = DlpEngine::new(false);
        let violations = engine.inspect("alice@example.com");
        assert!(violations.is_empty());
    }

    #[test]
    fn test_inspect_json() {
        let engine = DlpEngine::new(true);
        let data = serde_json::json!({
            "user": "alice@example.com",
            "metadata": {
                "ssn": "123-45-6789"
            }
        });
        let violations = engine.inspect_json(&data);
        assert!(
            violations.iter().any(|v| v.pattern_name == "email"),
            "should find email: {:?}",
            violations
        );
        assert!(
            violations.iter().any(|v| v.pattern_name == "ssn"),
            "should find ssn: {:?}",
            violations
        );
    }

    #[test]
    fn test_has_critical_violation() {
        let engine = DlpEngine::new(true);
        let violations = engine.inspect("SSN: 123-45-6789");
        assert!(engine.has_critical_violation(&violations));

        let violations = engine.inspect("just some text");
        assert!(!engine.has_critical_violation(&violations));
    }

    #[test]
    fn test_detect_aws_key() {
        let engine = DlpEngine::new(true);
        let violations = engine.inspect("AWS key: AKIAIOSFODNN7EXAMPLE");
        assert!(violations.iter().any(|v| v.pattern_name == "aws_key"));
    }

    #[test]
    fn test_detect_jwt() {
        let engine = DlpEngine::new(true);
        let violations = engine.inspect("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
        assert!(violations.iter().any(|v| v.pattern_name == "jwt"));
    }
}
