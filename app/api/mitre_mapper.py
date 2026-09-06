TAG_TO_TACTIC = {
    "phishing":      "Initial Access (T1566)",
    "malware":       "Execution (T1059)",
    "ransomware":    "Impact (T1486)",
    "c2":            "Command & Control (T1071)",
    "c&c":           "Command & Control (T1071)",
    "exfiltration":  "Exfiltration (T1041)",
    "persistence":   "Persistence (T1053)",
    "brute":         "Credential Access (T1110)",
    "scan":          "Reconnaissance (T1595)",
    "recon":         "Reconnaissance (T1595)",
    "botnet":        "Command & Control (T1071)",
    "trojan":        "Execution (T1059)",
    "backdoor":      "Persistence (T1053)",
    "rat":           "Command & Control (T1071)",
    "ddos":          "Impact (T1498)",
    "spam":          "Initial Access (T1566)",
    "exploit":       "Execution (T1203)",
    "keylogger":     "Collection (T1056)",
    "stealer":       "Credential Access (T1555)",
    "miner":         "Impact (T1496)",
    "apt":           "Reconnaissance (T1595)",
}

def map_tags_to_mitre(tags_str):
    if not tags_str:
        return "Unknown"
    tags = [t.lower().strip() for t in tags_str.split(",")]
    for tag in tags:
        for keyword, tactic in TAG_TO_TACTIC.items():
            if keyword in tag:
                return tactic
    return "Unknown"