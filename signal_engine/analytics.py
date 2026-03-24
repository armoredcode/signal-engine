import sqlite3
from signal_engine.ingest import get_repo_db_path

EXTENSION_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".java": "Java",
    ".c": "C",
    ".cpp": "C++",
    ".h": "C/C++ Header",
    ".rb": "Ruby",
    ".php": "PHP",
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 3.0,
    "LOW": 1.0,
    "INFO": 0.1,
}

def get_language_from_path(path):
    import os
    _, ext = os.path.splitext(path)
    return EXTENSION_MAP.get(ext.lower(), "Unknown")

def get_vulnerability_density(repo_name, tool=None):
    """
    Calculate risk-weighted vulnerability density per 1000 LOC for each language.
    Risk Score = Sum(finding_weight)
    Risk Density = (Risk Score / LOC) * 1000
    """
    import os
    db_path = get_repo_db_path(repo_name)
    if not os.path.exists(db_path):
        return []

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 1. Get findings with their severity
        query = "SELECT file_path, severity FROM findings"
        params = []
        if tool:
            query += " WHERE tool = ?"
            params.append(tool)
        
        cursor.execute(query, params)
        findings = cursor.fetchall()
    except sqlite3.OperationalError:
        conn.close()
        return []

    # 2. Calculate Risk Score by language
    risk_by_lang = {}
    findings_count_by_lang = {}
    
    for path, severity in findings:
        lang = get_language_from_path(path)
        weight = SEVERITY_WEIGHTS.get(str(severity).upper(), 1.0) # Default to LOW weight if unknown
        
        risk_by_lang[lang] = risk_by_lang.get(lang, 0.0) + weight
        findings_count_by_lang[lang] = findings_count_by_lang.get(lang, 0) + 1

    # 3. Get LOC from metrics table
    try:
        cursor.execute("""
            SELECT language, value 
            FROM metrics 
            WHERE tool = 'cloc' AND metric_type = 'code_lines'
        """)
        loc_by_lang = dict(cursor.fetchall())
    except sqlite3.OperationalError:
        loc_by_lang = {}
    finally:
        conn.close()

    # 4. Consolidate results
    results = []
    for lang, loc in loc_by_lang.items():
        findings_count = findings_count_by_lang.get(lang, 0)
        risk_score = risk_by_lang.get(lang, 0.0)
        
        # Risk Density calculation
        density = (risk_score / loc * 1000) if loc > 0 else 0.0
        
        results.append({
            "language": lang,
            "findings": findings_count,
            "risk_score": round(risk_score, 1),
            "loc": int(loc),
            "density": round(density, 2)
        })

    # Sort by risk density (severity-weighted)
    return sorted(results, key=lambda x: x["density"], reverse=True)
