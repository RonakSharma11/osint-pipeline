# scoring.py
# Deterministic, reproducible scoring function

def clamp(x, lo, hi):
    return max(lo, min(hi, x))

def bucketed_log_scale(x, lo, hi):
    if x <= 0:
        return 0
    import math
    return clamp(int(math.log10(x + 1) * 6), lo, hi)

def bucketed_scale(x, lo, hi):
    if x <= 0:
        return 0
    return clamp(int(x ** 0.5), lo, hi)

def suspicious_ptr(ptr):
    if not ptr:
        return False
    ptr = ptr.lower()
    keywords = ["scan", "security", "ipip", "crawler"]
    return any(k in ptr for k in keywords)

def country_weight(enrichment):
    country = enrichment.get("geoip", {}).get("country_iso")
    if country in {"RU", "CN", "IR", "KP"}:
        return 5
    return 0

def compute_score(ioc):
    enrichment = ioc.get("enrichment", {})
    abuse = enrichment.get("abuseipdb", {})

    base = 10
    source_weight = 20 if ioc.get("source") == "AbuseIPDB" else 10

    abuse_conf = abuse.get("abuseConfidenceScore", 0)
    C_abuse = min(25, round(abuse_conf / 100 * 25))

    reports = abuse.get("totalReports", 0)
    C_reports = bucketed_log_scale(reports, 0, 18)

    users = abuse.get("numDistinctUsers", 0)
    C_users = bucketed_scale(users, 0, 10)

    ptr = enrichment.get("reverse", {}).get("ptr")
    C_ptr = 12 if suspicious_ptr(ptr) else 0

    C_country = country_weight(enrichment)

    raw = base + source_weight + C_abuse + C_reports + C_users + C_ptr + C_country
    final = clamp(round(raw), 0, 100)

    breakdown = {
        "base": base,
        "source_weight": source_weight,
        "abuse_contrib": C_abuse,
        "reports_contrib": C_reports,
        "users_contrib": C_users,
        "ptr_contrib": C_ptr,
        "country_contrib": C_country,
        "final_score": final
    }

    return final, breakdown
