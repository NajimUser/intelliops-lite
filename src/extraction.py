import re
from src.contrat import Evenement

def masquer_secrets(texte: str) -> str:
    pattern = r'(?i)\b(password|passwd|token|secret|api_key|apikey)([:=])([^\s&,;]+)'
    texte = re.sub(pattern, r'\1\2[SECRET]', texte)
    texte = re.sub(r'Bearer\s+[^\s&,;]+', 'Bearer [SECRET]', texte, flags=re.IGNORECASE)
    return texte

def normaliser_log(ligne: str, numero: int, source: str = "DOCKER", environment: str = "production") -> Evenement:
    champs = ligne.split(maxsplit=4)
    if len(champs) < 5:
        raise ValueError("Ligne de log invalide : moins de 5 champs")
    
    date_str, heure_str, niveau_str, composant, reste = champs
    timestamp = f"{date_str}T{heure_str}Z"
    event_id = f"EVT-{numero:05d}"
    
    niv = niveau_str.upper()
    if niv in ("CRITICAL", "FATAL"):
        severity = "CRITICAL"
    elif niv == "ERROR":
        severity = "HIGH"
    elif niv in ("WARN", "WARNING"):
        severity = "MEDIUM"
    else:
        severity = "LOW"
        
    message = masquer_secrets(reste)
    return Evenement(
        id=event_id,
        timestamp=timestamp,
        source=source,
        component=composant,
        environment=environment,
        event_type="LOG",
        severity=severity,
        message=message
    )

def normaliser_scan(rapport: dict, numero: int, environment: str = "production") -> Evenement:
    for cle in ("cve", "package", "severity", "date"):
        if cle not in rapport:
            raise ValueError(f"Cle manquante dans le scan: {cle}")
            
    sev = rapport["severity"].upper()
    severity = sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "LOW"
    
    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=rapport["date"],
        source="TRIVY",
        component=rapport["package"],
        environment=environment,
        event_type="VULNERABILITY",
        severity=severity,
        message=f"Vulnerabilite {rapport['cve']} dans {rapport['package']}"
    )

def normaliser_pipeline(rapport: dict, numero: int, environment: str = "production") -> Evenement:
    for cle in ("job", "status", "date"):
        if cle not in rapport:
            raise ValueError(f"Cle manquante dans le pipeline: {cle}")
            
    is_failed = rapport["status"].lower() == "failed"
    return Evenement(
        id=f"EVT-{numero:05d}",
        timestamp=rapport["date"],
        source="CI",
        component=rapport["job"],
        environment=environment,
        event_type="PIPELINE_FAILURE" if is_failed else "PIPELINE_OK",
        severity="HIGH" if is_failed else "LOW",
        message=f"Pipeline {rapport['job']}: {rapport['status']}"
    )