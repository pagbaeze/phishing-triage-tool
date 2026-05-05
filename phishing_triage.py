import csv
from datetime import datetime
import uuid

INPUT_FILE = "phishing_emails.csv"
OUTPUT_FILE = "phishing_triage_report.txt"

SUSPICIOUS_KEYWORDS = {
    "urgent", "verify", "password", "locked", "suspended",
    "invoice", "payment", "wire", "gift card", "click here",
    "reset", "confirm", "unusual activity", "account alert"
}

SUSPICIOUS_DOMAINS = {
    "paypa1.com", "micros0ft-login.com", "secure-login.ru",
    "account-verify.net", "freegiftcards.com"
}

DANGEROUS_ATTACHMENTS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs",
    ".docm", ".xlsm", ".zip", ".rar"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
}

TRUSTED_DOMAINS = {
    "microsoft.com", "paypal.com", "company.com"
}

def get_domain(email):
    if "@" in email:
        return email.split("@")[-1].lower()
    return ""

def get_url_domain(url):
    url = url.lower()
    url = url.replace("https://", "").replace("http://", "")
    return url.split("/")[0]

def get_file_extension(filename):
    if "." in filename:
        return "." + filename.split(".")[-1].lower()
    return ""

def get_severity(score):
    if score >= 80:
        return "High"
    elif score >= 50:
        return "Medium"
    else:
        return "Low"

def get_classification(score):
    if score >= 80:
        return "Likely Malicious"
    elif score >= 50:
        return "Suspicious"
    else:
        return "Low Risk"

def get_mitre_mapping(reasons):
    mappings = []
    reason_text = " ".join(reasons).lower()

    if "suspicious sender domain" in reason_text or "display name" in reason_text:
        mappings.append("T1585 - Establish Accounts / Impersonation-style infrastructure")

    if "link" in reason_text or "url shortener" in reason_text or "http" in reason_text:
        mappings.append("T1566.002 - Phishing: Spearphishing Link")

    if "attachment" in reason_text:
        mappings.append("T1566.001 - Phishing: Spearphishing Attachment")

    if "keyword" in reason_text:
        mappings.append("T1204 - User Execution")

    return mappings

def extract_iocs(sender_email, link, attachment):
    iocs = []

    if sender_email:
        iocs.append(f"Sender Email: {sender_email}")

        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].lower()
            iocs.append(f"Sender Domain: {sender_domain}")

    if link:
        iocs.append(f"URL: {link}")
        url_domain = get_url_domain(link)
        iocs.append(f"URL Domain: {url_domain}")

    if attachment:
        iocs.append(f"Attachment: {attachment}")
        attachment_ext = get_file_extension(attachment)
        if attachment_ext:
            iocs.append(f"Attachment Type: {attachment_ext}")

    return iocs

alerts = []

with open(INPUT_FILE, "r", encoding="utf-8") as file:
    reader = csv.DictReader(file)

    for row in reader:
        reported_by = row["reported_by"]
        sender_name = row["sender_name"]
        sender_email = row["sender_email"]
        subject = row["subject"]
        body = row["body"]
        link = row["link"]
        attachment = row["attachment"]

        risk_score = 0
        reasons = []

        sender_domain = get_domain(sender_email)
        text_to_check = f"{subject} {body}".lower()

        if sender_domain in SUSPICIOUS_DOMAINS:
            risk_score += 40
            reasons.append(f"Known suspicious sender domain: {sender_domain}")

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in text_to_check:
                risk_score += 15
                reasons.append(f"Suspicious keyword found: {keyword}")

        if link:
            link_domain = get_url_domain(link)

            if link_domain in SUSPICIOUS_DOMAINS:
                risk_score += 40
                reasons.append(f"Link points to suspicious domain: {link_domain}")

            if link_domain in SHORTENER_DOMAINS:
                risk_score += 25
                reasons.append(f"URL shortener detected: {link_domain}")

            if link.startswith("http://"):
                risk_score += 15
                reasons.append("Link uses insecure HTTP")

        if attachment:
            attachment_extension = get_file_extension(attachment)

            if attachment_extension in DANGEROUS_ATTACHMENTS:
                risk_score += 35
                reasons.append(f"Dangerous attachment type: {attachment_extension}")

        if sender_name.lower() in {"microsoft", "paypal", "hr", "it support"} and sender_domain not in TRUSTED_DOMAINS:
            risk_score += 30
            reasons.append("Sender display name does not match trusted domain")

        risk_score = min(risk_score, 100)

        if risk_score > 0:
            mitre_mapping = get_mitre_mapping(reasons)
            iocs = extract_iocs(sender_email, link, attachment)

            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "reported_by": reported_by,
                "sender_name": sender_name,
                "sender_email": sender_email,
                "subject": subject,
                "link": link,
                "attachment": attachment,
                "risk_score": risk_score,
                "severity": get_severity(risk_score),
                "classification": get_classification(risk_score),
                "reasons": reasons,
                "mitre_mapping": mitre_mapping,
                "iocs": iocs
            })

with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
    report.write("===== Mini Phishing Triage Report =====\n")
    report.write(f"Generated: {datetime.now()}\n\n")

    if not alerts:
        report.write("No suspicious phishing indicators detected.\n")
    else:
        for alert in alerts:
            report.write(f"Alert ID: {alert['alert_id']}\n")
            report.write(f"Reported By: {alert['reported_by']}\n")
            report.write(f"Sender: {alert['sender_name']} <{alert['sender_email']}>\n")
            report.write(f"Subject: {alert['subject']}\n")
            report.write(f"Severity: {alert['severity']}\n")
            report.write(f"Classification: {alert['classification']}\n")
            report.write(f"Risk Score: {alert['risk_score']}/100\n")
            report.write(f"Link: {alert['link']}\n")
            report.write(f"Attachment: {alert['attachment']}\n")

            report.write("Reasons:\n")
            for reason in alert["reasons"]:
                report.write(f"- {reason}\n")

            report.write("MITRE ATT&CK Mapping:\n")
            for technique in alert["mitre_mapping"]:
                report.write(f"- {technique}\n")

            report.write("Indicators of Compromise (IOCs):\n")
            for ioc in alert["iocs"]:
                report.write(f"- {ioc}\n")

            report.write("Recommended Action:\n")

            if alert["classification"] == "Likely Malicious":
                report.write("- Block malicious sender/domain at the email or security gateway.\n")
                report.write("- Analyze the link and attachment in a secure sandbox environment.\n")
                report.write("- Search across mailboxes for similar messages or indicators.\n")
                report.write("- Identify whether any users clicked links, downloaded attachments, or submitted credentials.\n")
                report.write("- If compromise is confirmed, initiate incident response procedures.\n")
            elif alert["classification"] == "Suspicious":
                report.write("- Review email headers, validate sender legitimacy, and confirm whether the message is expected.\n")
                report.write("- Monitor for similar reported emails or repeated indicators.\n")
            else:
                report.write("- Log the report and continue monitoring.\n")

            report.write("-" * 50 + "\n")

print(f"Phishing triage report created: {OUTPUT_FILE}")