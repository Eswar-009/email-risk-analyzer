import argparse, re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

URGENT = {"urgent","immediately","verify now","act now","account suspended",
          "account locked","payment required","confirm your identity","security alert"}
SUSPICIOUS_TLDS = {".zip",".mov",".click",".top",".xyz",".tk"}

def body_of(msg):
    if msg.is_multipart():
        return "\n".join(p.get_content() for p in msg.walk()
                          if p.get_content_type()=="text/plain")
    return msg.get_content()

def urls(text):
    return re.findall(r"https?://[^\s<>"]+", text, re.I)

def analyze(msg, body):
    score, findings = 0, []
    auth = msg.get("Authentication-Results","")
    spf = msg.get("Received-SPF","")
    sender = msg.get("From","")
    rp = msg.get("Return-Path","")

    a=auth.lower()
    if "spf=fail" in a or "spf=softfail" in a:
        score += 25; findings.append("SPF failure/soft-failure detected.")
    if "dkim=fail" in a:
        score += 25; findings.append("DKIM failure detected.")
    if "dmarc=fail" in a:
        score += 30; findings.append("DMARC failure detected.")
    if spf and re.search(r"\b(fail|softfail|neutral)\b", spf, re.I):
        score += 20; findings.append("Received-SPF is not passing.")

    sd=re.findall(r"@([A-Za-z0-9.-]+)",sender)
    rd=re.findall(r"@([A-Za-z0-9.-]+)",rp)
    if sd and rd and sd[-1].lower()!=rd[-1].lower():
        score += 20; findings.append("From and Return-Path domains differ.")

    hits=[x for x in URGENT if x in body.lower()]
    if hits:
        score += min(20,5*len(hits))
        findings.append("Urgent/lure language: "+", ".join(hits))

    found=urls(body)
    for u in found:
        host=(urlparse(u).hostname or "").lower()
        if any(host.endswith(t) for t in SUSPICIOUS_TLDS):
            score += 10; findings.append("Suspicious URL TLD: "+host)
        if re.fullmatch(r"\d+(?:\.\d+){3}",host):
            score += 15; findings.append("URL uses an IP address: "+host)

    score=min(score,100)
    level="HIGH" if score>=70 else "MEDIUM" if score>=40 else "LOW"
    return score,level,findings,found

def main():
    p=argparse.ArgumentParser(description="Local email phishing-risk analyzer")
    p.add_argument("email_file")
    a=p.parse_args()
    with open(a.email_file,"rb") as f: msg=BytesParser(policy=policy.default).parse(f)
    score,level,findings,found=analyze(msg,body_of(msg))
    print("="*65); print("                 EMAIL RISK ANALYZER"); print("="*65)
    print("Subject     :",msg.get("Subject","(none)"))
    print("From        :",msg.get("From","(none)"))
    print("Return-Path :",msg.get("Return-Path","(none)"))
    print(f"Risk Score  : {score}/100"); print("Risk Level  :",level); print("-"*65)
    print("Findings:")
    for x in findings or ["No major indicators detected."]: print("-",x)
    print("-"*65); print("URLs detected:",len(found)); print("="*65)
if __name__=="__main__": main()
