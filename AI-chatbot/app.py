from flask_cors import CORS
from flask import Flask, render_template, request, jsonify
from groq import Groq
from dotenv import load_dotenv
import os
import json
import re

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

print("KEY FOUND:", api_key is not None)

app = Flask(__name__)
CORS(app)

client = Groq(
    api_key=api_key
)


# ============================================================
# OBVIOUS CYBERSECURITY CHECK
# ============================================================

def obvious_cybersecurity_question(topic):

    text = topic.lower().strip()


    # ========================================================
    # 1. FRAUD / SCAMS / ONLINE MONEY THEFT
    # ========================================================

    fraud_words = [
        "scam",
        "scammed",
        "scammer",
        "fraud",
        "fraudulent",
        "cyber fraud",
        "online fraud",
        "online scam",
        "upi fraud",
        "upi scam",
        "payment fraud",
        "payment scam",
        "money stolen",
        "money was stolen",
        "money got stolen",
        "unauthorized payment",
        "unauthorised payment",
        "someone took my money",
        "someone stole my money",
    ]

    if any(word in text for word in fraud_words):
        return True


    # ========================================================
    # 2. URL / LINK / WEBSITE SECURITY
    # ========================================================

    has_url = bool(
        re.search(
            r"(https?://|www\.|"
            r"[a-zA-Z0-9-]+\.(com|org|net|in|io|co|dev|xyz)\b)",
            text
        )
    )

    link_words = [
        "link",
        "url",
        "website",
        "web site",
        "domain",
        "ip address",
        "shortened url",
    ]

    security_words = [
        "safe",
        "secure",
        "security",
        "malicious",
        "dangerous",
        "fake",
        "phishing",
        "scam",
        "suspicious",
        "legit",
        "legitimate",
        "trust",
        "trustworthy",
        "hack",
        "hacked",
        "virus",
        "malware",
    ]

    # Example:
    # "is this link safe?"
    # "is this website malicious?"
    # "https://example.com is this safe?"
    if any(word in text for word in link_words):
        if any(word in text for word in security_words):
            return True

    if has_url and any(word in text for word in security_words):
        return True


    # ========================================================
    # 3. PHONE / COMPUTER / DEVICE SECURITY
    # ========================================================

    device_words = [
        "phone",
        "mobile",
        "smartphone",
        "device",
        "computer",
        "laptop",
        "desktop",
        "tablet",
        "pc",
    ]

    suspicious_device_words = [
        "malicious",
        "malicious activity",
        "malicious activities",
        "suspicious",
        "suspicious activity",
        "suspicious activities",
        "strange",
        "strangely",
        "weird",
        "abnormal",
        "not normal",
        "behaving strange",
        "behaving strangely",
        "behaving weird",
        "behaving normally",
        "acting strange",
        "acting strangely",
        "acting weird",
        "unusual",
        "unknown activity",
        "unknown app",
        "unknown apps",
        "unknown process",
        "unknown processes",
    ]

    compromise_words = [
        "hack",
        "hacked",
        "hacking",
        "compromised",
        "compromise",
        "virus",
        "malware",
        "spyware",
        "keylogger",
        "infected",
        "infect",
        "attacked",
        "accessed",
        "someone accessed",
        "someone is accessing",
        "being monitored",
        "monitoring me",
        "spying",
        "spy on me",
        "stolen data",
        "data stolen",
    ]

    has_device = any(word in text for word in device_words)
    has_suspicious_behavior = any(
        word in text for word in suspicious_device_words
    )
    has_compromise = any(
        word in text for word in compromise_words
    )

    # Device + suspicious behavior
    #
    # Example:
    # "my phone is behaving weird"
    # "my phone is getting hot and showing malicious activity"
    #
    if has_device and has_suspicious_behavior:
        return True

    # Device + compromise
    #
    # Example:
    # "is my phone hacked?"
    # "I think my computer has malware"
    #
    if has_device and has_compromise:
        return True


    # ========================================================
    # 4. ACCOUNT SECURITY
    # ========================================================

    account_words = [
        "account",
        "gmail",
        "email account",
        "instagram account",
        "facebook account",
        "whatsapp account",
        "bank account",
        "social media account",
    ]

    account_security_words = [
        "hacked",
        "hack",
        "compromised",
        "stolen",
        "password stolen",
        "password changed",
        "unauthorized login",
        "unauthorised login",
        "suspicious login",
        "someone accessed",
        "someone logged in",
        "security",
        "secure",
        "2fa",
        "mfa",
        "authentication",
    ]

    if (
        any(word in text for word in account_words)
        and any(word in text for word in account_security_words)
    ):
        return True


    # ========================================================
    # 5. PHISHING / EMAIL / SMS / QR
    # ========================================================

    phishing_words = [
        "phishing",
        "phishing email",
        "phishing message",
        "phishing sms",
        "suspicious email",
        "suspicious message",
        "suspicious sms",
        "malicious email",
        "malicious message",
        "malicious sms",
        "qr code scam",
        "malicious qr",
        "suspicious qr",
        "qr scam",
    ]

    if any(word in text for word in phishing_words):
        return True


    # ========================================================
    # 6. GENERAL CYBERSECURITY TERMS
    # ========================================================

    cyber_words = [
        "cybersecurity",
        "cyber security",
        "malware",
        "ransomware",
        "spyware",
        "keylogger",
        "trojan",
        "botnet",
        "phishing",
        "vulnerability",
        "vulnerabilities",
        "cve",
        "firewall",
        "encryption",
        "cryptography",
        "penetration testing",
        "security testing",
        "network security",
        "web security",
        "application security",
        "api security",
        "database security",
        "password security",
        "account security",
        "two factor authentication",
        "two-factor authentication",
        "2fa",
        "mfa",
        "identity theft",
        "data breach",
        "security breach",
        "social engineering",
        "digital forensics",
        "incident response",
        "cybercrime",
        "cyber crime",
        "secure coding",
        "digital safety",
        "online safety",
    ]

    if any(word in text for word in cyber_words):
        return True


    # ========================================================
    # 7. CYBERSECURITY PROGRAMMING
    # ========================================================

    cyber_programming_words = [
        "phishing url detector",
        "phishing detector",
        "malware scanner",
        "malware detection",
        "virus scanner",
        "vulnerability scanner",
        "security scanner",
        "password checker",
        "password strength",
        "secure authentication",
        "security automation",
        "security script",
        "network scanner",
        "port scanner",
        "secure api",
        "security tool",
    ]

    if any(word in text for word in cyber_programming_words):
        return True


    # ========================================================
    # NOT OBVIOUSLY CYBERSECURITY
    # ========================================================

    return False


# ============================================================
# AI CYBERSECURITY SCOPE CHECK
# ============================================================

def is_cybersecurity_question(topic):

    # First handle obvious cybersecurity questions locally.
    if obvious_cybersecurity_question(topic):
        print("SCOPE CHECK: obvious cybersecurity question")
        return True


    try:

        completion = client.chat.completions.create(

            model="openai/gpt-oss-120b",

            messages=[
                {
                    "role": "system",
                    "content": """
You are a strict cybersecurity topic classifier.

Your ONLY job is to determine whether the user's request is related to
CYBERSECURITY.

Return ONLY valid JSON in this exact format:

{"is_cyber": true}

or

{"is_cyber": false}


============================================================
RETURN TRUE FOR CYBERSECURITY QUESTIONS
============================================================

The user's INTENT matters more than the exact words they use.

Cybersecurity includes:

- Cybersecurity
- Online safety
- Cyber fraud
- Online scams
- Financial cyber fraud
- UPI scams
- Unauthorized digital payments
- Account compromise
- Identity theft
- Password security
- Authentication
- MFA / 2FA
- Phishing
- Suspicious links
- Suspicious URLs
- Suspicious websites
- QR-code scams
- Malicious QR codes
- Suspicious emails
- Suspicious SMS/messages
- Malware
- Ransomware
- Viruses
- Spyware
- Trojans
- Keyloggers
- Hacked phones
- Hacked computers
- Compromised devices
- Vulnerabilities
- CVEs
- Web security
- Application security
- Network security
- API security
- Database security
- Cloud security
- Firewalls
- Encryption
- Cryptography
- Penetration testing
- Security testing
- Digital forensics
- Incident response
- Data breaches
- Social engineering
- Privacy/security
- Secure coding


============================================================
IMPORTANT INTENT RULES
============================================================

A question DOES NOT need to contain the word "cybersecurity".

For example:

"I got scammed for 5000 what should I do?"
=> TRUE

"I got fraud of 5000 what should I do?"
=> TRUE

"Someone stole money from my UPI account"
=> TRUE

"My phone is behaving strangely and I think it is hacked"
=> TRUE

"My phone is getting very hot and I see malicious activity. How can I
check whether it has been hacked?"
=> TRUE

"Is this link safe?"
=> TRUE

"Is this URL malicious?"
=> TRUE

"Can this link hack me?"
=> TRUE

"Is this MongoDB URL safe?"
=> TRUE

"I clicked a suspicious link. What should I do?"
=> TRUE

"Is this QR code safe?"
=> TRUE

"I received a suspicious email"
=> TRUE

"Someone accessed my account"
=> TRUE


============================================================
URL / LINK RULE
============================================================

If the user provides a URL or asks about a link, website, domain,
IP address, shortened URL, or similar resource AND their intent is
to determine whether it is safe, legitimate, suspicious, malicious,
phishing, dangerous, or secure:

=> TRUE

Do NOT judge the question based on the website's domain.

For example:

"https://cloud.mongodb.com/... is this link safe?"
=> TRUE

The fact that the URL belongs to MongoDB does NOT make the question
non-cybersecurity.


============================================================
CYBERSECURITY PROGRAMMING
============================================================

Programming questions ARE allowed when the PURPOSE is cybersecurity.

Examples:

"How do I build a phishing URL detector?"
=> TRUE

"How do I make a malware scanner?"
=> TRUE

"How do I check password strength using Python?"
=> TRUE

"How do I implement secure authentication?"
=> TRUE

"How do I scan my application for vulnerabilities?"
=> TRUE

"How do I build a network security tool?"
=> TRUE


============================================================
RETURN FALSE FOR GENERAL PROGRAMMING
============================================================

Generic programming without a cybersecurity purpose is NOT cybersecurity.

Examples:

"How do I reverse a linked list?"
=> FALSE

"How do I sort an array in C++?"
=> FALSE

"How do I write a calculator in Python?"
=> FALSE

"Explain JavaScript"
=> FALSE

"How do I make an HTML website?"
=> FALSE

"How do I create a React app?"
=> FALSE


============================================================
RETURN FALSE FOR UNRELATED QUESTIONS
============================================================

Examples:

"How do I order pizza?"
=> FALSE

"What is the weather?"
=> FALSE

"Tell me a joke"
=> FALSE

"Help me with mathematics"
=> FALSE

"Write an essay"
=> FALSE

"Who is the president?"
=> FALSE


============================================================
FINAL RULE
============================================================

Judge the user's INTENT.

If the user is trying to understand, prevent, detect, investigate,
respond to, or protect against a digital/cybersecurity threat:

=> TRUE

If the request has no meaningful cybersecurity/security purpose:

=> FALSE

Return ONLY the JSON object.
"""
                },
                {
                    "role": "user",
                    "content": topic
                }
            ],

            temperature=0,

            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "cybersecurity_scope",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "is_cyber": {
                                "type": "boolean"
                            }
                        },
                        "required": [
                            "is_cyber"
                        ],
                        "additionalProperties": False
                    }
                }
            },

            max_tokens=50
        )


        result = json.loads(
            completion.choices[0].message.content
        )

        print("SCOPE RESULT:", result)

        return result.get("is_cyber", False)


    except Exception as e:

        print("SCOPE CHECK ERROR:", e)

        # Fail closed.
        return False


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template("index.html")


# ============================================================
# AI GENERATION
# ============================================================

@app.route("/generate", methods=["POST"])
def generate():

    try:

        data = request.get_json()

        if not data:

            return jsonify({
                "answer": "❌ Invalid request."
            }), 400


        topic = data.get("topic", "").strip()


        # ----------------------------------------------------
        # EMPTY QUESTION
        # ----------------------------------------------------

        if not topic:

            return jsonify({
                "answer": "❌ Please enter a cybersecurity question."
            }), 400


        # ----------------------------------------------------
        # CYBERSECURITY SCOPE CHECK
        # ----------------------------------------------------

        cyber_question = is_cybersecurity_question(topic)


        if not cyber_question:

            return jsonify({
                "answer": (
                    "❌ **Cybersecurity questions only.**\n\n"
                    "I’m the **AI CyberSecurity Assistant**, so I can "
                    "only help with cybersecurity-related topics.\n\n"
                    "You can ask me about things like:\n\n"
                    "- 🔗 Malicious or phishing links\n"
                    "- 📱 Suspicious QR codes\n"
                    "- 🛡️ Cybersecurity and online safety\n"
                    "- 🚨 Cyber fraud and scams\n"
                    "- 🔐 Passwords and account security\n"
                    "- 🦠 Malware and ransomware\n"
                    "- 🌐 Network and web security\n"
                    "- 🔎 Vulnerability analysis\n"
                    "- 💻 Secure coding\n"
                    "- 🚑 Cyber incident response\n\n"
                    "Please ask a cybersecurity-related question."
                )
            })


        # ----------------------------------------------------
        # CYBERSECURITY AI
        # ----------------------------------------------------

        completion = client.chat.completions.create(

            model="openai/gpt-oss-120b",

            messages=[
                {
                    "role": "system",
                    "content": """
You are an AI CyberSecurity Assistant.

You ONLY answer cybersecurity-related questions.

The application has already performed a cybersecurity
scope check before sending the question to you.

Stay strictly within the cybersecurity domain.

============================================================
CYBERSECURITY TOPICS
============================================================

- Cyber threats
- Phishing
- Malicious links
- Malicious QR codes
- Cyber fraud
- Online scams
- UPI/payment fraud
- Account security
- Password security
- Authentication
- MFA / 2FA
- Malware
- Ransomware
- Viruses
- Spyware
- Vulnerabilities
- CVEs
- Exploitation
- Web security
- Application security
- Secure coding
- Penetration testing
- Security testing
- Network security
- Firewalls
- VPN security
- Encryption
- Cryptography
- Digital forensics
- Incident response
- Data breaches
- Privacy and security
- OS security
- Cloud security
- API security
- Database security
- DevSecOps
- Social engineering
- Identity theft
- Digital safety
- Device compromise


============================================================
CYBERSECURITY PROGRAMMING
============================================================

Cybersecurity-related programming questions ARE allowed.

Examples:

- Phishing URL detector
- Malicious URL analysis
- Malware scanner
- Password strength checker
- Vulnerability scanner
- Network security scripts
- Security automation
- Secure authentication
- Secure API implementation
- Security monitoring


============================================================
RESPONSE STYLE
============================================================

Always format responses using Markdown.

Rules:

- Use ## headings
- Use bullet points
- Use numbered lists where appropriate
- Use tables if useful
- Put code inside triple backticks
- Leave one blank line between sections
- Never write one huge paragraph
- Explain step-by-step
- Give practical examples
- Use emojis only when helpful


============================================================
DOMAIN RESTRICTION
============================================================

Do not answer unrelated questions.

If the user somehow asks something outside cybersecurity,
politely explain that you can only help with cybersecurity
questions.

Never artificially turn a general question into a cybersecurity
question simply to answer it.
"""
                },
                {
                    "role": "user",
                    "content": topic
                }
            ],

            temperature=0.7,

            max_tokens=2000

        )


        answer = completion.choices[0].message.content


        return jsonify({
            "answer": answer
        })


    except Exception as e:

        print("ERROR:", e)

        return jsonify({
            "answer": f"❌ Error: {str(e)}"
        }), 500


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5004
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )