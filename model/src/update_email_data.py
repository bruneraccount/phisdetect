import gzip
import json
import os
import random
import re
import sys
import tarfile
import mailbox

from email_text_features import extract_parts, record_text

HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(HERE)
DATA = os.path.join(_ROOT, "data")
PHISH_MBOXES = [
    os.path.join(DATA, "phishing0.mbox"),
    os.path.join(DATA, "phishing1.mbox"),
    os.path.join(DATA, "phishing2.mbox"),
    os.path.join(DATA, "phishing3.mbox"),
]
PHISH_URLS = {
    f"phishing{i}.mbox": f"https://monkey.org/~jose/phishing/phishing{i}.mbox"
    for i in range(4)
}
EASY_HAM = os.path.join(DATA, "easy_ham.tar.bz2")
ENRON_TGZ = os.path.join(DATA, "enron.tgz")
OUT = os.path.join(DATA, "email_text_dataset.jsonl")
EASY_HAM_URL = "https://spamassassin.apache.org/old/publiccorpus/20021010_easy_ham.tar.bz2"

URGENT_PHRASES = [
    "urgent", "immediately", "act now", "verify your account", "verify your identity",
    "suspended", "account locked", "unusual activity", "security alert", "password expired",
    "click here", "you have won", "claim your prize", "limited time", "update your payment",
    "confirm your details", "your account will be closed",
]
BRANDS = ["PayPal", "Apple", "Microsoft", "Netflix", "Amazon", "eBay", "Chase", "Bank of America",
          "Google", "Facebook", "LinkedIn", "Coinbase", "Binance", "Wells Fargo", "Citibank"]

SYNTH_PHISH_SUBJECTS = [
    "Urgent action required - account suspended", "Your payment method needs updating",
    "We detected unusual activity on your account", "Claim your prize today",
    "Your account will be closed in 24 hours", "Password expired - reset now",
    "Security alert: login from a new device", "Confirm your identity immediately",
    "Invoice overdue - pay now", "Your package is on hold",
]
SYNTH_PHISH_BODIES = [
    "Dear user, we have detected unusual activity on your account. Click here immediately to "
    "verify your identity or your account will be closed within 24 hours. This is an urgent "
    "security alert, please act now and confirm your details.",
    "Hello customer, your payment method has failed and your subscription is suspended. "
    "Update your payment information right away by clicking the link below. Limited time "
    "offer - act now before your account is locked.",
    "Dear account holder, you have won a prize of $1,000,000. Claim your prize today by "
    "confirming your bank details. Hurry, this is a limited time offer and your winnings "
    "expire soon. Do not tell anyone about this email.",
    "Dear member, our records show unusual activity on your account from a new device. "
    "Please verify your identity immediately by clicking here and entering your password. "
    "If you do not act now your account will be suspended for security reasons.",
    "We are writing to inform you that your password has expired. You must reset your "
    "password immediately to continue using our service. Click here to update your password "
    "and confirm your details within 24 hours or your account will be closed.",
]
SYNTH_BENIGN_SUBJECTS = [
    "Re: budget meeting notes", "Weekly status update", "Lunch plans for Friday",
    "Project timeline discussion", "Invoice #4521 attached", "Team offsite agenda",
    "Question about the report", "Updated contact list", "Reminder: standup at 9",
    "Follow up from yesterday",
]
SYNTH_BENIGN_BODIES = [
    "Hi Alex, thanks for sending over the notes from yesterday. I had a look at the budget "
    "and I think the numbers for Q3 need a small adjustment. Let me know when you have time "
    "to discuss. Best, Sarah",
    "Hello everyone, the weekly status update is now available in the shared folder. Please "
    "review the project timeline before tomorrow's meeting and add any comments. Thanks, "
    "Mark",
    "Hi, are we still on for lunch on Friday at the usual place? I can book a table for 12 "
    "if you want. Let me know what you think. Cheers, Daniel",
    "Team, the client asked for a revised estimate on the migration project. I have attached "
    "the updated spreadsheet with the new hourly rates. Please take a look and share your "
    "feedback by end of week. Regards, Priya",
    "Hi John, I just spoke with the vendor and they confirmed delivery for next Tuesday. "
    "Could you prepare the receiving dock and update the inventory sheet? Appreciate your "
    "help. Thanks, Linda",
    "All, reminder that the standup is at 9am instead of 10 this week due to the holiday "
    "schedule. See you then. Best regards, Tom",
]


def _norm_header_text(raw):
    lines = []
    for line in raw.splitlines():
        if not line.strip() or line.startswith(">"):
            continue
        lines.append(re.sub(r"\s+", " ", line.strip()))
    return "\n".join(lines)


def _enron_mailbox_names():
    return [
        "allen-p", "arnold-j", "arora-h", "bass-e", "baughman-d", "beck-s", "benson-r",
        "campbell-l", "cash-m", "chambers-j", "clark-k", "corman-s", "cuilla-m", "dasovich-j",
        "davis-d", "deitrich-j", "delainey-d", "derrick-j", "dockter-t", "epps-j", "farmer-d",
        "fossum-d", "gay-r", "germany-c", "giron-d", "grigsby-m", "haedicke-m", "hain-m",
        "hayslett-r", "hearn-j", "hendrickson-s", "hernandez-j", "hodge-k", "holst-k",
        "horton-s", "hyatt-k", "kaminski-v", "kean-s", "keavey-d", "kenneth-c", "kerr-k",
        "kitchen-l", "lavorato-j", "lay-k", "lenhart-m", "lokay-m", "love-p", "lucci-p",
        "manning-d", "mark-taylor", "martin-t", "mccarty-d", "mcconnell-m", "mckay-m",
        "mckee-m", "mehta-v", "menard-c", "meyers-c", "mitchell-d", "moncrief-k", "moore-b",
        "myers-m", "nemec-g", "nolte-m", "okeefe-m", "panus-s", "parks-j", "perlingiere-k",
        "phillip-m", "pritchard-d", "quisling-g", "redmond-b", "reitmeyer-j", "ring-r",
        "roberts-c", "roderick-d", "rohr-e", "saibi-e", "sager-e", "sanchez-m", "schneider-e",
        "shackleton-s", "shankman-j", "shively-h", "smith-m", "solberg-g", "sosa-d",
        "springman-m", "stanton-b", "steffes-j", "stokley-c", "stone-r", "sturgeon-p",
        "swerzbin-m", "taylor-m", "thomas-p", "tholt-j", "tian-j", "townsend-j", "tracy-m",
        "tycholiz-m", "upchurch-h", "vanroekel-j", "vickers-d", "waanders-t", "weber-j",
        "west-p", "whalley-g", "williams-j", "williams-w", "winkelman-d", "withers-t",
        "wolf-d", "woodward-d", "worker-c", "wright-j", "zylicz-m",
    ]


def load_phishing():
    texts = []
    seen = set()
    for mbox_path in PHISH_MBOXES:
        if not (os.path.exists(mbox_path) and os.path.getsize(mbox_path) > 10000):
            continue
        try:
            box = mailbox.mbox(mbox_path)
            count = 0
            for msg in box:
                try:
                    subject, body = extract_parts(msg.as_string())
                    record = record_text(subject, body)
                    key = re.sub(r"\s+", "", record)[:400]
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    texts.append(record)
                    count += 1
                except Exception:
                    continue
            print(f"phishing: {count} emails from {os.path.basename(mbox_path)}")
        except Exception as e:
            print(f"phishing mbox parse failed ({os.path.basename(mbox_path)}): {e}")
    if not texts:
        texts = _synthetic_phish(400)
        print("phishing: synthetic fallback (400)")
    return texts


def load_enron():
    texts = []
    seen = set()
    if os.path.exists(EASY_HAM) and os.path.getsize(EASY_HAM) > 10000:
        try:
            with tarfile.open(EASY_HAM, "r:bz2") as tf:
                for member in tf.getmembers():
                    if not member.isfile() or member.name.startswith("."):
                        continue
                    raw = tf.extractfile(member).read().decode("latin-1", "ignore")
                    subject, body = extract_parts(raw)
                    record = record_text(subject, body)
                    key = re.sub(r"\s+", "", record)[:400]
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    if len(body) > 200:
                        texts.append(record)
                    if len(texts) >= 2500:
                        break
            print(f"benign: {len(texts)} emails from easy_ham (SpamAssassin)")
        except Exception as e:
            print(f"easy_ham parse failed ({e}); using synthetic")
            texts = []
    if not texts and os.path.exists(ENRON_TGZ) and os.path.getsize(ENRON_TGZ) > 10_000_000:
        try:
            names = set(_enron_mailbox_names())
            chosen = random.sample(sorted(names), min(15, len(names)))
            want = {f"maildir/{name}/" for name in chosen}
            count = 0
            with tarfile.open(ENRON_TGZ, "r:gz") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue
                    path = member.name.replace("\\", "/")
                    if not any(path.startswith(w) for w in want):
                        continue
                    if not path.lower().endswith((".txt", ".eml")):
                        continue
                    raw = tf.extractfile(member).read().decode("latin-1", "ignore")
                    body = _norm_header_text(raw)
                    if len(body) > 200:
                        texts.append(body)
                        count += 1
                    if count >= 2500:
                        break
            print(f"benign: {len(texts)} emails from Enron ({chosen})")
        except Exception as e:
            print(f"enron parse failed ({e}); using synthetic")
            texts = []
    if not texts:
        texts = _synthetic_benign(500)
        print("benign: synthetic fallback (500)")
    return texts


def _synthetic_phish(n):
    out = []
    for _ in range(n):
        brand = random.choice(BRANDS)
        subj = random.choice(SYNTH_PHISH_SUBJECTS)
        body = random.choice(SYNTH_PHISH_BODIES)
        link = random.choice([
            f"http://{brand.lower()}-{random.randint(100, 999)}.xyz/verify",
            f"http://{brand.lower()}.com.{random.choice(['xyz', 'top', 'link', 'site'])}/login",
            "http://secure-login-verify.tk/account/confirm.php?id=98213",
        ])
        sender = f"{random.choice(['security', 'support', 'billing', 'accounts'])}@{random.choice(BRANDS).lower()}-verify.net"
        out.append(record_text(
            subj,
            f"{body}\n\nPlease click here: {link} and follow the instructions. "
            f"Your account will be closed otherwise."))
    return out


def _synthetic_benign(n):
    out = []
    for _ in range(n):
        subj = random.choice(SYNTH_BENIGN_SUBJECTS)
        body = random.choice(SYNTH_BENIGN_BODIES)
        sender = f"{random.choice(['sarah', 'mark', 'linda', 'tom', 'priya', 'daniel'])}@example.com"
        out.append(record_text(subj, body))
    return out


NAMES = ["Aditya", "Alex", "Priya", "Daniel", "Sara", "Tom", "Lina", "Michael", "Ravi", "Emily"]
DEVICES = ["Windows 11 desktop", "MacBook Pro", "iPhone 15", "Pixel 8", "iPad",
           "Samsung Galaxy S24", "Chrome on Linux", "Safari on macOS"]
CITIES = ["San Francisco, CA", "Austin, TX", "Toronto, Canada", "London, UK", "Berlin, Germany",
          "Singapore", "Sydney, Australia", "Amsterdam, Netherlands"]
MODERN_BRANDS = ["Microsoft", "Apple", "Google", "Netflix", "LinkedIn", "Dropbox", "Spotify", "Adobe"]
PHISH_BRANDS = ["PayPal", "Microsoft", "Apple", "Netflix", "Amazon", "Chase", "Coinbase", "Binance",
                "Wells Fargo", "eBay", "DocuSign", "FedEx", "UPS"]


def _benign_signin(rng):
    name = rng.choice(NAMES)
    brand = rng.choice(MODERN_BRANDS)
    device = rng.choice(DEVICES)
    city = rng.choice(CITIES)
    t = rng.choice(["2:14 PM", "9:37 AM", "11:05 PM", "4:22 AM", "1:48 PM"])
    subj = rng.choice([
        f"Sign-in review for your {brand} account",
        f"New sign-in to your {brand} account",
        f"Security update: sign-in detected on a {device}",
    ])
    body = rng.choice([
        f"Hi {name}, a new sign-in to your {brand} account was detected on {device} at {t} from {city}. "
        f"If this was you, no further action is needed. Otherwise visit the security settings page of "
        f"your account to review active sessions and end any you do not recognize. Thanks, The {brand} Team",
        f"Hello {name}, we noticed a successful sign-in to your {brand} account at {t} using {device} "
        f"from {city}. If this was your activity, you can ignore this message. If not, review your "
        f"recent account activity and update your password from the security dashboard. Best regards, "
        f"{brand} Account Security",
    ])
    return record_text(subj, body)


def _benign_code(rng):
    name = rng.choice(NAMES)
    brand = rng.choice(MODERN_BRANDS)
    code = rng.randint(100000, 999999)
    subj = rng.choice([f"Your {brand} verification code", f"Security code for {brand}"])
    body = rng.choice([
        f"Hi {name}, your {brand} verification code is {code}. This code expires in 10 minutes. "
        f"If you did not request it, no one will be able to sign in without the code, so you can "
        f"ignore this email. Thanks, {brand} Security",
        f"Hello {name}, use the code {code} to complete the security verification for your {brand} "
        f"account. Do not share this code with anyone. If you did not ask for this code you can "
        f"disregard the message. Regards, The {brand} Team",
    ])
    return record_text(subj, body)


def _benign_reset(rng):
    name = rng.choice(NAMES)
    brand = rng.choice(MODERN_BRANDS)
    subj = rng.choice([f"Your {brand} password has been changed",
                       f"Confirmation: password reset for {brand}"])
    body = rng.choice([
        f"Hi {name}, the password for your {brand} account was successfully changed. If you made "
        f"this change, no further action is needed. If you did not, please contact our support team "
        f"as soon as possible. Sincerely, {brand} Security",
        f"Hello {name}, this confirms that your {brand} account password was updated. We recommend "
        f"using a unique password for each account. If this was not you, reset your password again "
        f"and enable two-step verification. Thank you, The {brand} Team",
    ])
    return record_text(subj, body)


def _benign_order(rng):
    name = rng.choice(NAMES)
    item = rng.choice(["a pair of wireless headphones", "an office chair", "a 4K monitor",
                       "a mechanical keyboard", "a desk lamp", "running shoes"])
    order = rng.randint(10000000, 99999999)
    subj = rng.choice([f"Your order {order} has shipped", f"Order confirmation {order}"])
    body = rng.choice([
        f"Hi {name}, good news! Your order {order} containing {item} has shipped and is on its way. "
        f"Delivery is expected within 3 to 5 business days. You can track your package on our website. "
        f"Thank you for shopping with us, The Store Team",
        f"Hello {name}, thank you for your purchase. Order {order} with {item} is confirmed and is "
        f"being prepared for shipment. You will receive an email when it leaves our warehouse. "
        f"Thanks again, Customer Service",
    ])
    return record_text(subj, body)


def _benign_receipt(rng):
    name = rng.choice(NAMES)
    brand = rng.choice(MODERN_BRANDS)
    amount = rng.choice(["9.99", "12.49", "19.99", "24.99", "49.00"])
    subj = rng.choice([f"Your receipt from {brand}", f"Thanks for your {brand} subscription"])
    body = rng.choice([
        f"Hi {name}, this is your receipt for your {brand} subscription. Amount charged: ${amount}. "
        f"If you have any questions about this charge, visit the billing page in your account settings. "
        f"Thanks for being a customer, {brand} Billing",
        f"Hello {name}, thank you for your recent purchase with {brand}. Your total was ${amount} and "
        f"your payment method was charged successfully. A detailed invoice is available in your "
        f"account dashboard. Regards, {brand} Finance Team",
    ])
    return record_text(subj, body)


def _benign_conference(rng):
    name = rng.choice(NAMES)
    conf = rng.choice(["the International Conference on Machine Learning", "DevConf 2026",
                       "the Annual Developer Summit", "the Cloud Infrastructure Symposium"])
    city = rng.choice(CITIES)
    subj = rng.choice([f"Registration open: {conf}", f"Call for papers: {conf}"])
    body = rng.choice([
        f"Dear {name}, we are pleased to announce that registration for {conf} is now open. The "
        f"event will take place in {city} this October. Early bird pricing ends next month. You can "
        f"find the full program and venue details on our website. We hope to see you there, The "
        f"Organizing Committee",
        f"Hello {name}, the program committee invites you to submit a talk for {conf}. Submissions "
        f"are welcome until the end of the month and notifications go out in September. Travel "
        f"grants are available for students. Questions can be sent to the committee chair. Best "
        f"wishes, {conf} Program Committee",
    ])
    return record_text(subj, body)


def _benign_team(rng):
    name = rng.choice(NAMES)
    topic = rng.choice(["the Q3 roadmap", "the migration plan", "the release schedule",
                        "the onboarding checklist", "the quarterly budget"])
    day = rng.choice(["Monday", "Wednesday", "Thursday", "Friday"])
    subj = rng.choice([f"Re: {topic}", f"Notes on {topic}", f"Reminder: meeting about {topic}"])
    body = rng.choice([
        f"Hi {name}, thanks for the notes on {topic}. I reviewed them and the plan looks good, with "
        f"a couple of small adjustments. Let's go over the changes in the standup on {day} if you "
        f"have time. Best, Sarah",
        f"Hello {name}, a quick reminder that we will discuss {topic} on {day} at 2pm. Please add any "
        f"items you would like to cover to the shared agenda ahead of the meeting. Thanks, Mark",
        f"Hi {name}, I wanted to follow up on {topic}. I have updated the shared document with my "
        f"comments and proposed a few next steps. Take a look when you get a chance and let me know "
        f"if you agree. Regards, Priya",
    ])
    return record_text(subj, body)


def _benign_newsletter(rng):
    name = rng.choice(NAMES)
    topic = rng.choice(["machine learning", "frontend engineering", "data science", "cybersecurity"])
    subj = rng.choice([f"{topic.title()} monthly digest", f"What's new in {topic} this month"])
    body = rng.choice([
        f"Hi {name}, welcome to this month's digest on {topic}. Inside you will find curated articles, "
        f"practical tutorials, and a roundup of the latest community discussions. If you enjoy the "
        f"content, share it with a colleague. Happy reading, The {topic.title()} Newsletter",
        f"Hello {name}, here is your monthly update for {topic}. We highlight the three most-read "
        f"articles, a hands-on tutorial, and links to upcoming live sessions. You can manage your "
        f"subscription preferences at any time. Thanks for subscribing, The Editorial Team",
    ])
    return record_text(subj, body)


def _benign_alert(rng):
    name = rng.choice(NAMES)
    brand = rng.choice(MODERN_BRANDS)
    subj = rng.choice([f"Update on recent activity for your {brand} account",
                       f"We blocked a sign-in attempt on your {brand} account"])
    body = rng.choice([
        f"Hi {name}, as a precaution we temporarily locked a sign-in attempt to your {brand} account "
        f"because the credentials entered did not match. No action is required from you right now. "
        f"If you have questions, review your account activity at your convenience. Best, {brand} "
        f"Security",
        f"Hello {name}, our system prevented a sign-in that used an incorrect password on your {brand} "
        f"account. The attempt did not succeed and no changes were made. If that was you, you can sign "
        f"in normally. If not, we recommend reviewing your security settings. Thanks, The {brand} Team",
    ])
    return record_text(subj, body)


def _modern_benign(n, rng):
    builders = [_benign_signin, _benign_code, _benign_reset, _benign_order, _benign_receipt,
                _benign_conference, _benign_team, _benign_newsletter, _benign_alert]
    return [rng.choice(builders)(rng) for _ in range(n)]


def _phish_suspended(rng):
    brand = rng.choice(PHISH_BRANDS)
    subj = rng.choice([f"[Action Required] Your {brand} account has been suspended",
                       f"URGENT: {brand} account restricted",
                       f"Your {brand} account will be closed in 24 hours"])
    body = rng.choice([
        f"Dear user, we recently detected several unusual login attempts to your {brand} account "
        f"from different locations. Because these attempts could not be verified, your account has "
        f"been placed under temporary restrictions. To prevent permanent suspension you must verify "
        f"your account ownership within the next 24 hours by clicking the link and confirming your "
        f"full name, email, password and phone number. Failure to complete verification will result "
        f"in permanent closure of your account and loss of all data.",
        f"Dear valued member, due to suspicious activity your {brand} account has been locked. Our "
        f"security system determined there is a high probability someone obtained access to your "
        f"credentials. Verify your identity immediately to avoid permanent suspension. You will be "
        f"asked to confirm your email address, password, and recovery information. Please act now, "
        f"your account will be terminated if you do not respond within 12 hours.",
    ])
    sender = f"{rng.choice(['security', 'account', 'support'])}@{brand.lower()}-secure.com"
    return record_text(subj, body)


def _phish_payment(rng):
    brand = rng.choice(PHISH_BRANDS)
    amount = rng.choice(["99.99", "249.99", "12.99", "59.99"])
    subj = rng.choice([f"Your {brand} payment method needs updating",
                       f"Payment failed for your {brand} subscription"])
    body = rng.choice([
        f"Dear customer, your latest payment of ${amount} for your {brand} subscription could not "
        f"be processed. To continue using the service your account has been put on hold. Update your "
        f"billing details immediately using the secure link, otherwise your subscription will be "
        f"cancelled. Please confirm your card number, expiry date, CVV and billing address.",
        f"Hello, we were unable to charge your {brand} account. Your services will be suspended "
        f"unless you confirm your credit card details right away. Click the link to re-enter your "
        f"payment information and reactivate your account. This is an automated notice, do not "
        f"ignore it or you will lose access permanently.",
    ])
    return record_text(subj, body)


def _phish_unusual(rng):
    brand = rng.choice(PHISH_BRANDS)
    subj = rng.choice([f"We detected unusual activity on your {brand} account",
                       f"Security alert: unauthorized access to your {brand} account"])
    body = rng.choice([
        f"Dear user, we have detected suspicious activity on your {brand} account from an unknown "
        f"device. As a security measure your account has been locked. Confirm your identity by "
        f"clicking the verification link and entering your username and password, otherwise your "
        f"account will be permanently deactivated within 48 hours.",
        f"Important security alert, someone tried to sign in to your {brand} account from an "
        f"unrecognized location. Verify it was you before your account is suspended. Follow the "
        f"link below and enter your login details to confirm ownership. If you do not verify within "
        f"24 hours your account and funds will be frozen.",
    ])
    return record_text(subj, body)


def _phish_prize(rng):
    brand = rng.choice(PHISH_BRANDS)
    amt = rng.choice(["1,000,000", "500,000", "250,000"])
    subj = rng.choice([f"CONGRATULATIONS! You have won ${amt}", f"You are a winner: ${amt} prize"])
    body = rng.choice([
        f"Dear lucky winner, congratulations you have been selected to receive ${amt} from the "
        f"{brand} promotion. To claim your prize you must confirm your bank account details and a "
        f"processing fee of $150 must be paid. This offer expires soon and your winnings will be "
        f"forfeited if you do not respond immediately. Keep this email confidential.",
        f"We are pleased to inform you that your email address won ${amt} in our annual draw. To "
        f"release the funds please provide your full name, address and bank routing information. "
        f"Note that a small transfer fee is required. Reply within 24 hours or the prize will be "
        f"given to another participant.",
    ])
    return record_text(subj, body)


def _phish_delivery(rng):
    carrier = rng.choice(["FedEx", "UPS", "DHL", "USPS"])
    subj = rng.choice([f"Your {carrier} package is waiting", f"{carrier}: delivery attempt failed"])
    body = rng.choice([
        f"Dear customer, your {carrier} package could not be delivered because of incorrect "
        f"shipping information. Please confirm your delivery address and pay the rescheduling fee "
        f"of $1.99 within 24 hours to avoid the package being returned to sender. Enter your card "
        f"details to complete the redelivery.",
        f"Hello, your {carrier} shipment is on hold. To release the parcel you must confirm your "
        f"address and verify your payment method. Failure to do so will result in the package being "
        f"sent back. Use the link to update your details immediately.",
    ])
    return record_text(subj, body)


def _phish_docs(rng):
    subj = rng.choice([f"DocuSign: document ready for your signature",
                       f"Electronic signature required - action needed"])
    body = rng.choice([
        f"Dear {rng.choice(NAMES)}, a document is waiting for your electronic signature. You have "
        f"48 hours to review and sign the document before it expires. Click the secure link to view "
        f"the file and sign using your email and password. This is an automated message, replies "
        f"are not monitored.",
        f"Hello, the attached agreement requires your immediate signature. If you do not sign the "
        f"document within 24 hours your request will be cancelled. Authenticate with your email "
        f"address and password to open the document. Do not share this email with anyone.",
    ])
    return record_text(subj, body)


def _phish_hr(rng):
    subj = rng.choice([f"HR update: confirm your benefits enrollment",
                       f"Action required: update your employee details"])
    body = rng.choice([
        f"Dear employee, our records show your benefits enrollment is incomplete. You must confirm "
        f"your personal information including your social security number and bank account before "
        f"the deadline, otherwise your benefits will be cancelled. Complete the form via the link "
        f"below using your work email and password.",
        f"Attention all staff, the HR portal requires you to re-verify your identity this week. "
        f"Login with your employee email and password and confirm your social security number to "
        f"avoid a hold on your next paycheck. Do this immediately, failure to comply will delay "
        f"your salary.",
    ])
    return record_text(subj, body)


def _phish_crypto(rng):
    exchange = rng.choice(["Coinbase", "Binance", "Kraken", "MetaMask"])
    subj = rng.choice([f"Your {exchange} wallet needs verification",
                       f"Withdrawal pending on your {exchange} account"])
    body = rng.choice([
        f"Dear member, a withdrawal of your {exchange} balance has been requested. To proceed, you "
        f"must verify your wallet by confirming your login password and recovery phrase. If this "
        f"request was not made by you, verify your account within 12 hours to prevent the "
        f"transaction from completing.",
        f"Hello, your {exchange} account has been flagged for a security review. Funds have been "
        f"temporarily frozen. Unlock your account by re-confirming your credentials and 2FA codes. "
        f"Failure to verify within 24 hours will result in your account being closed and funds "
        f"transferred to our retention wallet.",
    ])
    return record_text(subj, body)


def _phish_invoice(rng):
    amount = rng.choice(["450.00", "1,299.00", "780.50"])
    subj = rng.choice([f"Invoice {rng.randint(10000, 99999)} is overdue",
                       f"FINAL NOTICE: unpaid invoice"])
    body = rng.choice([
        f"Dear customer, invoice number {rng.randint(10000, 99999)} for ${amount} is now overdue. "
        f"Your account will be sent to collections if the amount is not paid within 24 hours. "
        f"Download the invoice and confirm your payment details via the link to settle the balance "
        f"immediately.",
        f"Hello, this is a final reminder that your outstanding balance of ${amount} remains unpaid. "
        f"To avoid legal action you must pay now. Enter your credit card information through the "
        f"secure portal to make a payment. Payment must be received today.",
    ])
    return record_text(subj, body)


def _modern_phish(n, rng):
    builders = [_phish_suspended, _phish_payment, _phish_unusual, _phish_prize, _phish_delivery,
                _phish_docs, _phish_hr, _phish_crypto, _phish_invoice]
    return [rng.choice(builders)(rng) for _ in range(n)]


def main():
    os.makedirs(DATA, exist_ok=True)
    rng = random.Random(42)
    phish = load_phishing()
    benign = load_enron()
    modern_phish = _modern_phish(4000, rng)
    modern_benign = _modern_benign(4000, rng)
    phish = phish + modern_phish
    benign = benign + modern_benign
    n = min(len(phish), len(benign))
    if n == 0:
        print("no data available at all")
        return 1
    random.seed(42)
    phish = random.sample(phish, n)
    benign = random.sample(benign, n)
    with open(OUT, "w") as f:
        for text in phish:
            f.write(json.dumps({"text": text, "label": 1}) + "\n")
        for text in benign:
            f.write(json.dumps({"text": text, "label": 0}) + "\n")
    print(f"wrote {OUT}: {n} phish + {n} benign (real phish {len(phish)} incl modern {len(modern_phish)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
