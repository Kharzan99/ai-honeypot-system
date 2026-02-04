# app/intelligence.py
import re
from typing import List, Dict

# URL regex (http/https/www)
URL_RE = re.compile(r'(https?://[^\s,;]+|www\.[^\s,;]+)', re.IGNORECASE)

# UPI id (common form: name@bank or name@upi). Allow dots, hyphens and digits.
UPI_RE = re.compile(r'\b[A-Za-z0-9._\-]{2,256}@[A-Za-z0-9._\-]{2,40}\b')

# Phone numbers: e.g. +91XXXXXXXXXX or 10-digit sequences
PHONE_RE = re.compile(r'(\+?\d{1,3}[-\s]?)?(?:\d[\d\s\-]{8,}\d)\b')

# Bank account-like numbers: long sequences of digits between 9 and 18 digits
BANK_ACC_RE = re.compile(r'\b\d{9,18}\b')

# Suspicious keywords (can expand later)
SUSPICIOUS_KW = [
    'verify', 'account blocked', 'account will be blocked', 'suspended',
    'upi', 'transfer now', 'send money', 'pay', 'paytm', 'bank account',
    'confirm otp', 'verify now', 'immediately', 'urgent', 'kyc', 'refund',
    'payment pending', 'award', 'prize', 'won', 'claim', 'suspend'
]

def unique_list(lst: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in lst:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out

def extract_urls(text: str) -> List[str]:
    return unique_list([m.group(0).strip('.,;') for m in URL_RE.finditer(text)])

def extract_upi_ids(text: str) -> List[str]:
    return unique_list([m.group(0) for m in UPI_RE.finditer(text)])

def extract_phone_numbers(text: str) -> List[str]:
    # Normalize phone: remove spaces/hyphens
    nums = []
    for m in PHONE_RE.finditer(text):
        raw = m.group(0)
        cleaned = re.sub(r'[\s\-]', '', raw)
        # keep plausible phone numbers (10-15 digits)
        digits = re.sub(r'\D', '', cleaned)
        if 8 <= len(digits) <= 15:
            nums.append('+' + digits if (len(digits) > 10 and not cleaned.startswith('+')) else digits)
    return unique_list(nums)

def extract_bank_accounts(text: str) -> List[str]:
    return unique_list([m.group(0) for m in BANK_ACC_RE.finditer(text)])

def extract_suspicious_keywords(text: str) -> List[str]:
    lower = text.lower()
    found = [kw for kw in SUSPICIOUS_KW if kw in lower]
    return unique_list(found)

def extract_all(text: str) -> Dict[str, List[str]]:
    """
    Run all extractors on raw/original text (not cleaned).
    Returns dict keys: phishingLinks, upiIds, phoneNumbers, bankAccounts, suspiciousKeywords
    """
    if not isinstance(text, str):
        text = str(text or "")
    urls = extract_urls(text)
    upis = extract_upi_ids(text)
    phones = extract_phone_numbers(text)
    banks = extract_bank_accounts(text)
    kws = extract_suspicious_keywords(text)
    return {
        "phishingLinks": urls,
        "upiIds": upis,
        "phoneNumbers": phones,
        "bankAccounts": banks,
        "suspiciousKeywords": kws
    }
