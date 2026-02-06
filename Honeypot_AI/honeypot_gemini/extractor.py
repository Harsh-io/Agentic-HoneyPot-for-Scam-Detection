"""
Intelligence Extraction Module
==============================
Extracts sensitive information from scam messages and conversations:
- Bank Account Numbers
- UPI IDs
- Phone Numbers
- Phishing Links
- Email Addresses

Part of the Agentic Honeypot for Scam Detection system.
"""

import re
from typing import Dict, List, Any


# ---------------------------------------------------------------------------
# Regex Patterns for Intelligence Extraction
# ---------------------------------------------------------------------------

# Indian Bank Account Number: 9-18 digits
BANK_ACCOUNT_PATTERN = r'\b\d{9,18}\b'

# UPI ID: username@bankcode (e.g., user@paytm, 9876543210@ybl)
UPI_ID_PATTERN = r'\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b'

# Indian Phone Numbers: +91, 91, or 10-digit starting with 6-9
PHONE_PATTERN = r'(?:\+91[\-\s]?|91[\-\s]?)?[6-9]\d{9}\b'

# URLs/Phishing Links
URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+'

# Short URLs (common in scams)
SHORT_URL_PATTERN = r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|buff\.ly|ow\.ly|rebrand\.ly)/[a-zA-Z0-9]+\b'

# Email addresses
EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

# IFSC Code (Indian Financial System Code)
IFSC_PATTERN = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'


# ---------------------------------------------------------------------------
# Extraction Functions
# ---------------------------------------------------------------------------

def extract_bank_accounts(text: str) -> List[str]:
    """
    Extract potential bank account numbers from text.
    
    Indian bank accounts are typically 9-18 digits.
    Filters out numbers that look like phone numbers.
    """
    # Find all digit sequences
    matches = re.findall(BANK_ACCOUNT_PATTERN, text)
    
    # Filter: exclude 10-digit numbers starting with 6-9 (likely phone numbers)
    filtered = []
    for match in matches:
        # Skip if it looks like a phone number
        if len(match) == 10 and match[0] in '6789':
            continue
        # Skip very short numbers (likely not account numbers)
        if len(match) < 9:
            continue
        filtered.append(match)
    
    return list(set(filtered))  # Remove duplicates


def extract_upi_ids(text: str) -> List[str]:
    """
    Extract UPI IDs from text.
    
    Format: username@provider (e.g., merchant@paytm, 9876543210@ybl)
    """
    matches = re.findall(UPI_ID_PATTERN, text, re.IGNORECASE)
    
    # Filter out common email domains to avoid false positives
    email_domains = {'gmail', 'yahoo', 'hotmail', 'outlook', 'proton', 'mail'}
    filtered = [
        m for m in matches 
        if m.split('@')[1].lower() not in email_domains
    ]
    
    return list(set(filtered))


def extract_phone_numbers(text: str) -> List[str]:
    """
    Extract Indian phone numbers from text.
    
    Handles formats: +91XXXXXXXXXX, 91XXXXXXXXXX, XXXXXXXXXX
    """
    matches = re.findall(PHONE_PATTERN, text)
    
    # Normalize: extract just the 10 digits
    normalized = []
    for match in matches:
        # Remove +91, 91, spaces, hyphens
        digits = re.sub(r'[\+\s\-]', '', match)
        if digits.startswith('91') and len(digits) > 10:
            digits = digits[2:]
        if len(digits) == 10:
            normalized.append(digits)
    
    return list(set(normalized))


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs and phishing links from text.
    
    Includes regular URLs and common URL shorteners.
    """
    urls = re.findall(URL_PATTERN, text, re.IGNORECASE)
    short_urls = re.findall(SHORT_URL_PATTERN, text, re.IGNORECASE)
    
    all_urls = list(set(urls + short_urls))
    return all_urls


def extract_emails(text: str) -> List[str]:
    """
    Extract email addresses from text.
    """
    matches = re.findall(EMAIL_PATTERN, text, re.IGNORECASE)
    return list(set(matches))


def extract_ifsc_codes(text: str) -> List[str]:
    """
    Extract IFSC codes from text.
    
    Format: 4 letters + 0 + 6 alphanumeric (e.g., SBIN0001234)
    """
    matches = re.findall(IFSC_PATTERN, text)
    return list(set(matches))


# ---------------------------------------------------------------------------
# Main Extraction Function
# ---------------------------------------------------------------------------

def extract_intelligence(text: str) -> Dict[str, Any]:
    """
    Extract all intelligence from a text message or conversation.
    
    Args:
        text: The message or conversation text to analyze
        
    Returns:
        Dictionary containing all extracted intelligence:
        {
            "bank_accounts": [...],
            "upi_ids": [...],
            "phone_numbers": [...],
            "phishing_links": [...],
            "emails": [...],
            "ifsc_codes": [...],
            "has_intelligence": bool
        }
    """
    if not text or not isinstance(text, str):
        return {
            "bank_accounts": [],
            "upi_ids": [],
            "phone_numbers": [],
            "phishing_links": [],
            "emails": [],
            "ifsc_codes": [],
            "has_intelligence": False
        }
    
    bank_accounts = extract_bank_accounts(text)
    upi_ids = extract_upi_ids(text)
    phone_numbers = extract_phone_numbers(text)
    phishing_links = extract_urls(text)
    emails = extract_emails(text)
    ifsc_codes = extract_ifsc_codes(text)
    
    # Check if any intelligence was found
    has_intelligence = bool(
        bank_accounts or upi_ids or phone_numbers or 
        phishing_links or emails or ifsc_codes
    )
    
    return {
        "bank_accounts": bank_accounts,
        "upi_ids": upi_ids,
        "phone_numbers": phone_numbers,
        "phishing_links": phishing_links,
        "emails": emails,
        "ifsc_codes": ifsc_codes,
        "has_intelligence": has_intelligence
    }


# ---------------------------------------------------------------------------
# Module Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Test messages
    test_messages = [
        "Send money to my account 1234567890123456 IFSC: SBIN0001234",
        "Pay via UPI: scammer@paytm or call 9876543210",
        "Click here: https://bit.ly/fakebank to verify your account",
        "Transfer to account 50100123456789, contact: +91 98765 43210",
        "Normal message without any sensitive info",
        "Pay me at merchant@ybl, my number is 8765432109, account: 123456789012"
    ]
    
    print("=" * 60)
    print("Intelligence Extraction Test")
    print("=" * 60)
    
    for msg in test_messages:
        print(f"\nMessage: {msg[:50]}...")
        result = extract_intelligence(msg)
        print(f"Result: {result}")
