"""
Agentic Honeypot Module - GUVI Hackathon Version
=================================================
An autonomous AI agent that:
1. Detects scam messages
2. Engages scammers with a believable persona
3. Extracts intelligence (bank accounts, UPI IDs, links)
4. Reports results to GUVI callback endpoint

Uses Google Gemini for intelligent conversation generation.
"""

import os
import json
import re
import requests
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime

from dotenv import load_dotenv
from google import genai

from detector import detect_scam
from extractor import extract_intelligence

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    print("[WARNING] GEMINI_API_KEY not found - using fallback responses")

# Initialize Gemini client only if API key exists
client = None
if GEMINI_API_KEY:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as e:
        print(f"[WARNING] Failed to initialize Gemini client: {e}")

MODEL_NAME = "gemini-2.0-flash"

# GUVI Callback endpoint
GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# Suspicious keywords for extraction
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify now", "account blocked", "KYC", "OTP", 
    "lottery", "winner", "prize", "blocked", "suspended",
    "immediately", "verify", "click here", "link", "expire"
]

# ---------------------------------------------------------------------------
# Honeypot Personas (Believable Victim Profiles)
# ---------------------------------------------------------------------------

PERSONAS = {
    "elderly_uncle": {
        "name": "Ramesh Kumar",
        "age": 62,
        "occupation": "Retired Bank Manager",
        "characteristics": [
            "Trusting and polite",
            "Slightly confused by technology",
            "Has savings but cautious",
            "Asks for reassurance",
            "Types slowly with some typos"
        ],
        "style": "Polite, uses 'beta' and 'ji', asks clarifying questions"
    },
    "curious_housewife": {
        "name": "Sunita Sharma",
        "age": 45,
        "occupation": "Homemaker",
        "characteristics": [
            "Excited about winning prizes",
            "Asks many questions",
            "Mentions husband for approval",
            "Worried about safety",
            "Uses Hindi-English mix"
        ],
        "style": "Enthusiastic but cautious, asks about process"
    },
    "naive_student": {
        "name": "Arjun Patel",
        "age": 22,
        "occupation": "College Student",
        "characteristics": [
            "Eager for quick money",
            "Tech-savvy but inexperienced",
            "Asks about legitimacy",
            "Mentions friends",
            "Uses casual language"
        ],
        "style": "Casual, uses slang, asks if friends can join"
    }
}

DEFAULT_PERSONA = "elderly_uncle"


# ---------------------------------------------------------------------------
# Conversation State Management
# ---------------------------------------------------------------------------

class ConversationState:
    """Tracks the state of a honeypot conversation with full context."""
    
    def __init__(self, session_id: str, persona: str = DEFAULT_PERSONA):
        self.session_id = session_id
        self.persona = PERSONAS.get(persona, PERSONAS[DEFAULT_PERSONA])
        self.messages: List[Dict[str, Any]] = []
        self.extracted_intelligence: Dict[str, List] = {
            "bankAccounts": [],
            "upiIds": [],
            "phoneNumbers": [],
            "phishingLinks": [],
            "suspiciousKeywords": []
        }
        self.scam_detected = False
        self.scam_type = None
        self.created_at = datetime.utcnow().isoformat()
        self.turn_count = 0
        self.callback_sent = False
        self.agent_notes = ""
    
    def rebuild_from_history(self, conversation_history: List[Dict]):
        """Rebuild session state from conversationHistory (for Cloud Run resilience)."""
        self.messages = []
        for msg in conversation_history:
            sender = msg.get("sender", "unknown")
            text = msg.get("text", "")
            timestamp = msg.get("timestamp", 0)
            
            self.messages.append({
                "role": sender,
                "content": text,
                "timestamp": timestamp
            })
            
            # Extract intelligence from historical messages
            if sender == "scammer":
                self._extract_and_merge(text)
        
        self.turn_count = len(self.messages)
    
    def add_message(self, role: str, content: str, timestamp: int = None):
        """Add a message to conversation history."""
        self.messages.append({
            "role": role,
            "content": content,
            "timestamp": timestamp or int(datetime.utcnow().timestamp() * 1000)
        })
        self.turn_count += 1
        
        # Extract intelligence from scammer messages
        if role == "scammer":
            self._extract_and_merge(content)
    
    def _extract_and_merge(self, text: str):
        """Extract and merge intelligence from text."""
        intel = extract_intelligence(text)
        
        # Merge bank accounts
        for acc in intel.get("bank_accounts", []):
            if acc not in self.extracted_intelligence["bankAccounts"]:
                self.extracted_intelligence["bankAccounts"].append(acc)
        
        # Merge UPI IDs
        for upi in intel.get("upi_ids", []):
            if upi not in self.extracted_intelligence["upiIds"]:
                self.extracted_intelligence["upiIds"].append(upi)
        
        # Merge phone numbers
        for phone in intel.get("phone_numbers", []):
            if phone not in self.extracted_intelligence["phoneNumbers"]:
                self.extracted_intelligence["phoneNumbers"].append(phone)
        
        # Merge phishing links
        for link in intel.get("phishing_links", []):
            if link not in self.extracted_intelligence["phishingLinks"]:
                self.extracted_intelligence["phishingLinks"].append(link)
        
        # Extract suspicious keywords
        text_lower = text.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in text_lower:
                if keyword not in self.extracted_intelligence["suspiciousKeywords"]:
                    self.extracted_intelligence["suspiciousKeywords"].append(keyword)
    
    def has_valuable_intelligence(self) -> bool:
        """Check if we've extracted valuable intelligence worth reporting."""
        return (
            len(self.extracted_intelligence["bankAccounts"]) > 0 or
            len(self.extracted_intelligence["upiIds"]) > 0 or
            len(self.extracted_intelligence["phishingLinks"]) > 0 or
            len(self.extracted_intelligence["phoneNumbers"]) > 0
        )
    
    def get_full_conversation_context(self) -> str:
        """Get formatted conversation history for LLM with full context."""
        if not self.messages:
            return "No previous conversation."
        
        context = []
        for msg in self.messages[-15:]:  # Last 15 messages for context
            role = "Scammer" if msg["role"] == "scammer" else "You"
            context.append(f"{role}: {msg['content']}")
        return "\n".join(context)
    
    def generate_agent_notes(self) -> str:
        """Generate summary notes about the scammer's behavior."""
        notes = []
        
        if self.extracted_intelligence["suspiciousKeywords"]:
            notes.append(f"Used urgency tactics: {', '.join(self.extracted_intelligence['suspiciousKeywords'][:5])}")
        
        if self.extracted_intelligence["upiIds"]:
            notes.append("Requested UPI payment")
        
        if self.extracted_intelligence["bankAccounts"]:
            notes.append("Provided bank account details")
        
        if self.extracted_intelligence["phishingLinks"]:
            notes.append("Shared suspicious links")
        
        return ". ".join(notes) if notes else "Scam conversation detected"


# In-memory session storage
_sessions: Dict[str, ConversationState] = {}


def get_or_create_session(
    session_id: str, 
    persona: str = DEFAULT_PERSONA,
    conversation_history: List[Dict] = None
) -> ConversationState:
    """
    Get existing session or create new one.
    If conversationHistory is provided, rebuild state from it (Cloud Run resilience).
    """
    if session_id not in _sessions:
        _sessions[session_id] = ConversationState(session_id, persona)
    
    session = _sessions[session_id]
    
    # Rebuild from history if provided and session is fresh
    if conversation_history and len(conversation_history) > len(session.messages):
        session.rebuild_from_history(conversation_history)
    
    return session


# ---------------------------------------------------------------------------
# GUVI Callback Function (MANDATORY)
# ---------------------------------------------------------------------------

def send_guvi_callback(session: ConversationState) -> bool:
    """
    Send final results to GUVI evaluation endpoint.
    This is MANDATORY for scoring.
    
    Returns True if callback was successful.
    """
    if session.callback_sent:
        print(f"[INFO] Callback already sent for session {session.session_id}")
        return True
    
    payload = {
        "sessionId": session.session_id,
        "scamDetected": session.scam_detected,
        "totalMessagesExchanged": session.turn_count,
        "extractedIntelligence": session.extracted_intelligence,
        "agentNotes": session.generate_agent_notes()
    }
    
    print(f"[CALLBACK] Sending to GUVI: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        print(f"[CALLBACK] Response: {response.status_code} - {response.text}")
        
        if response.status_code == 200:
            session.callback_sent = True
            return True
        else:
            print(f"[CALLBACK ERROR] Status {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"[CALLBACK ERROR] Failed to send callback: {e}")
        return False


# ---------------------------------------------------------------------------
# Response Generation with Full Context
# ---------------------------------------------------------------------------

def generate_contextual_response(session: ConversationState, latest_message: str) -> str:
    """Generate response using Gemini with full conversation context."""
    
    if not client:
        return _get_fallback_response(session)
    
    persona = session.persona
    full_context = session.get_full_conversation_context()
    
    prompt = f"""You are playing the role of a potential scam victim to safely engage a scammer and extract information.

CHARACTER PROFILE:
- Name: {persona['name']}
- Age: {persona['age']}
- Occupation: {persona['occupation']}
- Personality: {', '.join(persona['characteristics'])}
- Speaking style: {persona['style']}

YOUR GOAL:
1. Stay in character as a believable potential victim
2. Show interest but ask clarifying questions
3. Try to get the scammer to reveal:
   - Bank account numbers
   - UPI IDs (like xyz@paytm, abc@upi)
   - Phone numbers
   - Payment links or websites
4. Never actually send money or real personal info
5. Keep responses short (1-3 sentences)
6. Sound like a real Indian person - use Hindi-English mix naturally

FULL CONVERSATION HISTORY:
{full_context}

LATEST MESSAGE FROM SCAMMER:
{latest_message}

Generate your next response as {persona['name']}. Stay in character. Be curious but slightly hesitant. Ask about payment details naturally.

RESPOND WITH ONLY THE MESSAGE TEXT (no quotes, no "Response:", just the message):"""

    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )
        return response.text.strip()
    except Exception as e:
        print(f"[ERROR] Gemini API failed: {e}")
        return _get_fallback_response(session)


def _get_fallback_response(session: ConversationState) -> str:
    """Fallback responses when LLM fails."""
    fallbacks = [
        "Ji ji, please tell me more about this. How do I proceed?",
        "Okay beta, but how will I receive the money? What details you need?",
        "This sounds interesting. Where should I send the payment?",
        "I am interested, but first tell me your bank details for verification.",
        "My husband is asking - please share your UPI ID so we can verify.",
        "Haan ji, I understand. What is the account number I should note down?",
        "Beta, is this genuine? Please share your contact number also.",
        "Ok ji, I will do the needful. Just tell me where to pay.",
    ]
    
    # Rotate through fallbacks based on turn count
    idx = session.turn_count % len(fallbacks)
    return fallbacks[idx]


# ---------------------------------------------------------------------------
# Main Processing Function (Called by FastAPI)
# ---------------------------------------------------------------------------

def process_scam_message(
    message: str,
    session_id: str,
    conversation_history: List[Dict] = None,
    metadata: Dict = None,
    persona: str = DEFAULT_PERSONA
) -> Dict[str, Any]:
    """
    Main entry point for processing a scam message.
    
    Args:
        message: The incoming message text
        session_id: Session ID for conversation continuity
        conversation_history: Previous messages in conversation
        metadata: Channel, language, locale info
        persona: Which victim persona to use
        
    Returns:
        {"status": "success", "reply": "..."} or {"status": "error", "message": "..."}
    """
    try:
        # Get or create session with history rebuild
        session = get_or_create_session(
            session_id=session_id,
            persona=persona,
            conversation_history=conversation_history or []
        )
        
        # Add the current message to session
        session.add_message("scammer", message)
        
        # Detect scam on first turn or if not yet detected
        if not session.scam_detected:
            scam_result = detect_scam(message)
            session.scam_detected = scam_result.get("is_scam", False)
            session.scam_type = scam_result.get("reason", "Unknown")
        
        # Generate contextual response
        reply = generate_contextual_response(session, message)
        
        # Add our response to history
        session.add_message("user", reply)
        
        # Check if we should send the GUVI callback
        # Trigger: scam detected AND valuable intelligence extracted
        if session.scam_detected and session.has_valuable_intelligence():
            send_guvi_callback(session)
        
        # Return in strict schema format
        return {
            "status": "success",
            "reply": reply
        }
        
    except Exception as e:
        print(f"[ERROR] process_scam_message failed: {e}")
        return {
            "status": "error",
            "message": str(e)
        }


# ---------------------------------------------------------------------------
# Module Test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Agentic Honeypot Test")
    print("=" * 60)
    
    # Simulate a scam conversation
    test_messages = [
        "Congratulations! You won ₹50,00,000 in our lottery! Reply to claim.",
        "To claim your prize, please share your bank account number.",
        "Transfer ₹500 registration fee to UPI: lottery@paytm",
    ]
    
    session_id = "test-session-001"
    history = []
    
    for i, msg in enumerate(test_messages, 1):
        print(f"\n--- Turn {i} ---")
        print(f"Scammer: {msg}")
        
        result = process_scam_message(
            message=msg,
            session_id=session_id,
            conversation_history=history,
            persona="elderly_uncle"
        )
        
        print(f"Response: {result}")
        
        # Build history for next turn
        history.append({"sender": "scammer", "text": msg, "timestamp": 123456})
        if result.get("status") == "success":
            history.append({"sender": "user", "text": result["reply"], "timestamp": 123457})
