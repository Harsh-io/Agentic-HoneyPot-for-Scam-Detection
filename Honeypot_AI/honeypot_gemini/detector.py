"""
Scam Detection Module using Google Gemini 1.5 Flash
====================================================
This module classifies messages as scam or legitimate using the
Google GenAI SDK (google-genai). Part of an Agentic Honeypot system.

Author: Honeypot AI Team
"""

import os
import json
import re
from typing import Dict, Any

from dotenv import load_dotenv
from google import genai

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Load environment variables from .env file
load_dotenv()

# Retrieve API key from environment
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Validate API key exists
if not GEMINI_API_KEY:
    raise EnvironmentError(
        "GEMINI_API_KEY not found in environment. "
        "Please add it to your .env file."
    )

# Initialize the Gemini client
client = genai.Client(api_key=GEMINI_API_KEY)

# Model to use for classification
# For google-genai SDK, use gemini-2.0-flash or gemini-1.5-flash-latest
MODEL_NAME = "gemini-2.0-flash"

# ---------------------------------------------------------------------------
# JSON Extraction Utilities
# ---------------------------------------------------------------------------

def extract_json_safe(text: str) -> Dict[str, Any]:
    """
    Safely extract a JSON object from raw model output.
    
    Gemini may wrap JSON in markdown code blocks or add extra commentary.
    This function handles multiple formats:
      1. Raw JSON: {"is_scam": true, ...}
      2. Markdown block: ```json\n{...}\n```
      3. JSON embedded in text: "Here is the result: {...}"
    
    Args:
        text: Raw text response from Gemini
        
    Returns:
        Parsed dictionary from JSON
        
    Raises:
        ValueError: If no valid JSON object is found
    """
    if not text or not text.strip():
        raise ValueError("Empty response from model")
    
    # Step 1: Try to extract JSON from markdown code block
    # Matches ```json {...} ``` or ``` {...} ```
    code_block_pattern = r"```(?:json)?\s*(\{[\s\S]*?\})\s*```"
    code_match = re.search(code_block_pattern, text)
    if code_match:
        try:
            return json.loads(code_match.group(1))
        except json.JSONDecodeError:
            pass  # Fall through to next method
    
    # Step 2: Try to find a JSON object anywhere in the text
    # Uses greedy matching to find the outermost { }
    json_pattern = r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}"
    json_match = re.search(json_pattern, text)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass  # Fall through to next method
    
    # Step 3: Last resort - find anything between first { and last }
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace:last_brace + 1])
        except json.JSONDecodeError:
            pass
    
    raise ValueError(f"No valid JSON found in response: {text[:200]}...")


def validate_scam_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalize the scam detection response.
    
    Ensures the response has all required fields with correct types.
    Applies sensible defaults for missing or invalid fields.
    
    Args:
        data: Raw parsed JSON dictionary
        
    Returns:
        Normalized dictionary with guaranteed structure
    """
    # Extract is_scam with type coercion
    is_scam = data.get("is_scam")
    if isinstance(is_scam, bool):
        is_scam_normalized = is_scam
    elif isinstance(is_scam, str):
        is_scam_normalized = is_scam.lower() in ("true", "yes", "1")
    else:
        is_scam_normalized = bool(is_scam)
    
    # Extract confidence with bounds checking
    confidence = data.get("confidence", 0)
    try:
        confidence_normalized = int(confidence)
        confidence_normalized = max(0, min(100, confidence_normalized))
    except (TypeError, ValueError):
        confidence_normalized = 0
    
    # Extract reason with fallback
    reason = data.get("reason", "No reason provided")
    if not isinstance(reason, str) or not reason.strip():
        reason = "No reason provided"
    
    return {
        "is_scam": is_scam_normalized,
        "confidence": confidence_normalized,
        "reason": reason.strip()
    }


# ---------------------------------------------------------------------------
# Main Detection Function
# ---------------------------------------------------------------------------

def detect_scam(message: str) -> Dict[str, Any]:
    """
    Classify a message as scam or legitimate using Gemini 1.5 Flash.
    
    This function is designed to be robust:
      - Never throws exceptions to the caller
      - Always returns a valid dictionary
      - Handles malformed model responses gracefully
    
    Args:
        message: The text message to classify
        
    Returns:
        Dictionary with the following structure:
        {
            "is_scam": bool,      # True if message is likely a scam
            "confidence": int,    # 0-100 confidence score
            "reason": str         # Brief explanation
        }
    
    Example:
        >>> result = detect_scam("You won $1000! Click here!")
        >>> print(result)
        {'is_scam': True, 'confidence': 95, 'reason': 'Prize scam with suspicious link'}
    """
    
    # Handle empty or invalid input
    if not message or not isinstance(message, str) or not message.strip():
        return {
            "is_scam": False,
            "confidence": 0,
            "reason": "Empty or invalid message"
        }
    
    # Construct the prompt with strict JSON instructions
    prompt = f"""You are an expert scam detection system. Analyze the following message and determine if it is a scam.

CRITICAL: You must respond with ONLY a valid JSON object. No explanations, no markdown, no extra text.

The JSON must have exactly this structure:
{{"is_scam": true or false, "confidence": 0-100, "reason": "brief explanation"}}

Rules:
- "is_scam": boolean (true if scam, false if legitimate)
- "confidence": integer from 0 to 100
- "reason": short string explaining why (max 50 words)

Message to analyze:
\"\"\"{message}\"\"\"

JSON response:"""

    try:
        # Call Gemini API
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )
        
        # Extract the text response
        raw_text = response.text
        
        if not raw_text:
            return {
                "is_scam": False,
                "confidence": 0,
                "reason": "Empty response from model"
            }
        
        # Parse and validate the JSON response
        parsed_data = extract_json_safe(raw_text)
        validated_result = validate_scam_response(parsed_data)
        
        return validated_result
        
    except json.JSONDecodeError as e:
        # JSON parsing failed
        return {
            "is_scam": False,
            "confidence": 0,
            "reason": f"JSON parsing error: {str(e)[:50]}"
        }
        
    except ValueError as e:
        # No JSON found in response
        return {
            "is_scam": False,
            "confidence": 0,
            "reason": f"Response format error: {str(e)[:50]}"
        }
        
    except Exception as e:
        # Catch-all for API errors, network issues, etc.
        error_msg = str(e)[:100] if str(e) else "Unknown error"
        return {
            "is_scam": False,
            "confidence": 0,
            "reason": f"Detection failed: {error_msg}"
        }


# ---------------------------------------------------------------------------
# Module Test (runs when executed directly)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Quick sanity check
    test_messages = [
        "Congratulations! You won ₹10,00,000. Click the link to claim.",
        "Your bank KYC is pending. Send OTP immediately.",
        "Hey, are we still meeting for coffee tomorrow?",
        "URGENT: Your account will be suspended. Verify now: bit.ly/xyz",
        "",  # Edge case: empty string
    ]
    
    print("=" * 60)
    print("Scam Detection Module Test")
    print("=" * 60)
    
    for msg in test_messages:
        result = detect_scam(msg)
        display_msg = msg[:50] + "..." if len(msg) > 50 else msg or "(empty)"
        print(f"\nMessage: {display_msg}")
        print(f"Result:  {result}")
