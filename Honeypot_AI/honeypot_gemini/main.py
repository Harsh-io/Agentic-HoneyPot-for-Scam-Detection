"""
FastAPI Main Application - GUVI Hackathon Honeypot API
======================================================
Endpoints:
1. POST /api/v1/analyze - Main honeypot endpoint (GUVI format)
2. GET /health - Health check
3. GET / - API info

STRICT Schema Compliance:
- Success: {"status": "success", "reply": "STRING"}
- Error: {"status": "error", "message": "STRING"}
"""

import os
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from honeypot import process_scam_message

# ---------------------------------------------------------------------------
# Load Environment Variables
# ---------------------------------------------------------------------------
load_dotenv()

API_KEY = os.getenv("API_KEY", "hackathon-honeypot-api-key-2026")

# ---------------------------------------------------------------------------
# Pydantic Models - STRICT GUVI FORMAT
# ---------------------------------------------------------------------------

class MessagePayload(BaseModel):
    """Inner message structure from GUVI."""
    sender: str = Field(default="scammer", description="Who sent the message")
    text: str = Field(..., description="The message text content")
    timestamp: Optional[int] = Field(default=None, description="Unix timestamp in ms")


class ConversationHistoryItem(BaseModel):
    """Single item in conversation history."""
    sender: str = Field(default="scammer")
    text: str = Field(default="")
    timestamp: Optional[int] = Field(default=None)


class AnalyzeRequest(BaseModel):
    """
    GUVI request format:
    {
        "sessionId": "unique-session-id",
        "message": {
            "sender": "scammer",
            "text": "the message",
            "timestamp": 1234567890123
        },
        "conversationHistory": [...],
        "metadata": {...}
    }
    """
    sessionId: str = Field(..., description="Unique session identifier")
    message: MessagePayload = Field(..., description="The incoming message object")
    conversationHistory: Optional[List[ConversationHistoryItem]] = Field(
        default=[], 
        description="Previous messages in conversation"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default={}, 
        description="Channel, language, locale info"
    )


class SuccessResponse(BaseModel):
    """Success response format per Section 8 of problem statement."""
    status: str = Field(default="success", description="Must be 'success'")
    reply: str = Field(..., description="The honeypot's reply text")


class ErrorResponse(BaseModel):
    """Error response format per Section 8 of problem statement."""
    status: str = Field(default="error", description="Must be 'error'")
    message: str = Field(..., description="Error description")


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Agentic Honeypot for Scam Detection",
    description="AI-powered honeypot that engages scammers and extracts intelligence. Built for GUVI x HCL AI Impact Summit Hackathon.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS for browser-based testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Exception Handler - Always return proper schema
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Ensure all errors return proper schema."""
    print(f"[GLOBAL ERROR] {type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=200,  # Return 200 even on errors per some tester requirements
        content={
            "status": "error",
            "message": str(exc)
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with proper schema."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail
        }
    )


# ---------------------------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    """Health check endpoint for Cloud Run."""
    return {
        "status": "healthy",
        "service": "honeypot-api",
        "version": "2.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }


# ---------------------------------------------------------------------------
# Root Endpoint
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """API information."""
    return {
        "service": "Agentic Honeypot API",
        "version": "2.0.0",
        "description": "AI-powered scam detection and intelligence extraction",
        "hackathon": "GUVI x HCL AI Impact Summit",
        "endpoints": {
            "analyze": "POST /api/v1/analyze",
            "health": "GET /health",
            "docs": "GET /docs"
        }
    }


# ---------------------------------------------------------------------------
# Main Analyze Endpoint - GUVI Format
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/analyze",
    response_model=SuccessResponse,
    responses={
        200: {
            "description": "Successful response",
            "content": {
                "application/json": {
                    "example": {"status": "success", "reply": "Ji ji, please tell me more about this."}
                }
            }
        },
        400: {
            "description": "Bad request",
            "content": {
                "application/json": {
                    "example": {"status": "error", "message": "Invalid request format"}
                }
            }
        }
    }
)
async def analyze_message(request: AnalyzeRequest):
    """
    Main honeypot endpoint that receives scam messages and generates responses.
    
    **GUVI Request Format:**
    ```json
    {
        "sessionId": "unique-session-id",
        "message": {
            "sender": "scammer",
            "text": "Your message here",
            "timestamp": 1234567890123
        },
        "conversationHistory": [],
        "metadata": {}
    }
    ```
    
    **Response Format (Success):**
    ```json
    {
        "status": "success",
        "reply": "Response message here"
    }
    ```
    
    **Response Format (Error):**
    ```json
    {
        "status": "error",
        "message": "Error description"
    }
    ```
    """
    try:
        # Log incoming request for debugging
        print(f"[REQUEST] sessionId={request.sessionId}")
        print(f"[REQUEST] message.text={request.message.text[:100]}...")
        print(f"[REQUEST] history_length={len(request.conversationHistory or [])}")
        
        # Convert Pydantic history to dict list
        history_dicts = []
        if request.conversationHistory:
            for item in request.conversationHistory:
                history_dicts.append({
                    "sender": item.sender,
                    "text": item.text,
                    "timestamp": item.timestamp
                })
        
        # Convert metadata to dict
        metadata_dict = request.metadata if request.metadata else {}
        
        # Process the message through honeypot
        result = process_scam_message(
            message=request.message.text,
            session_id=request.sessionId,
            conversation_history=history_dicts,
            metadata=metadata_dict
        )
        
        print(f"[RESPONSE] {result}")
        
        # Check result status
        if result.get("status") == "success":
            return SuccessResponse(
                status="success",
                reply=result.get("reply", "I am interested, please tell me more.")
            )
        else:
            # Return error in proper format
            return JSONResponse(
                status_code=200,
                content={
                    "status": "error",
                    "message": result.get("message", "Processing failed")
                }
            )
            
    except Exception as e:
        print(f"[ERROR] analyze_message: {type(e).__name__}: {e}")
        return JSONResponse(
            status_code=200,
            content={
                "status": "error",
                "message": str(e)
            }
        )


# ---------------------------------------------------------------------------
# Alternative endpoint (backward compatibility)
# ---------------------------------------------------------------------------

@app.post("/analyze")
async def analyze_message_alt(request: AnalyzeRequest):
    """Alias for /api/v1/analyze for backward compatibility."""
    return await analyze_message(request)


# ---------------------------------------------------------------------------
# Debug endpoint - only for testing
# ---------------------------------------------------------------------------

@app.post("/debug/echo")
async def echo_request(request: Request):
    """Echo back the raw request for debugging."""
    body = await request.body()
    try:
        json_body = await request.json()
    except:
        json_body = None
    
    return {
        "raw_body": body.decode("utf-8"),
        "parsed_json": json_body,
        "headers": dict(request.headers)
    }


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 8080))
    print(f"Starting Honeypot API on port {port}...")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
