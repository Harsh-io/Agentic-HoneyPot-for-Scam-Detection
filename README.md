# 🍯 Agentic Honey-Pot for Scam Detection & Intelligence Extraction

> Build an AI-powered agentic honeypot API that detects scam messages, engages scammers in multi-turn conversations, extracts intelligence, and reports results back to the GUVI evaluation endpoint.

**Hackathon Project** | AI Impact Summit Community by **HCL × GUVI**

---

## 📋 Problem Statement

Online scams such as bank fraud, UPI fraud, phishing, and fake offers are becoming increasingly adaptive. Scammers change their tactics based on user responses, making traditional detection systems ineffective.

This project implements an **Agentic Honey-Pot** — an AI-powered system that:
- Detects scam intent in incoming messages
- Activates an autonomous AI Agent
- Maintains a believable human-like persona
- Handles multi-turn conversations
- Extracts scam-related intelligence
- Returns structured results via an API

---
##  Work Flow 
<img width="712" height="1570" alt="Honeypot_Flowchart" src="https://github.com/user-attachments/assets/6c1609d1-530a-42a3-ae03-7088288b1213" />

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         HONEYPOT API SYSTEM                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐     ┌─────────────────────────────────────────┐    │
│  │   Incoming  │────▶│            main.py (FastAPI)            │    │
│  │   Message   │     │  - API Endpoint: /api/v1/analyze        │    │
│  └─────────────┘     │  - Request Validation                   │    │
│                      │  - API Key Authentication               │    │
│                      └─────────────┬───────────────────────────┘    │
│                                    │                                 │
│                                    ▼                                 │
│                      ┌─────────────────────────────────────────┐    │
│                      │          detector.py (Gemini AI)        │    │
│                      │  - Scam Classification                  │    │
│                      │  - Confidence Scoring (0-100)           │    │
│                      │  - Scam Type Identification             │    │
│                      └─────────────┬───────────────────────────┘    │
│                                    │                                 │
│              ┌────────────────────┬┴────────────────────┐           │
│              ▼                    ▼                     ▼           │
│  ┌───────────────────┐  ┌─────────────────┐  ┌──────────────────┐  │
│  │   honeypot.py     │  │  extractor.py   │  │   GUVI Callback  │  │
│  │  - Persona Engine │  │  - Bank Accounts│  │  - Final Report  │  │
│  │  - Response Gen   │  │  - UPI IDs      │  │  - Intelligence  │  │
│  │  - Context Mgmt   │  │  - Phone Numbers│  │    Submission    │  │
│  └───────────────────┘  │  - Phishing URLs│  └──────────────────┘  │
│                         └─────────────────┘                         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Core Components

| Module | Purpose |
|--------|---------|
| `main.py` | FastAPI application entry point, request routing, authentication |
| `detector.py` | Scam detection using Google Gemini 2.0 Flash with JSON parsing |
| `honeypot.py` | Agentic engagement engine with persona management & response generation |
| `extractor.py` | Regex-based intelligence extraction (bank accounts, UPI, phones, URLs) |

---

## 🚀 Key Features

| Feature | Description |
|---------|-------------|
| **Scam Detection** | Classifies messages as scam or legitimate using Google Gemini AI |
| **Agentic Engagement** | AI personas (elderly uncle, curious housewife, naive student) engage scammers |
| **Intelligence Extraction** | Automatically extracts bank accounts, UPI IDs, phone numbers, phishing links |
| **Multi-turn Conversations** | Maintains conversation context across multiple messages |
| **REST API** | FastAPI-based endpoint with API key authentication |
| **GUVI Callback** | Reports extracted intelligence to GUVI evaluation endpoint |

---

## 📖 API Documentation

### Endpoint

| Method | URL | Description |
|--------|-----|-------------|
| `POST` | `/api/v1/analyze` | Main honeypot analysis endpoint |
| `GET` | `/health` | Health check for Cloud Run |
| `GET` | `/` | API information |

**Base URL:** `https://honeypot-api-990599758009.asia-south1.run.app`

---

### Headers

```http
x-api-key: YOUR_SECRET_API_KEY
Content-Type: application/json
```

---

### Request / Response Examples

#### First Message (Start of Conversation)

**Request:**
```json
{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "Oh my! What happened beta? Why will my account be blocked? I have all my retirement savings there..."
}
```

---

#### Follow-Up Message (Continuation)

**Request:**
```json
{
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Share your UPI ID to avoid account suspension.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "Your bank account will be blocked today. Verify immediately.",
      "timestamp": 1770005528731
    },
    {
      "sender": "user",
      "text": "Oh my! What happened beta?",
      "timestamp": 1770005528731
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

---

### Request Fields

| Field | Required | Description |
|-------|----------|-------------|
| `sessionId` | Yes | Unique session identifier |
| `message.sender` | Yes | `scammer` or `user` |
| `message.text` | Yes | Message content |
| `message.timestamp` | Yes | Epoch time in milliseconds |
| `conversationHistory` | No | Previous messages (empty for first message) |
| `metadata.channel` | No | SMS / WhatsApp / Email / Chat |
| `metadata.language` | No | Language used |
| `metadata.locale` | No | Country or region |

### Response Fields

| Field | Description |
|-------|-------------|
| `status` | `success` or `error` |
| `reply` | AI Agent's response to engage the scammer |

---

## 🤖 Agent Behavior

The honeypot agent operates autonomously using three distinct personas:

| Persona | Name | Profile | Behavior |
|---------|------|---------|----------|
| **Elderly Uncle** | Ramesh Kumar | 62yo Retired Bank Manager | Trusting, polite, uses "beta" and "ji", slightly confused by technology |
| **Curious Housewife** | Sunita Sharma | 45yo Homemaker | Excited about prizes, asks many questions, mentions husband for approval |
| **Naive Student** | Arjun Patel | 22yo College Student | Eager for quick money, uses casual language, asks if friends can join |

### Agent Workflow

1. **Detect** → Classify incoming message as scam/legitimate (Gemini AI)
2. **Engage** → Generate believable human response using selected persona
3. **Extract** → Pull intelligence (accounts, UPI IDs, links, phones)
4. **Report** → Send final results to GUVI callback after conversation ends

---

## 📊 Evaluation Flow

```
Scammer Message → API Receives → Scam Detection → Engagement Response
                                        ↓
                               Intelligence Extraction
                                        ↓
                               GUVI Callback (Final)
```

| Step | Action | Timing |
|------|--------|--------|
| 1 | Receive scam message | Immediate |
| 2 | Detect scam type & confidence | < 2 seconds |
| 3 | Generate persona response | < 3 seconds |
| 4 | Extract intelligence from text | Real-time |
| 5 | Send GUVI callback | After conversation ends |

---

## 🔔 Final Result Callback (GUVI)

After scam detection and engagement, extracted intelligence is sent to GUVI for evaluation:

**Endpoint:**
```
POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
```

**Callback Payload:**
```json
{
  "sessionId": "abc123-session-id",
  "scamDetected": true,
  "totalMessagesExchanged": 18,
  "extractedIntelligence": {
    "bankAccounts": ["XXXX-XXXX-XXXX"],
    "upiIds": ["scammer@upi"],
    "phishingLinks": ["http://malicious-link.example"],
    "phoneNumbers": ["+91XXXXXXXXXX"],
    "suspiciousKeywords": ["urgent", "verify now", "account blocked"]
  },
  "agentNotes": "Scammer used urgency tactics and payment redirection"
}
```

---

## ☁️ Deployment (Cloud Run)

### Quick Deploy

```bash
gcloud run deploy honeypot-api \
  --source . \
  --region asia-south1 \
  --allow-unauthenticated \
  --set-env-vars="GEMINI_API_KEY=xxx,API_KEY=xxx"
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GEMINI_API_KEY` | Google AI Studio API key for Gemini |
| `API_KEY` | Secret key for API authentication |

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GEMINI_API_KEY=your_google_ai_studio_key
export API_KEY=your_secure_api_key

# Run locally
uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## ⚖️ Ethics & Constraints

| Rule | Description |
|------|-------------|
| ❌ No Impersonation | Never impersonate real individuals or authorities |
| ❌ No Illegal Instructions | Never provide instructions for illegal activities |
| ❌ No Harassment | Maintain ethical boundaries in all interactions |
| ✅ Data Responsibility | Handle extracted intelligence responsibly |
| ✅ Transparency | Agent never claims to be a real person when asked directly |

---

## 📄 License

MIT License - Built for educational and hackathon purposes.
