# CELL 2: LLM Setup
from google.colab import userdata
import os

# Colab Secrets-এ key রাখো: 🔑 (left sidebar) → Add new secret
OPENAI_KEY = userdata.get('OPENAI_API_KEY') if 'OPENAI_API_KEY' in dir(userdata) else None
GEMINI_KEY = userdata.get('GEMINI_API_KEY') if 'GEMINI_API_KEY' in dir(userdata) else None

# Fallback: hardcode (শুধু testing-এর জন্য)
# OPENAI_KEY = "sk-..."
# GEMINI_KEY = "AIza..."

import json, re

SYSTEM_PROMPT = """You are a reconnaissance analyst AI.

Analyze the given scan output and provide:
1. **Summary**: What was found (2-3 lines)
2. **Key Findings**: Most important discoveries (bullet points)
3. **Risks**: Security concerns spotted (severity: LOW/MED/HIGH/CRITICAL)
4. **Next Steps**: What to investigate next
5. **Tech Stack**: Detected technologies (if any)

Keep it concise. Use Markdown formatting."""

def analyze_with_llm(prompt_data, title="Recon Analysis"):
    """Send scan output to LLM for analysis"""

    # Try GPT
    if OPENAI_KEY:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=OPENAI_KEY)
            r = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"# {title}\n\n{prompt_data[:8000]}"}
                ]
            )
            return r.choices[0].message.content
        except Exception as e:
            print(f"⚠️ GPT failed: {e}")

    # Fallback: Gemini
    if GEMINI_KEY:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_KEY)
            model = genai.GenerativeModel('gemini-1.5-flash')
            r = model.generate_content(SYSTEM_PROMPT + f"\n\n# {title}\n\n{prompt_data[:8000]}")
            return r.text
        except Exception as e:
            print(f"⚠️ Gemini failed: {e}")

    return "⚠️ No LLM configured. Add OPENAI_API_KEY or GEMINI_API_KEY in Colab Secrets."

print("✅ LLM ready")
