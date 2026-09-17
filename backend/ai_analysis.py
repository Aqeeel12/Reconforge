import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

client = Groq(api_key=GROQ_API_KEY)

def analyze_scan(scan_results):
    try:
        prompt = f"""
You are an expert penetration tester and security analyst.
Analyze the following recon scan results and provide a detailed report.

SCAN RESULTS:
{scan_results}

Provide your analysis in this exact format:

## TARGET OVERVIEW
- IP/Domain:
- Organization:
- OS:

## OPEN PORTS & SERVICES
List each port with risk level (CRITICAL/HIGH/MEDIUM/LOW)

## SUBDOMAINS FOUND
List interesting subdomains with risk assessment

## VULNERABILITIES & RISKS
List potential vulnerabilities found

## ATTACK PRIORITIES
1. (highest priority first)
2.
3.

## RECOMMENDATIONS
What should be patched or fixed immediately

Keep it concise, technical and actionable.
"""

        response = client.chat.completions.create(
            model="groq/compound",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert penetration tester. Analyze recon data and provide clear, actionable security reports."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=1500
        )

        return response.choices[0].message.content

    except Exception as e:
        return {'error': str(e)}
