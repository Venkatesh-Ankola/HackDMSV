import os
import openai
import json

from dotenv import load_dotenv
load_dotenv()

openai.api_key = os.getenv("OPENAI_API_KEY")

def summarize_findings(enriched_data):
    with open("./service_summary_prompt.txt", "r") as file:
        system_prompt = file.read()

    user_prompt = "Analyze the following network vulnerability results and summarize the security posture:\n\n"
    user_prompt += json.dumps(enriched_data, indent=2)

    try:
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print("Error contacting LLM:", e)
        return "Error generating summary."
