import os
from PyPDF2 import PdfReader
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def extract_text_from_pdf(pdf_path: str) -> str:
    reader = PdfReader(pdf_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"
    return text.strip()

def query_pdf_with_llm(pdf_path: str, question: str) -> str:
    content = extract_text_from_pdf(pdf_path)

    system_prompt = "You are a cybersecurity assistant. Answer concisely and clearly using the report content."
    user_prompt = f"The following is the PDF content:\n\n{content}\n\nNow answer: {question}"

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3
        )
        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Error querying LLM: {e}"
