from flask_cors import CORS
from flask import Flask, render_template, request, jsonify
from groq import Groq
from dotenv import load_dotenv
import os

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

print("KEY FOUND:", api_key is not None)

app = Flask(__name__)
CORS(app)

client = Groq(
    api_key=api_key
)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/generate", methods=["POST"])
def generate():

    try:
        data = request.get_json()

        topic = data.get("topic", "")
        page = data.get("page", "assistant")

        completion = client.chat.completions.create(

            model="llama-3.3-70b-versatile",

            messages=[
                {
                    "role": "system",
                    "content": """
                    You are an AI CyberSecurity Assistant.
                    
                    Always format responses using Markdown.
                    
                    Rules:
                    
                    - Use ## headings
                    - Use bullet points
                    - Use numbered lists where appropriate
                    - Use tables if useful
                    - Put code inside triple backticks
                    - Leave one blank line between sections
                    - Never write one huge paragraph
                    - Explain step-by-step
                    - Give examples
                    - Use emojis only when helpful
                    """
                },
                {
                    "role": "user",
                    "content": topic
                }
            ],

            temperature=0.7,
            max_tokens=2000

        )

        answer = completion.choices[0].message.content

        return jsonify({
            "answer": answer
        })

    except Exception as e:

        print("ERROR:", e)

        return jsonify({
            "answer": f"❌ Error: {str(e)}"
        }), 500


if __name__ == "__main__":
    app.run(debug=True)


