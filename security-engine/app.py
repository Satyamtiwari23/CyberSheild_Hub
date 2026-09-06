from flask import Flask, request, jsonify
from flask_cors import CORS

from url.analyzer import analyze_url

app = Flask(__name__)
CORS(app)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "CyberShield Security Engine"
    })


@app.route("/analyze-url", methods=["POST"])
def analyze_url_route():

    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({
            "error": "URL is required"
        }), 400

    url = data["url"].strip()

    if not url:
        return jsonify({
            "error": "URL cannot be empty"
        }), 400

    result = analyze_url(url)

    return jsonify(result)


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5002,
        debug=True
    )