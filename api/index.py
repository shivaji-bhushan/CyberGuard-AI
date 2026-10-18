"""
Vercel Serverless Function entrypoint for CyberGuard AI.
Exposes the WSGI Flask application object 'app'.
"""
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import app

# Vercel's Python runtime uses the 'app' symbol by default
if __name__ == "__main__":
    app.run()
