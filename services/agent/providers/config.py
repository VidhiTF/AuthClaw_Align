import os
import startup.env_loader

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_API_URL = os.getenv("GOOGLE_API_URL", "https://generativelanguage.googleapis.com")
MODEL_PROVIDER = os.getenv("MODEL_PROVIDER", "gemini")
MODEL_NAME = os.getenv("MODEL_NAME", "gemini-2.5-flash-lite")
