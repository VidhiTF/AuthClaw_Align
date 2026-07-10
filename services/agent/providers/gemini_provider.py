from dotenv import load_dotenv
import os
import traceback

load_dotenv()
import logging
import requests
from typing import List, Dict, Any
from .base import BaseProvider
from .config import GOOGLE_API_KEY, MODEL_NAME, GOOGLE_API_URL

logger = logging.getLogger("authclaw.providers.gemini")


class GeminiProvider(BaseProvider):
    def __init__(self, api_key: str = None, model_name: str = None, api_url: str = None, timeout: float = 30.0):
        logger.info("Provider Startup")
        self.api_key = api_key or GOOGLE_API_KEY
        self.model_name = model_name or os.getenv("MODEL_NAME") or MODEL_NAME
        if self.model_name == "gemini-3.1-flash-lite":
            logger.warning(
                "Configured Gemini model %s is not available for the local runtime; using gemini-2.5-flash-lite.",
                self.model_name,
            )
            self.model_name = "gemini-2.5-flash-lite"
        self.api_url = api_url or GOOGLE_API_URL
        self.timeout = timeout

        is_configured = self.api_key is not None and self.api_key not in ("dummy", "dummy-api-key", "")
        logger.info(f"Provider configured: {is_configured}")
        logger.info(f"Using model: {self.model_name}")

        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY environment variable is not set.")

    def generate(self, prompt: str, system_instruction: str = None, history: List[Dict[str, Any]] = None, **kwargs) -> str:
        # ── DIAGNOSTIC BLOCK ──────────────────────────────────────────────────
        print("", flush=True)
        print("=" * 60, flush=True)
        print("=== GEMINI PROVIDER DIAGNOSTICS ===", flush=True)
        print(f"API KEY PRESENT : {bool(self.api_key)}", flush=True)
        print("API KEY (repr)  : <redacted>", flush=True)
        print(f"MODEL           : {self.model_name}", flush=True)
        print(f"API URL         : {self.api_url}", flush=True)

        # Verify env vars are actually loaded at runtime
        env_key = os.getenv("GOOGLE_API_KEY", "<NOT SET>")
        env_model = os.getenv("MODEL_NAME", "<NOT SET>")
        env_provider = os.getenv("MODEL_PROVIDER", "<NOT SET>")
        print(f"ENV GOOGLE_API_KEY  : {'<present>' if env_key != '<NOT SET>' else '<NOT SET>'}", flush=True)
        print(f"ENV MODEL_NAME      : {env_model}", flush=True)
        print(f"ENV MODEL_PROVIDER  : {env_provider}", flush=True)
        print("=" * 60, flush=True)
        print("", flush=True)
        # ─────────────────────────────────────────────────────────────────────

        if not self.api_key or self.api_key in ("dummy", "dummy-api-key"):
            msg = "GEMINI ERROR: GOOGLE_API_KEY is not configured or set to dummy"
            logger.error(msg)
            print(msg, flush=True)
            raise ValueError("Provider not configured")

        logger.info("Provider Initialized")
        logger.info("API Key Loaded")
        logger.info(f"Model Selected: {self.model_name}")

        request_url = f"{self.api_url}/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        print(f"REQUEST URL (model only): /v1beta/models/{self.model_name}:generateContent", flush=True)

        contents = []

        # Populate history mapping role from user/assistant to user/model
        if history:
            for msg in history:
                role = msg.get("role", "user")
                content = msg.get("content", "")
                gemini_role = "user" if role == "user" else "model"
                contents.append({
                    "role": gemini_role,
                    "parts": [{"text": content}]
                })

        # Append the new user prompt
        contents.append({
            "role": "user",
            "parts": [{"text": prompt}]
        })

        payload = {
            "contents": contents
        }

        # Format system instruction if provided
        if system_instruction:
            payload["systemInstruction"] = {
                "parts": [{"text": system_instruction}]
            }

        generation_config = {}
        if "temperature" in kwargs:
            generation_config["temperature"] = float(kwargs["temperature"])
        if "max_tokens" in kwargs:
            generation_config["maxOutputTokens"] = int(kwargs["max_tokens"])

        if generation_config:
            payload["generationConfig"] = generation_config

        headers = {
            "Content-Type": "application/json"
        }

        import time
        max_retries = 3
        backoff = 2.0
        response = None
        start_time = time.time()

        for attempt in range(max_retries):
            # Check if we've already exceeded the timeout before attempting
            if time.time() - start_time >= self.timeout:
                msg = f"GEMINI ERROR: Overall timeout ({self.timeout}s) exceeded before attempt {attempt + 1}"
                logger.error(msg)
                print(msg, flush=True)
                raise RuntimeError("Provider unavailable: Timeout exceeded before request")

            try:
                # Use remaining time as the request timeout
                remaining_time = max(1.0, self.timeout - (time.time() - start_time))
                logger.info(f"Provider Request Sent: URL={self.api_url}/v1beta/models/{self.model_name}:generateContent, model={self.model_name}")
                print(f"[Attempt {attempt + 1}] Sending request to Gemini... (timeout={remaining_time:.1f}s)", flush=True)

                response = requests.post(
                    request_url,
                    json=payload,
                    headers=headers,
                    timeout=remaining_time
                )

                logger.info(f"Provider Response Received: Status={response.status_code}")
                print(f"[Attempt {attempt + 1}] Response status: {response.status_code}", flush=True)

                # ── DETAILED ERROR BODY LOGGING ───────────────────────────────
                if response.status_code != 200:
                    print(f"=== GEMINI HTTP ERROR {response.status_code} ===", flush=True)
                    try:
                        error_body = response.json()
                        error_msg = error_body.get("error", {}).get("message", "<no message>")
                        error_status = error_body.get("error", {}).get("status", "<no status>")
                        print(f"  Status  : {error_status}", flush=True)
                        print(f"  Message : {error_msg}", flush=True)
                        logger.error(f"GEMINI API ERROR {response.status_code}: [{error_status}] {error_msg}")
                    except Exception:
                        print(f"  Raw body: {response.text[:500]}", flush=True)
                        logger.error(f"GEMINI API ERROR {response.status_code}: {response.text[:500]}")
                    print("=" * 40, flush=True)
                # ─────────────────────────────────────────────────────────────

                # Check for rate limit
                if response.status_code == 429:
                    retry_delay_val = backoff
                    try:
                        err_json = response.json()
                        for detail in err_json.get("error", {}).get("details", []):
                            if detail.get("@type") == "type.googleapis.com/google.rpc.RetryInfo":
                                delay_str = detail.get("retryDelay", "")
                                if delay_str.endswith("s"):
                                    retry_delay_val = float(delay_str[:-1])
                                    break
                    except Exception:
                        pass

                    sleep_time = max(retry_delay_val, backoff) + 1.0

                    if time.time() - start_time + sleep_time >= self.timeout:
                        msg = (f"GEMINI ERROR: 429 Rate limit — retry delay {sleep_time:.0f}s would exceed "
                               f"overall timeout {self.timeout}s. Aborting. This API key has exhausted its quota.")
                        logger.error(msg)
                        print(msg, flush=True)
                        raise RuntimeError("Provider unavailable: Quota Exceeded (Rate Limited and Timeout)")

                    if attempt < max_retries - 1:
                        warn_msg = f"GEMINI: Rate limited (429). Retrying in {sleep_time:.0f}s (Attempt {attempt + 1}/{max_retries})..."
                        logger.warning(warn_msg)
                        print(warn_msg, flush=True)
                        time.sleep(sleep_time)
                        backoff *= 2
                        continue
                    else:
                        raise RuntimeError("Provider unavailable: Quota Exceeded (Rate Limited)")

                elif response.status_code == 401:
                    msg = "GEMINI ERROR: 401 Unauthorized — API key is invalid or missing"
                    logger.error(msg)
                    print(msg, flush=True)
                    raise ValueError("Provider not configured: Invalid API Key (401 Unauthorized)")

                elif response.status_code == 403:
                    msg = "GEMINI ERROR: 403 Forbidden — API key does not have permission for this model"
                    logger.error(msg)
                    print(msg, flush=True)
                    raise ValueError("Provider not configured: Forbidden (403)")

                elif response.status_code == 404:
                    msg = f"GEMINI ERROR: 404 Not Found — model '{self.model_name}' does not exist or is not available for this API key"
                    logger.error(msg)
                    print(msg, flush=True)
                    raise RuntimeError(f"Provider unavailable: Model Not Found ({self.model_name})")

                elif response.status_code == 503:
                    msg = "GEMINI ERROR: 503 Service Unavailable — Gemini API is temporarily overloaded"
                    logger.error(msg)
                    print(msg, flush=True)
                    if attempt < max_retries - 1:
                        sleep_time = min(backoff, max(1.0, self.timeout - (time.time() - start_time)))
                        print(f"  Retrying in {sleep_time:.0f}s...", flush=True)
                        time.sleep(sleep_time)
                        backoff *= 2
                        continue
                    raise RuntimeError("Provider unavailable: Service Unavailable (503)")

                response.raise_for_status()
                break

            except requests.exceptions.Timeout as e:
                msg = f"GEMINI ERROR: Request timed out after {remaining_time:.1f}s (attempt {attempt + 1})"
                logger.error(msg)
                print(msg, flush=True)
                if attempt == max_retries - 1 or time.time() - start_time >= self.timeout:
                    raise RuntimeError("Provider unavailable: Timeout") from e
                time.sleep(min(backoff, max(1.0, self.timeout - (time.time() - start_time))))
                backoff *= 2

            except requests.exceptions.ConnectionError as e:
                msg = f"GEMINI ERROR: Network connection failed — {type(e).__name__}: {str(e)}"
                logger.error(msg)
                print(msg, flush=True)
                traceback.print_exc()
                if attempt == max_retries - 1 or time.time() - start_time >= self.timeout:
                    raise RuntimeError(f"Provider unavailable: Network Error — {str(e)}") from e
                time.sleep(min(backoff, max(1.0, self.timeout - (time.time() - start_time))))
                backoff *= 2

            except requests.exceptions.HTTPError as e:
                status_code = response.status_code if response else 500
                msg = f"GEMINI ERROR: HTTP {status_code} — {type(e).__name__}: {str(e)}"
                logger.error(msg)
                print(msg, flush=True)
                traceback.print_exc()
                if attempt == max_retries - 1 or time.time() - start_time >= self.timeout:
                    if status_code in (400, 401, 403):
                        raise ValueError(f"Provider not configured: HTTP {status_code}") from e
                    elif status_code == 404:
                        raise RuntimeError(f"Provider unavailable: Model Not Found ({self.model_name})") from e
                    elif status_code == 429:
                        raise RuntimeError("Provider unavailable: Quota Exceeded") from e
                    else:
                        raise RuntimeError(f"Provider unavailable: API Error ({status_code})") from e
                time.sleep(min(backoff, max(1.0, self.timeout - (time.time() - start_time))))
                backoff *= 2

            except RuntimeError:
                raise  # Already annotated above, propagate directly

            except Exception as e:
                msg = f"GEMINI ERROR: Unexpected exception — {type(e).__name__}: {str(e)}"
                logger.exception(msg)
                print(msg, flush=True)
                traceback.print_exc()
                if attempt == max_retries - 1 or time.time() - start_time >= self.timeout:
                    raise RuntimeError(f"Provider unavailable: Unexpected error ({type(e).__name__}: {str(e)})") from e
                time.sleep(min(backoff, max(1.0, self.timeout - (time.time() - start_time))))
                backoff *= 2

        if response is None:
            msg = "GEMINI ERROR: No response received (response object is None)"
            logger.error(msg)
            print(msg, flush=True)
            raise RuntimeError("Provider unavailable: No response received")

        resp_json = response.json()
        try:
            candidates = resp_json.get("candidates", [])
            if not candidates:
                prompt_feedback = resp_json.get("promptFeedback", {})
                if prompt_feedback:
                    msg = f"GEMINI ERROR: Response blocked by safety settings: {prompt_feedback}"
                    logger.error(msg)
                    print(msg, flush=True)
                    raise RuntimeError(f"Gemini API response blocked by safety settings: {prompt_feedback}")
                msg = f"GEMINI ERROR: No candidates in response: {resp_json}"
                logger.error(msg)
                print(msg, flush=True)
                raise RuntimeError(f"Gemini API response contains no candidates: {resp_json}")

            first_candidate = candidates[0]
            finish_reason = first_candidate.get("finishReason")
            if finish_reason and finish_reason not in ("STOP", None):
                logger.warning(f"Candidate finished with unexpected reason: {finish_reason}")
                print(f"GEMINI WARNING: Finish reason = {finish_reason}", flush=True)

            text = first_candidate["content"]["parts"][0]["text"]
            print(f"[Gemini] Response received: {len(text)} chars", flush=True)
            return text

        except (KeyError, IndexError) as e:
            msg = f"GEMINI ERROR: Failed to parse response — {type(e).__name__}: {str(e)}\nFull response: {resp_json}"
            logger.error(msg)
            print(msg, flush=True)
            traceback.print_exc()
            raise RuntimeError(f"Failed to parse text from Gemini API response: {resp_json}") from e
