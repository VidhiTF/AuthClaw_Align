import os
import subprocess
import sys

def main():
    env = os.environ.copy()
    
    # Read .env.local from parent directory
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env.local")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key_str = key.strip()
                    val_str = val.strip()
                    
                    # Ensure sslmode=disable is set for PostgreSQL
                    if key_str == "DATABASE_URL" and "sslmode" not in val_str:
                        if "?" in val_str:
                            val_str += "&sslmode=disable"
                        else:
                            val_str += "?sslmode=disable"
                            
                    env[key_str] = val_str
                    
    # Force PORT to 8080
    env["PORT"] = "8080"
    
    print("Starting AuthClaw Go Gateway via go run .")
    try:
        subprocess.run(["go", "run", "."], env=env, cwd=os.path.dirname(__file__))
    except KeyboardInterrupt:
        print("Stopping gateway...")

if __name__ == "__main__":
    main()
