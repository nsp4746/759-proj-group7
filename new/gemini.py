# to run
# python .\new\\gemini.py --sarif .\\out\shell-injection.sarif --src-zip .\databases\git-graph\src.zip
#

import argparse
import json
import os
import sys
from dotenv import load_dotenv

load_dotenv()

try:
    from google import genai
    from google.genai import types
except ImportError as exc:
    raise SystemExit(
        "The google-genai package is required. Install it with 'pip install google-genai'."
    ) from exc

# Ensure we can import local helpers.
sys.path.append(os.path.dirname(__file__))

from result_inspector import extract_context_records, format_finding_as_prompt

MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-2.5-pro")



def _as_content(text: str, role: str = "user") -> types.Content:
    return types.Content(role=role, parts=[types.Part.from_text(text=text)])


def _send_and_record_response(
    client: genai.Client, history: list[types.Content], prompt: str
) -> str:
    history.append(_as_content(prompt, role="user"))
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=history,
    )
    text = response.text or ""
    history.append(_as_content(text, role="model"))
    return text


def start_chat_session(client: genai.Client, finding_record: dict):
    """Starts an interactive chat session for a single security finding."""
    conversation_history: list[types.Content] = []
    initial_prompt = format_finding_as_prompt(finding_record)

    print("--- Sending Initial Prompt to Gemini ---")
    print(initial_prompt)
    print("----------------------------------------")

    try:
        reply_text = _send_and_record_response(client, conversation_history, initial_prompt)
        print("\n--- Gemini's Analysis ---")
        print(reply_text)
        print("-------------------------\n")
    except Exception as exc:
        print(f"An error occurred while communicating with the Gemini API: {exc}")
        return

    print("Entering interactive chat. Type 'next' to move to the next finding, or 'quit' to exit.")
    while True:
        try:
            user_input = input("You: ")
            lowered = user_input.strip().lower()
            if lowered == "quit":
                raise SystemExit("Exiting.")
            if lowered == "next":
                print("\nMoving to the next finding...")
                break

            print("...sending to Gemini...")
            reply_text = _send_and_record_response(client, conversation_history, user_input)
            print(f"\nGemini: {reply_text}\n")
        except KeyboardInterrupt:
            raise SystemExit("\nExiting.")
        except Exception as exc:
            print(f"An error occurred: {exc}")
            break


def main():
    parser = argparse.ArgumentParser(description="Triage security findings using Gemini (google-genai).")
    parser.add_argument("--sarif", required=True, help="Path to SARIF results file.")
    parser.add_argument("--src-zip", required=True, help="Path to database src.zip.")
    parser.add_argument("--context", type=int, default=5, help="Lines of context around each location.")
    parser.add_argument("--limit", type=int, help="Limit number of findings to process.")
    parser.add_argument(
        "--api-key",
        help="Gemini API key. If not provided, the GEMINI_API_KEY environment variable is used.",
    )
    args = parser.parse_args()

    api_key = args.api_key or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise SystemExit("Error: Gemini API key not provided. Use --api-key or set GEMINI_API_KEY.")

    client = genai.Client(api_key=api_key)

    try:
        records = extract_context_records(args.sarif, args.src_zip, args.context, args.limit)
    except SystemExit as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    if not records:
        print("No findings were extracted. Exiting.")
        return

    print(f"Found {len(records)} findings to analyze.")
    for idx, record in enumerate(records):
        print(f"\n--- Analyzing Finding {idx + 1}/{len(records)} ---")
        start_chat_session(client, record)

    print("\n--- All findings analyzed. ---")


if __name__ == "__main__":
    main()
