import json
import urllib.request
import urllib.error
import sys

OLLAMA_URL = "http://192.168.235.1:11434/api/chat"
MODEL = "qwen3:8b"

def analyse_with_ollama(input_file):
    with open(input_file, "r") as file:
        llm_input = json.load(file)

    prompt = json.dumps(llm_input, indent=2)

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a network security analysis assistant. "
                    "Analyse the provided network traffic data carefully. "
                    "Identify suspicious or anomalous behaviour only when "
                    "there is evidence in the provided data. "
                    "Explain your reasoning clearly and do not invent "
                    "information that is not present."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        "stream": False
    }

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            response_data = response.read().decode("utf-8")

        result = json.loads(response_data)
        return result["message"]["content"]

    except urllib.error.URLError as error:
        print("Error connecting to Ollama:")
        print(error)
        sys.exit(1)

    except KeyError:
        print("Error: Unexpected response received from Ollama.")
        print(response_data)
        sys.exit(1)

    except json.JSONDecodeError:
        print("Error: Ollama returned invalid JSON.")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ollama_analyser.py <llm_input.json>")
        sys.exit(1)

    input_file = sys.argv[1]

    try:
        answer = analyse_with_ollama(input_file)

        print("\n" + "=" * 60)
        print("QWEN3 NETWORK TRAFFIC ANALYSIS")
        print("=" * 60)
        print(answer)
        print("=" * 60)

        with open("llm_analysis.txt", "w") as output_file:
            output_file.write(answer)

        print("\nAnalysis saved to llm_analysis.txt")

    except FileNotFoundError:
        print("Error: LLM input file not found.")
        sys.exit(1)

    except json.JSONDecodeError:
        print("Error: LLM input file is not valid JSON.")
        sys.exit(1)

    except Exception as error:
        print("Error:", error)
        sys.exit(1)
