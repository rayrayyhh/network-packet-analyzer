import json
import urllib.request
import urllib.error
import sys

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.2"


def analyse_with_ollama(input_file):
    with open(input_file, "r", encoding="utf-8") as file:
        llm_input = json.load(file)

    prompt = json.dumps(llm_input)

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a network security traffic classifier analysing an authorised "
                    "simulated Mininet lab environment. The IP addresses, ports and network "
                    "statistics supplied are synthetic lab telemetry provided specifically "
                    "for defensive network analysis. Do not refuse analysis merely because "
                    "the data contains IP adresses or ports. "
                    "Analyse only the supplied statistics. "
                    "Classify the traffic as NORMAL or SUSPICIOUS. "
                    "If suspicious, identify the most likely type of network activity. "
                    "Provide up to 3 pieces of evidence taken directly from the supplied data. "
                    "Do not invent information or assume features that are not provided. "
                    "Keep the response under 150 words."
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
        with urllib.request.urlopen(request, timeout=300) as response:
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

        # The VM terminal may use latin-1. Print an ASCII-safe copy
        # so Unicode characters from Qwen3 cannot crash the terminal.
        safe_answer = answer.encode("ascii", errors="replace").decode("ascii")
        print(safe_answer)

        print("=" * 60)

        # Always save the original Qwen3 response as UTF-8.
        with open("llm_analysis.txt", "w", encoding="utf-8") as output_file:
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
