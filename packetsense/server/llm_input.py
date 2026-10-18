import json
import sys


def create_llm_input(analysis_file):
    with open(analysis_file, "r") as file:
        analysis = json.load(file)

    llm_input = {
        "task": "Analyse the captured network traffic and identify any suspicious or anomalous behaviour.",
        "instructions": [
            "Review the network traffic statistics provided below.",
            "Identify unusual traffic patterns or indicators of suspicious activity.",
            "Explain the reasoning behind any identified anomaly.",
            "If no clear anomaly is present, state that the traffic appears normal.",
            "Do not invent information that is not present in the traffic data."
        ],
        "network_analysis": analysis
    }

    return llm_input


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 llm_input.py <analysis_json>")
        sys.exit(1)

    analysis_file = sys.argv[1]

    try:
        llm_input = create_llm_input(analysis_file)

        with open("llm_input.json", "w") as output_file:
            json.dump(llm_input, output_file, indent=4)

        print(json.dumps(llm_input, indent=4))
        print("\nLLM input saved to llm_input.json")

    except FileNotFoundError:
        print("Error: Analysis file not found.")
        sys.exit(1)

    except json.JSONDecodeError:
        print("Error: The analysis file is not valid JSON.")
        sys.exit(1)

    except Exception as error:
        print("Error:", error)
        sys.exit(1)
