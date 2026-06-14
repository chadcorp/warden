"""word-count -- a Warden code skill.

Contract for a kind:"code" skill: read a JSON object from stdin, write a JSON
object to stdout. This one needs nothing -- no network, no filesystem, no
secrets -- so the sandbox runs it with every capability denied.
"""
import json
import sys


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        data = {}
    text = str(data.get("text", ""))
    words = len(text.split())
    result = {
        "words": words,
        "chars": len(text),
        "lines": text.count("\n") + 1 if text else 0,
        "avg_word_len": round(sum(len(w) for w in text.split()) / words, 2) if words else 0,
    }
    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()
