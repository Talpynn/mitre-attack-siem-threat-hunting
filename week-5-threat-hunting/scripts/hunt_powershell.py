from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data" / "sample_process_events.csv"
OUTDIR = ROOT / "output"
OUTPUT = OUTDIR / "hunt_results.csv"
KEYWORDS = ("-enc", "-encodedcommand", "downloadstring", "invoke-expression", "iex")

def main():
    with INPUT.open("r", newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    matches = []
    for row in rows:
        process = row.get("process_name", "").lower()
        command = row.get("command_line", "").lower()
        found = [key for key in KEYWORDS if key in command]
        if "powershell" in process and found:
            row["matched_keywords"] = "; ".join(found)
            row["analyst_note"] = "Investigate in context; a keyword match is not proof of malicious activity."
            matches.append(row)
    OUTDIR.mkdir(exist_ok=True)
    fields = list(rows[0].keys()) + ["matched_keywords", "analyst_note"]
    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(matches)
    print("Week 5 PowerShell threat-hunting demo")
    print(f"Input records: {len(rows)}")
    print(f"Matching events: {len(matches)}")
    for row in matches:
        print(f"- {row['timestamp']} | {row['host']} | {row['command_line']}")
        print(f"  Matched: {row['matched_keywords']}")
    print(f"Results saved to: {OUTPUT}")
    print("Reminder: the input is simulated; matches require investigation.")

if __name__ == "__main__":
    main()
