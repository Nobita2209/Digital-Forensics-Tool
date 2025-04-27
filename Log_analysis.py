import re
import sys
from collections import defaultdict

output_file = r"C:\Users\Nimbalkar\Desktop\Log_Analysis.txt"

def parse_event_log(file_path, output_handle):
    log_data = {
        'event_ids': defaultdict(int),
        'sources': defaultdict(int),
        'categories': defaultdict(int)
    }

    events = []

    log_pattern = re.compile(
        r'Event ID:\s+(?P<event_id>\d+)\s+'
        r'Source:\s+(?P<source>.+?)\s+'
        r'Time Generated:\s+(?P<time_generated>.+?)\s+'
        r'Category:\s+(?P<category>\d+)\s+'
        r'Description:\s+\((?P<description>.*?)\)'
    )

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines_processed = 0
            lines_matched = 0

            for line in file:
                lines_processed += 1
                match = log_pattern.search(line.strip())
                if match:
                    lines_matched += 1
                    event_id = match.group('event_id')
                    source = match.group('source')
                    time_generated = match.group('time_generated')
                    category = match.group('category')
                    description = match.group('description')

                    events.append(
                        f"Event ID: {event_id} | Source: {source} | "
                        f"Time: {time_generated} | Category: {category} | "
                        f"Description: {description}"
                    )

                    log_data['event_ids'][event_id] += 1
                    log_data['sources'][source] += 1
                    log_data['categories'][category] += 1

        print(f"\n--- File: {file_path} ---", file=output_handle)
        print(f"Total lines processed: {lines_processed}", file=output_handle)
        print(f"Valid log entries found: {lines_matched}", file=output_handle)
        print(f"Failed to parse: {lines_processed - lines_matched} lines", file=output_handle)

        if events:
            print("\n--- Raw Event Logs (First 5) ---", file=output_handle)
            for event in events[:5]:
                print(event, file=output_handle)
            if len(events) > 5:
                print(f"\nShowing 5 of {len(events)} total events...", file=output_handle)
        else:
            print("\nNo valid log entries found in the file.", file=output_handle)

        print("\n--- Log Analysis Report ---", file=output_handle)

        print("\nTop 5 Event IDs:", file=output_handle)
        for eid, count in sorted(log_data['event_ids'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {eid}: {count} occurrences", file=output_handle)

        print("\nTop 5 Sources:", file=output_handle)
        for src, count in sorted(log_data['sources'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {src}: {count} events", file=output_handle)

        print("\nTop 5 Categories:", file=output_handle)
        for cat, count in sorted(log_data['categories'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  Category {cat}: {count} events", file=output_handle)

        print("\nPotential Issues:", file=output_handle)
        issues_found = False
        for eid, count in log_data['event_ids'].items():
            if count > 10:
                print(f"  Frequent Event ID {eid} detected ({count} occurrences)", file=output_handle)
                issues_found = True
        if not issues_found:
            print("  No frequent errors detected", file=output_handle)

    except FileNotFoundError:
        print(f"Error: The file {file_path} was not found.", file=output_handle)
    except Exception as e:
        print(f"An error occurred: {str(e)}", file=output_handle)

# Redirect all output to the specified file
with open(output_file, 'w', encoding='utf-8') as output_handle:
    for log_file in ['Application', 'Security', 'System', 'Windows PowerShell', 'Microsoft-Windows-Sysmon%4Operational']:
        file_path = f'C:\\Users\\Nimbalkar\\Desktop\\New folder\\{log_file}.txt'
        parse_event_log(file_path, output_handle)