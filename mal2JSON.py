import json
import re

def parse_malware_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    entries = re.split(r'-{80,}', content)
    json_data = []

    for entry in entries:
        if entry.strip():
            matched = re.search(r'\[ MATCHED \] (.+)', entry)
            severity = re.search(r'SEVERITY:\[(?:\d+m)?(\d+)', entry)
            suspect = 'SUSPECT' in entry
            malware = 'MALWARE' in entry
            detections = re.findall(r'\d+\) (.+)', entry)
            malware_name = re.search(r'\[97m(.+)', entry)

            json_entry = {
                "matched": matched.group(1) if matched else None,
                "severity": int(severity.group(1)) if severity else None,
                "suspect": suspect,
                "malware": malware,
                "detections": detections,
                "malwareName": malware_name.group(1) if malware_name else None
            }
            json_data.append(json_entry)

    return json_data

def main():
    file_path = 'malware.txt'  # Assuming the file is in the same directory
    json_data = parse_malware_file(file_path)
    
    with open('malware.json', 'w') as outfile:
        json.dump(json_data, outfile, indent=2)

    print("JSON file 'malware_output.json' has been created.")

if __name__ == "__main__":
    main()
