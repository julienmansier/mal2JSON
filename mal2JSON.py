import argparse
import os
import json
import re

def parse_malware_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()

    entries = re.split(r'-{80,}', content)
    json_data = []

    for entry in entries:
        temp = {}

        if entry.strip():
            temp["malware_name"] = re.search(r"\[ SEVERITY:10/10 \] (.+)", entry).group(1).strip()
            
            if 'SUSPECT' in entry:
                temp["suspected_malware"] = True
            else:
                temp["suspected_malware"] = False
            temp["detections"] = re.findall(r'\d+\) (.+)', entry)


            json_data.append(temp)

    return json_data

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Process a file with an optional file path.")
    parser.add_argument("file_path", nargs="?", default="default_file.txt", help="Path to the file to process")

    # Parse arguments
    args = parser.parse_args()
    file_path = args.file_path

    # If the file path is not provided, prompt user
    if file_path == "default_file.txt" and not os.path.exists(file_path):
        # Prompt the user to enter the file path
        file_path = input("Enter the path to the input text file: ")
    
    
    
    
    json_data = parse_malware_file(file_path)
    
    with open('malware.json', 'w') as outfile:
        json.dump(json_data, outfile, indent=2)

    print("JSON file 'malware_output.json' has been created.")

if __name__ == "__main__":
    main()
