#!/usr/bin/env python
import re
import json
import argparse
from datetime import datetime
import sys
import load_files

parser = argparse.ArgumentParser(description='A program to filter results from security scans.')
parser.add_argument("log_file", help="path to logfile; ex: 'vuls_logs/cvb_r4.log'", type=str)
# parser.add_argument("-p", "--phase", help="incubation, maturity, or core; defaults to incubation", default="incubation", type=str)
parser.add_argument("-r", "--requirements", help="json file with tests to check; defaults to test_list.json", default="test_list.json", type=str)
parser.add_argument("-b", "--blueprint_name", help="input blueprint name", type=str)
parser.add_argument("-l", "--logging", help="set this flag to enable writing to log vuls_eval_[blueprintname]_[date_time].log", action='store_true')

args = parser.parse_args()

def get_os(log):
    regex = re.compile(r"centos\d+\.\d*|ubuntu\d+\.\d*")
    os_version = regex.search(log)
    print("Scan for OS: " + os_version.group())
    return re.sub('[^a-zA-Z0-9]+', '', os_version.group())

def check_cvss(log_lines):
    cve_list = []
    for line in log_lines:
        score = re.search(r"\d+\.\d*", line)
        if score == None:
            continue
        if(float(score.group()) >= 9):
            cve = re.search(r"CVE\-\d*\-\d*", line)
            if cve == None:
                continue
            cve_list.append(cve.group())
    return cve_list

def main(log_path, phase, req_path, blueprint_name, logging):
    log_string = load_files.load_log(log_path)
    log_list = load_files.load_log(log_path, False)
    requirements = load_files.load_requirements(req_path)
    
    now = datetime.now().strftime("%Y_%m_%d_%H#%M#%S")
    filename = "vuls_eval_" + blueprint_name + "_" + now +".log"
    if(logging):
        log_file = open(filename, "x")
        sys.stdout = log_file
    
    os_version = get_os(log_string)
    cve_list = check_cvss(log_list)

    for cve in cve_list:
        if cve in requirements['vuls'][os_version]:
            print(cve + ": failed in scan: EXCEPTION GRANTED")
        else:
            print(cve + ": failed in scan: NO EXCEPTION")



    if(logging):
        log_file.close()
        sys.stdout = sys.__stdout__  


if __name__ == "__main__":
    main(args.log_file, args.phase, args.requirements, args.blueprint_name, args.logging)
