#!/usr/bin/env python
import re
import json
import argparse
from datetime import datetime
import sys
import load_files

parser = argparse.ArgumentParser(description='A program to filter results from security scans.')
parser.add_argument("log_file", help="path to logfile; ex: 'vuls_logs/cvb_r4.log'", type=str)
parser.add_argument("-r", "--requirements", help="json file with tests to check; defaults to test_list.json", default="test_list.json", type=str)
parser.add_argument("-b", "--blueprint_name", help="input blueprint name", type=str)
parser.add_argument("-l", "--logging", help="set this flag to enable writing to log vuls_eval_[blueprintname]_[date_time].log", action='store_true')

args = parser.parse_args()

def check_mult_logs(log_list):
    cve_count = 0
    for line in log_list:
        if("CVE-ID" in line):
            cve_count += 1
    if cve_count > 1:
        return True

def get_os(log):
    regex = re.compile(r"centos\d+\.\d*|ubuntu\d+\.\d*")
    os_version = regex.search(log)
    print(load_files.bcolors.INFO + "Scan for OS: " + os_version.group() + load_files.bcolors.RESET)
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

def main(log_path, req_path, blueprint_name, logging):
    log_string = load_files.load_log(log_path)
    log_list = load_files.load_log(log_path, False)
    requirements = load_files.load_requirements(req_path)
    
    if check_mult_logs(log_list):
        print(load_files.bcolors.FAIL + "Please submit log files with only one log" + load_files.bcolors.RESET)
        return 0

    now = datetime.now().strftime("%Y_%m_%d_%H#%M#%S")
    filename = "vuls_eval_" + blueprint_name + "_" + now +".log"
    if(logging):
        log_file = open(filename, "x")
        sys.stdout = log_file
    
    os_version = get_os(log_string)
    cve_list = check_cvss(log_list)

    for cve in cve_list:
        if cve in requirements['vuls'][os_version]:
            print(load_files.bcolors.OK + cve + ": failed in scan: EXCEPTION GRANTED" + load_files.bcolors.RESET + "\n\tCVSS: " + requirements['vuls'][os_version][cve][0] + "\n\tPatch available: " + requirements['vuls'][os_version][cve][1])
        else:
            print(load_files.bcolors.FAIL + cve + ": failed in scan: NO EXCEPTION" + load_files.bcolors.RESET)

    if(logging):
        log_file.close()
        sys.stdout = sys.__stdout__  


if __name__ == "__main__":
    main(args.log_file, args.requirements, args.blueprint_name, args.logging)
