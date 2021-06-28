#!/usr/bin/env python
import re
import json
import argparse
from datetime import datetime
import sys
import load_files

parser = argparse.ArgumentParser(description='A program to filter results from security scans.')
parser.add_argument("log_file", help="path to logfile; ex: 'kubelogs/cvb_r4.log'", type=str)
parser.add_argument("-p", "--phase", help="incubation, maturity, or core; defaults to incubation", default="incubation", type=str)
parser.add_argument("-r", "--requirements", help="json file with tests to check; defaults to test_list.json", default="test_list.json", type=str)
parser.add_argument("-b", "--blueprint_name", help="input blueprint name", type=str)
parser.add_argument("-l", "--logging", help="set this flag to enable writing to log lynis_eval_[blueprintname]_[date_time].log", action='store_true')
args = parser.parse_args()


def check_success(log_list):
    if "No vulnerabilities were found" in log_list:
        return True

def get_req_id(requirement):
    if "KHV" in requirement:
        return requirement[0:5]
    else:
        return requirement


def main(log_path, phase, req_path, blueprint_name, logging):
    '''Takes log, phase, and requirements documents to find important failing tests
    '''
    # reads in json object of tests to be checked
    log_string = load_files.load_log(log_path)
    log_list = load_files.load_log(log_path, False)
    requirements = load_files.load_requirements(req_path)
    # else:
    #     for line in log_list:
    #         if requirements["kube-hunter"][phase] in line:
    #             print 
    #Controls logging of results if logging flag enabled
    now = datetime.now().strftime("%Y_%m_%d_%H#%M#%S")
    filename = "kube_eval_" + blueprint_name + "_" + now +".log"
    if(logging):
        log_file = open(filename, "x")
        sys.stdout = log_file

    print(load_files.bcolors.INFO + blueprint_name + ": Kube-Hunter Evaluation " + now + load_files.bcolors.RESET)
    if check_success(log_string):
        print("No vulnerabilities found")
    
    
    re.escape(r'\ a.*$')

    if(logging):
        log_file.close()
        sys.stdout = sys.__stdout__  

if __name__ == "__main__":
    main(args.log_file, args.phase, args.requirements, args.blueprint_name, args.logging)
