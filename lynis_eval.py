#!/usr/bin/env python
import re
import json
import argparse

parser = argparse.ArgumentParser(description='A program to filter results from security scans.')
parser.add_argument("log_file", help="path to logfile; ex: 'lynislogs/cvb_r4.log'", type=str)
parser.add_argument("-p", "--phase", help="incubation, maturity, or core; defaults to incubation", default="incubation", type=str)
parser.add_argument("-r", "--requirements", help="json file with tests to check; defaults to test_list.json", default="test_list.json", type=str)
args = parser.parse_args()

class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR

def make_raw_string(path_to_file):
    '''returns raw string of inputted text
    '''
    return r"{}".format(path_to_file)

def read_log_to_string(path_to_log):
    '''returns string of logfile specified in path:
    ex: "lynislogs/cvb_r4.log"
    '''
    log_file = make_raw_string(path_to_log)
    log_text = open(log_file)
    log_string = log_text.read()
    log_text.close()
    return log_string

def load_requirements(path_to_requirements):
    '''returns dictionary object of json object specified in path:
    path_to_requirements is a string (test_list.json)
    '''
    raw_path = make_raw_string(path_to_requirements)
    reqs_file = open(raw_path)
    reqs = json.load(reqs_file)
    reqs_file.close()
    return reqs

def check_failure(testname, log_entry):
    if log_entry == None:
        print(bcolors.WARNING + testname + ": NOT PRESENT IN THIS LOG" + bcolors.RESET)
        return False
    if 'assigned partial' in log_entry.group():
        print(bcolors.FAIL + testname + ": FAILED" + bcolors.RESET)
        return True
    else:
        print(bcolors.OK + testname + ": SUCCESS" + bcolors.RESET)
        return False

def main(log_path, phase, req_path):
    '''Takes log, phase, and requirements documents to find important failing tests
    '''
    # reads in json object of tests to be checked
    log_string = read_log_to_string(log_path)
    requirements = load_requirements(req_path)
    re.escape(r'\ a.*$')
    # Creates and compiles regular expressions as objects
    for testname in requirements['lynis'][phase]:
        testname_escaped = re.escape(testname)
        end = r'===='
        regex = re.compile(testname_escaped + '.*?' + end, re.DOTALL)
        # Runs regex against a string
        testdata = regex.search(log_string)
        if check_failure(testname, testdata):
            # print("\t" + testdata.group())
            print("\tIndent and list all lines in lynis.log between the ‘Test:’ and ‘Hardening:’ lines here")
            
if __name__ == "__main__":
    main(args.log_file, args.phase, args.requirements)