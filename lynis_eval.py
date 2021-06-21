#!/usr/bin/env python
import re
import json
import argparse
from datetime import datetime
import sys

parser = argparse.ArgumentParser(description='A program to filter results from security scans.')
parser.add_argument("log_file", help="path to logfile; ex: 'lynislogs/cvb_r4.log'", type=str)
parser.add_argument("-p", "--phase", help="incubation, maturity, or core; defaults to incubation", default="incubation", type=str)
parser.add_argument("-r", "--requirements", help="json file with tests to check; defaults to test_list.json", default="test_list.json", type=str)
parser.add_argument("-b", "--blueprint_name", help="input blueprint name", type=str)
parser.add_argument("-l", "--logging", help="set this flag to enable writing to log lynis_eval_[blueprintname]_[date_time].log", action='store_true')
args = parser.parse_args()

class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    INFO = '\u001b[36m' #CYAN
    RESET = '\033[0m' #RESET COLOR

def make_raw_string(path_to_file):
    '''returns raw string of inputted text
    '''
    return r"{}".format(path_to_file)

def load_log(path_to_log):
    '''returns string of logfile specified in path:
    ex: "lynislogs/cvb_r4.log"
    '''
    log_file = make_raw_string(path_to_log)
    log_text = open(log_file)
    log_string = log_text.read()
    log_text.close()
    return log_string

def find_compilers(path_to_log):
    log_file = make_raw_string(path_to_log)
    log_text = open(log_file)
    log_list = log_text.readlines()
    lines_with_compiler =[]
    for log in log_list:
        if 'compiler' in log:
            lines_with_compiler.append(log)
    lines_with_compiler.reverse()
    while "Performing test ID HRDN-7220" not in lines_with_compiler[0]:
        lines_with_compiler.pop(0)
    lines_with_compiler.pop(0)
    lines_with_compiler.reverse()
    for lines in lines_with_compiler:
        print("\t" + lines[:-1])
    log_text.close()

def load_requirements(path_to_requirements):
    '''returns dictionary object of json object specified in path:
    path_to_requirements is a string (test_list.json)
    '''
    raw_path = make_raw_string(path_to_requirements)
    reqs_file = open(raw_path)
    reqs = json.load(reqs_file)
    reqs_file.close()
    return reqs

def verify_complete(full_text):
    if 'Program ended successfully' not in full_text:
        print(bcolors.WARNING + "NO PROGRAM END DETECTED" + bcolors.RESET)
    if 'Lynis ended successfully' not in full_text:
        print(bcolors.WARNING + "NO LYNIS END DETECTED" + bcolors.RESET)

class scores:
    REGEXES = [
        "Hardening index : .*",
        "Hardening strength: .*",
        "Tests performed:.*",
        "Total tests:.*",
        "Active plugins:.*",
        "Total plugins:.*"
    ]

    def print_scores(full_text, regex_args):
        compiled = re.compile(regex_args)
        index = compiled.search(full_text)
        print(bcolors.INFO + index.group() + bcolors.RESET)

    def print_version_build_date(full_text):
        regex = re.compile('Starting Lynis.*')
        build = regex.search(full_text)
        build = re.search("Lynis.*", build.group())
        print(bcolors.INFO + "Build: " + build.group() + bcolors.RESET)

def check_failure(testname, log_entry, reqs):
    if log_entry == None:
        print(bcolors.WARNING + testname + ": NOT PRESENT IN THIS LOG" + bcolors.RESET)
        return False
    if 'assigned partial' in log_entry.group():
        print(bcolors.FAIL + testname + ": FAILED" + bcolors.RESET)
        if testname in reqs['lynis_recs']:
            for items in reqs['lynis_recs'][testname]:
                print("\t" + items)
        return True
    else:
        print(bcolors.OK + testname + ": SUCCESS" + bcolors.RESET)
        return False

def get_results(fulltext):
    # cleanup needed. Help w regex for anyone who might be more proficient

    splitlist1 = re.split("assigned partial", fulltext)
    splitlist1.pop()
    # print(len(splitlist1))
    regex1 = re.compile('.*\n', re.DOTALL)
    regex2 = re.compile("\n.*", re.DOTALL)
    # regex3 = re.compile("^.*$",  re.MULTILINE)
    splitlist2 = []
    splitlist3 = []
    splitlist4 = []
    for item in splitlist1:
        splitlist2.append(regex1.search(item))
    for item in splitlist2:
        splitlist3.append(re.split("Hardening|Test", item.group()))
    for item in splitlist3:
        cut = regex2.search(item[-1])
        cut = cut.group()[1:-1]
        cut = re.sub("\n", "\n\t", cut)
        print("\t" + cut)
        splitlist4.append(cut + "\n")

def main(log_path, phase, req_path, blueprint_name, logging):
    '''Takes log, phase, and requirements documents to find important failing tests
    '''
    # reads in json object of tests to be checked
    log_string = load_log(log_path)
    requirements = load_requirements(req_path)

    #Controls logging of results if logging flag enabled
    now = datetime.now().strftime("%Y_%m_%d_%H#%M#%S")
    filename = "lynis_eval_" + blueprint_name + "_" + now +".log"
    if(logging):
        log_file = open(filename, "x")
        sys.stdout = log_file


    verify_complete(log_string)
    print(bcolors.INFO + blueprint_name + ": Lynis Evaluation " + now + bcolors.RESET)
    scores.print_version_build_date(log_string)
    for expression in scores.REGEXES:
        scores.print_scores(log_string, expression)

    re.escape(r'\ a.*$')
    # Creates and compiles regular expressions as objects
    for testname in requirements['lynis'][phase]:
        testname_escaped = re.escape(testname)
        if("Result:" in testname):
            end = r'hardening points'
        else:
            end = r'===='       
        regex = re.compile(testname_escaped + '.*?' + end, re.DOTALL)
        # Runs regex against a string
        testdata = regex.search(log_string)
        if check_failure(testname, testdata, requirements):
            get_results(testdata.group())
    find_compilers(log_path)

    if(logging):
        log_file.close()
        sys.stdout = sys.__stdout__  

if __name__ == "__main__":
    main(args.log_file, args.phase, args.requirements, args.blueprint_name, args.logging)
