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
    INFO = '\u001b[36m' #CYAN
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

class scores:
    REGEXES = [
        "Hardening strength: .*",
        "Hardening index : .*",
        "Tests performed:.*",
        "Total tests:.*",
        "Active plugins:.*",
        "Total plugins:.*",
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

def verify_complete(full_text):
    if 'Program ended successfully' not in full_text:
        print(bcolors.WARNING + "NO PROGRAM END DETECTED" + bcolors.RESET)
    if 'Lynis ended successfully' not in full_text:
        print(bcolors.WARNING + "NO LYNIS END DETECTED" + bcolors.RESET)

def main(log_path, phase, req_path):
    '''Takes log, phase, and requirements documents to find important failing tests
    '''
    # reads in json object of tests to be checked
    log_string = read_log_to_string(log_path)
    requirements = load_requirements(req_path)

    verify_complete(log_string)
    scores.print_version_build_date(log_string)
    for expression in scores.REGEXES:
        scores.print_scores(log_string, expression)

    re.escape(r'\ a.*$')
    # Creates and compiles regular expressions as objects
    for testname in requirements['lynis'][phase]:
        testname_escaped = re.escape(testname)
        end = r'===='
        regex = re.compile(testname_escaped + '.*?' + end, re.DOTALL)
        # Runs regex against a string
        testdata = regex.search(log_string)
        if check_failure(testname, testdata):
            get_results(testdata.group())
            
if __name__ == "__main__":
    main(args.log_file, args.phase, args.requirements)
