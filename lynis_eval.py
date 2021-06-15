#!/usr/bin/env python
import re
import json

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
    pathToRequirements is a string (test_list.json)
    '''
    raw_path = make_raw_string(path_to_requirements)
    reqs_file = open(raw_path)
    reqs = json.load(reqs_file)
    reqs_file.close()
    return reqs

def main(log_path, phase, req_path):
    '''Takes log, phase, and requirements documents to find important failing tests
    '''
    # reads in json object of tests to be checked
    log_string = read_log_to_string(log_path)
    requirements = load_requirements(req_path)
    re.escape(r'\ a.*$')
    # Creates and compiles regular expressions as objects
    for testname in requirements['lynis'][phase]:
        testname = re.escape(testname)
        end = r'===='
        regex = re.compile(testname + '.*?' + end, re.DOTALL)

        # Runs regex against a string
        testdata = regex.search(log_string)
        print(testdata.group())

if __name__ == "__main__":
    main('lynislogs/cvb_r4.log', 'incubation', 'test_list.json')
