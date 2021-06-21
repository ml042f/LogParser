#!/usr/bin/env python
import re
import json
import argparse
from datetime import datetime
import sys
from lynis_eval import load_requirements, load_log, make_raw_string, bcolors

parser = argparse.ArgumentParser(description='A program to filter results from security scans.')
parser.add_argument("log_file", help="path to logfile; ex: 'vuls_logs/cvb_r4.log'", type=str)
parser.add_argument("-p", "--phase", help="incubation, maturity, or core; defaults to incubation", default="incubation", type=str)
parser.add_argument("-r", "--requirements", help="json file with tests to check; defaults to test_list.json", default="test_list.json", type=str)
parser.add_argument("-b", "--blueprint_name", help="input blueprint name", type=str)
parser.add_argument("-l", "--logging", help="set this flag to enable writing to log vuls_eval_[blueprintname]_[date_time].log", action='store_true')

args = parser.parse_args()

def main(log_path, phase, req_path, blueprint_name, logging):
    print(log_path + phase + req_path, + blueprint_name)
    if logging:
        print("logging is happening, save the rainforests!")


if __name__ == "__main__":
    main(args.log_file, args.phase, args.requirements, args.blueprint_name, args.logging)
