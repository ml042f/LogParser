import json

class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    INFO = '\u001b[36m' #CYAN
    RESET = '\033[0m' #RESET COLOR

def load_log(path_to_log, lines_or_string = True):
    '''returns string of logfile specified in path:
    ex: "lynislogs/cvb_r4.log"
    '''
    log_file = make_raw_string(path_to_log)
    log_text = open(log_file)
    if lines_or_string:
        log_string = log_text.read()
    else:
        log_string = log_text.readlines()

    log_text.close()
    return log_string

def make_raw_string(path_to_file):
    '''returns raw string of inputted text
    '''
    return r"{}".format(path_to_file)

def load_requirements(path_to_requirements):
    '''returns dictionary object of json object specified in path:
    path_to_requirements is a string (test_list.json)
    '''
    raw_path = make_raw_string(path_to_requirements)
    reqs_file = open(raw_path)
    reqs = json.load(reqs_file)
    reqs_file.close()
    return reqs
    