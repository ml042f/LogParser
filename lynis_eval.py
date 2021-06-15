import re
import json

# Reads in logfile
logfile = r"lynislogs/cvb_r4.log"
logtext = open(logfile)
logstring = logtext.read()
logtext.close()

# reads in json object of tests to be checked
reqsfile = open('test_list.json')
reqs = json.load(reqsfile)
reqsfile.close()


re.escape(r'\ a.*$')

listoftests = ['Test: Checking PASS_MAX_DAYS option in /etc/login.defs', 'Performing test ID AUTH-9328 (Default umask values)', 'Performing test ID SSH-7440 (Check OpenSSH option: AllowUsers and AllowGroups)', 'Test: checking for file /etc/network/if-up.d/ntpdate', 'Result: sysctl key fs.suid_dumpable', 'Result: sysctl key kernel.dmesg_restrict', 'Result: sysctl key net.ipv4.conf.default.accept_source_route', 'Performing test ID HRDN-7220 (Check if one or more compilers are installed)']

# Creates and compiles regular expressions as objects
for testname in reqs['lynis']['incubation']:
    testname = re.escape(testname)
    end = r'===='
    regex = re.compile(testname + '.*?' + end, re.DOTALL)

    # Runs regex against a string
    testdata = regex.search(logstring)
    print(testdata.group())
