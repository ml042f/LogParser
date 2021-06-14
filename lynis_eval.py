import re

# Creates and compiles regular expresions as objects
testname = 'Performing test ID KRNL-5820'
end = r'===='
regex = re.compile(testname + '.*?' + end, re.DOTALL)

# Runs regex against a string
# s = "This is just\na simple sentence"
# print(regex.match(s))

logfile = r"lynislogs/cvb_r4.log"
logtext = open(logfile)
logstring = logtext.read()
logtext.close()
 
# print(data)
testdata = regex.search(logstring)
print(testdata.group())
