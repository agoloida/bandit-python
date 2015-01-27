#!/usr/bin/python

import paramiko
import sys

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

working = 0
pwlist = ["bandit0"]

banditcmd = ["cat readme", "cat <-", "cat 'spaces in this filename'"]	

def banditlevel(level, banditusr, banditcmd, pwlist, working):
	print "now working on: " + str(working)
	print "running command " + banditcmd[level -1]
	print "username " + banditusr
	print "password " + pwlist[working]
	banditpw = pwlist[working]
	ssh.connect('bandit.labs.overthewire.org', username=banditusr, password=banditpw, allow_agent=False, look_for_keys=False)
	stdin, stdout, stderr = ssh.exec_command(banditcmd[level -1], timeout=30)
	data = stdout.read().rstrip()
	pwlist.append(data)
	
	print data
	

	return pwlist;

#######################################################################

if len(sys.argv) == 1:
	print "Please enter a level number"

else:
	level = int(sys.argv[1])
	
	for level in range(1, level + 1):
		banditusr = "bandit" + str(working)
		banditlevel(level, banditusr, banditcmd, pwlist, working) 
		working = working + 1
		print pwlist
		

#	else:
#		print "Haven't done that level yet"


