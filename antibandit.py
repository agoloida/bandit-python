#!/usr/bin/python

import sys, os, time, paramiko

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

working = 0
pwlist = ["bandit0"]

banditcmd = ["cat readme", 														#0
	     "cat <-", 															#1
	     "cat 'spaces in this filename'",												#2
	     '''cd inhere		         	
       		cat .hidden ''', 													#3
	     '''cd inhere
    		file ./-file* |grep ASCII | head -c 9 | xargs cat ''',									#4
	     "find -size 1033c | xargs cat",												#5
	     "find / -size 33c -group bandit6 -user bandit7 2>/dev/null | xargs cat",							#6
	     "cat data.txt | grep -wPo '(millionth\s)\K[^\s]*'",									#7
	     "sort data.txt | uniq -u",													#8
	     "strings data.txt | grep -Po '[^\s](=+\s)\K[\S]*' | sed -n '4p'",								#9
	     "base64 -d data.txt | tr ' ' '\n' | sed -n '4p'",										#10
	     "cat data.txt | tr '[A-Za-z]' '[N-ZA-Mn-za-m]' | tr ' ' '\n' | sed -n '4p'",						#11
	     '''mkdir /tmp/99
		xxd -r data.txt > /tmp/99/data 
		cd /tmp/99
		mv data data.gz
		gunzip data.gz
		mv data data.bz2
		bzip2 -d data.bz2
    		mv data data.gz
		gunzip data.gz
		mv data data.tar
		tar -xf data.tar
		tar -xf data5.bin
		tar -xf data6.bin
		mv data8.bin data.gz
		gunzip data.gz
		cat data | grep -oE '[^ ]+$' ''',											#12
	     '''ssh -o StrictHostKeyChecking=no -i sshkey.private bandit14@localhost "cat /etc/bandit_pass/bandit14" ''',		#13
	     "cat /etc/bandit_pass/bandit14 | nc localhost 30000 | sed -n '2p'",							#14
	     "cat /etc/bandit_pass/bandit15 | openssl s_client -quiet -connect localhost:30001 | grep '.\{32\}' ",			#15 
	     '''cat /etc/bandit_pass/bandit16 | openssl s_client -connect localhost:31790 -quiet | grep -A 26 "\-\-\-\-\-BEGIN" ''', 
		#I'm cheating here. Not sure how to determine what the correct port is. So I'm connecting to the known port.		#16
	     "grep -Fvf passwords.old passwords.new",											#17	
             "cat readme",														#18
             "./bandit20-do cat /etc/bandit_pass/bandit20",										#19
             '''./suconnect 9999 > /dev/null
		tail -1 /tmp/9999
		rm /tmp/9999''',													#20
             "cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv",#Hardcoded folder name is discovered in /usr/bin/cronjob_bandit22.sh		#21
             "cat /tmp/8ca319486bfbbc3663ea0fbe81326349",#Hardocded folder name is discovered by running md5sum on "I am user bandit23"	#22
             '''echo '#!/bin/bash' > /var/spool/bandit24/newnew.sh
             echo 'cp /etc/bandit_pass/bandit24 /var/spool/bandit24/test/password' >> /var/spool/bandit24/newnew.sh
             echo 'chmod 777 /var/spool/bandit24/test/password' >> /var/spool/bandit24/newnew.sh
             chmod 777 /var/spool/bandit24/newnew.sh
             sleep 40
             cat /var/spool/bandit24/test/password''' #This one takes at least 31 seconds to run. Be patient.				#23
             
		]
#######################################################################
def banditlevel(level, banditusr, banditcmd, pwlist, working): 
	print "\n\n\n Working on level: " + str(level)
	print "Running command: ".rjust(19) + banditcmd[level -1]
	print "Username: ".rjust(19) + banditusr
	print "Password: ".rjust(19) + pwlist[working]
	banditpw = pwlist[working]
	
	if level == 21:
		ssh.connect('bandit.labs.overthewire.org', username='bandit20', password=banditpw, allow_agent=False, look_for_keys=False)
		ssh.exec_command('''echo "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | nc -l -p 9999 > /tmp/9999''')

	if level == 18: # This level needs a key file so a different connect command needs to be sent
		ssh.connect('bandit.labs.overthewire.org', username=banditusr, key_filename='level17.key', allow_agent=False, look_for_keys=False)
	else:
		ssh.connect('bandit.labs.overthewire.org', username=banditusr, password=banditpw, allow_agent=False, look_for_keys=False)

	stdin, stdout, stderr = ssh.exec_command(banditcmd[level -1], timeout=60)
	data = stdout.read().rstrip()
	
	

	print ":::Found Password: " + data
    
	if level == 17: # This part creates the key file which will be used in level 18. No password is needed.
		f =  open('level17.key', 'w')
		f.write(data)
		f.close()
		os.chmod("level17.key", 0600)
		pwlist.append("Using key file.")
	else:
		pwlist.append(data)

	return pwlist;

def testnumber(n):
	try:
		float(n)
		return True
	except ValueError:
		return False
#######################################################################

if len(sys.argv) == 1:
	print "Too few arguments. Usage ./antibandit.py [level number]"
elif len(sys.argv) == 3:
	print "Too many arguments Usage ./antibandit.py [level number]"
else:
	if testnumber(sys.argv[1]):
		level = int(sys.argv[1])
		if level > 23:
			print "Out of range. Select level 1-23"
		elif level < 1:
			print "Out of range. Select level 1-23"
		else:
			for level in range(1, level + 1):
				banditusr = "bandit" + str(working)
				banditlevel(level, banditusr, banditcmd, pwlist, working)
				time.sleep(1)
				working = working + 1
	else:
		print "Please enter a number for level"