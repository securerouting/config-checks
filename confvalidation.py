#!/usr/bin/env python3
#
#  Copyright (c) 2015, Parsons, Inc
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  *  Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#
#  *  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
#  *  Neither the name of Parsons, Inc nor the names of its contributors may
#     be used to endorse or promote products derived from this software
#     without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS
#  IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
#  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
# confvalidation
#	This module contains a number of utility routines to be used in writing
#	validators for configuration files used by the rpki.net software.
#
# Revision History
#	1.0	Initial revision.				150317
#
#	Copyright 2015 PARSONS, Inc.  All rights reserved.
#	Written by Wayne Morrison, 150317.
#


import os
import sys
import pwd
import re
import urlparse

import rpki.config
import rpki.exceptions


#
# Version information.
#
NAME = "confvalidation.py"
VERS = NAME + " version: 1.0"

#------------------------------------------------------------------------
# Option fields.
#	options handled:
#		-verbose		turn on verbose output
#

listflag    = 0					# List section info.
nameflag    = 0					# List section names only.
untransflag = 0					# Give untranslated values.
verbose	    = 0					# Verbose flag.

#------------------------------------------------------------------------
# Other data.
#
loglevels = [
		'log_sys_err',
		'log_usage_err',
		'log_data_err',
		'log_telemetry',
		'log_verbose',
		'log_debug'
	    ]

sysloglevels =	[
			"auth",
			"authpriv",
			"cron",
			"daemon",
			"ftp",
			"kern",
			"lpr",
			"mail",
			"mark",
			"news",
			"security",
			"syslog",
			"user",
			"uucp",
			"local0",
			"local1",
			"local2",
			"local3",
			"local4",
			"local5",
			"local6",
			"local7",
		]

syslogpriorities = [
			'emerg',
			'alert',
			'crit',
			'err',
			'warning',
			'notice',
			'info',
			'debug'
		   ]


problems = list()				# List of problems we found.

#------------------------------------------------------------------------
# Routine:	setopts()
#
# Purpose:	Set the option values used in this module.
#
def setopts(nlistflag, nnameflag, nuntransflag, nverbose):
	global listflag
	global nameflag
	global untransflag
	global verbose

	listflag    = nlistflag
	nameflag    = nnameflag
	untransflag = nuntransflag
	verbose     = nverbose


#------------------------------------------------------------------------
# Routine:	prtopts()
#
# Purpose:	Print the option values used in this module.
#
def prtopts():
	global listflag   
	global nameflag  
	global untransflag
	global verbose	 

	print " "
	print "listflag    - %d" % listflag
	print "nameflag    - %d" % nameflag
	print "untransflag - %d" % untransflag
	print "verbose     - %d" % verbose
	print " "

#------------------------------------------------------------------------
# Routine:	getlistflag()
#
# Purpose:	Get the listflag option value.
#
def getlistflag():
	global listflag

	return(listflag)

#------------------------------------------------------------------------
# Routine:	getproblems()
#
# Purpose:	Return the current list of problems.  If the clearflag
#		is set, we'll zap the list.
#
def getproblems(clearflag):
	global problems				# List of found problems.

	locprobs = problems			# Local copy of problems.

	if(clearflag):
		problems = []

	return(locprobs)


#------------------------------------------------------------------------
# Routine:	readconf()
#
# Purpose:	This routine reads the specified configuration file.
#
#			*** It has only been tested with rpki.conf so far.
#
def readconf(conf):

	cnt = 0				# Count of fields in this file.

	#
	# Parse the config file.
	#
	try:
		cfg = rpki.config.parser(conf)

	except Exception, evt:
		print "unable to parse config file \"%s\"" % conf
		print evt
		exit(1);

	#
	# Return our parsed configuration.
	#
	return(cfg)


#------------------------------------------------------------------------
# Routine:	lister()
#
# Purpose:	Provides information on entries in the config file.  The
#		information displayed depends on other options:
#
#			-section	lists info in a specific config section
#			-names		lists the names of the config sections
#
#		Without any other options, the fields and values in each
#		config section are printed.
#
def lister(conf,cfg,sector):

	cnt = 0				# Count of all fields in all sections.
	scnt = 0			# Count of fields in a section.

	#
	# Get the sections in the config file.
	#
	sections = cfg.cfg.sections()

	#
	# If a section was specified on the command line, then we'll
	# only provide info for that section.
	#
	if(sector != None):
		maxlen = -1

		#
		# Get the count of fields in this section and the
		# maximum length of the keys.
		#
		for (fkey, fval) in cfg.cfg.items(sector):
			keylen = len(fkey)
			if(keylen > maxlen): maxlen = keylen
			scnt += 1

		vprint("%s fields (%d fields):", sector, scnt)

		#
		# Print the key and translated or untranslated value.
		#
		for (fkey, fval) in cfg.cfg.items(sector):
			trval = cfg.get(fkey, section = sector)
			prtval(maxlen, fkey, fval, trval)

		return
	else:
		vprint("sector is none")

	#
	# Display info for all the sections in the config file.
	#
	if(nameflag):
		for sect in sections:
			scnt = 0	# Count of fields in this section.

			for (fkey, fval) in cfg.cfg.items(sect):
				scnt += 1

			print "%s:  %d fields" % (sect, scnt)

		return

	#
	# Display info for all the sections in the config file.
	#
	for sect in sections:
		maxlen = -1		# Maximum length of key names.
		scnt = 0		# Count of fields in this section.

		#
		# Get the count of fields in this section and the
		# maximum length of the keys.
		#
		for (fkey, fval) in cfg.cfg.items(sect):
			keylen = len(fkey)
			if(keylen > maxlen): maxlen = keylen
			scnt += 1

		print "\n%s fields array (%d fields):" % (sect, scnt)

		for (fkey, fval) in cfg.cfg.items(sect):
			trval = cfg.get(fkey, section = sect)
			prtval(maxlen,fkey, fval, trval)
			cnt += 1
			scnt += 1

	print "\n\n%d fields in config file %s" % (cnt, conf)


#------------------------------------------------------------------------
# Routine:	prtval()
#
# Purpose:	Print the information for a particular config key.
#
def prtval(maxkeylen, fkey, rawval, transval):
	global untransflag

	if(untransflag):
		val = rawval
	else:
		val = transval

	print "%-*s\t\"%s\"" % (maxkeylen, fkey, val)


#========================================================================
#
# The following four functions perform basic file checks to see if a given
# file exists, is readable, is writeable, or is executable.  A boolean
# value is returned.  If the verbose flag was given, then an appropriate
# message will be displayed only if the access check fails.
#

def existchk(fn):
	global problems				# List of found problems.

	if(os.access(fn, os.F_OK) == 0):
		return(0)
	else:
		return(1)

def readchk(fn):
	global problems				# List of found problems.

	if(os.access(fn, os.R_OK) == 0):
		return(0)
	else:
		return(1)

def writechk(fn):
	global problems				# List of found problems.

	if(os.access(fn, os.W_OK) == 0):
		return(0)
	else:
		return(1)

def execchk(fn):
	global problems				# List of found problems.

	if(os.access(fn, os.X_OK) == 0):
		return(0)
	else:
		return(1)


#========================================================================
#
# The following functions perform standard sets of checks for certain
# types of file-system entities.  They make use of the <foo>chk() calls
# defined above.
#
# Warning:  These routines return 0 on success and 1 on failure.
#	    This is the *opposite* of the <foo>chk() calls!
#

#----------------------------------------------------------------------
# Routine:	chkbool()
#
# Purpose:	This routine checks the validity of a boolean value.  The
#		value must be one of the following:  "yes", "no", "true",
#		or "false".  Case doesn't matter.
#
#		0 is returned on a valid boolean value.
#		1 is returned on an invalid boolean value.
#
def chkbool(bval,sect):
	global problems				# List of found problems.

	#
	# Ensure a boolean value was given.
	#
	if((bval == None) or (len(bval) == 0)):
		problems.append("%s:  no boolean value given" % sect)
		return(1)

	#
	# Check the boolean's value for a caseless match to either
	# "yes" or "no".
	#
	if(re.search('^yes$|^no$|^true$|^false$', bval, re.I) == None):
		problems.append("%s:  invalid boolean value \"%s\"" % (sect, bval))
		return(1)

	return(0)

#----------------------------------------------------------------------
# Routine:	chkdir()
#
# Purpose:	This routine checks the validity of a directory.
#		The directory must exist, be readable, and be searchable.
#
#		0 is returned on a valid directory.
#		1 is returned on an invalid directory.
#
def chkdir(dn,sect):
	global problems				# List of found problems.

	#
	# Ensure a directory name was given.
	#
	if((dn == None) or (len(dn) == 0)):
		problems.append("%s:  no directory given" % sect)
		return(1)

	#
	# Check the directory permissions to ensure the directory exists,
	# is readable and is searchable.
	#
	if(existchk(dn) == 0):
		problems.append("%s:  directory %s does not exist" % (sect, dn))
		return(1)

	if(readchk(dn)  == 0):
		problems.append("%s:  directory %s is not readable" % (sect, dn))
		return(1)

	if(execchk(dn)  == 0):
		problems.append("%s:  directory %s is not searchable" % (sect, dn))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkfile()
#
# Purpose:	This routine checks the validity of a regular file.
#		The file must exist and be readable.
#
#		0 is returned on a valid file.
#		1 is returned on an invalid file.
#
def chkfile(fn,sect):
	global problems				# List of found problems.

	#
	# Ensure a filename was given.
	#
	if((fn == None) or (len(fn) == 0)):
		problems.append("%s:  no file given" % sect)
		return(1)

	#
	# Check the file permissions to ensure the file exists and is readable.
	#
	if(existchk(fn) == 0):
		problems.append("%s:  file %s does not exist" % (sect, fn))
		return(1)

	if(readchk(fn)  == 0):
		problems.append("%s:  file %s is not readable" % (sect, fn))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkint()
#
# Purpose:	This routine checks the validity of an integer field.
#
#		This is assumed to be a positive integer, since that's
#		what we're needing right now.  This may some time have
#		to be modified to check for any integer.
#
#		0 is returned on a valid integer.
#		1 is returned on an invalid integer.
#
def chkint(num,sect):
	global problems				# List of found problems.

	#
	# Ensure an integer name was given.
	#
	if((num == None) or (len(num) == 0)):
		problems.append("%s:  no integer given" % sect)
		return(1)

	#
	# Ensure the handle only has valid characters.
	#
	if(re.search("^[0-9]+$", num) == None):
		problems.append("%s:  integer \"%s\" is not an integer" % (sect, num))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkhandle()
#
# Purpose:	This routine checks the validity of a given handle.
#		A handle is valid if it contains:
#			- alphabetic characters
#			- numeric characters
#			- hyphens
#			- underscores
#
#		0 is returned on a valid handle.
#		1 is returned on an invalid handle.
#
def chkhandle(hndl,sect):
	global problems				# List of found problems.

	#
	# Ensure a handle was given.
	#
	if((hndl == None) or (len(hndl) == 0)):
		problems.append("%s:  no handle given" % sect)
		return(1)

	#
	# Ensure the handle only has valid characters.
	#
	if(re.search("^[a-z0-9\-\_]+$", hndl, re.I) == None):
		problems.append("%s:  handle \"%s\" contains invalid characters" % (sect, hndl))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkhostname()
#
# Purpose:	This routine checks the validity of a given hostname.
#		A host is valid if it contains:
#			- alphabetic characters
#			- numeric characters
#			- dots and dashes ('.' and '-')
#			- no consecutive dots
#
#		0 is returned on a valid hostname.
#		1 is returned on an invalid hostname.
#
def chkhostname(host,sect):
	global problems				# List of found problems.

	#
	# Ensure a host was given.
	#
	if((host == None) or (len(host) == 0)):
		problems.append("%s:  no host given" % sect)
		return(1)

	#
	# Ensure the host only has valid characters.
	#
	if(re.search("^[a-z0-9\.\-]+$", host, re.I) == None):
		problems.append("%s:  hostname \"%s\" contains invalid characters" % (sect, host))
		return(1)

	#
	# Ensure the host doesn't have consecutive dots.
	#
	if(re.search(r"\.\.", host) != None):
		problems.append("%s:  hostname \"%s\" contains consecutive dots" % (sect, host))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkhostport()
#
# Purpose:	This routine checks the validity of a given host port.
#		A port is valid if it is a positive integer, only contains
#		digits, and does not have a fractional part.
#
#		0 is returned on a valid host port.
#		1 is returned on an invalid host port.
#
def chkhostport(port,sect):
	global problems				# List of found problems.

	#
	# Ensure a port was given.
	#
	if((port == None) or (len(port) == 0)):
		problems.append("%s:  no port given" % sect)
		return(1)

	#
	# Ensure the port number doesn't start with negation.
	#
	if(port[0] == '-'):
		problems.append("%s:  host port \"%s\" must be positive" % (sect, port))
		return(1)

	#
	# Ensure the port number only contains digits.
	#
	for ch in port:
		if(ch.isdigit()):
			pass
		elif(ch == '.'):
			problems.append("%s:  host port \"%s\" must be an integer" % (sect, port))
			return(1)
		else:
			problems.append("%s:  host port \"%s\" contains invalid character \"%s\"" % (sect, port, ch))
			return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkkeyfile()
#
# Purpose:	This routine checks the validity of a key file.
#		The file must exist and not be readable by anyone but
#		its owner.
#
#		0 is returned on a valid key file.
#		1 is returned on an invalid key file.
#
def chkkeyfile(fn,sect):
	global problems				# List of found problems.

	#
	# Ensure a keyfile name was given.
	#
	if((fn == None) or (len(fn) == 0)):
		problems.append("%s:  no keyfile given" % sect)
		return(1)

	if(existchk(fn) == 0):
		problems.append("%s:  file %s does not exist" % (sect, fn))
		return(1)

	#
	# Get the file's mode.
	#
	sinfo = os.stat(fn)
	mode = sinfo.st_mode & 0777

	#
	# Ensure the file can only be read by its owner.
	#
	if((mode & 0077) != 0):
		problems.append("%s:  file %s is accessible by non-owner users" % (sect, fn))
		problems.append("%s:\tmode - %o" % (sect, mode))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkloglevel()
#
# Purpose:	This routine checks that the given log level is valid.
#
#		0 is returned on a valid log level.
#		1 is returned on an invalid log level.
#
def chkloglevel(lvl,sect):
	global problems				# List of found problems.

	#
	# Ensure a log level was given.
	#
	if((lvl == None) or (len(lvl) == 0)):
		problems.append("%s:  no log level given" % sect)
		return(1)

	#
	# See if the log level is in the list of log levels.
	# If so, we'll return success.
	#
	for ll in loglevels:
		if(lvl == ll):
			return(0)

	problems.append("%s:  invalid log level - \"%s\"" % (sect, lvl))
	return(1)


#----------------------------------------------------------------------
# Routine:	chknonnull()
#
# Purpose:	This routine checks that the given value is not empty.
#
#		0 is returned on a non-empty field.
#		1 is returned on an empty field.
#
def chknonnull(val,sect):
	global problems				# List of found problems.

	if((val == None) or
	   (val == '')	 or
	   (len(val) == 0)):
		problems.append("%s:  invalid empty field" % sect)
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkpass()
#
# Purpose:	This routine checks that a password is valid.
#		For now, this is checking that the password is not empty
#		and that it has a "decent" number of characters.
#		("decent" is the somewhat arbitrary value of 40.)
#
#		0 is returned on a non-empty field.
#		1 is returned on an empty field.
#

MINPASSLEN = 40					# Minimum password length.

def chkpass(pw,sect):
	global problems				# List of found problems.

	#
	# Not using for now; always return an error.
	#
	return(1)

	#
	# Ensure that the password is not empty.
	#
	if((pw == None) or
	   (pw == '')):
		problems.append("%s:  invalid empty password" % sect)
		return(1)

	#
	# Ensure that the password is nice and long.
	#
	if(len(pw) < MINPASSLEN):
		problems.append("%s:  password is too short (length %d, required minimum %d)" % (sect, len(pw), MINPASSLEN))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chksqlpass()
#
# Purpose:	This routine checks the validity of an SQL password.  It runs
#		these checks:
#			- it must be defined
#			- it must be at least 40 characters long
#
#		THIS IS LIKELY TO ACTUALLY BE A PASSWORD HASH RATHER THAN THE
#		REAL PASSWORD.  THIS ASSUMES THE HASH IS A NICE, HEFTY LENGTH.
#
#		0 is returned on a valid password.
#		1 is returned on an invalid password.
#

MINSQLPASSLEN = 40			# Minimum password length for SQL.

def chksqlpass(pw,sect):
	global problems				# List of found problems.

	#
	# Ensure an SQL password was given.
	#
	if((pw == None) or (len(pw) == 0)):
		problems.append("%s:  no password given" % sect)
		return(1)

	#
	# Ensure that the password is not empty.
	#
	if(len(pw) < 1):
		problems.append("%s:  SQL password must be specified" % sect)
		return(1)

	#
	# Ensure that the password is nice and long.
	#
	if(len(pw) < MINSQLPASSLEN):
		problems.append("%s:  SQL password is too short (length %d, required minimum %d)" % (sect, len(pw), MINSQLPASSLEN))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chksqluser()
#
# Purpose:	This routine checks the validity of an SQL user.  It runs
#		these checks:
#			- between 1 and 16 characters long
#			- ASCII characters
#
#		Username specs were taken from MySQL documentation on
#		http://dev.mysql.com/doc/refman/5.5/en/user-names.html
#
#		0 is returned on a valid user.
#		1 is returned on an invalid user.
#
def chksqluser(user,sect):
	global problems				# List of found problems.

	#
	# Ensure an SQL username was given.
	#
	if((user == None) or (len(user) == 0)):
		problems.append("%s:  no user given" % sect)
		return(1)

	#
	# Ensure that the username is not empty.
	#
	if(len(user) < 1):
		problems.append("%s:  an SQL user name must be specified" % sect)
		return(1)

	#
	# Ensure that the username is not too long.
	#
	if(len(user) > 16):
		problems.append("%s:  %s is too long; an SQL user name may not exceed 16 characters" % (sect,user))
		return(1)

	#
	# This check *supposedly* checks for ASCII characters.  I'm
	# not sure it's sufficient, but it'll do for the moment.	WGM
	#
	quser = "'" + user + "'"
	if(repr(user) != quser):
		problems.append("%s:  the SQL user name \"%s\" contains non-ASCII characters" % (sect,user))
		problems.append("")
		problems.append("\tuser - <%s>" % user)
		problems.append("\trepr - <%s>" % repr(user))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chksyslog()
#
# Purpose:	This routine checks that the given syslog level is valid.
#
#		0 is returned on a valid syslog level.
#		1 is returned on an invalid syslog level.
#
def chksyslog(lvl,sect):
	global problems				# List of found problems.

	#
	# Ensure a syslog level was given.
	#
	if((lvl == None) or (len(lvl) == 0)):
		problems.append("%s:  no syslog level given" % sect)
		return(1)

	#
	# See if the syslog level is in the list of syslog levels.
	# If so, we'll return success.
	#
	for ll in sysloglevels:
		if(lvl == ll):
			return(0)

	problems.append("%s:  invalid syslog level - \"%s\"" % (sect, lvl))
	return(1)


#----------------------------------------------------------------------
# Routine:	chksyslogpriority()
#
# Purpose:	This routine checks that the given syslog priority is valid.
#
#		0 is returned on a valid syslog priority.
#		1 is returned on an invalid syslog priority.
#
def chksyslogpriority(prio,sect):
	global problems				# List of found problems.

	#
	# Ensure a syslog priority was given.
	#
	if((prio == None) or (len(prio) == 0)):
		problems.append("%s:  no syslog priority given" % sect)
		return(1)

	#
	# See if the log priority is in the list of syslog priorities.
	# If so, we'll return success.
	#
	for pr in syslogpriorities:
		if(prio == pr):
			return(0)

	problems.append("%s:  invalid syslog priority - \"%s\"" % (sect, prio))
	return(1)


#----------------------------------------------------------------------
# Routine:	chktime()
#
# Purpose:	This routine checks the validity of a time value.  This
#		validity is defined as:
#			- has a numeric, positive length portion
#			- has a character unit portion in this set:
#				- h	hours
#				- d	days
#				- m	months
#
#		Should there be a minimum time enforced?
#		Should there be a maximum time enforced?
#
#		0 is returned on a valid time value.
#		1 is returned on an invalid time value.
#
def chktime(chronos,sect):
	global problems				# List of found problems.

	#
	# Ensure a time was given.
	#
	if((chronos == None) or (len(chronos) == 0)):
		problems.append("%s:  no time value given" % sect)
		return(1)

	#
	# Parse the time value.
	#
	if(re.search("^([1-9][0-9])*[hdm]$", chronos, re.I) == None):
		problems.append("%s:  time value \"%s\" contains invalid characters" % (sect, chronos))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkuri()
#
# Purpose:	This routine checks the validity of a URI.  This validity
#		is defined as:
#			- using one of these addressing schemes:
#				- http
#				- rsync
#			- having a non-empty net-location field
#			- having zero or one colons in the net-location field.
#
#		The difference between chkuri() and chkurl() is that chkurl()
#		is only looking for "http://" lines, while chkuri() has a
#		longer list of addressing schemes it'll recognize.
#		The name could perhaps be improved, but that's the way it is.
#		For now.
#
#		0 is returned on a valid URL.
#		1 is returned on an invalid URL.
#
def chkuri(url,sect):
	global problems				# List of found problems.

	#
	# Ensure a URL was given.
	#
	if((url == None) or (len(url) == 0)):
		problems.append("%s:  no URL given" % sect)
		return(1)

	#
	# Parse the URL.
	#
	try:
		upo = urlparse.urlparse(url)
	except Exception, evt:
		problems.append("%s:  unable to parse URL \"%s\"" % (sect, url))
		problems.append(evt)

	#
	# Ensure 'http' was used as the addressing scheme.
	#
	if((upo.scheme != 'http')	and
	   (upo.scheme != 'rsync')):
		problems.append("%s:  unexpected addressing scheme in url (%s); got %s" % (sect, url, upo.scheme))
		return(1)

	#
	# Ensure the network location wasn't empty.
	#
	if((upo.netloc == None) or (len(upo.netloc) == 0)):
		problems.append("%s:  no network location given in url (%s)" % (sect, url))
		return(1)

	#
	# Ensure only zero or one colons was given in the network location.
	#
	if(upo.netloc.count(':') > 1):
		problems.append("%s:  more than one colon in url (%s); found %d" % (sect, url, upo.netloc.count(':')))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkurl()
#
# Purpose:	This routine checks the validity of a URL.  This validity
#		is defined as:
#			- using HTTP for the addressing scheme
#			- having a non-empty net-location field
#			- having zero or one colons in the net-location field.
#
#		0 is returned on a valid URL.
#		1 is returned on an invalid URL.
#
def chkurl(url,sect):
	global problems				# List of found problems.

	#
	# Ensure a URL was given.
	#
	if((url == None) or (len(url) == 0)):
		problems.append("%s:  no URL given" % sect)
		return(1)

	#
	# Parse the URL.
	#
	try:
		upo = urlparse.urlparse(url)
	except Exception, evt:
		problems.append("%s:  unable to parse URL \"%s\"" % (sect, url))
		problems.append(evt)

	#
	# Ensure 'http' was used as the addressing scheme.
	#
	if(upo.scheme != 'http'):
		problems.append("%s:  expecting http for addressing scheme in url (%s); got %s" % (sect, url, upo.scheme))
		return(1)

	#
	# Ensure the network location wasn't empty.
	#
	if((upo.netloc == None) or (len(upo.netloc) == 0)):
		problems.append("%s:  no network location given in url (%s)" % (sect, url))
		return(1)

	#
	# Ensure only zero or one colons was given in the network location.
	#
	if(upo.netloc.count(':') > 1):
		problems.append("%s:  more than one colon in url (%s); found %d" % (sect, url, upo.netloc.count(':')))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	chkuser()
#
# Purpose:	This routine checks the validity of a user.  This validity
#		is defined as being a recognized user for the host on which
#		the validation command is executed.
#		The user may be specified by either name or uid.
#
#		0 is returned on a valid user.
#		1 is returned on an invalid user.
#
def chkuser(user,sect):
	global problems				# List of found problems.

	#
	# Not using for now; always return an error.
	#
	return(1)

	try:
		pw = pwd.getpwnam(user)
	except:
		try: 
			pw = pwd.getpwuid(user)
		except:
			problems.append("%s:  %s is not a valid user" % (sect,user))
			return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	comprange()
#
# Purpose:	Compare a values as being within a range of numbers.
#
#		0 is returned if value is within the range.
#		1 is returned if value is not within the range.
#
def comprange(cfg, lsect, lkey, lrng, hrng):

	#
	# Ensure the low value is not greater than the high value.
	#
	if(lrng > hrng):
		problems.append("low value (%d) is greater than high value (%d) for %s:%s" % (lrng, hrng, lsect, cfg))
		return(1)

	#
	# Look up the value for the local section and key.  If there's a
	# problem, we'll save the event string.
	#
	try:
		lval = cfg.get(lkey, section = lsect)
		lval = int(lval)
	except Exception, evt:
		#
		# Problem getting the value, so we'll save the event string.
		#
		evtstr = str(evt)
		problems.append(evtstr)
		return(1)

	#
	# Complain and return if the value is outside the range on the
	# low end.
	#
	if(lval < lrng):
		problems.append("value for %s:%s (%d) is lower than the low range boundary (%d)" % (lsect, lkey, lval, lrng))
		return(1)

	#
	# Complain and return if the value is outside the range on the
	# high end.
	#
	if(lval > hrng):
		problems.append("value for %s:%s (%d) is greater than the high range boundary (%d)" % (lsect, lkey, lval, hrng))
		return(1)

	return(0)


#========================================================================

#----------------------------------------------------------------------
# Routine:	compvals()
#
# Purpose:	Compare the values of two fields.  They may or may not be
#		in different sections in the config file.
#
#		0 is returned if fields are equal.
#		1 is returned if fields are not equal.
#
def compvals(cfg, lsect, lkey, rsect, rkey):

	path = ''				# Optional path in rkey.

	#
	# Look up the value for the local section and key.  If there's a
	# problem, we'll save the event string.
	#
	try:
		lval = cfg.get(lkey, section = lsect)
	except Exception, evt:
		#
		# Problem getting the value, so we'll save the event string.
		#
		evtstr = str(evt)
		problems.append(evtstr)
		return(1)

	#
	# If the remote key has a path at the end, we'll save it for later
	# and append it to the key's translated value.
	#
	if(re.search("/",rkey,re.I) != None):
		vals = re.split('/', rkey)
		rkey = vals[0]
		path = vals[1]

	#
	# Look up the value for the remote section and key.  If there's a
	# problem, we'll save the event string.
	#
	try:
		rval = cfg.get(rkey, section = rsect)

		#
		# Append a path, if there is one.
		#
		if(path != ''):
			rval += '/' + path

	except Exception, evt:
		#
		# Problem getting the value, so we'll save the event string.
		#
		evtstr = str(evt)
		problems.append(evtstr)
		return(1)

	if(lval != rval): 
		problems.append("unequal values for %s:%s (%s) and %s:%s (%s)" % (lsect, lkey, lval, rsect, rkey, rval))
		return(1)

	return(0)


#----------------------------------------------------------------------
# Routine:	comp1val()
#
# Purpose:	Compare the values of one field against a specific value.
#
#		0 is returned if the two are equal.
#		1 is returned if the two are not equal.
#
def comp1val(cfg, lsect, lkey, cval):

	#
	# Look up the value for the section and key.  If there's a problem,
	# we'll save the event string.
	#
	try:
		lval = cfg.get(lkey, section = lsect)
	except Exception, evt:
		evtstr = str(evt)
		problems.append(evtstr)
		return(1)

	if(lval != cval): 
		problems.append("unequal values for %s:%s (%s) and \"%s\"" % (lsect, lkey, lval, cval))
		return(1)

	return(0)


#========================================================================

#----------------------------------------------------------------------
# Routine:	vprint()
#
# Purpose:	Prints the given string iff the -verbose option was given.
#
def vprint(str,*args):
	global verbose

	if verbose:
		print str % args


#------------------------------------------------------------------------


'''

NAME

confvalidation - general routines used in validating an rpki.net configuration file

SYNOPSIS

  setopts(nlistflag, nnameflag, nuntransflag, nverbose)

  prtopts()

  getlistflag()

  readconf(conf)

  lister(conf,cfg,sector)

  prtval(maxkeylen, fkey, rawval, transval)

  existchk(fn)

  readchk(fn)

  writechk(fn)

  execchk(fn)

  chkdir(dn,sect)

  chknonnull(val,sect)

  chkpass(pw,sect)

  chkuser(user,sect)

  vprint(str,*args)

DESCRIPTION

The confvalidation.py modules contains general routines used in validating
rpki.net configuration files.

It is currently only used by rpkichk to validate the rpki.conf file.  It
is assumed that it will eventually be used in validating the rcynic.conf
and rsyncd.conf files.

Further documentation for these interfaces will be provided in the fullness
of time.

INTERFACES

The confvalidation.py interfaces may be divided into the following groups:

	options interfaces
	configuration-file interfaces
	low-level checking interfaces
	higher-level checking interfaces
	miscellaneous interfaces

The interfaces in these groups are described below.

Options Interfaces:

- setopts(nlistflag, nnameflag, nuntransflag, nverbose)

- prtopts()

- getlistflag()

Configuration File Interfaces:

- readconf(conf)

- lister(conf,cfg,sector)

- prtval(maxkeylen, fkey, rawval, transval)

Low-level Checking Interfaces:

- existchk(fn)

- readchk(fn)

- writechk(fn)

- execchk(fn)

Higher-level Checking Interfaces:

- chkdir(dn,sect)

- chknonnull(val,sect)

- chkpass(pw,sect)

- chkuser(user,sect)

Miscellaneous Interfaces:

- vprint(str,*args)

COPYRIGHT

Copyright 2015 PARSONS, Inc.  All rights reserved.

AUTHOR

Wayne Morrison, tewok@tislabs.com

'''
