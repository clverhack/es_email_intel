#!/usr/bin/env python
# -*- coding: utf-8 -*- 

'''
You may want to play around with the send_mail() utf-8 encoding stuff.
Might not be necessary anymore after changes I did.
'''

import smtplib
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email import Encoders
import json
import re
import common_functions
import syslog
import codecs
import fortunes # If you want them.

BB_DEBUG = False # Turn on some syslog bitching and whining.

# Tunable. I really hope you tune this.
EMAIL_SERVER = '192.168.3.2'
EMAIL_FROM = 'pierre@userid.org'
# End tunable.

def json2string(json_string):
	retstring = 'This is an automated IOC extraction engine. The results may not be perfect. Here be dragons!\n\n'
	retstring += 'Your fortune: '+fortunes.ret_fortune()+'\n\n'
	json_blob = json.loads(json_string)
	if 'md5' in json_blob:
		if len(json_blob['md5']) > 0:
			retstring += '.:: MD5 entries::.\n\n'
			for md5 in json_blob['md5']:
				retstring += md5+'\n'
			retstring += '\n'
	if 'sha1' in json_blob:
		if len(json_blob['sha1']) > 0:
			retstring += '.:: SHA1 entries::.\n\n'
			for sha1 in json_blob['sha1']:
				retstring += sha1+'\n'
			retstring += '\n'
	if 'sha256' in json_blob:
		if len(json_blob['sha256']) > 0:
			retstring += '.:: SHA256 entries::.\n\n'
			for sha256 in json_blob['sha256']:
				retstring += sha256+'\n'
			retstring += '\n'
	if 'ipv4' in json_blob:
		if len(json_blob['ipv4']) > 0:
			retstring += '.:: IPv4 entries::.\n\n'
			for ipv4 in json_blob['ipv4']:
				retstring += ipv4+'\n'
			retstring += '\n'
	if 'url' in json_blob:
		if len(json_blob['url']) > 0:
			retstring += '.:: URL entries::.\n\n'
			for url in json_blob['url']:
				cleanurl = re.sub('\[\.\]', '.', url)
				retstring += cleanurl+'\n'
			retstring += '\n'
	if 'domain' in json_blob:
		if len(json_blob['domain']) > 0:
			retstring += '.:: Domain entries::.\n\n'
			for domain in json_blob['domain']:
				cleandom = re.sub('\[\.\]', '.', domain)
				retstring += cleandom+'\n'
			retstring += '\n'
	if 'email' in json_blob:
		if len(json_blob['email']) > 0:
			retstring += '.:: Email entries::.\n\n'
			for email in json_blob['email']:
				retstring += email+'\n'
			retstring += '\n'
	if 'ssdeep' in json_blob:
		if len(json_blob['ssdeep']) > 0:
			retstring += '.:: SSDeep entries::.\n\n'
			for ssdeep in json_blob['ssdeep']:
				retstring += ssdeep+'\n'
			retstring += '\n'
	if 'filename' in json_blob:
		if len(json_blob['filename']) > 0:
			retstring += '.:: Filename entries::.\n\n'
			for filename in json_blob['filename']:
				retstring += filename+'\n'
			retstring += '\n'
	if 'mutex' in json_blob:
		if len(json_blob['mutex']) > 0:
			retstring += '.:: Mutex entries (may be unreliable)::.\n\n'
			for mutex in json_blob['mutex']:
				retstring += mutex+'\n'
			retstring += '\n'
	
	return retstring

def send_mail(json_string):
	# Extract sender and subject
	json_blob = json.loads(json_string)
	sender = json_blob['headers']['From']
	sender = re.sub('^.*\<', '', sender)
	EMAIL_TO = re.sub('\>.*$', '', sender)
	if BB_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Invoked send_mail(json_string) for '+EMAIL_TO)
	subj = common_functions.extract_subject(json_blob['headers'])
	if BB_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Invoked send_mail(json_string) subject '+subj)
	#SUBJECT = 'Extracted IOCs for: '+subj.decode("utf-8", "ignore")
	SUBJECT = 'Extracted IOCs for: '+str(codecs.utf_8_decode(subj.encode('utf8'))[0])
	if BB_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Invoked send_mail(json_string) subject '+SUBJECT)
	
	msg = MIMEText(json2string(json_string), _charset='utf-8')
	
	msg['Subject'] = SUBJECT 
	msg['From'] = EMAIL_FROM
	msg['To'] = EMAIL_TO
	if BB_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Invoked send_mail(json_string) msg composed ')

	server = smtplib.SMTP(EMAIL_SERVER)
	server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
	if BB_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Finished')
	
