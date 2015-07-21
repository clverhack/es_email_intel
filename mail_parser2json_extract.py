#!/usr/bin/env python
# -*- coding: utf-8 -*- 

# Regexes sourced from:
# https://raw.githubusercontent.com/stephenbrannon/IOCextractor/master/IOCextractor.py
# SSDeep regex from <Anonymous FS-ISAC donor>
# Others from yet another anonymous FS-ISAC donor

import re
import sys
import time
import json
import base64
import io

import bounceback_es

DEBUG_MAIL2PARSER = False

BOUNCEBACK = False
PUSH2ES = False
JSONOUTPUT = False
JUSTDEBUG = False

# Whether to output json, or else push to ES
if len(sys.argv) == 2:
	if sys.argv[1] == '1': BOUNCEBACK = True
	if sys.argv[1] == '2': JSONOUTPUT = True
	if sys.argv[1] == '3': JUSTDEBUG = True
else:
	PUSH2ES = True

# For PDF reading
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.pdfpage import PDFPage
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.image import ImageWriter
from cStringIO import StringIO

from elasticsearch import Elasticsearch
import email, os
from email.parser import HeaderParser

# For Excel file reading
import xlrd

# Globals
md5s = []
sha1s = []
sha256s = []
ipv4s = []
urls = []
domains = []
emails = []
ssdeeps = []
bitcoin_wallets = []
filenames = []
mutexes = []
msg_id = ''

# ES Server details
es_server = '192.168.3.208'
es = Elasticsearch([{'host': es_server, 'port': 9200}])
es_collection_name = 'mail2json'

# I can't help but feel I didn't really leverage regex exceptions much
reExclusions = r"(^\:)"

reMD5 = r"\b([A-F]|[0-9]){32}\b"
reIPv4 = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|\[\.\])){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
reURL = r"[A-Z0-9\-\.\[\]]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)(/\S+)"
reDomain = r"[A-Z0-9\-\.\[\]]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)\b"
reEmail = r"\b[A-Za-z0-9._%+-]+(@|\[@\])[A-Za-z0-9.-]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)\b"
reSHA1 = r"\b[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9af][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]\b"
reSHA256 = r"\b([a-f0-9]{64}|[A-F0-9]{64})\b"
reBitcoinWallet = r"\b[13][a-km-zA-HJ-NP-Z0-9]{26,33}\b"
reSSDeep = r"\b\d*:[0-9a-zA-Z\/+]{3,64}:[0-9a-zA-Z\/+]{3,64}\b"
reFilename = r"\b[A-Z0-9\-\.\[\]]+(\.)(exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif|tmp)\b"
reMutex = r"\b(Local|Global|.*MUTEX|.*Mutex).*\b"

# Does the actual ES injection
def push2es(collection_name, msg_id, json_data):
	global es
	es.index(index=collection_name, doc_type='indicators', id=msg_id, body=json_data)

# Parse headers, extract the message ID, and return a dictionary of all of the headers
# Note that we might miss some multiple-headers like received from... but I don't consider this critical
# since we already keep a whole copy of the message
def grab_headers(string):
	global msg_id
	ret_ar = {}
	
	# Pull the headers using the email library
	parser = email.parser.HeaderParser()
	headers = parser.parsestr(string)      
	
	# Needed a unique key for searching for a specific message
	# I think you could also leverage this for message threads
	msg_id = re.sub('[<>]', '', headers['Message-ID'])

	for h in headers.items():
		ret_ar[h[0]] = h[1]

	return ret_ar

# Do some basic sanity on the message contents
def preparser_email(string):
	string = string.strip()
	retstring = ''
	found = 0
	string = re.sub('\=\n', '', string)
	tmpstring = string.split('\n')
	for line in tmpstring:
		if not found:
			if line in ('\n', '\r\n', ''):
				found = 1
				pass
		else:
			line = re.sub('\[\.\]', '.', line)
			line = re.sub('\[d\]', '.', line)
			line = re.sub('\[dot\]', '.', line)
			line = re.sub('\[at\]', '@', line)
			line = re.sub('\<.*', '', line)
			retstring+=line
			retstring+="\n"
	return retstring

# Convert a base64 message into plain text and do basic sanity filtering
def b64_preparser_email(string):
	string = string.strip()
	retstring = ''
	found = 0
	b64decoded = ''
	tmpstring = string.split('\n')
	for line in tmpstring:
		if not found:
			if line in ('\n', '\r\n', ''):
				found = 1
				pass
		else:
			b64decoded+=line
			b64decoded+="\n"
	b64decoded = base64.b64decode(b64decoded)
	tmpstring = b64decoded.split('\n')
	for line in tmpstring:
		line = re.sub('\[\.\]', '.', line)
		line = re.sub('\[d\]', '.', line)
		line = re.sub('\[dot\]', '.', line)
		line = re.sub('\[at\]', '@', line)
		line = re.sub('\<.*', '', line)
		retstring+=line
		retstring+="\n"
	return retstring

# Given a list of lines and some regex, return any matches
def match_thing(lines, regex):
	ret_ar = []
	for line in lines:
		for m in re.finditer(regex, line, re.IGNORECASE):
			ret_ar.append(m.group())
	# Dedupe
	ret_ar = list(set(list(ret_ar)))
	
	# Remove exclusions from the result set
	for i in xrange(len(ret_ar) - 1, -1, -1):
		# If it terminates in a ], strip that out
		if re.search('\]$', ret_ar[i]):
			ret_ar[i] = re.sub('\]$', '', ret_ar[i])
		if re.search('\[\.\]', ret_ar[i]):
			ret_ar[i] = re.sub('\[\.\]', '.', ret_ar[i])
		# if it terminates in a ]. strip that out too
		if re.search('\]\.$', ret_ar[i]): 
			ret_ar[i] = re.sub('\]\.$', '', ret_ar[i])
		# If it leads off with a - strip it out
		if re.search('^\-', ret_ar[i]):
			del ret_ar[i]
		if re.search(reExclusions, ret_ar[i]):
			del ret_ar[i]
	
	return ret_ar

# Get a trimmed timestamp which doesn't have subsecond
# This is probably a dumb way of doing it.
def get_timestamp():
	now = str(time.time())
	now = re.sub('\..*', '', now)
	return now

# So... given a global list of variables, extract the whatevers, pop them into the global var, and then dedupe and return
def string_regex_matches(string):
	global md5s
	global sha1s
	global sha256s
	global ipv4s
	global urls
	global domains
	global emails
	global ssdeeps
	global bitcoin_wallets
	global filenames
	global mutexes
	
	md5s = md5s + do_thing_extract(string, reMD5)
	sha1s = sha1s + do_thing_extract(string, reSHA1)
	sha256s = sha256s + do_thing_extract(string, reSHA256)
	ipv4s = ipv4s + do_thing_extract(string, reIPv4)
	urls = urls + do_thing_extract(string, reURL)
	domains = domains + do_thing_extract(string, reDomain)
	emails = emails + do_thing_extract(string, reEmail)
	ssdeeps = ssdeeps + do_thing_extract(string, reSSDeep)
	bitcoin_wallets = bitcoin_wallets + do_thing_extract(string, reBitcoinWallet)
	filenames = filenames + do_thing_extract(string, reFilename)
	mutexes = mutexes + do_thing_extract_mutex(string, reMutex)
	
	md5s = list(set(list(md5s)))
	sha1s = list(set(list(sha1s)))
	sha256s = list(set(list(sha256s)))
	ipv4s = list(set(list(ipv4s)))
	urls = list(set(list(urls)))
	domains = list(set(list(domains)))
	emails = list(set(list(emails)))
	ssdeeps = list(set(list(ssdeeps)))
	bitcoin_wallets = list(set(list(bitcoin_wallets)))
	filenames = list(set(list(filenames)))
	mutexes = list(set(list(mutexes)))
	
	return
	
# Given a raw message, locate any attachments and process them.
# Support for PDF and Excel right now.
# If you want to add more, find a way to extract the data as a text stream
def pull_attachments(string):
	if DEBUG_MAIL2PARSER: print 'Entered pull_attachments()'
	message = email.message_from_string(string)
	if message.get_content_maintype() != 'multipart': return
	for part in message.walk():
		if DEBUG_MAIL2PARSER: print 'Checking a message part'
		if part.get_content_maintype() == 'multipart': 
			if DEBUG_MAIL2PARSER: print 'Multipart, skip this part.'
			continue
		if part.get('Content-Disposition') is None:
			if DEBUG_MAIL2PARSER: print 'None type for Content-Disposition, skip this part.'
			continue
		filename=part.get_filename()
		if filename is not None:
			if DEBUG_MAIL2PARSER: print 'Filename is not none, process it.'
			if re.search('\.pdf$', filename):
				if DEBUG_MAIL2PARSER: print 'PDF found, process it.'
				if DEBUG_MAIL2PARSER: print 'Before scanning, count of MD5s was: '+str(len(md5s))
				if DEBUG_MAIL2PARSER: print 'Before scanning, count of IPv4 was: '+str(len(ipv4s))
				if DEBUG_MAIL2PARSER: print 'Before scanning, count of domains was: '+str(len(domains))
				# We use a virtual IO filepointer here so that we don't have to write to the filesystem
				fp = io.BytesIO()
				fp.write(part.get_payload(decode=True))
				pdf_txt = extract_pdf(fp)
				string_regex_matches(pdf_txt)
				fp.close()
				if DEBUG_MAIL2PARSER: print 'After scanning, count of MD5s was: '+str(len(md5s))
				if DEBUG_MAIL2PARSER: print 'After scanning, count of IPv4 was: '+str(len(ipv4s))
				if DEBUG_MAIL2PARSER: print 'After scanning, count of domains was: '+str(len(domains))
			elif re.search('\.xlsx$', filename):
				if DEBUG_MAIL2PARSER: print 'XLSX found, process it.'
				# Write it to a temporary location
				tmpfile = '/tmp/'+get_timestamp()+'excelsheet.xlsx'
				f = open(tmpfile, 'w')
				# Hand it off to the excel reader
				f.write(part.get_payload(decode=True))
				# trash the file
				f.close()
				excel_text = extract_excel(tmpfile)
				os.remove(tmpfile)
				string_regex_matches(excel_text)
			elif re.search('\.txt$', filename):
				if DEBUG_MAIL2PARSER: print 'Text attachment found, process it.'
				txt_str = part.get_payload(decode=True)
				string_regex_matches(txt_str)
			else:
				pass
	return

# Most of the vars are not even needed but keeping this for someone else's future needs.
def extract_pdf(fp):
	password = ''
	pagenos = set()
	maxpages = 0
	imagewriter = None
	rotation = 0
	codec = 'utf-8'
	caching = True
	laparams = LAParams()

	rsrcmgr = PDFResourceManager(caching=caching)
	outtype = 'text'
	retstr = StringIO()
	device = TextConverter(rsrcmgr, retstr, codec=codec, laparams=laparams, imagewriter=imagewriter)

	interpreter = PDFPageInterpreter(rsrcmgr, device)
	try:
		for page in PDFPage.get_pages(fp, pagenos, maxpages=maxpages, password=password, caching=caching, check_extractable=True):
			page.rotate = (page.rotate+rotation) % 360
			interpreter.process_page(page)
	except:
		try:
			password = 'infected'
			for page in PDFPage.get_pages(fp, pagenos, maxpages=maxpages, password=password, caching=caching, check_extractable=True):
				page.rotate = (page.rotate+rotation) % 360
				interpreter.process_page(page)
		except:
			return ''
	device.close()
	str = retstr.getvalue()
	retstr.close()

	return str

# Converts the contents of an excel xml file to a text string
def extract_excel(filename):
	ret_string = ''
	book = xlrd.open_workbook(filename)
	sheets = book.sheet_names()
	
	for sheet in sheets:
		worksheet = book.sheet_by_name(sheet)
		num_rows = worksheet.nrows - 1
		num_cells = worksheet.ncols - 1
		curr_row = -1
		while curr_row < num_rows:
			curr_row += 1
			row = worksheet.row(curr_row)
			curr_cell = -1
			while curr_cell < num_cells:
				curr_cell += 1
				# Cell Types: 0=Empty, 1=Text, 2=Number, 3=Date, 4=Boolean, 5=Error, 6=Blank
				cell_type = worksheet.cell_type(curr_row, curr_cell)
				cell_value = worksheet.cell_value(curr_row, curr_cell)
				ret_string += cell_value+'\n'
	return ret_string	

# Given a big long string of text, split it by newline and try matching stuff in it.
def do_thing_extract(stringtext, pattern):
	ret_ar = []
	lines = stringtext.split('\n')
	
	matches = match_thing(lines, pattern)
	if len(matches) > 0:
		for line in matches: 
			ret_ar.append(line.lower())
	return ret_ar

# No lowercase conversion
# Given a big long string of text, split it by newline and try matching MUTEXs in it.
def do_thing_extract_mutex(stringtext, pattern):
	ret_ar = []
	lines = stringtext.split('\n')
	
	matches = match_thing_mutex(lines, pattern)
	if len(matches) > 0:
		for line in matches:
			if line == 'Mutex': continue
			if line == 'MUTEX': continue
			if line == 'Local': continue
			if line == 'Global': continue
			ret_ar.append(line)
	return ret_ar

# No lowercase matching is the only reason this is separate.
def match_thing_mutex(lines, regex):
	ret_ar = []
	for line in lines:
		for m in re.finditer(regex, line):
			ret_ar.append(m.group())
	ret_ar = list(set(list(ret_ar)))
	
	# Remove exclusions from the result set
	for i in xrange(len(ret_ar) - 1, -1, -1):
		if re.search('Global ', ret_ar[i]):
			del ret_ar[i]
		elif re.search('Local ', ret_ar[i]):
			del ret_ar[i]
		elif re.search(reExclusions, ret_ar[i]):
			del ret_ar[i]
	
	return ret_ar

# This is the main entry point to this script. Feed it a raw mail message.
def process_email_message(string):
	# Detect and extract the text of any attachments, pull indicators
	pull_attachments(string)
	
	prejson = {} # We will be dumping everything in here
	
	headers = grab_headers(string) # Dictionary of all message headers
	prejson['headers'] = headers # We use 'headers' later
	
	# If the content of the message is base64, extract it before processing
	# This is probably not ideal but it seems to work ok
	try:
		if ( headers['Content-Transfer-Encoding'] == 'base64' ):
			message_text = b64_preparser_email(string)
		else:
			message_text = preparser_email(string)
	except:
		message_text = preparser_email(string)
	
	# Pull the original message text and try and fix any encoding issues.
	prejson['message_text'] = message_text.decode("utf-8", "replace")
	
	# Plaintext IOC extraction
	string_regex_matches(prejson['message_text'])
	
	# Populate the JSON with any extracted indicators
	prejson['md5'] = md5s
	prejson['sha1'] = sha1s
	prejson['sha256'] = sha256s
	prejson['ipv4'] = ipv4s
	prejson['url'] = urls
	prejson['domain'] = domains
	prejson['email'] = emails
	prejson['ssdeep'] = ssdeeps # Mostly works OK
	prejson['bitcoin_wallet'] = bitcoin_wallets # Kind of crap, wallet format is not great at all.
	prejson['filename'] = filenames # Works OK
	prejson['mutex'] = mutexes # Not fantastic but works OK
	
	# Set some basic meta
	prejson['epoch'] = get_timestamp() # Unix epoch timetamp. Because screw your human readable, non-UTC timezoned crap formats.
	prejson['ctime'] = time.ctime() # Screw you epoch, humans prefer display times that they can read without using a calculator.
	
	# Convert the string we've generated to JSON and return it
	retstring = json.dumps(prejson, sort_keys=True, indent=4, separators=(',', ': '))
	retstring = retstring.decode("utf-8", "replace") # You shouldn't have to do this, but ffs, encodings.
	return retstring

# You could use this file as a library if you're crazy, otherwise just
# cat rawemail.txt | python <this script> [null = push2es, 1 = bounceback to originator, 2 = dump json to console]
if __name__ == "__main__":
	# Pull the content from the command line / stdin
	string = ''
	tmpstring = sys.stdin.readlines()
	for line in tmpstring:
		string+=line
	# Now my string is complete. Meow.
	
	# Process message.
	json_data = process_email_message(string)
	
	# "Do something" with it.
	if PUSH2ES:
		push2es(es_collection_name, msg_id, json_data)
	elif BOUNCEBACK:
		bounceback_es.send_mail(json_data)
	elif JSONOUTPUT:
		print
		print json_data
		print
	elif JUSTDEBUG:
		print
		print 'Debug done'
		print
	# This should never happen. Complain about it with a strongly worded letter.
	else:
		print 'Some problem happened selecting an output option.'
		print








