import time
import re
import ip_exceptions
import domain_exceptions
import url_exceptions
import syslog

'''
Shared code.
'''

CF_DEBUG = False

def extract_subject(headers):
	if CF_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Entered extract_subject(headers)')
	if 'Thread-Topic' in headers:
		if CF_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Found threat topic: '+headers['Thread-Topic'])
		return headers['Thread-Topic']
	elif 'Subject' in headers:
		if CF_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Found only subject: '+headers['Subject'])
		return headers['Subject']
	else:
		if CF_DEBUG: syslog.syslog(syslog.LOG_ERR, 'Found blank topic and subject')
		return 'Blank subject'

def queryrange(days):
	# Go back up to a month, but not up to the import date
	# That's the floor and we don't go any lower.
	days_seconds = int(days) * 86400
	now = time.time()
	then = str(int(now) - days_seconds)
	then = re.sub('\..*$', '', then)
	floor = 1433627249 # Import date, set this to just after any bulk import you did.
	if int(then) < floor:
		then = str(floor)
	return str(then)
	
def pull_ipv4_addresses(es, es_collection_name, body):
	res = es.search(index=es_collection_name, body=body)
	ipv4s = []
	for hit in res['hits']['hits']:
		if 'ipv4' in hit["_source"]:
			for v4 in hit["_source"]['ipv4']:
				v4 = re.sub('\[\.\]', '.', v4)
				ipv4s.append(v4)
	ipv4s = list(set(ipv4s))
	ipv4s.sort()
	
	for i in xrange(len(ipv4s) - 1, -1, -1):
		if ip_exceptions.checkIPexceptions(ipv4s[i]):
			del ipv4s[i]
	
	return ipv4s
	
def pull_mailtext_24hrs(es, es_collection_name, body, keywords):
	res = es.search(index=es_collection_name, body=body)
	text = ''
	
	rawtext = ''
	print 'Got '+str(len(res['hits']['hits']))+' hits'
	for hit in res['hits']['hits']:
		rawtext += hit["_source"]['message_text']

	for word in keywords:
		word = word.strip()
		if word == '': continue
		regex = r"\b(?=\w)" + re.escape(word) + r"\b(?!\w)"
		for m in re.finditer(regex, rawtext, re.IGNORECASE):
			text += str(m.group())+" "
	
	return text
	
def pull_domain_addresses(es, es_collection_name, body):
	res = es.search(index=es_collection_name, body=body)
	domains = []
	for hit in res['hits']['hits']:
		if 'domain' in hit["_source"]:
			for domain in hit["_source"]['domain']:
				domain = re.sub('^\.', '', domain)
				domains.append(domain)
	domains = list(set(domains))
	domains.sort()
	
	for i in xrange(len(domains) - 1, -1, -1):
		if domain_exceptions.checkDomainexceptions(domains[i]):
			del domains[i]
	
	return domains

def pull_md5s(es, es_collection_name, body):
	res = es.search(index=es_collection_name, body=body)
	md5s = []
	for hit in res['hits']['hits']:
		if 'md5' in hit["_source"]:
			for md5 in hit["_source"]['md5']:
				md5s.append(md5)
	md5s = list(set(md5s))
	md5s.sort()
	return md5s
	
def pull_urls(es, es_collection_name, body):
	res = es.search(index=es_collection_name, body=body)
	urls = []
	for hit in res['hits']['hits']:
		if 'url' in hit["_source"]:
			for url in hit["_source"]['url']:
				urls.append(url)
	urls = list(set(urls))
	urls.sort()
	
	for i in xrange(len(urls) - 1, -1, -1):
		if url_exceptions.checkURLexceptions(urls[i]):
			del urls[i]
	
	return urls

def describesources(es, es_collection_name, question):

	try:
		res = es.search(index=es_collection_name, q=question)
	except:
		print 'Search for "'+question+'" failed.'
		print
		return {}, {}
	else:
		pass

	subjectlist = []
	for hit in res['hits']['hits']:
		subject = re.sub('Re', '', hit["_source"]['headers']['Subject'].strip())
		subject = re.sub('\[cw general\]', '', subject)
		subject = subject.strip()
		if subject != '':
			try:
				subjectlist.append(str(subject).decode("utf-8", "replace"))
			except:
				subjectlist.append(repr(hit["_source"]['headers']['Subject']))
	listlist = []
	for hit in res['hits']['hits']:
		if 'List-Id' in hit["_source"]['headers']:
			listid = re.sub('^.*\<', '', hit["_source"]['headers']['List-Id'].strip())
		elif 'List-ID' in hit["_source"]['headers']:
			listid = re.sub('^.*\<', '', hit["_source"]['headers']['List-ID'].strip())
		elif 'X-BeenThere' in hit["_source"]['headers']:
			listid = re.sub('^.*\<', '', hit["_source"]['headers']['X-BeenThere'].strip())
		elif 'From' in hit["_source"]['headers']:
			listid = re.sub('^.*\<', '', hit["_source"]['headers']['From'].strip())
		else:
			print 'WTF, missing listid or beenthere or from\n\n'
			print hit["_source"]['headers']
			print '\n\n'
			exit()
		listid = re.sub('\>.*$', '', listid)
		listid = listid.strip()
		if listid != '':
			listlist.append(str(listid))
	
	return subjectlist, listlist