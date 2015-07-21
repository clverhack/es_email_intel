import re

def checkDomainexceptions(domain):

	domlist = [line.strip() for line in open("/home/pierre/es_email_intel/whitelist_domains.txt", 'r')]
	domlist = list(set(domlist)) # Dedupe

	domain = domain.strip()
	for dom in domlist:
		if re.search('\.\.', domain): return 1 # Double dots aren't allowed
		if re.search('^\-'+dom+'$', domain): return 1 # Starts with a dash, regex extraction problem
		if re.search('[\[\]]', domain): return 1 # Brackets aren't allowed in dom names
		if re.search('.*\.'+dom+'$', domain): return 1
		if re.search('^'+dom+'$', domain): return 1
	return 0
	
