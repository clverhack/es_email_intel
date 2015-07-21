import re

domlist = [line.strip() for line in open("whitelist_domains.txt", 'r')]
domlist = list(set(domlist)) # Dedupe

def checkURLexceptions(url):
	url = url.strip()
	if re.search('[\[\]]', url): return 1 # Brackets aren't allowed in URLs
	for dom in domlist:
		if re.search('.*\.'+dom, url): return 1
		if re.search('^'+dom, url): return 1
	return 0
	
