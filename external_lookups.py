import requests
import time
import json

# Contact Nathan Fowler for access.
# I don't process the result, just return it.
def packetmail_lookup(ip):
	apikey = 'abc123'
	ip = str(ip)
	feedaddr = 'https://www.packetmail.net/iprep.php/'
	requesturl = feedaddr+ip+'?apikey='+str(apikey)
	try:
		r = requests.get(requesturl)
		return r.content
	except:
		return


# Do your own lookups, this is a private system!
def ipv4_futurecrimes(ipv4):
	qstring = 'https://192.168.3.101/FClookupAPI.php?ip='+str(ipv4)
	try:
		r = requests.get(qstring, verify=False)
		return r.content
	except:
		return

'''
I needed a way to exclude previously-reported indicators from the past x time frame.

The remote end simply checks the DB for a matching thing-string, within the past 30 days.
If no result was found, add it to the DB with a now timestamp and return 0.
If a result was found, return 1.
'''
def check_newobserved(item):
	qstring = 'http://192.168.3.19/observed_cache.php?q='+str(item)
	try:
		r = requests.get(qstring)
		if r.content == '1':
			return 1
		else:
			return 0
	except:
		return


# VT domain lookup. Obviously you could add IP and MD5 lookups if you wanted.
# Very little error handling here.
def vt_domain(domain):
	# Either return an empty dictionary, or a full one
	# Empty dict == False
	ret_string = ''
	time.sleep(16)
	ret_list = []
	baseurl = "https://www.virustotal.com/vtapi/v2/domain/report"
	params = {
		"domain": domain,
		"apikey": "abc123"
	}
	r = requests.get(baseurl, params=params)

	try:
		json_data_string = json.loads(r.content)
	except:
		return

	if json_data_string['response_code'] == 1:
		ret_string += '\n'
		ret_string += 'The domain address '+str(domain)+" was found in the Virustotal dataset.\n"
		if hasattr(json_data_string, 'detected_urls'):
			for url in json_data_string['detected_urls']:
				ret_string += 'Malicious URL: '+str(url['url'])+'\n'
		else:
			ret_string += 'No further VT data available, no detected URLs.\n'
	else:
		ret_string += 'No Virustotal data about domain '+str(domain)+'\n'
	return ret_string
	
def vt_hash(filehash):
	# Either return an empty dictionary, or a full one
	# Empty dict == False
	ret_string = ''
	time.sleep(16)
	ret_list = []
	baseurl = "https://www.virustotal.com/vtapi/v2/file/report"
	params = {
		"resource": filehash,
		"apikey": "abc123"
	}
	r = requests.get(baseurl, params=params)

	try:
		json_data_string = json.loads(r.content)
	except:
		return ret_string
	if json_data_string['response_code'] == 1:
		ret_string += '\n'
		ret_string += 'The file hash '+str(filehash)+" was found in the Virustotal dataset.\n"
		ret_string += 'Positives/Total: '+str(json_data_string['positives'])+"/"+str(json_data_string['total'])+'\n'
		ret_string += 'VT Link: '+str(json_data_string['permalink'])+'\n'
	else:
		ret_string += 'No Virustotal data about file hash '+str(filehash)+'\n'
	return ret_string