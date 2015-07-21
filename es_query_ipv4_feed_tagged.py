from elasticsearch import Elasticsearch
import common_functions
import re
'''
Generate a plaintext feed for a SIEM
I invoke mine like this:

#!/bin/sh
/usr/local/bin/python <mypath>/es_query_ipv4_feed.py > /tmp/es_feed.txt
scp /tmp/es_feed.txt <webserver dir>/es_feed.txt &>/dev/null
'''

keywords = '''APT 28
APT 30
RAT
SEA
Zeus
Adobe
Angler
anonopsaudix2
APT 12
Axiom
Backoff
Badur
BlackPOS
brute force
Bugat
codoso
Cool EK
Cridex
cross team
cryptowall
CVE-2015-1635
Cyber Berkut
DD4BC
DDoS
Deep Panda
Dexter
DPRK
Dridex
Driveby
Duqu
Dyre
Equation Group
Feodor
Fiesta
FIN4
FlashPack
FlimKit
Gamarue
GhostSec
Heartbleed
ISIL
ISIS
LastPass
Lotus Blossom
Magnitude
Malum
MalumPOS
MS15-034
Neutrino
Newscaster
Nitlove
Nuclear
obfuscat
Ocean Lotus
OPM
password guess
Phishing
Poodle
PoS
Poweliks
Ransomware
Sakula
Sakura
Sandworm
Shell Crew
ShellShock
SQLi
SQLMap
Styx
Sweet Orange
Syrian Electronic Army
TESLACYRPT
Titan Rain
Upatre
vawtrak
vSkimmer
'''

es_server = '192.168.3.208'
es = Elasticsearch([{'host': es_server, 'port': 9200}])
es_collection_name = 'mail2json'

then = common_functions.queryrange(30)

body = '''{
	"size" : 10000,
    "query": {
        "constant_score": {
            "filter": {
                "range": {
                    "epoch": {
                        "from": '''+then+'''
                    }
                }
            }
        }
    }
}'''

def ipv4_matchkeywords(ipv4):
	ret_match = ''
	# Given an IPv4 address, pull 30 days worth of messages that contain the indicator and see what keywords are found
	then = common_functions.queryrange(30)
	json = '''
	{"size" : 10000,
	"query": {
	  "match": {
		"ipv4":{"query":"'''+ipv4+'''"}
	  }
	}}
	'''
	res = es.search(index=es_collection_name, body=json)
	
	keywords_list = keywords.split('\n')
	for keyword in keywords_list:
		if keyword.strip() == '': continue
		regex = r"\b(?=\w)" + re.escape(keyword) + r"\b(?!\w)"
		#print 'Looking at keyword: '+keyword
		#print 'Compiled this regex: '+regex
		for hit in res['hits']['hits']:
			rawtext = hit["_source"]['message_text']
			if re.search(regex, rawtext, re.IGNORECASE):
				if not re.search(r"\:?" + re.escape(keyword) + r"\:", ret_match):
					ret_match += keyword+':'
	if ret_match.endswith(":"): ret_match = ret_match[:-1]
	return ret_match
	

ipv4s = common_functions.pull_ipv4_addresses(es, es_collection_name, body)

for ipv4 in ipv4s:
	print ipv4+','+ipv4_matchkeywords(ipv4)



	
