from elasticsearch import Elasticsearch
from wordcloud import WordCloud, STOPWORDS
import common_functions

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

keywords_list = keywords.split('\n')

es_server = '192.168.3.208'
es = Elasticsearch([{'host': es_server, 'port': 9200}])
es_collection_name = 'mail2json'

def gen_wordcloud():

	then = common_functions.queryrange(1)

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

	text = common_functions.pull_mailtext_24hrs(es, es_collection_name, body, keywords_list).lower()

	print text
	print
	
	wc = WordCloud(background_color="white", max_words=40)
	fileloc = "/home/pierre/es_email_intel/wordcloud.png"
	try:
		wc.generate(text)
		wc.to_file(fileloc)
		print 'Finished!'
		return
	except:
		target = open(fileloc, 'w')
		target.truncate()
		target.close()
		print 'Except!'
		return


gen_wordcloud()