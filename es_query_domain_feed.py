from elasticsearch import Elasticsearch
import common_functions

'''
Generate a plaintext feed for a SIEM
I invoke mine like this:

#!/bin/sh
/usr/local/bin/python <mypath>/es_query_domain_feed.py > /tmp/es_feed_domain.txt
scp /tmp/es_feed_domain.txt <webserver dir>/es_feed_domain.txt &>/dev/null
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

domains = common_functions.pull_domain_addresses(es, es_collection_name, body)

for domain in domains:
	print domain

