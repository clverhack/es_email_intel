from elasticsearch import Elasticsearch
import common_functions

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

md5s = common_functions.pull_md5s(es, es_collection_name, body)

for md5 in md5s:
	print md5

