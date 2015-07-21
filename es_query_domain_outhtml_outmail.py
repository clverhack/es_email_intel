from elasticsearch import Elasticsearch
import requests
import os, sys
import time
import re
import hashlib
import common_functions
import external_lookups

import gen_wordcloud

import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEImage import MIMEImage
from email import Encoders
import time

EMAIL_SERVER = '192.168.3.2'
EMAIL_FROM = 'pierre@userid.org'
SUBJECT = "ES Intel Report (Domain) for "+time.ctime()
EMAIL_TO = {'pierre@userid.org'}

report_contents = ''

gen_wordcloud.gen_wordcloud()

def send_mail(report_contents):
	msg = MIMEMultipart()
	msg['Subject'] = SUBJECT 
	msg['From'] = EMAIL_FROM
	msg['To'] = ', '.join(EMAIL_TO)
	
	fp = open('/home/pierre/es_email_intel/wordcloud.png', 'rb')
	try:
		msgImage = MIMEImage(fp.read())
	except:
		fp = open('/home/pierre/es_email_intel/1x1.png', 'rb')
		msgImage = MIMEImage(fp.read())
	fp.close()
	msgImage.add_header('Content-ID', '<wordcloud>')
	msg.attach(msgImage)

	part = MIMEBase('application', "octet-stream")
	part.set_payload(report_contents)
	Encoders.encode_base64(part)

	part.add_header('Content-Disposition', 'attachment; filename="report.html"')

	msg.attach(part)

	server = smtplib.SMTP(EMAIL_SERVER)
	server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())


es_server = '192.168.3.208'
es = Elasticsearch([{'host': es_server, 'port': 9200}])
es_collection_name = 'mail2json'

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

preskel = '''
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <!-- The above 2 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">

    <!-- Note there is no responsive meta tag here -->

    <link rel="icon" href="../../favicon.ico">

    <title>Newly observed Domain indicator report</title>

    <!-- Bootstrap core CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.4/css/bootstrap.min.css">

    <!-- Custom styles for this template -->
    <link href="non-responsive.css" rel="stylesheet">

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>

  <body>

	<br/>
    <div class="container">
      <div class="page-header">
        <p class="lead">Here is a list of newly observed Domain indicators from our monitored email lists.</p>
      </div>

      <h3>Domain addresses</h3>
		<table class="table table-striped">
		  <thead>
			<tr>
			  <th>Address</th>
			  <th>Subject(s)</th>
			  <th>List-Id(s)</th>
			</tr>
		  </thead>
		  <tbody>
'''

postskel = '''
		  </tbody>
		</table>

	  
    </div> <!-- /container -->

	<br><br><br>
	<p> Raw data supplement</p>
'''

postskel2 = '''	
    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.2/jquery.min.js"></script>
    <script src="../../dist/js/bootstrap.min.js"></script>
    <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
    <script src="../../assets/js/ie10-viewport-bug-workaround.js"></script>
  </body>
</html>
'''

print 'Pulling domains...'

domains = common_functions.pull_domain_addresses(es, es_collection_name, body)

print 'Raw count of domains: '+str(len(domains))

# Remove recently-seen items from the result set
for i in xrange(len(domains) - 1, -1, -1):
	if re.search('^\-', domains[i]):
		del domains[i]
	if external_lookups.check_newobserved(domains[i]):
		del domains[i]

print 'Scrubbed count of domains: '+str(len(domains))
### Everything after this is to write the HTML page

report_contents += preskel

for domain in domains:
	meta = common_functions.describesources(es, es_collection_name, 'domain:'+domain)
	report_contents += '<tr>'
	v4hash = hashlib.sha224(domain).hexdigest()
	report_contents += '<th scope="row"><a href="#'+str(v4hash)+'">'+domain+'</a></th>'
	report_contents += '<td>'
	seensubjects = []
	for subject in meta[0]:
		subject = subject.strip()
		if subject in seensubjects: continue
		if re.search('^RE$', subject): continue
		seensubjects.append(subject)
		subject = re.sub('\[cw warroom\] ', '', subject)
		subject = re.sub('\[cw general\] ', '', subject)
		report_contents += subject+'</br/>'
	report_contents += '</td>'
	report_contents += '<th>'
	seenlists = []
	for list in meta[1]:
		if list in seenlists: continue
		seenlists.append(list)
		report_contents += list+'</br/>'
	report_contents += '</th>'
	report_contents += '</tr>'

report_contents += postskel
'''
for domain in domains:
	v4hash = hashlib.sha224(domain).hexdigest()
	report_contents += '<span id="'+v4hash+'">'
	report_contents += '<p>============================================================================</p>'
	report_contents += '<h3>'+str(domain)+'</h3>\n'
	report_contents += '<b>Virustotal lookup:</b><br>\n<pre>'
	report_contents += external_lookups.vt_domain(domain)
	report_contents += '</pre></span>'
'''
report_contents += postskel2


send_mail(report_contents)