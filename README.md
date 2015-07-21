# es_email_intel

Procmail config:

Standard email list extraction:

:0cr
* ^To.*somelist@somewhere.com.*
| /usr/local/bin/python /home/pierre/es_email_intel/mail_parser2json.py

Shoot a mail back to the originator with the extracted IOCs:

:0cr
* ^To.*extract@userid.org.*
| /usr/local/bin/python /home/pierre/es_email_intel/mail_parser2json.py 1

Crontab entries:

00 04 * * *     /bin/sh /home/pierre/es_email_intel/es_feeder.sh
30 06 * * *     /usr/local/bin/python /home/pierre/es_email_intel/es_query_ipv4_outhtml_outmail.py
35 06 * * *     /usr/local/bin/python /home/pierre/es_email_intel/es_query_domain_outhtml_outmail.py
40 06 * * *     /usr/local/bin/python /home/pierre/es_email_intel/es_query_md5_outhtml_outmail.py

Not included, the feeder script, but it's invoked like this:

/usr/local/bin/python /home/pierre/es_email_intel/es_query_ipv4_feed.py > /tmp/es_ipv4feed.txt


==

You'll obviously need to setup your own ElasticSearch box. I also backend to some external boxes for things, you'll need to fix or replace those entries.

