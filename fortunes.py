#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import random

# Feel free to add your own.
fortunes = '''meh.
Only listen to the fortune generator; disregard all other fortune telling units.
Never give up, unless defeat arouses that girl in Risk Management.
Ignore previous fortunes.
Confucius says: Go to bed with itchy bum, wake up with stinky finger.
You will die alone and poorly dressed.
The end is near, and it is all your fault.
Colleagues secretly agree that your head is too small for your body.
Help, I am being held prisoner in a Chinese fortune factory!
The fortune you seek is found in another PDF submission.
Marriage lets you annoy one special person for the rest of your life.
Never tease an armed midget with a high five.
Someone has Googled you recently.
I found your boyfriend on Craigslist. He wasn't selling his pool table...
Fortune not found? Abort, Retry, Ignore.
Life is like a bath, it's nice at first, but then you get wrinkles.
A conclusion is simply the place where you got tired of thinking.
He who laughs last is laughing at you.
Some men dream of fortunes, others dream of cookies.
Don’t fry bacon in the nude.
Some days you are pigeon, some days you are statue. Today, bring umbrella.
Wise person never try to get even. Wise person get odder.
Two days from now, tomorrow will be yesterday.
Your inferiority complex not good enough. Try harder.
Two can live as cheaply as one, for half as long.
Hard work pay off in future. Laziness pay off now.
Life is sexually transmitted condition.
Person who argue with idiot is taken for fool.
Wise husband is one who thinks twice before saying nothing.
Dijon vu -- the same mustard as before.
For rectal use only.
The MapReduce job to identify your ideal mate will finish very soon.
No one reads your blog.
Mandiant attributes this sample to China, Norse attributes to Iran. 12 year old Estonian make rich.
'''

def ret_fortune():
	fortune_cookie = fortunes.split('\n')
	return random.choice(fortune_cookie)

