
#!/usr/bin/env python3

import argparse
import validators
import requests
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(description='Website Vulnerability Analyzer version 0.1')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help="Website URL To Analyze")
parser.add_argument('--config', help='Path to configuration file')
parser.add_argument('-o', '--output', help='Path to vulnerability report')
args = parser.parse_args()

config = {'forms': True, 'comments': True, 'passwords': True }	#default config object

if(args.config):
	print('Using config file: ' + args.config)
	config_file = open(args.config, 'r')
	config_from_file = yaml.safe_load(config_file)
	if(config_from_file):
		config = { **config, **config_from_file }		
report = ''

url = args.url

if(validators.url(url)):
	result_html = requests.get(url).text
	parsed_html = BeautifulSoup(result_html, 'html.parser')
	
	#print(parsed_html.title)

	forms = (parsed_html.find_all('form'))
	comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment))

	password_inputs = parsed_html.find_all('input', {'name': 'password'})

	if(config['forms']):
		for form in forms:
			if((form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https')):
				report += 'Form Issue: Insecure form action ' + form.get('action') + ' found in document\n'

	if(config['comments']):	
		for comment in comments:
			if(comment.find('key: ') > -1):
				report += 'Comment Issue : Key is found in HTML comments. Remove It\n'

	if(config['passwords']):	
		for password_input in password_inputs:
			if(password_input.get('type') != 'password'):
				report += 'Password Issue: Plaintext password present. Remove It\n'  
else:
	print('Invalid URL. https://.. not present')


if(report == ''):
	report += 'This Website is secure\n'
else:
	header = 'Vulnerability Report Given Below:\n'
	header += '===================================\n'
	report = header + report
	print(report)

if(args.output):
	f = open(args.output, 'w')
	f.write(report)
	f.close()
	print('Saved report to: ' + args.output)
