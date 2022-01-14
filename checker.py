from datetime import datetime
from os.path import exists

import OpenSSL
import ssl
import csv


results = []


def main():
	check_urls()


def check_urls():
	if not exists('urls.txt'):
		print('urls.txt does not exist. How am I supposed to know what you want to scan?')
		exit(1)

	with open('urls.txt') as f:
		for line in f:
			process_host(line.strip())

	save_results()


def save_results():
	with open('output.csv', 'w', newline='', encoding='utf-8') as f:
		write = csv.writer(f)
		write.writerow(['host', 'port', 'before', 'after'])
		write.writerows(results)


def process_host(string):
	print(f"Checking certificate for host {string}")

	if ':' not in string:
		string += ':443'

	host = string.split(':')[0]
	port = string.split(':')[1]

	try:
		before, after = check_host(host, port)
	except Exception:
		print(f"Failed connecting to {host} on port {port}")
		return

	d_before, d_after = decode_result(before, after)
	str_before, str_after = string_date(d_before), string_date(d_after)

	print(f"Result: {str_before}, {str_after}")

	results.append(
		[host, port, str_before, str_after]
	)


def check_host(hostname, port):
	cert = ssl.get_server_certificate((hostname, port))

	x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

	before = x509.get_notBefore()
	after = x509.get_notAfter()

	return before, after


def decode_result(before, after):
	d_before = datetime.strptime(before.decode('ascii'), '%Y%m%d%H%M%SZ')
	d_after = datetime.strptime(after.decode('ascii'), '%Y%m%d%H%M%SZ')

	return d_before, d_after


def string_date(date):
	return date.strftime("%Y-%m-%d, %H:%M:%S")


if __name__ == '__main__':
	main()
