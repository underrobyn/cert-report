from datetime import datetime
from os.path import exists

import OpenSSL
import ssl
import csv

from cert_result import CertResult


def string_date(date):
	return date.strftime("%Y-%m-%d, %H:%M:%S")


class CertReport:

	results = []

	def __init__(self):
		pass

	def get_urls_from_file(self):
		if not exists('urls.txt'):
			print('urls.txt does not exist. How am I supposed to know what you want to scan?')
			exit(1)

		with open('urls.txt') as f:
			for line in f:
				self.add_host(line.strip())

	def add_host(self, host):
		if ':' not in host:
			host += ':443'

		host = host.split(':')[0]
		port = host.split(':')[1]

		self.results.append(
			CertResult(host, port)
		)

	def check_urls(self):
		for result in self.results:
			result.get_cert()
			result.get_san()
			result.get_info()

		pass

	def get_results_objects(self):
		# TODO: Make pythonic
		out = []
		for result in self.results:
			out.append(result.get_object())
		return out

	def save_results_csv(self):
		with open('report/output.csv', 'w', newline='', encoding='utf-8') as f:
			write = csv.writer(f)
			write.writerow(['host', 'port', 'encryption', 'start', 'end', 'result'])
			write.writerows(self.get_results_objects())


def check_host(hostname, port):
	cert = ssl.get_server_certificate((hostname, port))

	x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
	# print(get_dns_names(x509))
	print(str(x509.get_signature_algorithm()))
	print(str(x509.get_issuer()))

	key_type = 'RSA' if x509.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA else 'DSA'
	key_length = x509.get_pubkey().bits()
	key_security = f"{key_type}-{key_length}"

	before = x509.get_notBefore()
	after = x509.get_notAfter()

	return before, after, key_security


if __name__ == '__main__':
	cr = CertReport()
	cr.get_urls_from_file()
	cr.check_urls()
	cr.save_results_csv()
