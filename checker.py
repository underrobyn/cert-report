from os.path import exists

import csv
import logging

from OpenSSL.SSL import Error

from cert_result import CertResult
from ssl import HAS_TLSv1_2, HAS_TLSv1_3


class CertReport:
	results = []

	def __init__(self):
		if not HAS_TLSv1_2:
			raise Error('No TLS 1.2 support')

		if not HAS_TLSv1_3:
			logging.warning('No TLS 1.3 support, this may cause issues in a future version.')

	def get_hosts_from_file(self, file_name):
		if not exists(file_name):
			print('urls.txt does not exist. How am I supposed to know what you want to scan?')
			exit(1)

		with open(file_name) as f:
			for line in f:
				self.add_host(line.strip())

	def add_host(self, host):
		port = 443

		if ':' in host:
			host_parts = host.split(':')
			host = host_parts[0]
			port = host_parts[1]

		self.results.append(
			CertResult(host, port)
		)

	def check_hosts(self):
		for result in self.results:
			result.get_cert()
			if not result.connect_error:
				result.get_san()
				result.get_info()

	def get_results_objects(self):
		# TODO: Make pythonic
		out = []
		for result in self.results:
			out.append(result.get_object())
		return out

	def save_results_csv(self):
		headers = ['host', 'port', 'start', 'end', 'encryption', 'issued_to', 'issued_o', 'issuer_c', 'issuer_o',
				   'issuer_ou', 'issuer_cn', 'cert_serial', 'cert_sha1', 'cert_algorithm', 'cert_version']

		with open('report/output.csv', 'w', newline='', encoding='utf-8') as f:
			writer = csv.DictWriter(f, fieldnames=headers)

			writer.writeheader()
			for res in self.results:
				if res.connect_error:
					continue
				writer.writerow(res.get_object())


if __name__ == '__main__':
	cr = CertReport()
	cr.get_hosts_from_file('urls.txt')
	cr.check_hosts()
	cr.save_results_csv()
