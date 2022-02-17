from os.path import exists

import csv

from cert_result import CertResult


class CertReport:
	results = []

	def get_urls_from_file(self):
		if not exists('urls.txt'):
			print('urls.txt does not exist. How am I supposed to know what you want to scan?')
			exit(1)

		with open('urls.txt') as f:
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

	def check_urls(self):
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
	cr.get_urls_from_file()
	cr.check_urls()
	cr.save_results_csv()
