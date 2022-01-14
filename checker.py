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
	with open('report/output.csv', 'w', newline='', encoding='utf-8') as f:
		write = csv.writer(f)
		write.writerow(['host', 'port', 'algorithm', 'before', 'after', 'result'])
		write.writerows(results)


def process_host(string):
	print(f"\nChecking certificate for host {string}")

	if ':' not in string:
		string += ':443'

	host = string.split(':')[0]
	port = string.split(':')[1]

	try:
		before, after, key_security = check_host(host, port)
	except Exception:
		print(f"-> Failed connecting to {host} on port {port}")
		results.append(
			[host, port, "?", "0", "0", "Failed to connect"]
		)
		return

	d_before, d_after = decode_result(before, after)
	str_before, str_after = string_date(d_before), string_date(d_after)

	print(f"-> Result: {str_before}, {str_after}, {key_security}")

	results.append(
		[host, port, key_security, str_before, str_after, "Success"]
	)


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


def get_dns_names(req: OpenSSL.crypto.X509):
	dns_names = []

	for i in range(req.get_extension_count()):
		try:
			val = req.get_extension(i)
		except OpenSSL.crypto._exception_from_error_queue:
			continue
		except Exception:
			continue

		if 'DNS' in str(val):
			for alt in str(val).split(', '):
				if alt.startswith('DNS:'):
					dns_names.append(alt[4:])

	return dns_names


def decode_result(before, after):
	d_before = datetime.strptime(before.decode('ascii'), '%Y%m%d%H%M%SZ')
	d_after = datetime.strptime(after.decode('ascii'), '%Y%m%d%H%M%SZ')

	return d_before, d_after


def string_date(date):
	return date.strftime("%Y-%m-%d, %H:%M:%S")


if __name__ == '__main__':
	main()
