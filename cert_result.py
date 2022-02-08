import socket, json
from datetime import datetime
from ssl import PROTOCOL_TLSv1

from OpenSSL import SSL


class CertResult:

	def __init__(self, host, port):
		self.host = host
		self.port = int(port)

		self._cert = None
		self._subject = None

		self._san = ''
		self.san = []

		self.cert_start = None
		self.cert_end = None
		self.valid_days = None
		self.remaining_days = None
		self.is_valid = None
		self.has_expired = None

		self._ctx = {}

		self.key_type = None
		self.key_length = None

	def get_cert(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		ssl_ctx = SSL.Context(PROTOCOL_TLSv1)

		sock.connect((self.host, self.port))

		ssl_conn = SSL.Connection(ssl_ctx, sock)
		ssl_conn.set_tlsext_host_name(self.host.encode())
		ssl_conn.set_connect_state()
		ssl_conn.do_handshake()

		self._cert = ssl_conn.get_peer_certificate()
		self._subject = self._cert.get_subject()

		sock.close()

	def get_san(self):
		san = ''
		ext_count = self._cert.get_extension_count()
		for i in range(0, ext_count):
			ext = self._cert.get_extension(i)
			if 'subjectAltName' in str(ext.get_short_name()):
				san = ext.__str__()

		self._san = san.replace(',', ';')
		self.san = san.split(';')

	def get_info(self):
		self._ctx['issued_to'] = self._subject.CN
		self._ctx['issued_o'] = self._subject.O
		self._ctx['issuer_c'] = self._cert.get_issuer().countryName
		self._ctx['issuer_o'] = self._cert.get_issuer().organizationName
		self._ctx['issuer_ou'] = self._cert.get_issuer().organizationalUnitName
		self._ctx['issuer_cn'] = self._cert.get_issuer().commonName
		self._ctx['cert_sn'] = str(self._cert.get_serial_number())
		self._ctx['cert_sha1'] = self._cert.digest('sha1').decode()
		self._ctx['cert_alg'] = self._cert.get_signature_algorithm().decode()
		self._ctx['cert_ver'] = self._cert.get_version()

		self.has_expired = self._cert.has_expired()
		self.is_valid = False if self._cert.has_expired() else True

		self.cert_start = datetime.strptime(self._cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
		self.cert_end = datetime.strptime(self._cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
		self.valid_days = (self.cert_end - self.cert_start).days
		self.remaining_days = (self.cert_end - datetime.now()).days

	def get_key_security(self):
		# return f'{self.key_type}-{self.key_length}'
		return self._ctx

	def get_object(self):
		return {
			'host': self.host,
			'port': self.port,
			'start': self.cert_start.strftime("%Y-%m-%d, %H:%M:%S"),
			'end': self.cert_end.strftime("%Y-%m-%d, %H:%M:%S"),
			'encryption': self.get_key_security()
		}


if __name__ == '__main__':
	test = CertResult('google.co.uk', 443)
	test.get_cert()
	test.get_san()
	test.get_info()
	print(json.dumps(test.get_object()))
