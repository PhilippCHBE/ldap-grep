"""Local-only TLS negative tests; no production LDAP connection."""
import socket
import ssl
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ldapgrep.client import LdapClient, LdapGrepError, probe_server
from ldapgrep.config import Settings


@pytest.fixture
def certificates(tmp_path):
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ldapgrep synthetic test CA")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                        key_encipherment=False, data_encipherment=False,
                                        key_agreement=False, key_cert_sign=True, crl_sign=True,
                                        encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
    ca = tmp_path / "ca.pem"
    ca.write_bytes(root.public_bytes(serialization.Encoding.PEM))

    def leaf(host):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(root.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                               critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(root_key, hashes.SHA256()))
        cert_path, key_path = tmp_path / "leaf.pem", tmp_path / "leaf.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        return context

    return str(ca), leaf


@contextmanager
def local_server(handler):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    errors = []

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                handler(connection)
        except (ssl.SSLError, ConnectionResetError):
            pass  # Expected when the client rejects the certificate.
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        thread.join(4)
        listener.close()
        assert not thread.is_alive()
        assert not errors, errors


@pytest.fixture
def unintercepted_tls(certificates):
    ca, make_leaf = certificates
    context = make_leaf("localhost")

    def handler(connection):
        with context.wrap_socket(connection, server_side=True) as secure:
            secure.recv(1)

    # Diagnostic only: inspect the peer without sending credentials. Some endpoint
    # security tools replace even loopback certificates, invalidating these fixtures.
    with local_server(handler) as port:
        with ssl._create_unverified_context().wrap_socket(
                socket.create_connection(("localhost", port), timeout=2), server_hostname="localhost") as secure:
            observed = x509.load_der_x509_certificate(secure.getpeercert(binary_form=True))
            secure.sendall(b"x")
    expected = x509.load_pem_x509_certificate((Path(ca).parent / "leaf.pem").read_bytes())
    if observed != expected:
        pytest.skip("Local TLS certificates are replaced by endpoint security; run these tests in Linux/CI.")
    return certificates


@pytest.mark.parametrize("hostname,trusted,ok", [("localhost", True, True),
                                               ("wrong.example", True, False), ("localhost", False, False)])
def test_real_certificate_chain_and_hostname(unintercepted_tls, hostname, trusted, ok):
    ca, make_leaf = unintercepted_tls
    context = make_leaf(hostname)

    def handler(connection):
        with context.wrap_socket(connection, server_side=True):
            pass

    with local_server(handler) as port:
        settings = Settings(server=f"ldaps://localhost:{port}", ca_certs_file=ca if trusted else "", timeout=2)
        steps = list(probe_server(settings))
    assert steps[-1].name == "tls" and steps[-1].ok is ok, steps
    if not ok:
        assert "certificate" in steps[-1].detail.lower()
    if hostname == "wrong.example":
        assert "hostname mismatch" in steps[-1].detail.lower()


def test_real_starttls_refusal_never_sends_bind():
    from pyasn1.codec.ber.decoder import decode
    from pyasn1.codec.ber.encoder import encode
    from pyasn1.error import SubstrateUnderrunError
    from ldap3.protocol.rfc4511 import LDAPMessage

    operations = []

    def handler(connection):
        buffer = b""
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                raise AssertionError("Client disconnected before requesting StartTLS")
            buffer += chunk
            try:
                message, rest = decode(buffer, asn1Spec=LDAPMessage())
            except SubstrateUnderrunError:
                continue
            buffer = rest
            operation = message["protocolOp"].getName()
            operations.append(operation)
            message_id = int(message["messageID"])
            response = LDAPMessage()
            response["messageID"] = message_id
            if operation == "searchRequest":
                result = response["protocolOp"]["searchResDone"]
                result["resultCode"] = 0
            elif operation == "extendedReq":
                result = response["protocolOp"]["extendedResp"]
                result["resultCode"] = 53  # unwillingToPerform
            else:
                raise AssertionError(f"Unexpected LDAP operation: {operation}")
            result["matchedDN"] = ""
            result["diagnosticMessage"] = ""
            connection.sendall(encode(response))
            if operation == "extendedReq":
                return

    with local_server(handler) as port:
        with pytest.raises(LdapGrepError):
            LdapClient(Settings(server=f"ldap://127.0.0.1:{port}", start_tls=True, load_schema=False,
                                bind_dn="cn=audit", bind_password="synthetic", timeout=2)).connect()
    assert "extendedReq" in operations and "bindRequest" not in operations
