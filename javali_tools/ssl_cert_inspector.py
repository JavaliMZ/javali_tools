import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes



class Certificate:
    pass



def get_certificate(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert(binary_form=True)
    except ssl.SSLError:
        print("⚠️  Verification failed — retrying without validation...\n")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert(binary_form=True)

def format_name(name):
    return ", ".join(f"{attr.oid._name}={attr.value}" for attr in name)


def print_certificate_info(cert):
    print("\n" + "=" * 70)
    print("🔐 SSL Certificate Information")
    print("=" * 70)

    print(f"\n📌 Subject      : {format_name(cert.subject)}")
    print(f"🏢 Issuer       : {format_name(cert.issuer)}")

    print("\n⏳ Validity")
    # newer versions of cryptography use `not_valid_before`/`not_valid_after`
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after

    # the returned datetimes may be naive; normalize to UTC for display
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    print(f"   Not Before   : {not_before.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"   Not After    : {not_after.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    if days_left < 0:
        status = "❌ EXPIRED"
    elif days_left < 30:
        status = "⚠️ Expiring Soon"
    else:
        status = "✅ Valid"

    print(f"   Days Remaining: {days_left} days ({status})")

    print(f"\n🔢 Serial Number: {hex(cert.serial_number)}")

    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        dns_names = san.value.get_values_for_type(x509.DNSName)

        print("\n🌐 Subject Alternative Names (DNS)")
        for name in dns_names:
            print(f"   - {name}")
    except x509.ExtensionNotFound:
        print("\n🌐 Subject Alternative Names: None found")

    public_key = cert.public_key()
    print("\n🔑 Public Key")
    print(f"   Type         : {public_key.__class__.__name__}")
    if hasattr(public_key, "key_size"):
        print(f"   Key Size     : {public_key.key_size} bits")

    sha1_fp = cert.fingerprint(hashes.SHA1()).hex()
    sha256_fp = cert.fingerprint(hashes.SHA256()).hex()

    print("\n🧾 Fingerprints")
    print(f"   SHA1         : {':'.join(sha1_fp[i:i+2] for i in range(0, len(sha1_fp), 2))}")
    print(f"   SHA256       : {':'.join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))}")

    print("\n" + "=" * 70)


def run(args):
    hostname = args.target
    port = args.port

    der_cert = get_certificate(hostname, port)
    cert = x509.load_der_x509_certificate(der_cert)
    print_certificate_info(cert)




if __name__ == "__main__":
    class test_args:
        target = "google.pt"
        port = 443
    run(test_args())