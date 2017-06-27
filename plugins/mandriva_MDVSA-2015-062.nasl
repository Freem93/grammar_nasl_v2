#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:062. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82315);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/24 13:12:22 $");

  script_cve_id("CVE-2010-5298", "CVE-2014-0076", "CVE-2014-0160", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470", "CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0293");
  script_xref(name:"MDVSA", value:"2015:062");

  script_name(english:"Mandriva Linux Security Advisory : openssl (MDVSA-2015:062)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in 
openssl :

Race condition in the ssl3_read_bytes function in s3_pkt.c in OpenSSL
through 1.0.1g, when SSL_MODE_RELEASE_BUFFERS is enabled, allows
remote attackers to inject data across sessions or cause a denial of
service (use-after-free and parsing error) via an SSL connection in a
multithreaded environment (CVE-2010-5298).

The Montgomery ladder implementation in OpenSSL through 1.0.0l does
not ensure that certain swap operations have a constant-time behavior,
which makes it easier for local users to obtain ECDSA nonces via a
FLUSH+RELOAD cache side-channel attack (CVE-2014-0076).

The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before
1.0.1g do not properly handle Heartbeat Extension packets, which
allows remote attackers to obtain sensitive information from process
memory via crafted packets that trigger a buffer over-read, as
demonstrated by reading private keys, related to d1_both.c and
t1_lib.c, aka the Heartbleed bug (CVE-2014-0160).

The dtls1_reassemble_fragment function in d1_both.c in OpenSSL before
0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not
properly validate fragment lengths in DTLS ClientHello messages, which
allows remote attackers to execute arbitrary code or cause a denial of
service (buffer overflow and application crash) via a long non-initial
fragment (CVE-2014-0195).

The do_ssl3_write function in s3_pkt.c in OpenSSL 1.x through 1.0.1g,
when SSL_MODE_RELEASE_BUFFERS is enabled, does not properly manage a
buffer pointer during certain recursive calls, which allows remote
attackers to cause a denial of service (NULL pointer dereference and
application crash) via vectors that trigger an alert condition
(CVE-2014-0198).

The dtls1_get_message_fragment function in d1_both.c in OpenSSL before
0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h allows remote
attackers to cause a denial of service (recursion and client crash)
via a DTLS hello message in an invalid DTLS handshake (CVE-2014-0221).

OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
does not properly restrict processing of ChangeCipherSpec messages,
which allows man-in-the-middle attackers to trigger use of a
zero-length master key in certain OpenSSL-to-OpenSSL communications,
and consequently hijack sessions or obtain sensitive information, via
a crafted TLS handshake, aka the CCS Injection vulnerability
(CVE-2014-0224).

The ssl3_send_client_key_exchange function in s3_clnt.c in OpenSSL
before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h, when an
anonymous ECDH cipher suite is used, allows remote attackers to cause
a denial of service (NULL pointer dereference and client crash) by
triggering a NULL certificate value (CVE-2014-3470).

Memory leak in d1_srtp.c in the DTLS SRTP extension in OpenSSL 1.0.1
before 1.0.1j allows remote attackers to cause a denial of service
(memory consumption) via a crafted handshake message (CVE-2014-3513).

The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
products, uses nondeterministic CBC padding, which makes it easier for
man-in-the-middle attackers to obtain cleartext data via a
padding-oracle attack, aka the POODLE issue (CVE-2014-3566).

Memory leak in the tls_decrypt_ticket function in t1_lib.c in OpenSSL
before 0.9.8zc, 1.0.0 before 1.0.0o, and 1.0.1 before 1.0.1j allows
remote attackers to cause a denial of service (memory consumption) via
a crafted session ticket that triggers an integrity-check failure
(CVE-2014-3567).

The ssl23_get_client_hello function in s23_srvr.c in OpenSSL 0.9.8zc,
1.0.0o, and 1.0.1j does not properly handle attempts to use
unsupported protocols, which allows remote attackers to cause a denial
of service (NULL pointer dereference and daemon crash) via an
unexpected handshake, as demonstrated by an SSLv3 handshake to a
no-ssl3 application with certain error handling. NOTE: this issue
became relevant after the CVE-2014-3568 fix (CVE-2014-3569).

The BN_sqr implementation in OpenSSL before 0.9.8zd, 1.0.0 before
1.0.0p, and 1.0.1 before 1.0.1k does not properly calculate the square
of a BIGNUM value, which might make it easier for remote attackers to
defeat cryptographic protection mechanisms via unspecified vectors,
related to crypto/bn/asm/mips.pl, crypto/bn/asm/x86_64-gcc.c, and
crypto/bn/bn_asm.c (CVE-2014-3570).

OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k
allows remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a crafted DTLS message that is
processed with a different read operation for the handshake header
than for the handshake body, related to the dtls1_get_record function
in d1_pkt.c and the ssl3_read_n function in s3_pkt.c (CVE-2014-3571).

The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before
0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote
SSL servers to conduct ECDHE-to-ECDH downgrade attacks and trigger a
loss of forward secrecy by omitting the ServerKeyExchange message
(CVE-2014-3572).

OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k
does not enforce certain constraints on certificate data, which allows
remote attackers to defeat a fingerprint-based certificate-blacklist
protection mechanism by including crafted data within a certificate's
unsigned portion, related to crypto/asn1/a_verify.c,
crypto/dsa/dsa_asn1.c, crypto/ecdsa/ecs_vrf.c, and crypto/x509/x_all.c
(CVE-2014-8275).

The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before
0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote
SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and
facilitate brute-force decryption by offering a weak ephemeral RSA key
in a noncompliant role, related to the FREAK issue. NOTE: the scope of
this CVE is only client code based on OpenSSL, not EXPORT_RSA issues
associated with servers or other TLS implementations (CVE-2015-0204).

The ssl3_get_cert_verify function in s3_srvr.c in OpenSSL 1.0.0 before
1.0.0p and 1.0.1 before 1.0.1k accepts client authentication with a
Diffie-Hellman (DH) certificate without requiring a CertificateVerify
message, which allows remote attackers to obtain access without
knowledge of a private key via crafted TLS Handshake Protocol traffic
to a server that recognizes a Certification Authority with DH support
(CVE-2015-0205).

Memory leak in the dtls1_buffer_record function in d1_pkt.c in OpenSSL
1.0.0 before 1.0.0p and 1.0.1 before 1.0.1k allows remote attackers to
cause a denial of service (memory consumption) by sending many
duplicate records for the next epoch, leading to failure of replay
detection (CVE-2015-0206).

Use-after-free vulnerability in the d2i_ECPrivateKey function in
crypto/ec/ec_asn1.c in OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r,
1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a might allow remote
attackers to cause a denial of service (memory corruption and
application crash) or possibly have unspecified other impact via a
malformed Elliptic Curve (EC) private-key file that is improperly
handled during import (CVE-2015-0209).

The ASN1_TYPE_cmp function in crypto/asn1/a_type.c in OpenSSL before
0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before
1.0.2a does not properly perform boolean-type comparisons, which
allows remote attackers to cause a denial of service (invalid read
operation and application crash) via a crafted X.509 certificate to an
endpoint that uses the certificate-verification feature
(CVE-2015-0286).

The ASN1_item_ex_d2i function in crypto/asn1/tasn_dec.c in OpenSSL
before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2
before 1.0.2a does not reinitialize CHOICE and ADB data structures,
which might allow attackers to cause a denial of service (invalid
write operation and memory corruption) by leveraging an application
that relies on ASN.1 structure reuse (CVE-2015-0287).

The X509_to_X509_REQ function in crypto/x509/x509_req.c in OpenSSL
before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2
before 1.0.2a might allow attackers to cause a denial of service (NULL
pointer dereference and application crash) via an invalid certificate
key (CVE-2015-0288).

The PKCS#7 implementation in OpenSSL before 0.9.8zf, 1.0.0 before
1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a does not properly
handle a lack of outer ContentInfo, which allows attackers to cause a
denial of service (NULL pointer dereference and application crash) by
leveraging an application that processes arbitrary PKCS#7 data and
providing malformed data with ASN.1 encoding, related to
crypto/pkcs7/pk7_doit.c and crypto/pkcs7/pk7_lib.c (CVE-2015-0289).

The SSLv2 implementation in OpenSSL before 0.9.8zf, 1.0.0 before
1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a allows remote
attackers to cause a denial of service (s2_lib.c assertion failure and
daemon exit) via a crafted CLIENT-MASTER-KEY message (CVE-2015-0293).

The updated packages have been upgraded to the 1.0.1m version where
these security flaws has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openssl.org/news/secadv_20150108.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openssl.org/news/secadv_20150319.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-engines1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64openssl-devel-1.0.1m-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64openssl-engines1.0.0-1.0.1m-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64openssl-static-devel-1.0.1m-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64openssl1.0.0-1.0.1m-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"openssl-1.0.1m-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
