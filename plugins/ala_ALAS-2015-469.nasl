#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-469.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80461);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/10/22 14:14:48 $");

  script_cve_id("CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206");
  script_xref(name:"ALAS", value:"2015-469");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2015-469) (FREAK)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k
allows remote attackers to cause a denial of service (NULL pointer
dereference and application crash) via a crafted DTLS message that is
processed with a different read operation for the handshake header
than for the handshake body, related to the dtls1_get_record function
in d1_pkt.c and the ssl3_read_n function in s3_pkt.c.

The BN_sqr implementation in OpenSSL before 0.9.8zd, 1.0.0 before
1.0.0p, and 1.0.1 before 1.0.1k does not properly calculate the square
of a BIGNUM value, which might make it easier for remote attackers to
defeat cryptographic protection mechanisms via unspecified vectors,
related to crypto/bn/asm/mips.pl, crypto/bn/asm/x86_64-gcc.c, and
crypto/bn/bn_asm.c.

The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before
0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote
SSL servers to conduct ECDHE-to-ECDH downgrade attacks and trigger a
loss of forward secrecy by omitting the ServerKeyExchange message.

The ssl23_get_client_hello function in s23_srvr.c in OpenSSL 0.9.8zc,
1.0.0o, and 1.0.1j does not properly handle attempts to use
unsupported protocols, which allows remote attackers to cause a denial
of service (NULL pointer dereference and daemon crash) via an
unexpected handshake, as demonstrated by an SSLv3 handshake to a
no-ssl3 application with certain error handling. NOTE: this issue
became relevant after the CVE-2014-3568 fix.

OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k
does not enforce certain constraints on certificate data, which allows
remote attackers to defeat a fingerprint-based certificate-blacklist
protection mechanism by including crafted data within a certificate's
unsigned portion, related to crypto/asn1/a_verify.c,
crypto/dsa/dsa_asn1.c, crypto/ecdsa/ecs_vrf.c, and
crypto/x509/x_all.c.

The ssl3_get_cert_verify function in s3_srvr.c in OpenSSL 1.0.0 before
1.0.0p and 1.0.1 before 1.0.1k accepts client authentication with a
Diffie-Hellman (DH) certificate without requiring a CertificateVerify
message, which allows remote attackers to obtain access without
knowledge of a private key via crafted TLS Handshake Protocol traffic
to a server that recognizes a Certification Authority with DH support.

The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before
0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote
SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and
facilitate brute-force decryption by offering a weak ephemeral RSA key
in a noncompliant role.

Memory leak in the dtls1_buffer_record function in d1_pkt.c in OpenSSL
1.0.0 before 1.0.0p and 1.0.1 before 1.0.1k allows remote attackers to
cause a denial of service (memory consumption) by sending many
duplicate records for the next epoch, leading to failure of replay
detection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-469.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"openssl-1.0.1k-1.82.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.1k-1.82.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.1k-1.82.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.1k-1.82.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.1k-1.82.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
