#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-550.
#

include("compat.inc");

if (description)
{
  script_id(84251);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2014-8176", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-3216", "CVE-2015-4000");
  script_xref(name:"ALAS", value:"2015-550");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2015-550) (Logjam)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"LOGJAM: A flaw was found in the way the TLS protocol composes the
Diffie-Hellman exchange (for both export and non-export grade cipher
suites). An attacker could use this flaw to downgrade a DHE connection
to use export-grade key sizes, which could then be broken by
sufficient pre-computation. This can lead to a passive
man-in-the-middle attack in which the attacker is able to decrypt all
traffic. (CVE-2015-4000)

An out-of-bounds read flaw was found in the X509_cmp_time() function
of OpenSSL, which is used to test the expiry dates of SSL/TLS
certificates. An attacker could possibly use a specially crafted
SSL/TLS certificate or CRL (Certificate Revocation List), which when
parsed by an application would cause that application to crash.
(CVE-2015-1789)

A NULL pointer dereference was found in the way OpenSSL handled
certain PKCS#7 inputs. An attacker able to make an application using
OpenSSL verify, decrypt, or parse a specially crafted PKCS#7 input
could cause that application to crash. TLS/SSL clients and servers
using OpenSSL were not affected by this flaw. (CVE-2015-1790)

A race condition was found in the session handling code of OpenSSL. An
attacker could cause a multi-threaded SSL/TLS server to crash.
(CVE-2015-1791)

A denial of service flaw was found in OpenSSL in the way it verified
certain signed messages using CMS (Cryptographic Message Syntax). A
remote attacker could cause an application using OpenSSL to use
excessive amounts of memory by sending a specially crafted message for
verification. (CVE-2015-1792)

An invalid-free flaw was found in the way OpenSSL handled certain DTLS
handshake messages. A malicious DTLS client or server could send a
specially crafted message to the peer, which could cause the
application to crash or potentially cause arbitrary code execution.
(CVE-2014-8176)

A regression was found in the ssleay_rand_bytes() function. This could
lead a multi-threaded application to crash. (CVE-2015-3216)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-550.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openssl-1.0.1k-10.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.1k-10.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.1k-10.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.1k-10.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.1k-10.86.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
