#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-391.
#

include("compat.inc");

if (description)
{
  script_id(78334);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511", "CVE-2014-3512", "CVE-2014-5139");
  script_xref(name:"ALAS", value:"2014-391");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2014-391)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was discovered in the way OpenSSL handled DTLS packets. A
remote attacker could use this flaw to cause a DTLS server or client
using OpenSSL to crash or use excessive amounts of memory.

Multiple buffer overflows in crypto/srp/srp_lib.c in the SRP
implementation in OpenSSL 1.0.1 before 1.0.1i allow remote attackers
to cause a denial of service (application crash) or possibly have
unspecified other impact via an invalid SRP (1) g, (2) A, or (3) B
parameter.

A flaw was found in the way OpenSSL handled fragmented handshake
packets. A man-in-the-middle attacker could use this flaw to force a
TLS/SSL server using OpenSSL to use TLS 1.0, even if both the client
and the server supported newer protocol versions.

A NULL pointer dereference flaw was found in the way OpenSSL performed
a handshake when using the anonymous Diffie-Hellman (DH) key exchange.
A malicious server could cause a DTLS client using OpenSSL to crash if
that client had anonymous DH cipher suites enabled.

It was discovered that the OBJ_obj2txt() function could fail to
properly NUL-terminate its output. This could possibly cause an
application using OpenSSL functions to format fields of X.509
certificates to disclose portions of its memory.

A race condition was found in the way OpenSSL handled ServerHello
messages with an included Supported EC Point Format extension. A
malicious server could possibly use this flaw to cause a
multi-threaded TLS/SSL client using OpenSSL to write into freed
memory, causing the client to crash or execute arbitrary code.

The ssl_set_client_disabled function in t1_lib.c in OpenSSL 1.0.1
before 1.0.1i allows remote SSL servers to cause a denial of service
(NULL pointer dereference and client application crash) via a
ServerHello message that includes an SRP ciphersuite without the
required negotiation of that ciphersuite with the client."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-391.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openssl-1.0.1i-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.1i-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.1i-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.1i-1.78.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.1i-1.78.amzn1")) flag++;

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
