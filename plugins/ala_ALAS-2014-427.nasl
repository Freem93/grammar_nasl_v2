#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-427.
#

include("compat.inc");

if (description)
{
  script_id(78485);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-3513", "CVE-2014-3567", "CVE-2014-3568");
  script_xref(name:"ALAS", value:"2014-427");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2014-427)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A memory leak flaw was found in the way OpenSSL parsed the DTLS Secure
Real-time Transport Protocol (SRTP) extension data. A remote attacker
could send multiple specially crafted handshake messages to exhaust
all available memory of an SSL/TLS or DTLS server. (CVE-2014-3513)

A memory leak flaw was found in the way an OpenSSL handled failed
session ticket integrity checks. A remote attacker could exhaust all
available memory of an SSL/TLS or DTLS server by sending a large
number of invalid session tickets to that server. (CVE-2014-3567)

When OpenSSL is configured with 'no-ssl3' as a build option, servers
could accept and complete a SSL 3.0 handshake, and clients could be

configured to send them. (CVE-2014-3568)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-427.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update openssl' to update your system. Note that you may need
to run 'yum clean all' first."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/16");
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
if (rpm_check(release:"ALA", reference:"openssl-1.0.1j-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.1j-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.1j-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.1j-1.80.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.1j-1.80.amzn1")) flag++;

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
