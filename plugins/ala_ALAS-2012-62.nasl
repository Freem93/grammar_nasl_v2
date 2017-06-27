#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-62.
#

include("compat.inc");

if (description)
{
  script_id(69669);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-0884", "CVE-2012-1165");
  script_xref(name:"ALAS", value:"2012-62");
  script_xref(name:"RHSA", value:"2012:0426");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2012-62)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference flaw was found in the way OpenSSL parsed
Secure/Multipurpose Internet Mail Extensions (S/MIME) messages. An
attacker could use this flaw to crash an application that uses OpenSSL
to decrypt or verify S/MIME messages. (CVE-2012-1165)

A flaw was found in the PKCS#7 and Cryptographic Message Syntax (CMS)
implementations in OpenSSL. An attacker could possibly use this flaw
to perform a Bleichenbacher attack to decrypt an encrypted CMS,
PKCS#7, or S/MIME message by sending a large number of chosen
ciphertext messages to a service using OpenSSL and measuring error
response times. (CVE-2012-0884)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-62.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openssl-1.0.0g-2.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.0g-2.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.0g-2.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.0g-2.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.0g-2.39.amzn1")) flag++;

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
