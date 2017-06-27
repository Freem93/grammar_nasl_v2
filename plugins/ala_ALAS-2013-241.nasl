#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-241.
#

include("compat.inc");

if (description)
{
  script_id(70903);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/25 13:16:45 $");

  script_cve_id("CVE-2013-1752", "CVE-2013-4238");
  script_xref(name:"ALAS", value:"2013-241");

  script_name(english:"Amazon Linux AMI : python26 (ALAS-2013-241)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that multiple Python standard library modules
implementing network protocols (such as httplib or smtplib) failed to
restrict sizes of server responses. A malicious server could cause a
client using one of the affected modules to consume an excessive
amount of memory. (CVE-2013-1752)

The ssl.match_hostname function in the SSL module in Python 2.6
through 3.4 does not properly handle a '\0' character in a domain name
in the Subject Alternative Name field of an X.509 certificate, which
allows man-in-the-middle attackers to spoof arbitrary SSL servers via
a crafted certificate issued by a legitimate Certification Authority,
a related issue to CVE-2009-2408 . (CVE-2013-4238)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-241.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python26' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/14");
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
if (rpm_check(release:"ALA", reference:"python26-2.6.9-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-debuginfo-2.6.9-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-devel-2.6.9-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-libs-2.6.9-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-test-2.6.9-1.40.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-tools-2.6.9-1.40.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python26 / python26-debuginfo / python26-devel / python26-libs / etc");
}
