#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-428.
#

include("compat.inc");

if (description)
{
  script_id(78558);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6500", "CVE-2014-6559");
  script_xref(name:"ALAS", value:"2014-428");

  script_name(english:"Amazon Linux AMI : mysql55 (ALAS-2014-428)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: SERVER:SSL:yaSSL). Supported versions that are affected
are 5.5.39 and earlier and 5.6.20 and earlier. Easily exploitable
vulnerability allows successful unauthenticated network attacks via
multiple protocols. Successful attack of this vulnerability can result
in unauthorized takeover of MySQL Server possibly including arbitrary
code execution within the MySQL Server. (CVE-2014-6491)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: C API SSL CERTIFICATE HANDLING). Supported versions
that are affected are 5.5.39 and earlier and 5.6.20 and earlier.
Difficult to exploit vulnerability allows successful unauthenticated
network attacks via multiple protocols. Successful attack of this
vulnerability can result in unauthorized read access to all MySQL
Server accessible data. (CVE-2014-6559)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: SERVER:SSL:yaSSL). Supported versions that are affected
are 5.5.39 and earlier and 5.6.20 and earlier. Easily exploitable
vulnerability allows successful unauthenticated network attacks via
multiple protocols. Successful attack of this vulnerability can result
in unauthorized takeover of MySQL Server possibly including arbitrary
code execution within the MySQL Server. (CVE-2014-6500)

Vulnerability in the MySQL Server component of Oracle MySQL
(subcomponent: CLIENT:SSL:yaSSL). Supported versions that are affected
are 5.5.39 and earlier and 5.6.20 and earlier. Difficult to exploit
vulnerability allows successful unauthenticated network attacks via
multiple protocols. Successful attack of this vulnerability can result
in unauthorized ability to cause a hang or frequently repeatable crash
(complete DOS) of MySQL Server. (CVE-2014-6494)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-428.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql55' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql55-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/20");
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
if (rpm_check(release:"ALA", reference:"mysql55-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-bench-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-common-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-debuginfo-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-devel-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-embedded-devel-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-libs-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-server-5.5.40-1.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql55-test-5.5.40-1.3.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql55 / mysql55-bench / mysql55-common / mysql55-debuginfo / etc");
}
