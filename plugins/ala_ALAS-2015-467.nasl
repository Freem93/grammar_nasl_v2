#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-467.
#

include("compat.inc");

if (description)
{
  script_id(80418);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2004-2771", "CVE-2014-7844");
  script_xref(name:"ALAS", value:"2015-467");
  script_xref(name:"RHSA", value:"2014:1999");

  script_name(english:"Amazon Linux AMI : mailx (ALAS-2015-467)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way mailx handled the parsing of email
addresses. A syntactically valid email address could allow a local
attacker to cause mailx to execute arbitrary shell commands through
shell meta-characters and the direct command execution functionality.
(CVE-2004-2771 , CVE-2014-7844)

Note: Applications using mailx to send email to addresses obtained
from untrusted sources will still remain vulnerable to other attacks
if they accept email addresses which start with '-' (so that they can
be confused with mailx options). To counteract this issue, this update
also introduces the '--' option, which will treat the remaining
command line arguments as email addresses."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-467.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mailx' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mailx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mailx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/09");
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
if (rpm_check(release:"ALA", reference:"mailx-12.4-8.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mailx-debuginfo-12.4-8.8.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mailx / mailx-debuginfo");
}
