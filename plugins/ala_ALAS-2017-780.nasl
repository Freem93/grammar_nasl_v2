#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-780.
#

include("compat.inc");

if (description)
{
  script_id(96282);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/26 13:35:46 $");

  script_cve_id("CVE-2016-7032", "CVE-2016-7076");
  script_xref(name:"ALAS", value:"2017-780");

  script_name(english:"Amazon Linux AMI : sudo (ALAS-2017-780)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the sudo noexec restriction could have been
bypassed if application run via sudo executed system() or popen() C
library functions with a user supplied argument. A local user
permitted to run such application via sudo with noexec restriction
could use this flaw to execute arbitrary commands with elevated
privileges. (CVE-2016-7032)

It was discovered that the sudo noexec restriction could have been
bypassed if application run via sudo executed wordexp() C library
function with a user supplied argument. A local user permitted to run
such application via sudo with noexec restriction could possibly use
this flaw to execute arbitrary commands with elevated privileges.
(CVE-2016-7076)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-780.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update sudo' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sudo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sudo-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"sudo-1.8.6p3-25.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sudo-debuginfo-1.8.6p3-25.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sudo-devel-1.8.6p3-25.23.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo / sudo-debuginfo / sudo-devel");
}
