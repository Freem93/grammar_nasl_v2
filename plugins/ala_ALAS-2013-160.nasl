#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-160.
#

include("compat.inc");

if (description)
{
  script_id(69719);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2011-3148", "CVE-2011-3149");
  script_xref(name:"ALAS", value:"2013-160");
  script_xref(name:"RHSA", value:"2013:0521");

  script_name(english:"Amazon Linux AMI : pam (ALAS-2013-160)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack-based buffer overflow flaw was found in the way the pam_env
module parsed users' '~/.pam_environment' files. If an application's
PAM configuration contained 'user_readenv=1' (this is not the
default), a local attacker could use this flaw to crash the
application or, possibly, escalate their privileges. (CVE-2011-3148)

A denial of service flaw was found in the way the pam_env module
expanded certain environment variables. If an application's PAM
configuration contained 'user_readenv=1' (this is not the default), a
local attacker could use this flaw to cause the application to enter
an infinite loop. (CVE-2011-3149)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-160.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update pam' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/02");
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
if (rpm_check(release:"ALA", reference:"pam-1.1.1-13.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam-debuginfo-1.1.1-13.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam-devel-1.1.1-13.20.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam / pam-debuginfo / pam-devel");
}
