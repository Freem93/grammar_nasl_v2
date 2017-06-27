#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-765.
#

include("compat.inc");

if (description)
{
  script_id(94685);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/01/23 15:31:52 $");

  script_cve_id("CVE-2016-7545");
  script_xref(name:"ALAS", value:"2016-765");

  script_name(english:"Amazon Linux AMI : policycoreutils (ALAS-2016-765)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the sandbox tool provided in policycoreutils was
vulnerable to a TIOCSTI ioctl attack. A specially crafted program
executed via the sandbox command could use this flaw to execute
arbitrary commands in the context of the parent bash, escaping the
sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-765.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update policycoreutils' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-newrole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:policycoreutils-restorecond");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"policycoreutils-2.1.12-5.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"policycoreutils-debuginfo-2.1.12-5.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"policycoreutils-newrole-2.1.12-5.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"policycoreutils-python-2.1.12-5.25.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"policycoreutils-restorecond-2.1.12-5.25.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "policycoreutils / policycoreutils-debuginfo / etc");
}
