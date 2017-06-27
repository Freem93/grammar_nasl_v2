#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-794.
#

include("compat.inc");

if (description)
{
  script_id(97024);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/02/07 14:52:10 $");

  script_cve_id("CVE-2016-8734");
  script_xref(name:"ALAS", value:"2017-794");

  script_name(english:"Amazon Linux AMI : subversion / mod_dav_svn (ALAS-2017-794)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Subversion's mod_dontdothat module and
Subversion clients using http(s):// are vulnerable to a
denial-of-service attack caused by exponential XML entity expansion.
An authenticated remote attacker can cause denial-of-service
conditions on the server using mod_dontdothat by sending a specially
crafted REPORT request. The attack does not require access to a
particular repository."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-794.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update subversion' to update your system.

Run 'yum update mod_dav_svn' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_dav_svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/07");
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
if (rpm_check(release:"ALA", reference:"mod24_dav_svn-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_dav_svn-1.9.5-2.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_dav_svn-debuginfo-1.9.5-2.53.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-debuginfo-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-devel-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-javahl-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-libs-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-perl-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python26-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python27-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-ruby-1.9.5-1.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-tools-1.9.5-1.56.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod24_dav_svn / mod_dav_svn / mod_dav_svn-debuginfo / subversion / etc");
}
