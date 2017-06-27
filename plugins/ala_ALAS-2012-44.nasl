#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-44.
#

include("compat.inc");

if (description)
{
  script_id(69651);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0490", "CVE-2012-0492");
  script_xref(name:"ALAS", value:"2012-44");
  script_xref(name:"RHSA", value:"2012:0105");

  script_name(english:"Amazon Linux AMI : mysql (ALAS-2012-44)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several vulnerabilities in the MySQL database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2011-2262 , CVE-2012-0075 , CVE-2012-0087 , CVE-2012-0101 ,
CVE-2012-0102 , CVE-2012-0112 , CVE-2012-0113 , CVE-2012-0114 ,
CVE-2012-0115 , CVE-2012-0116 , CVE-2012-0118 , CVE-2012-0119 ,
CVE-2012-0120 , CVE-2012-0484 , CVE-2012-0485 , CVE-2012-0490 ,
CVE-2012-0492)

These updated packages upgrade MySQL to version 5.1.61. Refer to the
MySQL release notes for a full list of changes :"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-44.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
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
if (rpm_check(release:"ALA", reference:"mysql-5.1.61-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql-bench-5.1.61-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql-debuginfo-5.1.61-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql-devel-5.1.61-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql-embedded-5.1.61-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql-embedded-devel-5.1.61-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql-libs-5.1.61-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql-server-5.1.61-1.27.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql-test-5.1.61-1.27.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-debuginfo / mysql-devel / etc");
}
