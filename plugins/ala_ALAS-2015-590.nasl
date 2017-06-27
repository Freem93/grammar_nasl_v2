#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-590.
#

include("compat.inc");

if (description)
{
  script_id(85748);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/03 13:42:47 $");

  script_cve_id("CVE-2015-5621");
  script_xref(name:"ALAS", value:"2015-590");
  script_xref(name:"RHSA", value:"2015:1636");

  script_name(english:"Amazon Linux AMI : net-snmp (ALAS-2015-590)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the snmp_pdu_parse() function could leave
incompletely parsed varBind variables in the list of variables. A
remote, unauthenticated attacker could use this flaw to crash snmpd
or, potentially, execute arbitrary code on the system with the
privileges of the user running snmpd. (CVE-2015-5621)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-590.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update net-snmp' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:net-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
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
if (rpm_check(release:"ALA", reference:"net-snmp-5.5-54.1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"net-snmp-debuginfo-5.5-54.1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"net-snmp-devel-5.5-54.1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"net-snmp-libs-5.5-54.1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"net-snmp-perl-5.5-54.1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"net-snmp-python-5.5-54.1.20.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"net-snmp-utils-5.5-54.1.20.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp / net-snmp-debuginfo / net-snmp-devel / net-snmp-libs / etc");
}
