#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-61.
#

include("compat.inc");

if (description)
{
  script_id(69668);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-0060");
  script_xref(name:"ALAS", value:"2012-61");
  script_xref(name:"RHSA", value:"2012:0451");

  script_name(english:"Amazon Linux AMI : rpm (ALAS-2012-61)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple flaws were found in the way RPM parsed package file headers.
An attacker could create a specially crafted RPM package that, when
its package header was accessed, or during package signature
verification, could cause an application using the RPM library (such
as the rpm command line tool, or the yum and up2date package managers)
to crash or, potentially, execute arbitrary code. (CVE-2012-0060 ,
CVE-2012-0061 , CVE-2012-0815)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-61.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update rpm' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rpm-python");
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
if (rpm_check(release:"ALA", reference:"rpm-4.8.0-19.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-apidocs-4.8.0-19.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-build-4.8.0-19.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-cron-4.8.0-19.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-debuginfo-4.8.0-19.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-devel-4.8.0-19.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-libs-4.8.0-19.38.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rpm-python-4.8.0-19.38.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rpm / rpm-apidocs / rpm-build / rpm-cron / rpm-debuginfo / etc");
}
