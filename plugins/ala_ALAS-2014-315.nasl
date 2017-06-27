#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-315.
#

include("compat.inc");

if (description)
{
  script_id(73234);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-0022");
  script_xref(name:"ALAS", value:"2014-315");

  script_name(english:"Amazon Linux AMI : yum (ALAS-2014-315)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The installUpdates function in yum-cron/yum-cron.py in yum 3.4.3 and
earlier does not properly check the return value of the sigCheckPkg
function, which allows remote attackers to bypass the RMP package
signing restriction via an unsigned package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-315.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update yum' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-cron-daily");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-cron-hourly");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-cron-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/28");
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
if (rpm_check(release:"ALA", reference:"yum-3.4.3-137.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"yum-cron-3.4.3-137.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"yum-cron-daily-3.4.3-137.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"yum-cron-hourly-3.4.3-137.49.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"yum-cron-security-3.4.3-137.49.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "yum / yum-cron / yum-cron-daily / yum-cron-hourly / etc");
}
