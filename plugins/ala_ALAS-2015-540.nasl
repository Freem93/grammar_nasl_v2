#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-540.
#

include("compat.inc");

if (description)
{
  script_id(84128);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/12 14:38:59 $");

  script_cve_id("CVE-2014-9092");
  script_xref(name:"ALAS", value:"2015-540");

  script_name(english:"Amazon Linux AMI : libjpeg-turbo (ALAS-2015-540)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw in libjpeg-turbo was reported that could lead to a local denial
of service when processing a specially crafted JPEG issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2014/q4/557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-540.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libjpeg-turbo' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libjpeg-turbo-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:turbojpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:turbojpeg-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");
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
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-1.2.90-5.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-debuginfo-1.2.90-5.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-devel-1.2.90-5.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-static-1.2.90-5.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libjpeg-turbo-utils-1.2.90-5.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"turbojpeg-1.2.90-5.10.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"turbojpeg-devel-1.2.90-5.10.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjpeg-turbo / libjpeg-turbo-debuginfo / libjpeg-turbo-devel / etc");
}
