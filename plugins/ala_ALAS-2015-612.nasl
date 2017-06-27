#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-612.
#

include("compat.inc");

if (description)
{
  script_id(87016);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/11/24 14:17:20 $");

  script_cve_id("CVE-2015-6816");
  script_xref(name:"ALAS", value:"2015-612");

  script_name(english:"Amazon Linux AMI : ganglia (ALAS-2015-612)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ganglia-web auth can be bypassed using boolean serialization
(CVE-2015-6816)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-612.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ganglia' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ganglia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ganglia-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ganglia-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ganglia-gmetad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ganglia-gmond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ganglia-gmond-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ganglia-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
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
if (rpm_check(release:"ALA", reference:"ganglia-3.7.2-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ganglia-debuginfo-3.7.2-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ganglia-devel-3.7.2-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ganglia-gmetad-3.7.2-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ganglia-gmond-3.7.2-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ganglia-gmond-python-3.7.2-2.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ganglia-web-3.7.1-2.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ganglia / ganglia-debuginfo / ganglia-devel / ganglia-gmetad / etc");
}
