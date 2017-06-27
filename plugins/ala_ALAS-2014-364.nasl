#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-364.
#

include("compat.inc");

if (description)
{
  script_id(78307);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:55:42 $");

  script_cve_id("CVE-2014-2913");
  script_xref(name:"ALAS", value:"2014-364");

  script_name(english:"Amazon Linux AMI : nrpe (ALAS-2014-364)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"** DISPUTED ** Incomplete blacklist vulnerability in nrpe.c in Nagios
Remote Plugin Executor (NRPE) 2.15 and earlier allows remote attackers
to execute arbitrary commands via a newline character in the -a option
to libexec/check_nrpe. NOTE: this issue is disputed by multiple
parties. It has been reported that the vendor allows newlines as
'expected behavior.' Also, this issue can only occur when the
administrator enables the 'dont_blame_nrpe' option in nrpe.conf
despite the 'HIGH security risk' warning within the comments."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-364.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update nrpe' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nagios-plugins-nrpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nrpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nrpe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
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
if (rpm_check(release:"ALA", reference:"nagios-plugins-nrpe-2.15-2.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nrpe-2.15-2.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nrpe-debuginfo-2.15-2.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nagios-plugins-nrpe / nrpe / nrpe-debuginfo");
}
