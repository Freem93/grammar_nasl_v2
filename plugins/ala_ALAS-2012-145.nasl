#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-145.
#

include("compat.inc");

if (description)
{
  script_id(69635);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2012-5611");
  script_xref(name:"ALAS", value:"2012-145");
  script_xref(name:"RHSA", value:"2012:1551");

  script_name(english:"Amazon Linux AMI : mysql51 (ALAS-2012-145)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack-based buffer overflow flaw was found in the user permission
checking code in MySQL. An authenticated database user could use this
flaw to crash the mysqld daemon or, potentially, execute arbitrary
code with the privileges of the user running the mysqld daemon.
(CVE-2012-5611)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-145.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mysql51' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mysql51-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/06");
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
if (rpm_check(release:"ALA", reference:"mysql51-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-bench-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-common-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-debuginfo-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-devel-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-embedded-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-embedded-devel-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-libs-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-server-5.1.66-1.57.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mysql51-test-5.1.66-1.57.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql51 / mysql51-bench / mysql51-common / mysql51-debuginfo / etc");
}
