#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-741.
#

include("compat.inc");

if (description)
{
  script_id(93253);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/24 13:45:58 $");

  script_cve_id("CVE-2016-1000110");
  script_xref(name:"ALAS", value:"2016-741");

  script_name(english:"Amazon Linux AMI : python34 / python27,python26 (ALAS-2016-741) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Python CGIHandler class did not properly
protect against the HTTP_PROXY variable name clash in a CGI context. A
remote attacker could possibly use this flaw to redirect HTTP requests
performed by a Python CGI script to an attacker-controlled proxy via a
malicious HTTP request."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-741.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update python34' to update your system.

Run 'yum update python27' to update your system.

Run 'yum update python26' to update your system."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python26-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python34-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"python26-2.6.9-2.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-debuginfo-2.6.9-2.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-devel-2.6.9-2.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-libs-2.6.9-2.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-test-2.6.9-2.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-tools-2.6.9-2.88.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-2.7.12-2.120.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-debuginfo-2.7.12-2.120.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-devel-2.7.12-2.120.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libs-2.7.12-2.120.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-test-2.7.12-2.120.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-tools-2.7.12-2.120.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-3.4.3-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-debuginfo-3.4.3-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-devel-3.4.3-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-libs-3.4.3-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-test-3.4.3-1.33.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-tools-3.4.3-1.33.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python26 / python26-debuginfo / python26-devel / python26-libs / etc");
}
