#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-724.
#

include("compat.inc");

if (description)
{
  script_id(92471);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/07 15:17:41 $");

  script_cve_id("CVE-2016-0772", "CVE-2016-5636", "CVE-2016-5699");
  script_xref(name:"ALAS", value:"2016-724");

  script_name(english:"Amazon Linux AMI : python26 / python27,python34 (ALAS-2016-724)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that Python's httplib library (used urllib, urllib2 and
others) did not properly check HTTP header input in
HTTPConnection.putheader(). An attacker could use this flow to inject
additional headers in a Python application that allows user provided
header name or values. (CVE-2016-5699)

It was found that Python's smtplib library did not return an exception
if StartTLS fails to establish correctly in the SMTP.starttls()
function. An attacker with ability to launch an active man in the
middle attack could strip out the STARTTLS command without generating
an exception on the python SMTP client application, preventing the
establishment of the TLS layer. (CVE-2016-0772)

A vulnerability was discovered in Python, in the built-in zipimporter.
A specially crafted zip file placed in a module path such that it
would be loaded by a later 'import' statement could cause a heap
overflow, leading to arbitrary code execution. (CVE-2016-5636)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-724.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update python26' to update your system.

Run 'yum update python27' to update your system.

Run 'yum update python34' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/21");
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
if (rpm_check(release:"ALA", reference:"python26-2.6.9-2.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-debuginfo-2.6.9-2.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-devel-2.6.9-2.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-libs-2.6.9-2.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-test-2.6.9-2.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python26-tools-2.6.9-2.86.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-2.7.10-4.122.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-debuginfo-2.7.10-4.122.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-devel-2.7.10-4.122.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libs-2.7.10-4.122.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-test-2.7.10-4.122.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-tools-2.7.10-4.122.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-3.4.3-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-debuginfo-3.4.3-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-devel-3.4.3-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-libs-3.4.3-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-test-3.4.3-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python34-tools-3.4.3-1.32.amzn1")) flag++;

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
