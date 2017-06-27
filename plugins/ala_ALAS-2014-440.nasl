#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-440.
#

include("compat.inc");

if (description)
{
  script_id(78873);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-4650", "CVE-2014-7185");
  script_xref(name:"ALAS", value:"2014-440");

  script_name(english:"Amazon Linux AMI : python27 (ALAS-2014-440)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Python built-in module CGIHTTPServer does not
properly handle URL-encoded path separators in URLs which may enable
attackers to disclose a CGI script's source code or execute arbitrary
scripts in the server's document root. (CVE-2014-4650)

Integer overflow in bufferobject.c in Python before 2.7.8 allows
context-dependent attackers to obtain sensitive information from
process memory via a large size and offset in a 'buffer' function.
(CVE-2014-7185)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.python.org/issue21766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-440.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python27' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");
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
if (rpm_check(release:"ALA", reference:"python27-2.7.8-6.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-debuginfo-2.7.8-6.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-devel-2.7.8-6.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libs-2.7.8-6.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-test-2.7.8-6.74.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-tools-2.7.8-6.74.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python27 / python27-debuginfo / python27-devel / python27-libs / etc");
}
