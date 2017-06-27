#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-123.
#

include("compat.inc");

if (description)
{
  script_id(69613);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871");
  script_xref(name:"ALAS", value:"2012-123");
  script_xref(name:"RHSA", value:"2012:1265");

  script_name(english:"Amazon Linux AMI : libxslt (ALAS-2012-123)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow flaw was found in the way libxslt applied
templates to nodes selected by certain namespaces. An attacker could
use this flaw to create a malicious XSL file that, when used by an
application linked against libxslt to perform an XSL transformation,
could cause the application to crash or, possibly, execute arbitrary
code with the privileges of the user running the application.
(CVE-2012-2871)

Several denial of service flaws were found in libxslt. An attacker
could use these flaws to create a malicious XSL file that, when used
by an application linked against libxslt to perform an XSL
transformation, could cause the application to crash. (CVE-2012-2825 ,
CVE-2012-2870 , CVE-2011-3970)

An information leak could occur if an application using libxslt
processed an untrusted XPath expression, or used a malicious XSL file
to perform an XSL transformation. If combined with other flaws, this
leak could possibly help an attacker bypass intended memory corruption
protections. (CVE-2011-1202)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-123.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libxslt' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxslt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/22");
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
if (rpm_check(release:"ALA", reference:"libxslt-1.1.26-2.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxslt-debuginfo-1.1.26-2.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxslt-devel-1.1.26-2.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libxslt-python-1.1.26-2.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt / libxslt-debuginfo / libxslt-devel / libxslt-python");
}
