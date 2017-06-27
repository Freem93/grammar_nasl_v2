#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-46.
#

include("compat.inc");

if (description)
{
  script_id(69653);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2011-3607", "CVE-2011-3639", "CVE-2012-0031", "CVE-2012-0053");
  script_xref(name:"ALAS", value:"2012-46");
  script_xref(name:"RHSA", value:"2012:0128");

  script_name(english:"Amazon Linux AMI : httpd (ALAS-2012-46)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the fix for CVE-2011-3368 did not completely
address the problem. An attacker could bypass the fix and make a
reverse proxy connect to an arbitrary server not directly accessible
to the attacker by sending an HTTP version 0.9 request, or by using a
specially crafted URI. (CVE-2011-3639 , CVE-2011-4317)

The httpd server included the full HTTP header line in the default
error page generated when receiving an excessively long or malformed
header. Malicious JavaScript running in the server's domain context
could use this flaw to gain access to httpOnly cookies.
(CVE-2012-0053)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way httpd performed substitutions in regular expressions.
An attacker able to set certain httpd settings, such as a user
permitted to override the httpd configuration for a specific directory
using a '.htaccess' file, could use this flaw to crash the httpd child
process or, possibly, execute arbitrary code with the privileges of
the 'apache' user. (CVE-2011-3607)

A flaw was found in the way httpd handled child process status
information. A malicious program running with httpd child process
privileges (such as a PHP or CGI script) could use this flaw to cause
the parent httpd process to crash during httpd service shutdown.
(CVE-2012-0031)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-46.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update httpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-410");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
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
if (rpm_check(release:"ALA", reference:"httpd-2.2.22-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-debuginfo-2.2.22-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-devel-2.2.22-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-manual-2.2.22-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-tools-2.2.22-1.23.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_ssl-2.2.22-1.23.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
}
