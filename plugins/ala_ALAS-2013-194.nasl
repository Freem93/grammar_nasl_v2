#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-194.
#

include("compat.inc");

if (description)
{
  script_id(69752);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2012-3499", "CVE-2012-4558", "CVE-2013-1862");
  script_xref(name:"ALAS", value:"2013-194");
  script_xref(name:"RHSA", value:"2013:0815");

  script_name(english:"Amazon Linux AMI : httpd24 (ALAS-2013-194)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Cross-site scripting (XSS) flaws were found in the mod_proxy_balancer
module's manager web interface. If a remote attacker could trick a
user, who was logged into the manager web interface, into visiting a
specially crafted URL, it would lead to arbitrary web script execution
in the context of the user's manager interface session.
(CVE-2012-4558)

It was found that mod_rewrite did not filter terminal escape sequences
from its log file. If mod_rewrite was configured with the RewriteLog
directive, a remote attacker could use specially crafted HTTP requests
to inject terminal escape sequences into the mod_rewrite log file. If
a victim viewed the log file with a terminal emulator, it could result
in arbitrary command execution with the privileges of that user.
(CVE-2013-1862)

Cross-site scripting (XSS) flaws were found in the mod_info,
mod_status, mod_imagemap, mod_ldap, and mod_proxy_ftp modules. An
attacker could possibly use these flaws to perform XSS attacks if they
were able to make the victim's browser generate an HTTP request with a
specially crafted Host header. (CVE-2012-3499)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-194.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update httpd24' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/24");
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
if (rpm_check(release:"ALA", reference:"httpd24-2.4.4-2.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-debuginfo-2.4.4-2.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-devel-2.4.4-2.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-manual-2.4.4-2.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-tools-2.4.4-2.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ldap-2.4.4-2.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_proxy_html-2.4.4-2.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_session-2.4.4-2.46.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ssl-2.4.4-2.46.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd24 / httpd24-debuginfo / httpd24-devel / httpd24-manual / etc");
}
