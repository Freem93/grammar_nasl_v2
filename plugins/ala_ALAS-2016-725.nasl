#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-725.
#

include("compat.inc");

if (description)
{
  script_id(92472);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/16 16:05:32 $");

  script_cve_id("CVE-2016-5387");
  script_xref(name:"ALAS", value:"2016-725");
  script_xref(name:"IAVA", value:"2017-A-0010");

  script_name(english:"Amazon Linux AMI : httpd24 / httpd (ALAS-2016-725) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that httpd used the value of the Proxy header from
HTTP requests to initialize the HTTP_PROXY environment variable for
CGI scripts, which in turn was incorrectly used by certain HTTP client
implementations to configure the proxy for outgoing HTTP requests. A
remote attacker could possibly use this flaw to redirect HTTP requests
performed by a CGI script to an attacker-controlled proxy via a
malicious HTTP request (known as the 'httpoxy' class of
vulnerabilities)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://httpoxy.org/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-725.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update httpd24' to update your system.

Run 'yum update httpd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"httpd-2.2.31-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-debuginfo-2.2.31-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-devel-2.2.31-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-manual-2.2.31-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-tools-2.2.31-1.8.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-debuginfo-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-devel-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-manual-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-tools-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ldap-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_proxy_html-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_session-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ssl-2.4.23-1.65.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_ssl-2.2.31-1.8.amzn1")) flag++;

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
