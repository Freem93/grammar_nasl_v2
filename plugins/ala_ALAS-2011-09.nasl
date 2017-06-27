#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-09.
#

include("compat.inc");

if (description)
{
  script_id(69568);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-3348", "CVE-2011-3368");
  script_xref(name:"ALAS", value:"2011-09");
  script_xref(name:"RHSA", value:"2011:1391");

  script_name(english:"Amazon Linux AMI : httpd (ALAS-2011-09)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The MITRE CVE database describes these CVEs as :

The mod_proxy module in the Apache HTTP Server 1.3.x through 1.3.42,
2.0.x through 2.0.64, and 2.2.x through 2.2.21 does not properly
interact with use of (1) RewriteRule and (2) ProxyPassMatch pattern
matches for configuration of a reverse proxy, which allows remote
attackers to send requests to intranet servers via a malformed URI
containing an initial @ (at sign) character. 

The mod_proxy_ajp module in the Apache HTTP Server before 2.2.21, when
used with mod_proxy_balancer in certain configurations, allows remote
attackers to cause a denial of service (temporary 'error state' in the
backend server) via a malformed HTTP request.

It was discovered that the Apache HTTP Server did not properly
validate the request URI for proxied requests. In certain
configurations, if a reverse proxy used the ProxyPassMatch directive,
or if it used the RewriteRule directive with the proxy flag, a remote
attacker could make the proxy connect to an arbitrary server, possibly
disclosing sensitive information from internal web servers not
directly accessible to the attacker.

It was discovered that mod_proxy_ajp incorrectly returned an 'Internal
Server Error' response when processing certain malformed HTTP
requests, which caused the back-end server to be marked as failed in
configurations where mod_proxy was used in load balancer mode. A
remote attacker could cause mod_proxy to not send requests to back-end
AJP (Apache JServ Protocol) servers for the retry timeout period or
until all back-end servers were marked as failed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-9.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum upgrade httpd' to upgrade your system. Then run 'service
httpd restart' to restart the Apache HTTP Server."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/31");
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
if (rpm_check(release:"ALA", reference:"httpd-2.2.21-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-debuginfo-2.2.21-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-devel-2.2.21-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-manual-2.2.21-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd-tools-2.2.21-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod_ssl-2.2.21-1.19.amzn1")) flag++;

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
