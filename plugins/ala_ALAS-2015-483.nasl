#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-483.
#

include("compat.inc");

if (description)
{
  script_id(81329);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/26 04:39:24 $");

  script_cve_id("CVE-2013-5704", "CVE-2014-3581", "CVE-2014-3583", "CVE-2014-8109");
  script_xref(name:"ALAS", value:"2015-483");

  script_name(english:"Amazon Linux AMI : httpd24 (ALAS-2015-483)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mod_lua.c in the mod_lua module in the Apache HTTP Server 2.3.x and
2.4.x through 2.4.10 does not support an httpd configuration in which
the same Lua authorization provider is used with different arguments
within different contexts, which allows remote attackers to bypass
intended access restrictions in opportunistic circumstances by
leveraging multiple Require directives, as demonstrated by a
configuration that specifies authorization for one group to access a
certain directory, and authorization for a second group to access a
second directory. (CVE-2014-8109)

A flaw was found in the way httpd handled HTTP Trailer headers when
processing requests using chunked encoding. A malicious client could
use Trailer headers to set additional HTTP headers after header
processing was performed by other modules. This could, for example,
lead to a bypass of header restrictions defined with mod_headers.
(CVE-2013-5704)

A NULL pointer dereference flaw was found in the way the mod_cache
httpd module handled Content-Type headers. A malicious HTTP server
could cause the httpd child process to crash when the Apache HTTP
server was configured to proxy to a server with caching enabled.
(CVE-2014-3581)

The handle_headers function in mod_proxy_fcgi.c in the mod_proxy_fcgi
module in the Apache HTTP Server 2.4.10 allows remote FastCGI servers
to cause a denial of service (buffer over-read and daemon crash) via
long response headers. (CVE-2014-3583)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-483.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update httpd24' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"httpd24-2.4.10-15.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-debuginfo-2.4.10-15.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-devel-2.4.10-15.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-manual-2.4.10-15.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-tools-2.4.10-15.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ldap-2.4.10-15.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_proxy_html-2.4.10-15.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_session-2.4.10-15.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ssl-2.4.10-15.58.amzn1")) flag++;

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
