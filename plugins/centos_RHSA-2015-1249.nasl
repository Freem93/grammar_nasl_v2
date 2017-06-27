#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1249 and 
# CentOS Errata and Security Advisory 2015:1249 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85008);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/28 16:58:13 $");

  script_cve_id("CVE-2013-5704");
  script_bugtraq_id(66550);
  script_osvdb_id(105190);
  script_xref(name:"RHSA", value:"2015:1249");

  script_name(english:"CentOS 6 : httpd (CESA-2015:1249)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix one security issue, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

A flaw was found in the way httpd handled HTTP Trailer headers when
processing requests using chunked encoding. A malicious client could
use Trailer headers to set additional HTTP headers after header
processing was performed by other modules. This could, for example,
lead to a bypass of header restrictions defined with mod_headers.
(CVE-2013-5704)

This update also fixes the following bugs :

* The order of mod_proxy workers was not checked when httpd
configuration was reloaded. When mod_proxy workers were removed,
added, or their order was changed, their parameters and scores could
become mixed. The order of mod_proxy workers has been made internally
consistent during configuration reload. (BZ#1149906)

* The local host certificate created during firstboot contained CA
extensions, which caused the httpd service to return warning messages.
This has been addressed by local host certificates being generated
with the '-extensions v3_req' option. (BZ#906476)

* The default mod_ssl configuration no longer enables support for SSL
cipher suites using the single DES, IDEA, or SEED encryption
algorithms. (BZ#1086771)

* The apachectl script did not take into account the HTTPD_LANG
variable set in the /etc/sysconfig/httpd file during graceful
restarts. Consequently, httpd did not use a changed value of
HTTPD_LANG when the daemon was restarted gracefully. The script has
been fixed to handle the HTTPD_LANG variable correctly. (BZ#963146)

* The mod_deflate module failed to check the original file size while
extracting files larger than 4 GB, making it impossible to extract
large files. Now, mod_deflate checks the original file size properly
according to RFC1952, and it is able to decompress files larger than 4
GB. (BZ#1057695)

* The httpd service did not check configuration before restart. When a
configuration contained an error, an attempt to restart httpd
gracefully failed. Now, httpd checks configuration before restart and
if the configuration is in an inconsistent state, an error message is
printed, httpd is not stopped and a restart is not performed.
(BZ#1146194)

* The SSL_CLIENT_VERIFY environment variable was incorrectly handled
when the 'SSLVerifyClient optional_no_ca' and 'SSLSessionCache'
options were used. When an SSL session was resumed, the
SSL_CLIENT_VERIFY value was set to 'SUCCESS' instead of the previously
set 'GENEROUS'. SSL_CLIENT_VERIFY is now correctly set to GENEROUS in
this scenario. (BZ#1149703)

* The ab utility did not correctly handle situations when an SSL
connection was closed after some data had already been read. As a
consequence, ab did not work correctly with SSL servers and printed
'SSL read failed' error messages. With this update, ab works as
expected with HTTPS servers. (BZ#1045477)

* When a client presented a revoked certificate, log entries were
created only at the debug level. The log level of messages regarding a
revoked certificate has been increased to INFO, and administrators are
now properly informed of this situation. (BZ#1161328)

In addition, this update adds the following enhancement :

* A mod_proxy worker can now be set into drain mode (N) using the
balancer-manager web interface or using the httpd configuration file.
A worker in drain mode accepts only existing sticky sessions destined
for itself and ignores all other requests. The worker waits until all
clients currently connected to this worker complete their work before
the worker is stopped. As a result, drain mode enables to perform
maintenance on a worker without affecting clients. (BZ#767130)

Users of httpd are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement. After installing the updated packages, the httpd service
will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/002081.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2997bcaf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"httpd-2.2.15-45.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-devel-2.2.15-45.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-manual-2.2.15-45.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"httpd-tools-2.2.15-45.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mod_ssl-2.2.15-45.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
