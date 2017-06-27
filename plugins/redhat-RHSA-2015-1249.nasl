#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1249. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84911);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2013-5704");
  script_bugtraq_id(66550);
  script_osvdb_id(105190);
  script_xref(name:"RHSA", value:"2015:1249");

  script_name(english:"RHEL 6 : httpd (RHSA-2015:1249)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1249.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1249";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"httpd-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"httpd-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpd-debuginfo-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpd-devel-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"httpd-manual-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"httpd-tools-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"httpd-tools-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_ssl-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_ssl-2.2.15-45.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.15-45.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
  }
}
