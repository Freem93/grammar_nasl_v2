#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0325. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81629);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2013-5704", "CVE-2014-3581");
  script_osvdb_id(105190, 112168);
  script_xref(name:"RHSA", value:"2015:0325");

  script_name(english:"RHEL 7 : httpd (RHSA-2015:0325)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix two security issues, several bugs, and
add various enhancements are for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. Common Vulnerability Scoring System (CVSS) base scores, which
give detailed severity ratings, are available for each vulnerability
from the CVE links in the References section.

The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

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

This update also fixes the following bugs :

* Previously, the mod_proxy_fcgi Apache module always kept the
back-end connections open even when they should have been closed. As a
consequence, the number of open file descriptors was increasing over
the time. With this update, mod_proxy_fcgi has been fixed to check the
state of the back-end connections, and it closes the idle back-end
connections as expected. (BZ#1168050)

* An integer overflow occurred in the ab utility when a large request
count was used. Consequently, ab terminated unexpectedly with a
segmentation fault while printing statistics after the benchmark. This
bug has been fixed, and ab no longer crashes in this scenario.
(BZ#1092420)

* Previously, when httpd was running in the foreground and the user
pressed Ctrl+C to interrupt the httpd processes, a race condition in
signal handling occurred. The SIGINT signal was sent to all children
followed by SIGTERM from the main process, which interrupted the
SIGINT handler. Consequently, the affected processes became
unresponsive or terminated unexpectedly. With this update, the SIGINT
signals in the child processes are ignored, and httpd no longer hangs
or crashes in this scenario. (BZ#1131006)

In addition, this update adds the following enhancements :

* With this update, the mod_proxy module of the Apache HTTP Server
supports the Unix Domain Sockets (UDS). This allows mod_proxy back
ends to listen on UDS sockets instead of TCP sockets, and as a result,
mod_proxy can be used to connect UDS back ends. (BZ#1168081)

* This update adds support for using the SetHandler directive together
with the mod_proxy module. As a result, it is possible to configure
SetHandler to use proxy for incoming requests, for example, in the
following format: SetHandler 'proxy:fcgi://127.0.0.1:9000'.
(BZ#1136290)

* The htaccess API changes introduced in httpd 2.4.7 have been
backported to httpd shipped with Red Hat Enterprise Linux 7.1. These
changes allow for the MPM-ITK module to be compiled as an httpd
module. (BZ#1059143)

All httpd users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements. After installing the updated packages, the httpd daemon
will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-5704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3581.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0325.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0325";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"httpd-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"httpd-debuginfo-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd-debuginfo-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"httpd-devel-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd-devel-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"httpd-manual-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"httpd-tools-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"httpd-tools-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mod_ldap-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_ldap-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mod_proxy_html-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_proxy_html-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mod_session-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_session-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"mod_ssl-2.4.6-31.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_ssl-2.4.6-31.el7")) flag++;

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
