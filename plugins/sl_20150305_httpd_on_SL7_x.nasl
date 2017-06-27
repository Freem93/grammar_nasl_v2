#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82252);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/26 04:39:25 $");

  script_cve_id("CVE-2013-5704", "CVE-2014-3581");

  script_name(english:"Scientific Linux Security Update : httpd on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way httpd handled HTTP Trailer headers when
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

  - Previously, the mod_proxy_fcgi Apache module always kept
    the back-end connections open even when they should have
    been closed. As a consequence, the number of open file
    descriptors was increasing over the time. With this
    update, mod_proxy_fcgi has been fixed to check the state
    of the back- end connections, and it closes the idle
    back-end connections as expected.

  - An integer overflow occurred in the ab utility when a
    large request count was used. Consequently, ab
    terminated unexpectedly with a segmentation fault while
    printing statistics after the benchmark. This bug has
    been fixed, and ab no longer crashes in this scenario.

  - Previously, when httpd was running in the foreground and
    the user pressed Ctrl+C to interrupt the httpd
    processes, a race condition in signal handling occurred.
    The SIGINT signal was sent to all children followed by
    SIGTERM from the main process, which interrupted the
    SIGINT handler. Consequently, the affected processes
    became unresponsive or terminated unexpectedly. With
    this update, the SIGINT signals in the child processes
    are ignored, and httpd no longer hangs or crashes in
    this scenario.

In addition, this update adds the following enhancements :

  - With this update, the mod_proxy module of the Apache
    HTTP Server supports the Unix Domain Sockets (UDS). This
    allows mod_proxy back ends to listen on UDS sockets
    instead of TCP sockets, and as a result, mod_proxy can
    be used to connect UDS back ends.

  - This update adds support for using the SetHandler
    directive together with the mod_proxy module. As a
    result, it is possible to configure SetHandler to use
    proxy for incoming requests, for example, in the
    following format: SetHandler
    'proxy:fcgi://127.0.0.1:9000'.

  - The htaccess API changes introduced in httpd 2.4.7 have
    been backported to httpd shipped with Scientific Linux
    7.1. These changes allow for the MPM-ITK module to be
    compiled as an httpd module.

After installing the updated packages, the httpd daemon will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=2522
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9beb5dbf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-2.4.6-31.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-debuginfo-2.4.6-31.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-devel-2.4.6-31.sl7")) flag++;
if (rpm_check(release:"SL7", reference:"httpd-manual-2.4.6-31.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"httpd-tools-2.4.6-31.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_ldap-2.4.6-31.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_proxy_html-2.4.6-31.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_session-2.4.6-31.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"mod_ssl-2.4.6-31.sl7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
