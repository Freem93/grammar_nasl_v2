#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1579 and 
# Oracle Linux Security Advisory ELSA-2009-1579 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67958);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
  script_bugtraq_id(36254, 36260, 36935);
  script_osvdb_id(57851, 57882, 59968, 59969, 59970, 59971);
  script_xref(name:"RHSA", value:"2009:1579");

  script_name(english:"Oracle Linux 3 / 5 : httpd (ELSA-2009-1579)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1579 :

Updated httpd packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A flaw was found in the way the TLS/SSL (Transport Layer
Security/Secure Sockets Layer) protocols handle session renegotiation.
A man-in-the-middle attacker could use this flaw to prefix arbitrary
plain text to a client's session (for example, an HTTPS connection to
a website). This could force the server to process an attacker's
request as if authenticated using the victim's credentials. This
update partially mitigates this flaw for SSL sessions to HTTP servers
using mod_ssl by rejecting client-requested renegotiation.
(CVE-2009-3555)

Note: This update does not fully resolve the issue for HTTPS servers.
An attack is still possible in configurations that require a
server-initiated renegotiation. Refer to the following Knowledgebase
article for further information:
http://kbase.redhat.com/faq/docs/DOC-20491

A NULL pointer dereference flaw was found in the Apache mod_proxy_ftp
module. A malicious FTP server to which requests are being proxied
could use this flaw to crash an httpd child process via a malformed
reply to the EPSV or PASV commands, resulting in a limited denial of
service. (CVE-2009-3094)

A second flaw was found in the Apache mod_proxy_ftp module. In a
reverse proxy configuration, a remote attacker could use this flaw to
bypass intended access restrictions by creating a carefully-crafted
HTTP Authorization header, allowing the attacker to send arbitrary
commands to the FTP server. (CVE-2009-3095)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-November/001243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-November/001245.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(3|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-2.0.46-77.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-2.0.46-77.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"httpd-devel-2.0.46-77.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"httpd-devel-2.0.46-77.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"mod_ssl-2.0.46-77.0.1.ent")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"mod_ssl-2.0.46-77.0.1.ent")) flag++;

if (rpm_check(release:"EL5", reference:"httpd-2.2.3-31.0.1.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"httpd-devel-2.2.3-31.0.1.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"httpd-manual-2.2.3-31.0.1.el5_4.2")) flag++;
if (rpm_check(release:"EL5", reference:"mod_ssl-2.2.3-31.0.1.el5_4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / mod_ssl");
}
