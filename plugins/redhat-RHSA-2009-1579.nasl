#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1579. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42469);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
  script_bugtraq_id(36254, 36260, 36935);
  script_osvdb_id(57851, 57882, 59968, 59969, 59970, 59971);
  script_xref(name:"RHSA", value:"2009:1579");

  script_name(english:"RHEL 3 / 5 : httpd (RHSA-2009:1579)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix multiple security issues are now
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
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-20491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1579.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:1579";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL3", reference:"httpd-2.0.46-77.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"httpd-devel-2.0.46-77.ent")) flag++;

  if (rpm_check(release:"RHEL3", reference:"mod_ssl-2.0.46-77.ent")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"httpd-devel-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-manual-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"httpd-manual-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-manual-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_ssl-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"mod_ssl-2.2.3-31.el5_4.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_ssl-2.2.3-31.el5_4.2")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / mod_ssl");
  }
}
