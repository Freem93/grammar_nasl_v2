#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:582. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19296);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/28 17:55:19 $");

  script_cve_id("CVE-2005-1268", "CVE-2005-2088");
  script_osvdb_id(17738, 18286);
  script_xref(name:"RHSA", value:"2005:582");

  script_name(english:"RHEL 3 / 4 : httpd (RHSA-2005:582)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages to correct two security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a powerful, full-featured, efficient, and
freely-available Web server.

Watchfire reported a flaw that occured when using the Apache server as
an HTTP proxy. A remote attacker could send an HTTP request with both
a 'Transfer-Encoding: chunked' header and a 'Content-Length' header.
This caused Apache to incorrectly handle and forward the body of the
request in a way that the receiving server processes it as a separate
HTTP request. This could allow the bypass of Web application firewall
protection or lead to cross-site scripting (XSS) attacks. The Common
Vulnerabilities and Exposures project (cve.mitre.org) assigned the
name CVE-2005-2088 to this issue.

Marc Stern reported an off-by-one overflow in the mod_ssl CRL
verification callback. In order to exploit this issue the Apache
server would need to be configured to use a malicious certificate
revocation list (CRL). The Common Vulnerabilities and Exposures
project (cve.mitre.org) assigned the name CVE-2005-1268 to this issue.

Users of Apache httpd should update to these errata packages that
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-2088.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.watchfire.com/resources/HTTP-Request-Smuggling.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://issues.apache.org/bugzilla/show_bug.cgi?id=35081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://issues.apache.org/bugzilla/show_bug.cgi?id=34588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-582.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2005:582";
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
  if (rpm_check(release:"RHEL3", reference:"httpd-2.0.46-46.2.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"httpd-devel-2.0.46-46.2.ent")) flag++;
  if (rpm_check(release:"RHEL3", reference:"mod_ssl-2.0.46-46.2.ent")) flag++;

  if (rpm_check(release:"RHEL4", reference:"httpd-2.0.52-12.1.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-devel-2.0.52-12.1.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-manual-2.0.52-12.1.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"httpd-suexec-2.0.52-12.1.ent")) flag++;
  if (rpm_check(release:"RHEL4", reference:"mod_ssl-2.0.52-12.1.ent")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-suexec / mod_ssl");
  }
}
