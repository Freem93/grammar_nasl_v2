#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1133. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76239);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-1862", "CVE-2013-1896");
  script_osvdb_id(93366, 95498);
  script_xref(name:"RHSA", value:"2013:1133");

  script_name(english:"RHEL 5 / 6 : JBoss Web Server (RHSA-2013:1133)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix two security issues are now available
for Red Hat JBoss Web Server 2.0.1 for Red Hat Enterprise Linux 5 and
6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat JBoss Web Server is a fully integrated and certified set of
components for hosting Java web applications. It is comprised of the
Apache HTTP Server, the Apache Tomcat Servlet container, Apache Tomcat
Connector (mod_jk), JBoss HTTP Connector (mod_cluster), Hibernate, and
the Tomcat Native library.

A flaw was found in the way the mod_dav module of the Apache HTTP
Server handled merge requests. An attacker could use this flaw to send
a crafted merge request that contains URIs that are not configured for
DAV, causing the httpd child process to crash. (CVE-2013-1896)

It was found that mod_rewrite did not filter terminal escape sequences
from its log file. If mod_rewrite was configured with the RewriteLog
directive, a remote attacker could use specially crafted HTTP requests
to inject terminal escape sequences into the mod_rewrite log file. If
a victim viewed the log file with a terminal emulator, it could result
in arbitrary command execution with the privileges of that user.
(CVE-2013-1862)

Warning: Before applying the update, back up your existing Red Hat
JBoss Web Server installation (including all applications and
configuration files).

All users of Red Hat JBoss Web Server 2.0.1 should upgrade to these
updated packages, which contain backported patches to correct these
issues. After installing the updated packages, users must restart the
httpd service for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1133.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1133";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"mod_cluster") || rpm_exists(release:"RHEL6", rpm:"mod_cluster"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss Web Server");

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-devel-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-devel-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-manual-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-manual-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"httpd-tools-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"httpd-tools-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_ssl-2.2.22-25.ep6.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_ssl-2.2.22-25.ep6.el5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-devel-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-devel-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-manual-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-manual-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"httpd-tools-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i386", reference:"mod_ssl-2.2.22-25.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.22-25.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-tools / mod_ssl");
  }
}
