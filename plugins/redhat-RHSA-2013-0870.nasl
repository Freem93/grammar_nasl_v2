#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0870. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66661);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-1976");
  script_bugtraq_id(60186);
  script_osvdb_id(95550);
  script_xref(name:"RHSA", value:"2013:0870");

  script_name(english:"RHEL 5 : tomcat5 (RHSA-2013:0870)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tomcat5 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Apache Tomcat is a servlet container for the Java Servlet and
JavaServer Pages (JSP) technologies.

A flaw was found in the way the tomcat5 init script handled the
catalina.out log file. A malicious web application deployed on Tomcat
could use this flaw to perform a symbolic link attack to change the
ownership of an arbitrary system file to that of the tomcat user,
allowing them to escalate their privileges to root. (CVE-2013-1976)

Note: With this update, /var/log/tomcat5/catalina.out has been moved
to the /var/log/tomcat5-initd.log file.

Red Hat would like to thank Simon Fayer of Imperial College London for
reporting this issue.

Users of Tomcat are advised to upgrade to these updated packages,
which correct this issue. Tomcat must be restarted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1976.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0870.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jsp-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-jsp-2.0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-servlet-2.4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-servlet-2.4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0870";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-admin-webapps-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-admin-webapps-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-admin-webapps-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-common-lib-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-common-lib-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-common-lib-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-debuginfo-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-debuginfo-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-debuginfo-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-jasper-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-jasper-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-jasper-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-server-lib-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-server-lib-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-server-lib-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat5-webapps-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tomcat5-webapps-5.5.23-0jpp.40.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat5-webapps-5.5.23-0jpp.40.el5_9")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat5 / tomcat5-admin-webapps / tomcat5-common-lib / etc");
  }
}
