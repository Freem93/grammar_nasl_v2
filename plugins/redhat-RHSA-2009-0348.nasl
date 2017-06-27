#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0348. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63876);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/03 17:27:01 $");

  script_cve_id("CVE-2009-0027");
  script_osvdb_id(56358);
  script_xref(name:"RHSA", value:"2009:0348");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2009:0348)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform (JBoss EAP) 4.2 packages
that fix various issues are now available for Red Hat Enterprise Linux
5 as JBEAP 4.2.0.CP06.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

JBoss Enterprise Application Platform (JBoss EAP) is the
market-leading platform for innovative and scalable Java applications.
JBoss EAP integrates the JBoss Application Server with JBoss Hibernate
and JBoss Seam into a complete, simple enterprise solution.

This release of JBoss EAP for Red Hat Enterprise Linux 5 serves as a
replacement for JBEAP 4.2.0.CP05.

These updated packages include bug fixes and enhancements which are
detailed in the release notes. The link to the release notes is
available below in the References section.

The following security issue is also fixed with this release :

The request handler in JBossWS did not correctly verify the resource
path when serving WSDL files for custom web service endpoints. This
allowed remote attackers to read arbitrary XML files with the
permissions of the EAP process. (CVE-2009-0027)

Warning: before applying this update, make sure to back up the JBEAP
'server/[configuration]/deploy/' directory, as well as any other
customized configuration files.

All users of JBoss EAP 4.2 on Red Hat Enterprise Linux 5 are advised
to upgrade to these updated packages, which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0027.html"
  );
  # http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13c46bfa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0348.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-logging-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.2.0.GA_CP06-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-jboss42");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tanukiwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-scout0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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
  rhsa = "RHSA-2009:0348";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossas-client-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf-1.2_10-0jpp.ep1.5.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-3.2.4-1.SP1_CP07.0jpp.ep1.14.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP07.0jpp.ep1.14.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jacorb-2.3.0-1jpp.ep1.7.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jakarta-commons-logging-jboss-1.1-4.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-cache-1.4.1-6.SP11.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jaxr-1.2.0-SP2.0jpp.ep1.3.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.2.2-3.SP11.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-1.2.1-1.ep1.12.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-docs-1.2.1-1.ep1.12.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-vfs-1.0.0-1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0-4.GA_CP06.3.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0.GA_CP06-bin-4.2.0-4.GA_CP06.3.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-client-4.2.0-4.GA_CP06.3.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.2.3-1.SP5_CP04.1jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-2.0.0-6.CP09.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-jboss42-1.2.1-1.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-2.4.5-2.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-4.2.0-5.GA_CP06.ep1.3.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-examples-4.2.0-5.GA_CP06.ep1.3.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tanukiwrapper-3.2.1-2jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tanukiwrapper-3.2.1-2jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ws-commons-policy-1.0-2jpp.ep1.7.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ws-scout0-0.7-0.rc2.4.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glassfish-jsf / hibernate3 / hibernate3-javadoc / jacorb / etc");
  }
}
