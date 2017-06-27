#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0213. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63851);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2007-4575", "CVE-2007-5461", "CVE-2007-6306", "CVE-2007-6433", "CVE-2008-0002");
  script_bugtraq_id(26703, 26752);
  script_xref(name:"RHSA", value:"2008:0213");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2008:0213)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"New JBoss Enterprise Application Platform (JBEAP) packages, comprising
the 4.2.0.CP02 release, are now available for Red Hat Enterprise Linux
5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

JBEAP is a middleware platform for Java 2 Platform, Enterprise Edition
(J2EE) applications.

This release of JBEAP for Red Hat Enterprise Linux 5 contains the
JBoss Application Server and JBoss Seam and serves as a replacement
for JBEAP 4.2.0.GA_CP01. As well as fixing numerous bugs and adding
enhancements, these updated packages addresses several security
issues.

The JFreeChart component was vulnerable to multiple cross-site
scripting (XSS) vulnerabilities. An attacker could misuse the image
map feature to inject arbitrary web script or HTML via several
attributes of the chart area. (CVE-2007-6306)

A vulnerability caused by exposing static java methods was located
within the HSQLDB component. This could be utilized by an attacker to
execute arbitrary static java methods. (CVE-2007-4575)

The setOrder method in the org.jboss.seam.framework.Query class did
not properly validate user-supplied parameters. This vulnerability
allowed remote attackers to inject and execute arbitrary EJBQL
commands via the order parameter. (CVE-2007-6433)

For details regarding the bug fixes and enhancements included with
this update, please see the JBoss Enterprise Application Platform
4.2.0.CP02 Release Notes, linked to in the References section below.

All Red Hat Enterprise Linux 5 users wanting to use the JBoss
Enterprise Application Platform are advised to install these new
packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6306.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-6433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://redhat.com/docs/manuals/jboss/jboss-eap-4.2.0.cp02/readme.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0213.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 22, 79, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jstl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jbpm-bpel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jbpm-jpdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-jboss42");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-wsconsume-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:juddi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ws-commons-policy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/02");
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
  rhsa = "RHSA-2008:0213";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossas-4"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"concurrent-1.3.4-8jpp.ep1.6.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaf-1.1.0-0jpp.ep1.9.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-javamail-1.4.0-0jpp.ep1.8.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf-1.2_04-1.p02.0jpp.ep1.18.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jstl-1.2.0-0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-3.2.1-1.patch02.1jpp.ep1.2.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-javadoc-3.2.1-1.patch02.1jpp.ep1.2.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-3.2.1-1jpp.ep1.6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-javadoc-3.2.1-1jpp.ep1.6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP02.0jpp.ep1.1.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jacorb-2.3.0-1jpp.ep1.5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-aop-1.5.5-1.CP01.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-cache-1.4.1-4.SP8_CP01.1jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-common-1.2.1-0jpp.ep1.2.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jbpm-bpel-1.1.0-0jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jbpm-jpdl-3.2.0-0jpp.ep1.6.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.2.2-3.SP4.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-1.2.1-1.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-docs-1.2.1-1.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0-4.GA_CP02.ep1.3.el5.3")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-2.0.0-3.CP05.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-jboss42-1.2.1-0jpp.ep1.2.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-wsconsume-impl-2.0.0-0jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossxb-1.0.0-2.SP1.0jpp.ep1.2.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jcommon-1.0.12-1jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jfreechart-1.0.9-1jpp.ep1.2.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-2.4.1-1.SP4.0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"juddi-0.9-0.rc4.2jpp.ep1.3.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-4.2.0-3.GA_CP02.ep1.1.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-examples-4.2.0-3.GA_CP02.ep1.1.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ws-commons-policy-1.0-2jpp.ep1.4.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "concurrent / glassfish-jaf / glassfish-javamail / glassfish-jsf / etc");
  }
}
