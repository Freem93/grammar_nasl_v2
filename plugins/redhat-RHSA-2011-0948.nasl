#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0948. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63990);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/01/05 14:44:34 $");

  script_cve_id("CVE-2011-2196");
  script_osvdb_id(74277);
  script_xref(name:"RHSA", value:"2011:0948");
  script_xref(name:"IAVB", value:"2011-B-0086");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2011:0948)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform 5.1.1 packages that fix
one security issue and various bugs are now available for Red Hat
Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

JBoss Enterprise Application Platform is the market-leading platform
for innovative and scalable Java applications. JBoss Enterprise
Application Platform integrates the JBoss Application Server with
JBoss Hibernate and JBoss Seam into a complete and simple enterprise
solution.

This JBoss Enterprise Application Platform 5.1.1 release for Red Hat
Enterprise Linux 5 serves as a replacement for JBoss Enterprise
Application Platform 5.1.0.

These updated packages include the bug fixes detailed in the release
notes, which are linked to from the References section of this
erratum.

The following security issue is also fixed with this release :

It was found that the fix for CVE-2011-1484 was incomplete: JBoss Seam
2 did not block access to all malicious JBoss Expression Language (EL)
constructs in page exception handling, allowing arbitrary Java methods
to be executed. A remote attacker could use this flaw to execute
arbitrary code via a specially crafted URL provided to certain
applications based on the JBoss Seam 2 framework. Note: A properly
configured and enabled Java Security Manager would prevent
exploitation of this flaw. (CVE-2011-2196)

Red Hat would like to thank the ObjectWorks+ Development Team at
Nomura Research Institute for reporting this issue.

Warning: Before applying this update, please back up your JBoss
Enterprise Application Platform's 'jboss-as/server/[PROFILE]/deploy/'
directory, along with all other customized configuration files.

All users of JBoss Enterprise Application Platform 5.1.0 on Red Hat
Enterprise Linux 5 are advised to upgrade to these updated packages.
Manual action is required for this update to take effect. Refer to the
Solution section for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2196.html"
  );
  # http://docs.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/5/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f390cc27"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0948.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bsh2-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-stax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:codehaus-stax-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:concurrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dom4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facelets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-search-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hornetq-jopr-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb-jboss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-collections-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-dbcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-dbcp-tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-fileupload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jaxen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aspects-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cluster-ha-server-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common-logging-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-deployers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-eap5-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb-3.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-proxy-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ejb3-timerservice-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jacc-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jad-1.2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaspi-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-javaee-poms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxrpc-api_1.1_spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jca-1.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jms-1.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-logmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-mdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting-aspects");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-security-xacml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-serialization");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-specs-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-transaction-1.0.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-messaging511");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-tp-licenses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-cxf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-ws-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbosssx2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-el-1.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-spi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jdom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jettison");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-hibernate-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-as-5-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jopr-jboss-cache-v3-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-jbossweb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_cluster-tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_jk-ap20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:resteasy-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-ant-bundle-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-common-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-client-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-comm-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-dbutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-domain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-native-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugin-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-plugindoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-core-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-filetemplate-bundle-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jboss-as-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-jmx-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-modules-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-platform-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugin-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-pluginAnnotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-pluginGen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-plugins-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhq-rtfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-cdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-root");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:richfaces-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j-jboss-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-saaj-1.3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sun-ws-metadata-2.0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:wss4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  rhsa = "RHSA-2011:0948";
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

  if (rpm_check(release:"RHEL5", reference:"antlr-2.7.7-7.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"apache-cxf-2.2.12-3.patch_01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bcel-5.2-8.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bsh2-2.0-0.b4.11.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"bsh2-bsf-2.0-0.b4.11.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"codehaus-stax-1.2.0-0.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"codehaus-stax-api-1.2.0-0.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"concurrent-1.3.4-10.1.4_jboss_update1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"dom4j-1.6.1-11.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"facelets-1.1.15-1.B1.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-javamail-1.4.2-0.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-3.3.2-1.4.GA_CP04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-3.4.0-3.2.GA_CP04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-javadoc-3.4.0-3.2.GA_CP04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-commons-annotations-3.1.0-1.8.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-commons-annotations-javadoc-3.1.0-1.8.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-3.4.0-4.3.GA_CP04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-javadoc-3.4.0-4.3.GA_CP04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-javadoc-3.3.2-1.4.GA_CP04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-search-3.1.1-2.3.GA_CP04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-search-javadoc-3.1.1-2.3.GA_CP04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-validator-3.1.0-1.5.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-validator-javadoc-3.1.0-1.5.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hornetq-jopr-plugin-2.0.0-1.Final.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hsqldb-1.8.0.10-9_patch_01.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jacorb-jboss-2.3.1-9.patch02.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jakarta-commons-collections-3.2.1-4.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jakarta-commons-collections-tomcat5-3.2.1-4.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jakarta-commons-dbcp-1.2.1-16.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jakarta-commons-dbcp-tomcat5-1.2.1-16.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jakarta-commons-fileupload-1.1.1-7.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jaxen-1.1.2-6.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-aop2-2.1.6-1.CP02.1.3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-aspects-build-1.0.1-0.CR5.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-cache-core-3.2.7-5.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-cluster-ha-server-api-1.2.0-1.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-common-core-2.2.17-1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-common-logging-jdk-2.1.2-1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-common-logging-log4j-2.1.2-1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-common-logging-spi-2.1.2-1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-deployers-2.0.10-4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jboss-eap5-native-5.1.1-3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jboss-eap5-native-5.1.1-3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-ejb-3.0-api-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-ejb3-core-1.3.7-0.3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-ejb3-proxy-impl-1.0.6-2.SP1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-ejb3-timerservice-spi-1.0.4-0.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jacc-1.1-api-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jad-1.2-api-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jaspi-1.0-api-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-javaee-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-javaee-poms-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jaxr-2.0.1-7.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jaxrpc-api_1.1_spec-1.0.0-15.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jca-1.5-api-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jms-1.1-api-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-logbridge-1.0.1-1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-logmanager-1.1.2-2.1.GA.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-mdr-2.0.3-1.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-messaging-1.4.8-6.SP1.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.5.4-8.SP2.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-aspects-1.0.3-0.6.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-2.2.4.EAP5-4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-docs-2.2.4.EAP5-4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-examples-2.2.4.EAP5-4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam2-runtime-2.2.4.EAP5-4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-security-spi-2.0.4-5.SP7.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-security-xacml-2.0.5-1.jdk6.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-serialization-1.0.5-2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-specs-parent-1.0.0-0.3.Beta2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-transaction-1.0.1-api-5.0.1-2.9.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-vfs2-2.2.0-4.SP1.3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-5.1.1-16.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-client-5.1.1-16.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-messaging511-5.1.1-17.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-tp-licenses-5.1.1-1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-ws-cxf-5.1.1-5.3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-ws-native-5.1.1-16.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbosssx2-2.0.4-5.SP7.2.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.6.1-10.CP11_patch_01.3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-javadoc-4.6.1-10.CP11_patch_01.3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-2.1.11-5.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-el-1.0-api-2.1.11-5.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-jsp-2.1-api-2.1.11-5.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-lib-2.1.11-5.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-servlet-2.5-api-2.1.11-5.4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-3.1.2-6.SP10.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-common-1.1.0-3.SP7.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-framework-3.1.2-5.SP9.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-spi-1.1.2-4.SP6.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jdom-1.1.1-2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jettison-1.2-4.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-2.6.19-2.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jopr-embedded-1.3.4-17.SP4.7.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jopr-hibernate-plugin-3.0.0-10.EmbJopr3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jopr-jboss-as-5-plugin-3.0.0-8.EmbJopr3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jopr-jboss-cache-v3-plugin-3.0.0-8.EmbJopr3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mod_cluster-demo-1.0.10-2.1.GA_CP01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mod_cluster-jbossas-1.0.10-2.1.GA_CP01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mod_cluster-jbossweb2-1.0.10-2.1.GA_CP01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_cluster-native-1.0.10-2.1.GA_CP01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_cluster-native-1.0.10-2.1.GA_CP01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"mod_cluster-tomcat6-1.0.10-2.1.GA_CP01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"mod_jk-ap20-1.2.31-1.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"mod_jk-ap20-1.2.31-1.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"netty-3.2.3-5.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-1.2.1-8.CP01.8.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-examples-1.2.1-8.CP01.8.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-javadoc-1.2.1-8.CP01.8.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"resteasy-manual-1.2.1-8.CP01.8.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-5.1.1-6.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-examples-5.1.1-6.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-ant-bundle-common-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-common-parent-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-client-api-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-comm-api-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-dbutils-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-domain-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-gui-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-native-system-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-parent-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-plugin-api-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-plugin-container-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-plugindoc-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-core-util-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-filetemplate-bundle-common-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-helpers-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-jboss-as-common-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-jmx-plugin-3.0.0-14.EmbJopr3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-modules-parent-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-parent-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-platform-plugin-3.0.0-11.EmbJopr3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-plugin-validator-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-pluginAnnotations-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-pluginGen-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-plugins-parent-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rhq-rtfilter-3.0.0-17.EmbJopr3.2.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-3.3.1-1.SP3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-cdk-3.3.1-1.SP3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-demo-3.3.1-1.SP3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-docs-3.3.1-1.SP3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-framework-3.3.1-1.SP3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-root-3.3.1-1.SP3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"richfaces-ui-3.3.1-1.SP3.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"slf4j-1.5.8-8.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"slf4j-jboss-logging-1.0.3-1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"sun-saaj-1.3-api-1.3-6.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"sun-ws-metadata-2.0-api-1.0.MR1-11.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tomcat-native-1.1.20-2.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tomcat-native-1.1.20-2.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"wss4j-1.5.10-3_patch_01.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xalan-j2-2.7.1-5.3_patch_04.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xerces-j2-2.9.1-3.patch01.1.ep5.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xerces-j2-scripts-2.9.1-3.patch01.1.ep5.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "antlr / apache-cxf / bcel / bsh2 / bsh2-bsf / codehaus-stax / etc");
  }
}
