#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0832. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63865);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2007-5342", "CVE-2008-3519");
  script_xref(name:"RHSA", value:"2008:0832");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2008:0832)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform (JBEAP) 4.3 packages
that fix various security issues are now available for Red Hat
Enterprise Linux 5 as JBEAP 4.3.0.CP02.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

JBoss Enterprise Application Platform is the market leading platform
for innovative and scalable Java applications; integrating the JBoss
Application Server, with JBoss Hibernate and JBoss Seam into a
complete, simple enterprise solution.

This release of JBEAP for Red Hat Enterprise Linux 5 serves as a
replacement to JBEAP 4.3.0.CP01.

These updated packages include bug fixes and enhancements which are
detailed in the release notes. The link to the release notes is
available below in the References section.

The following security issues are also fixed with this release :

The default security policy in the JULI logging component did not
restrict access permissions to files. This could be misused by
untrusted web applications to access and write arbitrary files in the
context of the tomcat process. (CVE-2007-5342)

The property that controls the download of server classes was set to
'true' in the 'production' configuration. When the class download
service is bound to an external interface, a remote attacker was able
to download arbitrary class files from the server class path.
(CVE-2008-3519)

Warning: before applying this update, please backup the JBEAP
'server/[configuration]/deploy/' directory, and any other customized
configuration files.

All users of JBEAP 4.3 on Red Hat Enterprise Linux 5 are advised to
upgrade to these updated packages, which resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-5342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3519.html"
  );
  # http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13c46bfa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0832.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cwe_id(16, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxb-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jaxws-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jstl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:javassist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-jaxr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws-framework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossxb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/22");
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
  rhsa = "RHSA-2008:0832";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"jbossweb-2"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"glassfish-jaf-1.1.0-0jpp.ep1.12.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-javamail-1.4.0-0jpp.ep1.10.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaxb-2.1.4-1jpp.ep1.4.el5.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaxb-javadoc-2.1.4-1jpp.ep1.4.el5.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaxws-2.1.1-1jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jaxws-javadoc-2.1.1-1jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glassfish-jstl-1.2.0-0jpp.ep1.10.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-3.2.4-1.SP1_CP04.0jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-3.2.1-4.GA_CP02.1jpp.ep1.7.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-javadoc-3.2.1-4.GA_CP02.1jpp.ep1.7.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-commons-annotations-0.0.0-1.1jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-3.2.1-2.GA_CP03.1jpp.ep1.9.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-javadoc-3.2.1-2.GA_CP03.1jpp.ep1.9.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP04.0jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-validator-0.0.0-1.1jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"javassist-3.8.0-1jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-aop-1.5.5-2.CP02.0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-jaxr-1.2.0-SP1.0jpp.ep1.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-messaging-1.4.0-1.SP3_CP03.0jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.2.2-3.SP9.0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-1.2.1-3.JBPAPP_4_3_0_GA.ep1.7.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-docs-1.2.1-3.JBPAPP_4_3_0_GA.ep1.7.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.3.0-2.GA_CP02.ep1.10.el5.2")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.2.3-1.SP5_CP02.1jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-2.0.0-4.CP06.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-2.0.1-2.SP2_CP03.0jpp.ep1.1.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-common-1.0.0-1.GA_CP01.0jpp.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossws-framework-2.0.1-0jpp.ep1.11.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossxb-1.0.0-2.SP3.0jpp.ep1.3.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-4.3.0-2.GA_CP02.ep1.6.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glassfish-jaf / glassfish-javamail / glassfish-jaxb / etc");
  }
}
