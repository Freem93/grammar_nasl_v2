#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1143. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63882);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/03 17:27:02 $");

  script_cve_id("CVE-2008-5515", "CVE-2009-0580", "CVE-2009-0783");
  script_bugtraq_id(35196, 35263, 35416);
  script_xref(name:"RHSA", value:"2009:1143");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2009:1143)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform (JBEAP) 4.2 packages
that fix various issues are now available for Red Hat Enterprise Linux
5 as JBEAP 4.2.0.CP07.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

JBoss Enterprise Application Platform is the market leading platform
for innovative and scalable Java applications; integrating the JBoss
Application Server, with JBoss Hibernate and JBoss Seam into a
complete, simple enterprise solution.

This release of JBEAP for Red Hat Enterprise Linux 5 serves as a
replacement to JBEAP 4.2.0.CP06.

These updated packages include bug fixes and enhancements which are
detailed in the release notes. The link to the release notes is
available below in the References section of this errata.

The following security issues are also fixed with this release :

It was discovered that request dispatchers did not properly normalize
user requests that have trailing query strings, allowing remote
attackers to send specially crafted requests that would cause an
information leak. (CVE-2008-5515)

It was discovered that the error checking methods of certain
authentication classes did not have sufficient error checking,
allowing remote attackers to enumerate (via brute-force methods)
usernames registered with applications deployed on JBossWeb when
FORM-based authentication was used. (CVE-2009-0580)

It was discovered that web applications containing their own XML
parsers could replace the XML parser JBossWeb uses to parse
configuration files. A malicious web application running on a JBossWeb
instance could read or, potentially, modify the configuration and
XML-based data of other web applications deployed on the same JBossWeb
instance. (CVE-2009-0783)

Warning: before applying this update, please back up the JBEAP
'server/[configuration]/deploy/' directory, and any other customized
configuration files.

All users of JBEAP 4.2 on Red Hat Enterprise Linux 5 are advised to
upgrade to these updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0580.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0783.html"
  );
  # http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13c46bfa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1143.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-commons-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-validator-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-slide-webdavclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.2.0.GA_CP07-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/06");
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
  rhsa = "RHSA-2009:1143";
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

  if (rpm_check(release:"RHEL5", reference:"hibernate3-3.2.4-1.SP1_CP08.0jpp.ep1.2.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-3.3.1-1.10.1GA_CP01.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-javadoc-3.3.1-1.10.1GA_CP01.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-commons-annotations-3.0.0-1jpp.ep1.5.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-commons-annotations-javadoc-3.0.0-1jpp.ep1.5.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-3.3.2-2.4.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-javadoc-3.3.2-2.4.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP08.0jpp.ep1.2.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-validator-3.0.0-1jpp.ep1.8.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-validator-javadoc-3.0.0-1jpp.ep1.8.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jakarta-slide-webdavclient-2.1-9.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-cache-1.4.1-6.SP13.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.2.3-2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-1.2.1-1.ep1.13.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-docs-1.2.1-1.ep1.13.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0-4.GA_CP07.5.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0.GA_CP07-bin-4.2.0-4.GA_CP07.5.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-client-4.2.0-4.GA_CP07.5.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.2.3-1.SP5_CP05.1jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-2.0.0-6.CP11.0jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-2.4.6-1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-4.2.0-5.GA_CP07.ep1.1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-examples-4.2.0-5.GA_CP07.ep1.1.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hibernate3 / hibernate3-annotations / etc");
  }
}
