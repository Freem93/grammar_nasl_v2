#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1650. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63906);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/03 17:27:03 $");

  script_cve_id("CVE-2009-0217", "CVE-2009-1380", "CVE-2009-2405", "CVE-2009-2625", "CVE-2009-3554");
  script_osvdb_id(56984, 60898, 60899, 61059, 61060);
  script_xref(name:"RHSA", value:"2009:1650");

  script_name(english:"RHEL 5 : JBoss EAP (RHSA-2009:1650)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated JBoss Enterprise Application Platform (JBEAP) 4.2 packages
that fix multiple security issues, several bugs, and add enhancements
are now available for Red Hat Enterprise Linux 5 as JBEAP 4.2.0.CP08.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

JBoss Enterprise Application Platform is the market leading platform
for innovative and scalable Java applications; integrating the JBoss
Application Server, with JBoss Hibernate and JBoss Seam into a
complete, simple enterprise solution.

This release of JBEAP for Red Hat Enterprise Linux 5 serves as a
replacement to JBEAP 4.2.0.CP07.

These updated packages include bug fixes and enhancements which are
detailed in the Release Notes, available shortly from:
http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform
/

The following security issues are also fixed with this release :

A missing check for the recommended minimum length of the truncated
form of HMAC-based XML signatures was found in xml-security. An
attacker could use this flaw to create a specially crafted XML file
that forges an XML signature, allowing the attacker to bypass
authentication that is based on the XML Signature specification.
(CVE-2009-0217)

Swatej Kumar discovered cross-site scripting (XSS) flaws in the JBoss
Application Server Web Console. An attacker could use these flaws to
present misleading data to an authenticated user, or execute arbitrary
scripting code in the context of the authenticated user's browser
session. (CVE-2009-2405)

A flaw was found in the way the Apache Xerces2 Java Parser processed
the SYSTEM identifier in DTDs. A remote attacker could provide a
specially crafted XML file, which once parsed by an application using
the Apache Xerces2 Java Parser, would lead to a denial of service
(application hang due to excessive CPU use). (CVE-2009-2625)

An information leak flaw was found in the twiddle command line client.
The JMX password was logged in plain text to 'twiddle.log'.
(CVE-2009-3554)

An XSS flaw was found in the JMX Console. An attacker could use this
flaw to present misleading data to an authenticated user, or execute
arbitrary scripting code in the context of the authenticated user's
browser session. (CVE-2009-1380)

Warning: Before applying this update, please backup the JBEAP
'server/[configuration]/deploy/' directory, and any other customized
configuration files.

All users of JBEAP 4.2 on Red Hat Enterprise Linux 5 are advised to
upgrade to these updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0217.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1380.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2405.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3554.html"
  );
  # http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13c46bfa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1650.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glassfish-jsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-entitymanager-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.2.0.GA_CP08-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcommon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xml-security");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/09");
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
  rhsa = "RHSA-2009:1650";
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

  if (rpm_check(release:"RHEL5", reference:"glassfish-jsf-1.2_13-2.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-3.2.4-1.SP1_CP09.0jpp.ep1.2.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-3.3.1-1.11GA_CP02.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-annotations-javadoc-3.3.1-1.11GA_CP02.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-3.3.2-2.5.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-entitymanager-javadoc-3.3.2-2.5.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP09.0jpp.ep1.2.4.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jacorb-2.3.0-1jpp.ep1.9.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-aop-1.5.5-3.CP04.2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-common-1.2.1-0jpp.ep1.3.el5.1")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-remoting-2.2.3-3.SP1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-1.2.1-1.ep1.14.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jboss-seam-docs-1.2.1-1.ep1.14.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0-5.GA_CP08.5.2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-4.2.0.GA_CP08-bin-4.2.0-5.GA_CP08.5.2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossas-client-4.2.0-5.GA_CP08.5.2.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossts-4.2.3-1.SP5_CP08.1jpp.ep1.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jbossweb-2.0.0-6.CP12.0jpp.ep1.2.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jcommon-1.0.16-1.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jfreechart-1.0.13-2.3.1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"jgroups-2.4.7-1.ep1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"quartz-1.5.2-1jpp.patch01.ep1.4.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-4.2.0-6.GA_CP08.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"rh-eap-docs-examples-4.2.0-6.GA_CP08.ep1.3.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"xml-security-1.3.0-1.3.patch01.ep1.2.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glassfish-jsf / hibernate3 / hibernate3-annotations / etc");
  }
}
