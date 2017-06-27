#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0829. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40706);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/29 15:45:03 $");

  script_cve_id("CVE-2007-2435", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3503", "CVE-2007-3655", "CVE-2007-3922", "CVE-2007-4381");
  script_bugtraq_id(24004, 24832, 25054);
  script_osvdb_id(35483, 36199, 36200, 36201, 36202, 36488, 36662, 37756);
  script_xref(name:"RHSA", value:"2007:0829");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-ibm (RHSA-2007:0829)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.5.0-ibm packages that correct several security issues
are now available for Red Hat Enterprise Linux 4 Extras and 5
Supplementary.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

IBM's 1.5.0 Java release includes the IBM Java 2 Runtime Environment
and the IBM Java 2 Software Development Kit.

A security vulnerability in the Java Web Start component was
discovered. An untrusted application could elevate it's privileges,
allowing it to read and write local files that are accessible to the
user running the Java Web Start application. (CVE-2007-2435)

A buffer overflow in the Java Runtime Environment image handling code
was found. An untrusted applet or application could use this flaw to
elevate its privileges and potentially execute arbitrary code as the
user running the java virtual machine. (CVE-2007-2788, CVE-2007-2789,
CVE-2007-3004)

An unspecified vulnerability was discovered in the Java Runtime
Environment. An untrusted applet or application could cause the java
virtual machine to become unresponsive. (CVE-2007-3005)

The Javadoc tool was able to generate HTML documentation pages that
contained cross-site scripting (XSS) vulnerabilities. A remote
attacker could use this to inject arbitrary web script or HTML.
(CVE-2007-3503)

The Java Web Start URL parsing component contains a buffer overflow
vulnerability within the parsing code for JNLP files. A remote
attacker could create a malicious JNLP file that could trigger this
flaw and execute arbitrary code when opened. (CVE-2007-3655)

A flaw was found in the applet class loader. An untrusted applet could
use this flaw to circumvent network access restrictions, possibly
connecting to services hosted on the machine that executed the applet.
(CVE-2007-3922)

All users of java-ibm-1.5.0 should upgrade to these updated packages,
which contain IBM's 1.5.0 SR5a Java release that resolves these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2788.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-2789.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4381.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0829.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0829";
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
  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-1.5.0.5-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-demo-1.5.0.5-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-devel-1.5.0.5-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-javacomm-1.5.0.5-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.5-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-jdbc-1.5.0.5-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.5-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-plugin-1.5.0.5-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-src-1.5.0.5-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-1.5.0.5-1jpp.0.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-demo-1.5.0.5-1jpp.0.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-devel-1.5.0.5-1jpp.0.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-javacomm-1.5.0.5-1jpp.0.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.5-1jpp.0.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-jdbc-1.5.0.5-1jpp.0.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.5-1jpp.0.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-plugin-1.5.0.5-1jpp.0.1.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-src-1.5.0.5-1jpp.0.1.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.5.0-ibm / java-1.5.0-ibm-demo / java-1.5.0-ibm-devel / etc");
  }
}
