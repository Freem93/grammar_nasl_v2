#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0210. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40718);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/01/03 17:16:33 $");

  script_cve_id("CVE-2008-0657", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
  script_bugtraq_id(27650, 28083, 28125);
  script_osvdb_id(42599);
  script_xref(name:"RHSA", value:"2008:0210");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-ibm (RHSA-2008:0210)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.5.0-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 4 Extras and 5
Supplementary.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

IBM's 1.5.0 Java release includes the IBM Java 2 Runtime Environment
and the IBM Java 2 Software Development Kit.

Two vulnerabilities in the Java Runtime Environment allowed an
untrusted application or applet to elevate the assigned privileges.
This could be misused by a malicious website to read and write local
files or execute local applications in the context of the user running
the Java process. (CVE-2008-0657)

A flaw was found in the Java XSLT processing classes. An untrusted
application or applet could cause a denial of service, or execute
arbitrary code with the permissions of the user running the JRE.
(CVE-2008-1187)

Several buffer overflow flaws were found in Java Web Start (JWS). An
untrusted JNLP application could access local files or execute local
applications accessible to the user running the JRE. (CVE-2008-1188,
CVE-2008-1189, CVE-2008-1190, CVE-2008-1196)

A flaw was found in the Java Plug-in. A remote attacker could bypass
the same origin policy, executing arbitrary code with the permissions
of the user running the JRE. (CVE-2008-1192)

A flaw was found in the JRE image parsing libraries. An untrusted
application or applet could cause a denial of service, or possible
execute arbitrary code with the permissions of the user running the
JRE. (CVE-2008-1193)

A flaw was found in the JRE color management library. An untrusted
application or applet could trigger a denial of service (JVM crash).
(CVE-2008-1194)

The JRE allowed untrusted JavaScript code to create local network
connections by the use of Java APIs. A remote attacker could use these
flaws to access local network services. (CVE-2008-1195)

All users of java-ibm-1.5.0 are advised to upgrade to these updated
packages, that contain IBM's 1.5.0 SR7 Java release which resolves
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-0657.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1189.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1190.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1193.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0210.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2008:0210";
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
  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-1.5.0.7-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-demo-1.5.0.7-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-devel-1.5.0.7-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-javacomm-1.5.0.7-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.7-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-jdbc-1.5.0.7-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.7-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-plugin-1.5.0.7-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-src-1.5.0.7-1jpp.2.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-accessibility-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.5.0-ibm-accessibility-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-ibm-accessibility-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-demo-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-devel-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-javacomm-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-jdbc-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-plugin-1.5.0.7-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-src-1.5.0.7-1jpp.2.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.5.0-ibm / java-1.5.0-ibm-accessibility / java-1.5.0-ibm-demo / etc");
  }
}
