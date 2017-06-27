#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1647. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43079);
  script_version ("$Revision: 1.27 $");
  script_cvs_date("$Date: 2017/01/03 17:27:03 $");

  script_cve_id("CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2010-0079");
  script_bugtraq_id(36881);
  script_osvdb_id(59711);
  script_xref(name:"RHSA", value:"2009:1647");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-ibm (RHSA-2009:1647)");
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

The IBM 1.5.0 Java release includes the IBM Java 2 Runtime Environment
and the IBM Java 2 Software Development Kit.

This update fixes several vulnerabilities in the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit. These
vulnerabilities are summarized on the IBM 'Security alerts' page
listed in the References section. (CVE-2009-3867, CVE-2009-3868,
CVE-2009-3869, CVE-2009-3871, CVE-2009-3872, CVE-2009-3873,
CVE-2009-3874, CVE-2009-3875, CVE-2009-3876, CVE-2009-3877)

All users of java-1.5.0-ibm are advised to upgrade to these updated
packages, containing the IBM 1.5.0 SR11 Java release. All running
instances of IBM Java must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3868.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3869.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3873.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3875.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3877.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1647.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 310, 399);

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/09");
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
  rhsa = "RHSA-2009:1647";
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
  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-1.5.0.11-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-demo-1.5.0.11-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-devel-1.5.0.11-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-javacomm-1.5.0.11-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.11-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-jdbc-1.5.0.11-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.11-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.5.0-ibm-plugin-1.5.0.11-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"java-1.5.0-ibm-src-1.5.0.11-1jpp.1.el4")) flag++;


  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-accessibility-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"java-1.5.0-ibm-accessibility-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-ibm-accessibility-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-demo-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-devel-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-javacomm-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-jdbc-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390", reference:"java-1.5.0-ibm-jdbc-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.5.0-ibm-plugin-1.5.0.11-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"java-1.5.0-ibm-src-1.5.0.11-1jpp.1.el5")) flag++;


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
