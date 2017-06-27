#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0770. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49990);
  script_version ("$Revision: 1.27 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-1321", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574");
  script_bugtraq_id(40235, 43965, 43971, 43979, 43985, 43988, 43992, 43994, 43999, 44009, 44011, 44012, 44013, 44014, 44016, 44017, 44020, 44021, 44023, 44024, 44026, 44027, 44028, 44030, 44032, 44035, 44038, 44040);
  script_osvdb_id(68873, 69033, 69034, 69035, 69036, 69037, 69038, 69040, 69041, 69042, 69043, 69044, 69045, 69046, 69047, 69048, 69049, 69050, 69051, 69052, 69053, 69055, 69056, 69057, 69058, 69059);
  script_xref(name:"RHSA", value:"2010:0770");

  script_name(english:"RHEL 4 / 5 : java-1.6.0-sun (RHSA-2010:0770)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-sun packages that fix several security issues are
now available for Red Hat Enterprise Linux 4 Extras and 5
Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Sun 1.6.0 Java release includes the Sun Java 6 Runtime Environment
and the Sun Java 6 Software Development Kit.

This update fixes several vulnerabilities in the Sun Java 6 Runtime
Environment and the Sun Java 6 Software Development Kit. Further
information about these flaws can be found on the 'Oracle Java SE and
Java for Business Critical Patch Update Advisory' page, listed in the
References section. (CVE-2010-1321, CVE-2010-3541, CVE-2010-3548,
CVE-2010-3549, CVE-2010-3550, CVE-2010-3551, CVE-2010-3552,
CVE-2010-3553, CVE-2010-3554, CVE-2010-3555, CVE-2010-3556,
CVE-2010-3557, CVE-2010-3558, CVE-2010-3559, CVE-2010-3560,
CVE-2010-3561, CVE-2010-3562, CVE-2010-3563, CVE-2010-3565,
CVE-2010-3566, CVE-2010-3567, CVE-2010-3568, CVE-2010-3569,
CVE-2010-3570, CVE-2010-3571, CVE-2010-3572, CVE-2010-3573,
CVE-2010-3574)

The RHSA-2010:0337 update mitigated a man-in-the-middle attack in the
way the TLS/SSL (Transport Layer Security/Secure Sockets Layer)
protocols handle session renegotiation by disabling renegotiation.
This update implements the TLS Renegotiation Indication Extension as
defined in RFC 5746, allowing secure renegotiation between updated
clients and servers. (CVE-2009-3555)

Users of java-1.6.0-sun should upgrade to these updated packages,
which correct these issues. All running instances of Sun Java must be
restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1321.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3552.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3553.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3560.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3561.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3567.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3574.html"
  );
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2010-176258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc96963b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/kb/docs/DOC-20491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0770.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start BasicServiceImpl Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2010:0770";
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
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.6.0-sun-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.6.0-sun-demo-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.6.0-sun-devel-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.6.0-sun-jdbc-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.6.0-sun-plugin-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.6.0-sun-src-1.6.0.22-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.22-1jpp.1.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-demo-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-devel-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-jdbc-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-plugin-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-src-1.6.0.22-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.22-1jpp.1.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-sun / java-1.6.0-sun-demo / java-1.6.0-sun-devel / etc");
  }
}
