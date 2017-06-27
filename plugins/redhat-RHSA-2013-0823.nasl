#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0823. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66440);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2017/01/05 16:29:43 $");

  script_cve_id("CVE-2013-0169", "CVE-2013-0401", "CVE-2013-1491", "CVE-2013-1537", "CVE-2013-1540", "CVE-2013-1557", "CVE-2013-1563", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2394", "CVE-2013-2417", "CVE-2013-2418", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2422", "CVE-2013-2424", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2432", "CVE-2013-2433", "CVE-2013-2435", "CVE-2013-2440");
  script_bugtraq_id(57778, 58493, 58507, 59089, 59124, 59131, 59145, 59149, 59154, 59159, 59166, 59167, 59170, 59172, 59179, 59184, 59187, 59190, 59194, 59208, 59220, 59228, 59243);
  script_osvdb_id(89848, 91204, 91206, 92335, 92336, 92337, 92338, 92339, 92340, 92342, 92343, 92344, 92349, 92350, 92351, 92353, 92354, 92356, 92360, 92361, 92362, 92363, 92366);
  script_xref(name:"RHSA", value:"2013:0823");

  script_name(english:"RHEL 5 / 6 : java-1.6.0-ibm (RHSA-2013:0823)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 5 and 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

IBM Java SE version 6 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update fixes several vulnerabilities in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Detailed
vulnerability descriptions are linked from the IBM Security alerts
page, listed in the References section. (CVE-2013-0169, CVE-2013-0401,
CVE-2013-1491, CVE-2013-1537, CVE-2013-1540, CVE-2013-1557,
CVE-2013-1563, CVE-2013-1569, CVE-2013-2383, CVE-2013-2384,
CVE-2013-2394, CVE-2013-2417, CVE-2013-2418, CVE-2013-2419,
CVE-2013-2420, CVE-2013-2422, CVE-2013-2424, CVE-2013-2429,
CVE-2013-2430, CVE-2013-2432, CVE-2013-2433, CVE-2013-2435,
CVE-2013-2440)

All users of java-1.6.0-ibm are advised to upgrade to these updated
packages, containing the IBM Java SE 6 SR13-FP2 release. All running
instances of IBM Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0169.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2394.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2417.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0823.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");
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
if (! ereg(pattern:"^(5\.9|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.9 / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0823";
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
  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"java-1.6.0-ibm-accessibility-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"s390x", reference:"java-1.6.0-ibm-accessibility-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"java-1.6.0-ibm-accessibility-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-demo-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-devel-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"java-1.6.0-ibm-javacomm-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-jdbc-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"java-1.6.0-ibm-plugin-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"x86_64", reference:"java-1.6.0-ibm-plugin-1.6.0.13.2-1jpp.1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", reference:"java-1.6.0-ibm-src-1.6.0.13.2-1jpp.1.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-demo-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-demo-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-demo-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.6.0-ibm-devel-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-javacomm-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-javacomm-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-jdbc-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-jdbc-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-jdbc-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-plugin-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-plugin-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-ibm-src-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.6.0-ibm-src-1.6.0.13.2-1jpp.1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-ibm-src-1.6.0.13.2-1jpp.1.el6_4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-ibm / java-1.6.0-ibm-accessibility / java-1.6.0-ibm-demo / etc");
  }
}
