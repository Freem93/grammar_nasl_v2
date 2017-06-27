#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0873. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50641);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2010-1321", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3559", "CVE-2010-3562", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574");
  script_bugtraq_id(40235, 43971, 43979, 43985, 43988, 44009, 44011, 44012, 44016, 44017, 44026, 44027, 44028, 44030, 44032, 44040);
  script_osvdb_id(64744, 69033, 69034, 69035, 69036, 69038, 69039, 69041, 69044, 69049, 69050, 69053, 69055, 69056, 69057, 69058, 69059);
  script_xref(name:"RHSA", value:"2010:0873");

  script_name(english:"RHEL 6 : java-1.5.0-ibm (RHSA-2010:0873)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.5.0-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The IBM 1.5.0 Java release includes the IBM Java 2 Runtime Environment
and the IBM Java 2 Software Development Kit.

This update fixes several vulnerabilities in the IBM Java 2 Runtime
Environment and the IBM Java 2 Software Development Kit. Detailed
vulnerability descriptions are linked from the IBM 'Security alerts'
page, listed in the References section. (CVE-2010-1321, CVE-2010-3541,
CVE-2010-3548, CVE-2010-3549, CVE-2010-3550, CVE-2010-3551,
CVE-2010-3556, CVE-2010-3559, CVE-2010-3562, CVE-2010-3565,
CVE-2010-3566, CVE-2010-3568, CVE-2010-3569, CVE-2010-3572,
CVE-2010-3573, CVE-2010-3574)

All users of java-1.5.0-ibm are advised to upgrade to these updated
packages, containing the IBM 1.5.0 SR12-FP2 Java release. All running
instances of IBM Java must be restarted for this update to take
effect."
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
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3562.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3569.html"
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
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0873.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-javacomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/18");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0873";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.5.0-ibm-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.5.0-ibm-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-demo-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.5.0-ibm-demo-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.5.0-ibm-demo-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.5.0-ibm-devel-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-javacomm-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.5.0-ibm-javacomm-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.5.0-ibm-src-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.5.0-ibm-src-1.5.0.12.2-1jpp.1.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.5.0-ibm-src-1.5.0.12.2-1jpp.1.el6")) flag++;


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
