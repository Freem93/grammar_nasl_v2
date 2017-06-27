#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1020. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83753);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2005-1080", "CVE-2015-0138", "CVE-2015-0192", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-1914", "CVE-2015-2808");
  script_bugtraq_id(13083, 73326, 73684, 74072, 74083, 74094, 74104, 74111, 74119, 74141, 74147, 74545, 74645);
  script_osvdb_id(15435, 117855, 119390, 120702, 120705, 120709, 120710, 120712, 120713, 120714, 121762, 121763);
  script_xref(name:"RHSA", value:"2015:1020");

  script_name(english:"RHEL 6 / 7 : java-1.7.1-ibm (RHSA-2015:1020) (Bar Mitzvah)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.1-ibm packages that fix several security issues are
now available for Red Hat Enterprise Linux 6 and 7 Supplementary.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

IBM Java SE version 7 Release 1 includes the IBM Java Runtime
Environment and the IBM Java Software Development Kit.

This update fixes several vulnerabilities in the IBM Java Runtime
Environment and the IBM Java Software Development Kit. Further
information about these flaws can be found on the IBM Java Security
alerts page, listed in the References section. (CVE-2005-1080,
CVE-2015-0138, CVE-2015-0192, CVE-2015-0458, CVE-2015-0459,
CVE-2015-0469, CVE-2015-0477, CVE-2015-0478, CVE-2015-0480,
CVE-2015-0488, CVE-2015-0491, CVE-2015-1914, CVE-2015-2808)

The CVE-2015-0478 issue was discovered by Florian Weimer of Red Hat
Product Security.

Note: With this update, the IBM JDK now disables RC4 SSL/TLS cipher
suites by default to address the CVE-2015-2808 issue. Refer to Red Hat
Bugzilla bug 1207101, linked to in the References section, for
additional details about this change.

All users of java-1.7.1-ibm are advised to upgrade to these updated
packages, containing the IBM Java SE 7R1 SR3 release. All running
instances of IBM Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0491.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-1914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1207101#c4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1020.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.1-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1020";
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
  if (rpm_check(release:"RHEL6", reference:"java-1.7.1-ibm-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-demo-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-demo-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-demo-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.7.1-ibm-devel-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-plugin-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-plugin-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.1-ibm-src-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.7.1-ibm-src-1.7.1.3.0-1jpp.2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.1-ibm-src-1.7.1.3.0-1jpp.2.el6_6")) flag++;


  if (rpm_check(release:"RHEL7", reference:"java-1.7.1-ibm-1.7.1.3.0-1jpp.2.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-demo-1.7.1.3.0-1jpp.2.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-demo-1.7.1.3.0-1jpp.2.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.7.1-ibm-devel-1.7.1.3.0-1jpp.2.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.0-1jpp.2.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-jdbc-1.7.1.3.0-1jpp.2.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-plugin-1.7.1.3.0-1jpp.2.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.1-ibm-src-1.7.1.3.0-1jpp.2.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.1-ibm-src-1.7.1.3.0-1jpp.2.el7_1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.1-ibm / java-1.7.1-ibm-demo / java-1.7.1-ibm-devel / etc");
  }
}
