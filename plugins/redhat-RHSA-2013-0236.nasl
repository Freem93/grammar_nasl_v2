#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0236. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64467);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/13 15:25:21 $");

  script_cve_id("CVE-2012-1541", "CVE-2012-3213", "CVE-2012-3342", "CVE-2013-0351", "CVE-2013-0409", "CVE-2013-0419", "CVE-2013-0423", "CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0430", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0438", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0445", "CVE-2013-0446", "CVE-2013-0450", "CVE-2013-1473", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-1481");
  script_bugtraq_id(57686, 57687, 57689, 57691, 57692, 57694, 57696, 57697, 57699, 57700, 57702, 57703, 57708, 57709, 57710, 57711, 57713, 57714, 57715, 57716, 57717, 57718, 57720, 57722, 57724, 57727, 57728, 57729, 57730, 57731);
  script_osvdb_id(89758, 89759, 89760, 89761, 89762, 89763, 89764, 89765, 89766, 89767, 89769, 89771, 89772, 89773, 89774, 89786, 89787, 89788, 89790, 89791, 89792, 89794, 89795, 89796, 89797, 89798, 89800, 89801, 89802, 89803, 89804, 89806);
  script_xref(name:"RHSA", value:"2013:0236");

  script_name(english:"RHEL 5 / 6 : java-1.6.0-sun (RHSA-2013:0236)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-sun packages that fix several security issues are
now available for Red Hat Enterprise Linux 5 and 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Oracle Java SE version 6 includes the Oracle Java Runtime Environment
and the Oracle Java Software Development Kit.

This update fixes several vulnerabilities in the Oracle Java Runtime
Environment and the Oracle Java Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch Update Advisory page, listed in the References section.
(CVE-2012-1541, CVE-2012-3213, CVE-2012-3342, CVE-2013-0351,
CVE-2013-0409, CVE-2013-0419, CVE-2013-0423, CVE-2013-0424,
CVE-2013-0425, CVE-2013-0426, CVE-2013-0427, CVE-2013-0428,
CVE-2013-0429, CVE-2013-0430, CVE-2013-0432, CVE-2013-0433,
CVE-2013-0434, CVE-2013-0435, CVE-2013-0438, CVE-2013-0440,
CVE-2013-0441, CVE-2013-0442, CVE-2013-0443, CVE-2013-0445,
CVE-2013-0446, CVE-2013-0450, CVE-2013-1473, CVE-2013-1475,
CVE-2013-1476, CVE-2013-1478, CVE-2013-1480, CVE-2013-1481)

All users of java-1.6.0-sun are advised to upgrade to these updated
packages, which provide Oracle Java 6 Update 39. All running instances
of Oracle Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0351.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0409.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0425.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0426.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0427.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0428.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0430.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0443.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0445.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0450.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1475.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1476.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1481.html"
  );
  # http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a915dbbd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0236.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-demo-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-devel-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-jdbc-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-plugin-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-src-1.6.0.39-1jpp.4.el5_9")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.39-1jpp.4.el5_9")) flag++;


if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-demo-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-devel-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-jdbc-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-plugin-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-src-1.6.0.39-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.39-1jpp.1.el6_3")) flag++;



if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-sun / java-1.6.0-sun-demo / java-1.6.0-sun-devel / etc");
}
