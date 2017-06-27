#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0857. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82909);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 16:01:51 $");

  script_cve_id("CVE-2005-1080", "CVE-2015-0458", "CVE-2015-0459", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0484", "CVE-2015-0488", "CVE-2015-0491", "CVE-2015-0492");
  script_bugtraq_id(13083, 74072, 74083, 74094, 74097, 74104, 74111, 74119, 74129, 74135, 74141, 74147);
  script_osvdb_id(15435, 120702, 120703, 120704, 120705, 120706, 120709, 120710, 120712, 120713, 120714);
  script_xref(name:"RHSA", value:"2015:0857");

  script_name(english:"RHEL 5 / 6 / 7 : java-1.7.0-oracle (RHSA-2015:0857)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-oracle packages that fix several security issues
are now available for Oracle Java for Red Hat Enterprise Linux 5, 6,
and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Oracle Java SE version 7 includes the Oracle Java Runtime Environment
and the Oracle Java Software Development Kit.

This update fixes several vulnerabilities in the Oracle Java Runtime
Environment and the Oracle Java Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch Update Advisory page, listed in the References section.
(CVE-2005-1080, CVE-2015-0458, CVE-2015-0459, CVE-2015-0460,
CVE-2015-0469, CVE-2015-0477, CVE-2015-0478, CVE-2015-0480,
CVE-2015-0484, CVE-2015-0488, CVE-2015-0491, CVE-2015-0492)

The CVE-2015-0478 issue was discovered by Florian Weimer of Red Hat
Product Security.

All users of java-1.7.0-oracle are advised to upgrade to these updated
packages, which provide Oracle Java 7 Update 79 and resolve these
issues. All running instances of Oracle Java must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-1080.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0460.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0484.html"
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
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0492.html"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef68d9ef"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0857.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-javafx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/21");
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
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0857";
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
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-devel-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-javafx-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-jdbc-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-plugin-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-src-1.7.0.79-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.79-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-javafx-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-jdbc-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-plugin-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-src-1.7.0.79-1jpp.1.el6_6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.79-1jpp.1.el6_6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.79-1jpp.1.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.79-1jpp.1.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.79-1jpp.1.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.79-1jpp.1.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.79-1jpp.1.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.79-1jpp.1.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.79-1jpp.1.el7_1")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.79-1jpp.1.el7_1")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-oracle / java-1.7.0-oracle-devel / etc");
  }
}
