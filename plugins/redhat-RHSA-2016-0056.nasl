#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0056. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88075);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/01/10 20:34:11 $");

  script_cve_id("CVE-2015-7575", "CVE-2015-8126", "CVE-2015-8472", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_osvdb_id(130175, 132305, 133156, 133157, 133159, 133160, 133161);
  script_xref(name:"RHSA", value:"2016:0056");

  script_name(english:"RHEL 5 / 6 / 7 : java-1.7.0-oracle (RHSA-2016:0056) (SLOTH)");
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
(CVE-2015-7575, CVE-2015-8126, CVE-2015-8472, CVE-2016-0402,
CVE-2016-0448, CVE-2016-0466, CVE-2016-0483, CVE-2016-0494)

Note: This update also disallows the use of the MD5 hash algorithm in
the certification path processing. The use of MD5 can be re-enabled by
removing MD5 from the jdk.certpath.disabledAlgorithms security
property defined in the java.security file.

All users of java-1.7.0-oracle are advised to upgrade to these updated
packages, which provide Oracle Java 7 Update 95 and resolve these
issues. All running instances of Oracle Java must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-7575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-8126.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-8472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0448.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0466.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0494.html"
  );
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54e827c2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0056.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2016:0056";
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
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-devel-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-javafx-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-jdbc-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-plugin-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.7.0-oracle-src-1.7.0.95-1jpp.1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.95-1jpp.1.el5_11")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-javafx-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-jdbc-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-plugin-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-src-1.7.0.95-1jpp.1.el6_7")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.95-1jpp.1.el6_7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.95-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.95-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.95-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.95-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-javafx-1.7.0.95-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.95-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.95-1jpp.2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.95-1jpp.2.el7")) flag++;

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
