#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1462. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62923);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2012-0540", "CVE-2012-1688", "CVE-2012-1689", "CVE-2012-1690", "CVE-2012-1703", "CVE-2012-1734", "CVE-2012-2749", "CVE-2012-3150", "CVE-2012-3158", "CVE-2012-3160", "CVE-2012-3163", "CVE-2012-3166", "CVE-2012-3167", "CVE-2012-3173", "CVE-2012-3177", "CVE-2012-3180", "CVE-2012-3197");
  script_bugtraq_id(53058, 53067, 53074, 54540, 54547, 54551, 55120, 55990, 56003, 56005, 56017, 56018, 56021, 56027, 56028, 56036, 56041);
  script_osvdb_id(81373, 81376, 81378, 83976, 83979, 83980, 84755, 86260, 86261, 86262, 86264, 86265, 86267, 86268, 86271, 86272, 86273);
  script_xref(name:"RHSA", value:"2012:1462");

  script_name(english:"RHEL 6 : mysql (RHSA-2012:1462)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix several security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

This update fixes several vulnerabilities in the MySQL database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory pages, listed in the References
section. (CVE-2012-1688, CVE-2012-1690, CVE-2012-1703, CVE-2012-2749,
CVE-2012-0540, CVE-2012-1689, CVE-2012-1734, CVE-2012-3163,
CVE-2012-3158, CVE-2012-3177, CVE-2012-3166, CVE-2012-3173,
CVE-2012-3150, CVE-2012-3180, CVE-2012-3167, CVE-2012-3197,
CVE-2012-3160)

These updated packages upgrade MySQL to version 5.1.66. Refer to the
MySQL release notes listed in the References section for a full list
of changes.

All MySQL users should upgrade to these updated packages, which
correct these issues. After installing this update, the MySQL server
daemon (mysqld) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1688.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1703.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1734.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3150.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3173.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3197.html"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0bd5117"
  );
  # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5c32e24"
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html#
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?687fd865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-62.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-63.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-64.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-65.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-66.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1462.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1462";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mysql-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mysql-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mysql-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mysql-bench-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mysql-bench-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mysql-bench-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mysql-debuginfo-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mysql-devel-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mysql-embedded-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mysql-embedded-devel-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mysql-libs-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mysql-server-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mysql-server-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mysql-server-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mysql-test-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mysql-test-5.1.66-1.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mysql-test-5.1.66-1.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-debuginfo / mysql-devel / etc");
  }
}
