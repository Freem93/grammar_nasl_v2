#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1861 and 
# Oracle Linux Security Advisory ELSA-2014-1861 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79370);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 19:01:51 $");

  script_cve_id("CVE-2012-5615", "CVE-2014-2494", "CVE-2014-4207", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6484", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559");
  script_bugtraq_id(66835, 66846, 66850, 66858, 66875, 66880, 66890, 66896, 69732, 70446, 70451, 70455, 70462, 70486, 70487, 70510, 70511, 70516, 70517, 70530, 70532, 70550);
  script_osvdb_id(88067, 109156, 109157, 109158, 109160, 109164, 109726, 113252, 113255, 113256, 113257, 113259, 113264, 113265, 113266, 113267, 113269, 113271, 113272);
  script_xref(name:"RHSA", value:"2014:1861");

  script_name(english:"Oracle Linux 7 : mariadb (ELSA-2014-1861)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1861 :

Updated mariadb packages that fix several security issues are now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

MariaDB is a multi-user, multi-threaded SQL database server that is
binary compatible with MySQL.

This update fixes several vulnerabilities in the MariaDB database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2014-2494, CVE-2014-4207, CVE-2014-4243, CVE-2014-4258,
CVE-2014-4260, CVE-2014-4287, CVE-2014-4274, CVE-2014-6463,
CVE-2014-6464, CVE-2014-6469, CVE-2014-6484, CVE-2014-6505,
CVE-2014-6507, CVE-2014-6520, CVE-2014-6530, CVE-2014-6551,
CVE-2014-6555, CVE-2014-6559)

These updated packages upgrade MariaDB to version 5.5.40. Refer to the
MariaDB Release Notes listed in the References section for a complete
list of changes.

All MariaDB users should upgrade to these updated packages, which
correct these issues. After installing this update, the MariaDB server
daemon (mysqld) will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-November/004646.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-bench-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-devel-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-embedded-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-libs-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-server-5.5.40-1.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-test-5.5.40-1.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb / mariadb-bench / mariadb-devel / mariadb-embedded / etc");
}
