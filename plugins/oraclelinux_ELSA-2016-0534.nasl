#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:0534 and 
# Oracle Linux Security Advisory ELSA-2016-0534 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(90296);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/07 21:08:17 $");

  script_cve_id("CVE-2015-4792", "CVE-2015-4802", "CVE-2015-4815", "CVE-2015-4816", "CVE-2015-4819", "CVE-2015-4826", "CVE-2015-4830", "CVE-2015-4836", "CVE-2015-4858", "CVE-2015-4861", "CVE-2015-4870", "CVE-2015-4879", "CVE-2015-4913", "CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-0642", "CVE-2016-0651", "CVE-2016-2047");
  script_osvdb_id(129164, 129165, 129167, 129171, 129173, 129174, 129176, 129177, 129179, 129181, 129186, 129189, 129190, 130156, 130157, 130158, 130160, 130161, 130162, 130163, 130164, 130165, 130166, 133169, 133171, 133175, 133177, 133179, 133180, 133181, 133185, 133186, 133190, 133627);
  script_xref(name:"RHSA", value:"2016:0534");

  script_name(english:"Oracle Linux 7 : mariadb (ELSA-2016-0534)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:0534 :

An update for mariadb is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

MariaDB is a multi-user, multi-threaded SQL database server that is
binary compatible with MySQL.

The following packages have been upgraded to a newer upstream version:
MariaDB (5.5.47). Refer to the MariaDB Release Notes listed in the
References section for a complete list of changes.

Security Fix(es) :

* It was found that the MariaDB client library did not properly check
host names against server identities noted in the X.509 certificates
when establishing secure connections using TLS/SSL. A
man-in-the-middle attacker could possibly use this flaw to impersonate
a server to a client. (CVE-2016-2047)

* This update fixes several vulnerabilities in the MariaDB database
server. Information about these flaws can be found on the Oracle
Critical Patch Update Advisory page, listed in the References section.
(CVE-2015-4792, CVE-2015-4802, CVE-2015-4815, CVE-2015-4816,
CVE-2015-4819, CVE-2015-4826, CVE-2015-4830, CVE-2015-4836,
CVE-2015-4858, CVE-2015-4861, CVE-2015-4870, CVE-2015-4879,
CVE-2015-4913, CVE-2016-0505, CVE-2016-0546, CVE-2016-0596,
CVE-2016-0597, CVE-2016-0598, CVE-2016-0600, CVE-2016-0606,
CVE-2016-0608, CVE-2016-0609, CVE-2016-0616)

Bug Fix(es) :

* When more than one INSERT operation was executed concurrently on a
non-empty InnoDB table with an AUTO_INCREMENT column defined as a
primary key immediately after starting MariaDB, a race condition could
occur. As a consequence, one of the concurrent INSERT operations
failed with a 'Duplicate key' error message. A patch has been applied
to prevent the race condition. Now, each row inserted as a result of
the concurrent INSERT operations receives a unique primary key, and
the operations no longer fail in this scenario. (BZ#1303946)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-March/005915.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-5.5.47-1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-bench-5.5.47-1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-devel-5.5.47-1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-embedded-5.5.47-1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-embedded-devel-5.5.47-1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-libs-5.5.47-1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-server-5.5.47-1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mariadb-test-5.5.47-1.el7_2")) flag++;


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
