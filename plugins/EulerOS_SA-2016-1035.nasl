#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99798);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2016-0640",
    "CVE-2016-0641",
    "CVE-2016-0643",
    "CVE-2016-0644",
    "CVE-2016-0646",
    "CVE-2016-0647",
    "CVE-2016-0648",
    "CVE-2016-0649",
    "CVE-2016-0650",
    "CVE-2016-0666",
    "CVE-2016-3452",
    "CVE-2016-3477",
    "CVE-2016-3521",
    "CVE-2016-3615",
    "CVE-2016-5440",
    "CVE-2016-5444"
  );
  script_osvdb_id(
    137324,
    137325,
    137326,
    137328,
    137336,
    137337,
    137339,
    137341,
    137342,
    137349,
    141889,
    141891,
    141898,
    141902,
    141903,
    141904
  );

  script_name(english:"EulerOS 2.0 SP1 : mariadb (EulerOS-SA-2016-1035)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the mariadb packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - MariaDB is a community developed branch of MySQL.
    MariaDB is a multi-user, multi-threaded SQL database
    server. It is a client/server implementation consisting
    of a server daemon (mysqld) and many different client
    programs and libraries. The base package contains the
    standard MariaDB/MySQL client programs and generic
    MySQL files.

  - Security Fix(es)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    integrity and availability via vectors related to
    DML.(CVE-2016-0640)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    confidentiality and availability via vectors related to
    MyISAM.(CVE-2016-0641)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows local users to affect
    confidentiality via vectors related to
    DML.(CVE-2016-0643)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    availability via vectors related to DDL.(CVE-2016-0644)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    availability via vectors related to DML.(CVE-2016-0646)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows local users to affect
    availability via vectors related to FTS.(CVE-2016-0647)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows local users to affect
    availability via vectors related to PS.(CVE-2016-0648)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    availability via vectors related to PS.(CVE-2016-0649)

  - Unspecified vulnerability in Oracle MySQL 5.5.47 and
    earlier, 5.6.28 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.48, 10.0.x before 10.0.24, and
    10.1.x before 10.1.12 allows local users to affect
    availability via vectors related to
    Replication.(CVE-2016-0650)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows local users to affect
    availability via vectors related to Security:
    Privileges.(CVE-2016-0666)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.10 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows remote attackers to affect
    confidentiality via vectors related to Server:
    Security: Encryption.(CVE-2016-3452)

  - Unspecified vulnerability in Oracle MySQL 5.5.49 and
    earlier, 5.6.30 and earlier, and 5.7.12 and earlier and
    MariaDB before 5.5.50, 10.0.x before 10.0.26, and
    10.1.x before 10.1.15 allows local users to affect
    confidentiality, integrity, and availability via
    vectors related to Server: Parser.(CVE-2016-3477)

  - Unspecified vulnerability in Oracle MySQL 5.5.49 and
    earlier, 5.6.30 and earlier, and 5.7.12 and earlier and
    MariaDB before 5.5.50, 10.0.x before 10.0.26, and
    10.1.x before 10.1.15 allows remote authenticated users
    to affect availability via vectors related to Server:
    Types.(CVE-2016-3521)

  - Unspecified vulnerability in Oracle MySQL 5.5.49 and
    earlier, 5.6.30 and earlier, and 5.7.12 and earlier and
    MariaDB before 5.5.50, 10.0.x before 10.0.26, and
    10.1.x before 10.1.15 allows remote authenticated users
    to affect availability via vectors related to Server:
    DML.(CVE-2016-3615)

  - Unspecified vulnerability in Oracle MySQL 5.5.49 and
    earlier, 5.6.30 and earlier, and 5.7.12 and earlier and
    MariaDB before 5.5.50, 10.0.x before 10.0.26, and
    10.1.x before 10.1.15 allows remote administrators to
    affect availability via vectors related to Server:
    RBR.(CVE-2016-5440)

  - Unspecified vulnerability in Oracle MySQL 5.5.48 and
    earlier, 5.6.29 and earlier, and 5.7.11 and earlier and
    MariaDB before 5.5.49, 10.0.x before 10.0.25, and
    10.1.x before 10.1.14 allows remote attackers to affect
    confidentiality via vectors related to Server:
    Connection.(CVE-2016-5444)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1035
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22e7de18");
  script_set_attribute(attribute:"solution", value:
"Update the affected mariadb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["mariadb-5.5.50-1",
        "mariadb-bench-5.5.50-1",
        "mariadb-devel-5.5.50-1",
        "mariadb-embedded-5.5.50-1",
        "mariadb-libs-5.5.50-1",
        "mariadb-server-5.5.50-1",
        "mariadb-test-5.5.50-1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
