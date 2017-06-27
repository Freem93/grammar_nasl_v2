#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1620-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93159);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0651", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0668", "CVE-2016-2047");
  script_osvdb_id(133169, 133171, 133175, 133177, 133179, 133180, 133181, 133185, 133186, 133190, 133627, 137324, 137325, 137326, 137328, 137334, 137336, 137337, 137339, 137341, 137342, 137343, 137344, 137348, 137349);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : mariadb (SUSE-SU-2016:1620-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mariadb was updated to version 10.0.25 to fix 25 security issues.

These security issues were fixed :

  - CVE-2016-0505: Unspecified vulnerability allowed remote
    authenticated users to affect availability via unknown
    vectors related to Options (bsc#980904).

  - CVE-2016-0546: Unspecified vulnerability allowed local
    users to affect confidentiality, integrity, and
    availability via unknown vectors related to Client
    (bsc#980904).

  - CVE-2016-0596: Unspecified vulnerability allowed remote
    authenticated users to affect availability via vectors
    related to DML (bsc#980904).

  - CVE-2016-0597: Unspecified vulnerability allowed remote
    authenticated users to affect availability via unknown
    vectors related to Optimizer (bsc#980904).

  - CVE-2016-0598: Unspecified vulnerability allowed remote
    authenticated users to affect availability via vectors
    related to DML (bsc#980904).

  - CVE-2016-0600: Unspecified vulnerability allowed remote
    authenticated users to affect availability via unknown
    vectors related to InnoDB (bsc#980904).

  - CVE-2016-0606: Unspecified vulnerability allowed remote
    authenticated users to affect integrity via unknown
    vectors related to encryption (bsc#980904).

  - CVE-2016-0608: Unspecified vulnerability allowed remote
    authenticated users to affect availability via vectors
    related to UDF (bsc#980904).

  - CVE-2016-0609: Unspecified vulnerability allowed remote
    authenticated users to affect availability via unknown
    vectors related to privileges (bsc#980904).

  - CVE-2016-0616: Unspecified vulnerability allowed remote
    authenticated users to affect availability via unknown
    vectors related to Optimizer (bsc#980904).

  - CVE-2016-0640: Unspecified vulnerability allowed local
    users to affect integrity and availability via vectors
    related to DML (bsc#980904).

  - CVE-2016-0641: Unspecified vulnerability allowed local
    users to affect confidentiality and availability via
    vectors related to MyISAM (bsc#980904).

  - CVE-2016-0642: Unspecified vulnerability allowed local
    users to affect integrity and availability via vectors
    related to Federated (bsc#980904).

  - CVE-2016-0643: Unspecified vulnerability allowed local
    users to affect confidentiality via vectors related to
    DML (bsc#980904).

  - CVE-2016-0644: Unspecified vulnerability allowed local
    users to affect availability via vectors related to DDL
    (bsc#980904).

  - CVE-2016-0646: Unspecified vulnerability allowed local
    users to affect availability via vectors related to DML
    (bsc#980904).

  - CVE-2016-0647: Unspecified vulnerability allowed local
    users to affect availability via vectors related to FTS
    (bsc#980904).

  - CVE-2016-0648: Unspecified vulnerability allowed local
    users to affect availability via vectors related to PS
    (bsc#980904).

  - CVE-2016-0649: Unspecified vulnerability allowed local
    users to affect availability via vectors related to PS
    (bsc#980904).

  - CVE-2016-0650: Unspecified vulnerability allowed local
    users to affect availability via vectors related to
    Replication (bsc#980904).

  - CVE-2016-0651: Unspecified vulnerability allowed local
    users to affect availability via vectors related to
    Optimizer (bsc#980904).

  - CVE-2016-0655: Unspecified vulnerability allowed local
    users to affect availability via vectors related to
    InnoDB (bsc#980904).

  - CVE-2016-0666: Unspecified vulnerability allowed local
    users to affect availability via vectors related to
    Security: Privileges (bsc#980904).

  - CVE-2016-0668: Unspecified vulnerability allowed local
    users to affect availability via vectors related to
    InnoDB (bsc#980904).

  - CVE-2016-2047: The ssl_verify_server_cert function in
    sql-common/client.c did not properly verify that the
    server hostname matches a domain name in the subject's
    Common Name (CN) or subjectAltName field of the X.509
    certificate, which allowed man-in-the-middle attackers
    to spoof SSL servers via a '/CN=' string in a field in a
    certificate, as demonstrated by
    '/OU=/CN=bar.com/CN=foo.com (bsc#963806).

These non-security issues were fixed :

  - bsc#961935: Remove the leftovers of 'openSUSE' string in
    the '-DWITH_COMMENT' and 'DCOMPILATION_COMMENT' options

  - bsc#970287: remove ha_tokudb.so plugin and
    tokuft_logprint and tokuftdump binaries as TokuDB
    storage engine requires the jemalloc library that isn't
    present in SLE-12-SP1

  - bsc#970295: Fix the leftovers of 'logrotate.d/mysql'
    string in the logrotate error message. Occurrences of
    this string were changed to 'logrotate.d/mariadb'

  - bsc#963810: Add 'log-error' and 'secure-file-priv'
    configuration options

  - add '/etc/my.cnf.d/error_log.conf' that specifies
    'log-error = /var/log/mysql/mysqld.log'. If no path is
    set, the error log is written to
    '/var/lib/mysql/$HOSTNAME.err', which is not picked up
    by logrotate.

  - add '/etc/my.cnf.d/secure_file_priv.conf' which
    specifies that 'LOAD DATA', 'SELECT ... INTO' and 'LOAD
    FILE()' will only work with files in the directory
    specified by 'secure-file-priv' option
    (='/var/lib/mysql-files').

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0505.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0546.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0596.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0600.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0606.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0609.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0616.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0640.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0641.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0642.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0644.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0646.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0648.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0649.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0650.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0651.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0666.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0668.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2047.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161620-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36fdc8e5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2016-963=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-963=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-963=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-963=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libmysqlclient18-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libmysqlclient18-debuginfo-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mariadb-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mariadb-client-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mariadb-client-debuginfo-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mariadb-debuginfo-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mariadb-debugsource-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mariadb-errormessages-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mariadb-tools-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mariadb-tools-debuginfo-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libmysqlclient18-32bit-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libmysqlclient18-debuginfo-32bit-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmysqlclient18-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmysqlclient_r18-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mariadb-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mariadb-client-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mariadb-client-debuginfo-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mariadb-debuginfo-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mariadb-debugsource-10.0.25-6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mariadb-errormessages-10.0.25-6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
