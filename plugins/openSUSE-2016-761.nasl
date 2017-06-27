#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-761.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91794);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:12 $");

  script_cve_id("CVE-2016-0505", "CVE-2016-0546", "CVE-2016-0596", "CVE-2016-0597", "CVE-2016-0598", "CVE-2016-0600", "CVE-2016-0606", "CVE-2016-0608", "CVE-2016-0609", "CVE-2016-0616", "CVE-2016-0640", "CVE-2016-0641", "CVE-2016-0642", "CVE-2016-0643", "CVE-2016-0644", "CVE-2016-0646", "CVE-2016-0647", "CVE-2016-0648", "CVE-2016-0649", "CVE-2016-0650", "CVE-2016-0651", "CVE-2016-0655", "CVE-2016-0666", "CVE-2016-0668", "CVE-2016-2047");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2016-761)");
  script_summary(english:"Check for the openSUSE-2016-761 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
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

  - Temporarily disable OQGraph. It seems to need the boost
    library with the version not earlier than 1.40 and not
    later than 1.55 (MDEV-9479)

  - boo#979524: Don't remove HandlerSocket plugin 

  - boo#970287: Add 'BuildRequires: jemalloc-devel' in order
    to allow enabling of the TokuDB plugin 

  - run 'usermod -g mysql mysql' only if mysql user is not
    in mysql group. Run 'usermod -s /bin/false/ mysql' only
    if mysql user doesn't have '/bin/false' shell set.

  - Re-enable profiling support"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980904"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqlclient_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysqld18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mariadb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient-devel-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient18-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient18-debuginfo-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient_r18-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld-devel-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld18-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld18-debuginfo-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-bench-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-bench-debuginfo-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-client-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-client-debuginfo-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-debuginfo-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-debugsource-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-errormessages-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-test-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-test-debuginfo-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-tools-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-tools-debuginfo-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.25-2.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.25-2.24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient18 / libmysqlclient18-32bit / etc");
}
