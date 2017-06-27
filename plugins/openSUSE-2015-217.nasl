#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-217.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81761);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/12 14:23:03 $");

  script_cve_id("CVE-2015-1027");

  script_name(english:"openSUSE Security Update : percona-toolkit / xtrabackup (openSUSE-2015-217)");
  script_summary(english:"Check for the openSUSE-2015-217 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Percona Toolkit and XtraBackup were updated to fix bugs and security
issues.

Percona XtraBackup was vulnerable to MITM attack which could allow
exfiltration of MySQL configuration information via the
--version-check option. [boo#919298] CVE-2015-1027 lp#1408375.

The openSUSE package has the version check disabled by default.

Percona Toolkit was updated to 2.2.13 :

  - Feature lp#1391240: pt-kill added query fingerprint hash
    to output

  - Fixed lp#1402668: pt-mysql-summary fails on cluster in
    Donor/Desynced status 

  - Fixed lp#1396870: pt-online-schema-change CTRL+C leaves
    terminal in inconsistent state 

  - Fixed lp#1396868: pt-online-schema-change --ask-pass
    option error

  - Fixed lp#1266869: pt-stalk fails to start if $HOME
    environment variable is not set 

  - Fixed lp#1019479: pt-table-checksum does not work with
    sql_mode ONLY_FULL_GROUP_BY

  - Fixed lp#1394934: pt-table-checksum error in debug mode

  - Fixed lp#1321297: pt-table-checksum reports diffs on
    timestamp columns in 5.5 vs 5.6 

  - Fixed lp#1399789: pt-table-checksum fails to find pxc
    nodes when wsrep_node_incoming_address is set to AUTO

  - Fixed lp#1388870: pt-table-checksum has some errors with
    different time zones

  - Fixed lp#1408375: vulnerable to MITM attack which would
    allow exfiltration of MySQL configuration information
    via --version-check [boo#919298] [CVE-2015-1027]

  - Fixed lp#1404298: missing MySQL5.7 test files for
    pt-table-checksum

  - Fixed lp#1403900: added sandbox and fixed sakila test db
    for 5.7

Percona XtraBackup was updated to version 2.2.9 :

  - xtrabackup_galera_info file isn't overwritten during the
    Galera auto-recovery. lp#1418584.

  - Percona XtraBackup now sets the maximum supported
    session value for lock_wait_timeout variable to prevent
    unnecessary timeouts when the global value is changed
    from the default. lp#1410339.

  - New option --backup-locks, enabled by default, has been
    implemented to control if backup locks will be used even
    if they are supported by the server. To disable backup
    locks innobackupex should be run with innobackupex
    --no-backup-locks option. lp#1418820."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919298"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected percona-toolkit / xtrabackup packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:percona-toolkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"percona-toolkit-2.2.13-2.14.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-2.1.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-debuginfo-2.1.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-debugsource-2.1.8-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"percona-toolkit-2.2.13-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtrabackup-2.2.9-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtrabackup-debuginfo-2.2.9-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtrabackup-debugsource-2.2.9-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtrabackup-test-2.2.9-4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "percona-toolkit / xtrabackup / xtrabackup-debuginfo / etc");
}
