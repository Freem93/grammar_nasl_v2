#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-963.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75227);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-6394");

  script_name(english:"openSUSE Security Update : xtrabackup (openSUSE-SU-2013:1864-1)");
  script_summary(english:"Check for the openSUSE-2013-963 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Percona XtraBackup was updated to 2.1.6 [bnc#852224]

  - New Features :

  - New innobackupex --force-non-empty-directories option

  - now supports logs created with the new log block
    checksums

  - New Features specific to MySQL 5.6: option
    innodb_log_checksum_algorithm in Percona Server 5.6

  - Bugs Fixed :

  - innobackupex --copy-back fails on empty
    innodb_data_home_dir

  - A fixed initialization vector (constant string) was used
    while encrypting the data. This opened the encrypted
    stream/data to plaintext attacks among others.
    CVE-2013-6394

  - innobackupex --version-check is now on by default.

  - Since Version Check is enabled by default, new optin 

    --no-version-check option has been introduced to disable
    it.

  - xtrabackup_slave_info didn't contain any GTID
    information, which could cause master_auto_position not
    to work properly

  - now supports absolute paths in innodb_data_file_path
    variable.

  - wouldn't back up the empty directory created with mkdir
    (i.e. test) outside of the server which could lead to
    inconsistencies during the Percona XtraDB Cluster State
    Snapshot Transfer.

  - wasn't able to perform backups to the NFS mount in some
    NFS configurations, because it was trying to preserve
    file ownership.

  - unable to perform backup if innodb_log_arch_dir variable
    was used in server configuration

  - Race condition in start_query_killer child code could
    cause parent MySQL connection to close.

  - Bugs Fixed specific to MySQL 5.6 :

  - xtrabackup_56 was using CRC32 as the default checksum
    algorithm This could cause error if the
    innodb_checksum_algorithm value was changed to
    strict_innodb value after a restore.

  - xtrabackup_56 binary didn't store the server&rsquo;s
    innodb_checksum_algorithm value to backup-my.cnf. This
    value is needed because it affects the on-disk data
    format.

  - update and tag percona-xtrabackup-2.1.x-nodoc.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00052.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852224"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xtrabackup packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-2.1.6-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-debuginfo-2.1.6-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtrabackup-debugsource-2.1.6-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xtrabackup");
}
