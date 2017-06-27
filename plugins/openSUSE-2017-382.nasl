#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-382.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99017);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");

  script_name(english:"openSUSE Security Update : xtrabackup (openSUSE-2017-382)");
  script_summary(english:"Check for the openSUSE-2017-382 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to xtrabackup 2.3.7 fixes one security issue and bugs.

The following security issue was fixed :

  - innobackupex and xtrabackup scripts were showing the
    password in the ps output when it was passed as a
    command line argument (boo#1026729)

The following functionality was added :

  - new --remove-original option for removing the original
    encrypted and compressed files

  - now supports -H, -h, -u and -p shortcuts for --hostname,
    --datadir, --user and --password respectively

The following bugs were fixed :

  - Pick up username from user's configuration file
    correctly

  - Incremental backups did not include
    xtrabackup_binlog_info and xtrabackup_galera_info files

  - --move-back option did not always restore out-of-datadir
    tablespaces to their original directories

  - Incremental backup would fail with a path like
    ~/backup/inc_1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1026729"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xtrabackup packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtrabackup-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"xtrabackup-2.3.7-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xtrabackup-debuginfo-2.3.7-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xtrabackup-debugsource-2.3.7-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xtrabackup-test-2.3.7-5.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xtrabackup / xtrabackup-debuginfo / xtrabackup-debugsource / etc");
}
