#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1274.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94649);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/09 14:23:24 $");

  script_cve_id("CVE-2016-3477", "CVE-2016-3521", "CVE-2016-3615", "CVE-2016-5440", "CVE-2016-5612", "CVE-2016-5630", "CVE-2016-6662");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2016-1274)");
  script_summary(english:"Check for the openSUSE-2016-1274 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mariadb to 10.0.27 fixes the following issues :

  - release notes :

  - https://kb.askmonty.org/en/mariadb-10027-release-notes

  - https://kb.askmonty.org/en/mariadb-10026-release-notes

  - changelog :

  - https://kb.askmonty.org/en/mariadb-10027-changelog

  - https://kb.askmonty.org/en/mariadb-10026-changelog

  - fixed CVE's 10.0.27: CVE-2016-5612, CVE-2016-5630,
    CVE-2016-6662 10.0.26: CVE-2016-5440, CVE-2016-3615,
    CVE-2016-3521, CVE-2016-3477

  - fix: [boo#1005561], [boo#1005570], [boo#998309],
    [boo#989926], [boo#989922], [boo#989919], [boo#989913]

  - requires devel packages for aio and lzo2

  - remove mariadb-10.0.21-mysql-test_main_bootstrap.patch
    that is no longer needed [boo#984858] 

  - append '--ignore-db-dir=lost+found' to the mysqld
    options in 'mysql-systemd-helper' script if 'lost+found'
    directory is found in $datadir [boo#986251]

  - remove syslog.target from *.service files [boo#983938]

  - add systemd to deps to build on leap and friends 

  - replace '%{_libexecdir}/systemd/system' with %{_unitdir}
    macro

  - remove useless mysql@default.service [boo#971456] 

  - make ORDER BY optimization functions take into account
    multiple equalities [boo#949520]

  - adjust mysql-test results in order to take account of a
    new option (orderby_uses_equalities) added by the
    optimizer patch [boo#1003800]

  - replace all occurrences of the string '@sysconfdir@'
    with '/etc' in
    mysql-community-server-5.1.46-logrotate.patch as it
    wasn't expanded properly [boo#990890]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10026-changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10026-release-notes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10027-changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10027-release-notes"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/09");
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

if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient-devel-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient18-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient18-debuginfo-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqlclient_r18-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld-devel-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld18-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysqld18-debuginfo-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-bench-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-bench-debuginfo-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-client-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-client-debuginfo-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-debuginfo-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-debugsource-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-errormessages-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-test-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-test-debuginfo-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-tools-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mariadb-tools-debuginfo-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.27-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.27-2.27.1") ) flag++;

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
