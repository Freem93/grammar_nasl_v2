#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1416.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95596);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/07 14:54:25 $");

  script_cve_id("CVE-2016-3492", "CVE-2016-5584", "CVE-2016-5616", "CVE-2016-5624", "CVE-2016-5626", "CVE-2016-5629", "CVE-2016-6663", "CVE-2016-7440", "CVE-2016-8283");

  script_name(english:"openSUSE Security Update : mariadb (openSUSE-2016-1416)");
  script_summary(english:"Check for the openSUSE-2016-1416 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This mariadb update to version 10.0.28 fixes the following issues
(bsc#1008318) :

Security fixes :

  - CVE-2016-8283: Unspecified vulnerability in subcomponent
    Types (bsc#1005582)

  - CVE-2016-7440: Unspecified vulnerability in subcomponent
    Encryption (bsc#1005581)

  - CVE-2016-5629: Unspecified vulnerability in subcomponent
    Federated (bsc#1005569)

  - CVE-2016-5626: Unspecified vulnerability in subcomponent
    GIS (bsc#1005566)

  - CVE-2016-5624: Unspecified vulnerability in subcomponent
    DML (bsc#1005564)

  - CVE-2016-5616: Unspecified vulnerability in subcomponent
    MyISAM (bsc#1005562)

  - CVE-2016-5584: Unspecified vulnerability in subcomponent
    Encryption (bsc#1005558)

  - CVE-2016-3492: Unspecified vulnerability in subcomponent
    Optimizer (bsc#1005555)

  - CVE-2016-6663: Privilege Escalation / Race Condition
    (bsc#1001367)

Bugfixes :

  - mariadb failing test sys_vars.optimizer_switch_basic
    (bsc#1003800)

  - Remove useless mysql@default.service (bsc#1004477)

  - Replace all occurrences of the string '@sysconfdir@'
    with '/etc' as it wasn't expanded properly (bsc#990890)

  - Notable changes :

  - XtraDB updated to 5.6.33-79.0

  - TokuDB updated to 5.6.33-79.0

  - Innodb updated to 5.6.33

  - Performance Schema updated to 5.6.33

  - Release notes and upstream changelog :

  - https://kb.askmonty.org/en/mariadb-10028-release-notes

  - https://kb.askmonty.org/en/mariadb-10028-changelog

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10028-changelog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://kb.askmonty.org/en/mariadb-10028-release-notes"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/07");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient-devel-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient18-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient18-debuginfo-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqlclient_r18-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld-devel-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld18-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libmysqld18-debuginfo-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-bench-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-bench-debuginfo-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-client-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-client-debuginfo-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-debuginfo-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-debugsource-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-errormessages-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-test-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-test-debuginfo-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-tools-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mariadb-tools-debuginfo-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient18-32bit-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient18-debuginfo-32bit-10.0.28-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libmysqlclient_r18-32bit-10.0.28-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysqlclient-devel / libmysqlclient18 / libmysqlclient18-32bit / etc");
}
