#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-608.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86182);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/10/24 14:57:04 $");

  script_cve_id("CVE-2015-2582", "CVE-2015-2611", "CVE-2015-2617", "CVE-2015-2620", "CVE-2015-2639", "CVE-2015-2641", "CVE-2015-2643", "CVE-2015-2648", "CVE-2015-2661", "CVE-2015-4737", "CVE-2015-4752", "CVE-2015-4756", "CVE-2015-4757", "CVE-2015-4761", "CVE-2015-4767", "CVE-2015-4769", "CVE-2015-4771", "CVE-2015-4772");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2015-608)");
  script_summary(english:"Check for the openSUSE-2015-608 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The MySQL Community Server edition was updated to 5.6.26, fixing
security issues and bugs.

All changes:
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-26.html

  - Fixed CVEs: CVE-2015-2617, CVE-2015-2648, CVE-2015-2611,
    CVE-2015-2582 CVE-2015-4752, CVE-2015-4756,
    CVE-2015-2643, CVE-2015-4772 CVE-2015-4761,
    CVE-2015-4757, CVE-2015-4737, CVE-2015-4771
    CVE-2015-4769, CVE-2015-2639, CVE-2015-2620,
    CVE-2015-2641 CVE-2015-2661, CVE-2015-4767

  - disable Performance Schema by default. Since MySQL 5.6.6
    upstream enabled Performance Schema by default which
    results in increased memory usage. The added option
    disable Performance Schema again in order to decrease
    MySQL memory usage [bnc#852477].

  - install INFO_BIN and INFO_SRC, noticed in MDEV-6912

  - remove superfluous '--group' parameter from
    mysql-systemd-helper

  - make -devel package installable in the presence of
    LibreSSL

  - cleanup after the update-message if it was displayed

  - add 'exec' to mysql-systemd-helper to shutdown
    mysql/mariadb cleanly [bnc#943096]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=852477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943096"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client18-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmysql56client_r18-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-bench-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-errormessages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-community-server-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/28");
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

if ( rpm_check(release:"SUSE13.1", reference:"libmysql56client18-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysql56client18-debuginfo-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysql56client_r18-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-bench-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-bench-debuginfo-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-client-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-client-debuginfo-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-debuginfo-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-debugsource-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-errormessages-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-test-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-test-debuginfo-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-tools-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-tools-debuginfo-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.26-7.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client18-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client18-debuginfo-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client_r18-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-bench-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-bench-debuginfo-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-client-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-client-debuginfo-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-debuginfo-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-debugsource-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-errormessages-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-test-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-test-debuginfo-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-tools-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-tools-debuginfo-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.26-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.26-2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmysql56client18-32bit / libmysql56client18 / etc");
}
