#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-474.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84630);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-4000");

  script_name(english:"openSUSE Security Update : mysql-community-server (openSUSE-2015-474) (Logjam)");
  script_summary(english:"Check for the openSUSE-2015-474 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mysql-community-server was updated to version 5.6.25 to fix one
security issue.

This security issue was fixed :

  - CVE-2015-4000: Logjam Attack: mysql uses 512 bit dh
    groups in SSL (bsc#934789).

For other changes and details please check
http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934789"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-community-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"libmysql56client18-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysql56client18-debuginfo-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmysql56client_r18-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-bench-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-bench-debuginfo-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-client-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-client-debuginfo-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-debuginfo-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-debugsource-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-errormessages-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-test-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-test-debuginfo-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-tools-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mysql-community-server-tools-debuginfo-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.25-7.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client18-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client18-debuginfo-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmysql56client_r18-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-bench-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-bench-debuginfo-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-client-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-client-debuginfo-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-debuginfo-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-debugsource-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-errormessages-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-test-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-test-debuginfo-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-tools-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-community-server-tools-debuginfo-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client18-32bit-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client18-debuginfo-32bit-5.6.25-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmysql56client_r18-32bit-5.6.25-2.3.1") ) flag++;

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
