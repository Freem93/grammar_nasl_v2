#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-997.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93069);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/24 13:46:11 $");

  script_cve_id("CVE-2014-4650", "CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5636", "CVE-2016-5699");

  script_name(english:"openSUSE Security Update : python3 (openSUSE-2016-997) (httpoxy)");
  script_summary(english:"Check for the openSUSE-2016-997 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python3 fixes the following issues :

  - apply fix for CVE-2016-1000110 - CGIHandler: sets
    environmental variable based on user-supplied Proxy
    request header (fixes boo#989523, CVE-2016-1000110)

  - update to 3.4.5 check:
    https://docs.python.org/3.4/whatsnew/changelog.html
    (fixes boo#984751, CVE-2016-0772) (fixes boo#985177,
    CVE-2016-5636) (fixes boo#985348, CVE-2016-5699)

  - Bump DH parameters to 2048 bit to fix logjam security
    issue. boo#935856

  - apply fix for CVE-2016-1000110 - CGIHandler: sets
    environmental variable based on user-supplied Proxy
    request header: (fixes boo#989523, CVE-2016-1000110)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=935856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.python.org/3.4/whatsnew/changelog.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_4m1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_4m1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_4m1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_4m1_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/22");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libpython3_4m1_0-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libpython3_4m1_0-debuginfo-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-base-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-base-debuginfo-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-base-debugsource-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-curses-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-curses-debuginfo-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-dbm-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-dbm-debuginfo-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-debuginfo-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-debugsource-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-devel-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-devel-debuginfo-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-doc-pdf-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-idle-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-testsuite-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-testsuite-debuginfo-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-tk-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-tk-debuginfo-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-tools-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpython3_4m1_0-32bit-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libpython3_4m1_0-debuginfo-32bit-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"python3-32bit-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"python3-base-32bit-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"python3-base-debuginfo-32bit-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"python3-debuginfo-32bit-3.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpython3_4m1_0-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libpython3_4m1_0-debuginfo-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-base-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-base-debuginfo-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-base-debugsource-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-curses-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-curses-debuginfo-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-dbm-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-dbm-debuginfo-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-debuginfo-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-debugsource-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-devel-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-devel-debuginfo-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-doc-pdf-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-idle-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-testsuite-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-testsuite-debuginfo-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-tk-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-tk-debuginfo-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"python3-tools-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpython3_4m1_0-32bit-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libpython3_4m1_0-debuginfo-32bit-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"python3-32bit-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"python3-base-32bit-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"python3-base-debuginfo-32bit-3.4.5-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"python3-debuginfo-32bit-3.4.5-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpython3_4m1_0 / libpython3_4m1_0-32bit / etc");
}
