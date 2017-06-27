#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-213.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75294);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/12/15 05:42:13 $");

  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2013-4238", "CVE-2014-1912");

  script_name(english:"openSUSE Security Update : python (openSUSE-SU-2014:0380-1)");
  script_summary(english:"Check for the openSUSE-2014-213 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Python was updated to 2.7.6 to fix bugs and security issues :

  - bugfix-only release

  - SSL-related fixes

  - upstream fix for CVE-2013-4238

  - upstream fixes for CVE-2013-1752

  - added patches for CVE-2013-1752 (bnc#856836) issues that
    are missing in 2.7.6: python-2.7.6-imaplib.patch
    python-2.7.6-poplib.patch smtplib_maxline-2.7.patch

  - CVE-2013-1753 (bnc#856835) gzip decompression bomb in
    xmlrpc client: xmlrpc_gzip_27.patch

  - python-2.7.6-bdist-rpm.patch: fix broken 'setup.py
    bdist_rpm' command (bnc#857470, issue18045)

  - multilib patch: add '~/.local/lib64' paths to search
    path (bnc#637176)

  - CVE-2014-1912-recvfrom_into.patch: fix potential buffer
    overflow in socket.recvfrom_into (CVE-2014-1912,
    bnc#863741)

  - Add Obsoletes/Provides for python-ctypes.

  - reintroduce audioop.so as the problems with it seem to
    be fixed (bnc#831442)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=637176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863741"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython2_7-1_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-gdbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/08");
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

if ( rpm_check(release:"SUSE13.1", reference:"libpython2_7-1_0-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libpython2_7-1_0-debuginfo-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-base-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-base-debuginfo-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-base-debugsource-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-curses-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-curses-debuginfo-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-debuginfo-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-debugsource-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-demo-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-devel-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-doc-pdf-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-gdbm-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-gdbm-debuginfo-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-idle-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-tk-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-tk-debuginfo-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-xml-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-xml-debuginfo-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-32bit-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-base-32bit-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-base-debuginfo-32bit-2.7.6-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"python-debuginfo-32bit-2.7.6-8.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
