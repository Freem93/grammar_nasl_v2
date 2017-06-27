#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-514.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99703);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/27 13:33:46 $");

  script_cve_id("CVE-2017-7585", "CVE-2017-7586", "CVE-2017-7741", "CVE-2017-7742");

  script_name(english:"openSUSE Security Update : libsndfile (openSUSE-2017-514)");
  script_summary(english:"Check for the openSUSE-2017-514 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libsndfile fixes the following security issues :

  - CVE-2017-7586: A stack-based buffer overflow via a
    specially crafted FLAC file was fixed (error in the
    'header_read()' function) (bsc#1033053)

  - CVE-2017-7585,CVE-2017-7741, CVE-2017-7742: Several
    stack-based buffer overflows via a specially crafted
    FLAC file (error in the 'flac_buffer_copy()' function)
    were fixed (bsc#1033054,bsc#1033915,bsc#1033914).

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1033915"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsndfile packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile-progs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsndfile1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libsndfile-debugsource-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsndfile-devel-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsndfile-progs-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsndfile-progs-debuginfo-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsndfile-progs-debugsource-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsndfile1-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsndfile1-debuginfo-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsndfile1-32bit-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsndfile1-debuginfo-32bit-1.0.25-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-debugsource-1.0.25-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-devel-1.0.25-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-progs-1.0.25-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-progs-debuginfo-1.0.25-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile-progs-debugsource-1.0.25-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile1-1.0.25-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsndfile1-debuginfo-1.0.25-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsndfile1-32bit-1.0.25-26.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsndfile1-debuginfo-32bit-1.0.25-26.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsndfile-progs / libsndfile-progs-debuginfo / etc");
}
