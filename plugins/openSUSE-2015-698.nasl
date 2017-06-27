#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-698.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86733);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/11/20 15:06:53 $");

  script_cve_id("CVE-2015-7747");

  script_name(english:"openSUSE Security Update : audiofile (openSUSE-2015-698)");
  script_summary(english:"Check for the openSUSE-2015-698 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"audiofile was updated to fix one security issue.

This security issue was fixed :

  - CVE-2015-7747: Overflow when changing both number of
    channels and sample format (bsc#949399)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949399"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected audiofile packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:audiofile-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaudiofile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaudiofile1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaudiofile1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libaudiofile1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"audiofile-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"audiofile-debuginfo-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"audiofile-debugsource-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"audiofile-devel-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libaudiofile1-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libaudiofile1-debuginfo-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"audiofile-devel-32bit-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libaudiofile1-32bit-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libaudiofile1-debuginfo-32bit-0.3.6-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"audiofile-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"audiofile-debuginfo-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"audiofile-debugsource-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"audiofile-devel-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libaudiofile1-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libaudiofile1-debuginfo-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"audiofile-devel-32bit-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libaudiofile1-32bit-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libaudiofile1-debuginfo-32bit-0.3.6-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"audiofile-0.3.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"audiofile-debuginfo-0.3.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"audiofile-debugsource-0.3.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"audiofile-devel-0.3.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libaudiofile1-0.3.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libaudiofile1-debuginfo-0.3.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"audiofile-devel-32bit-0.3.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libaudiofile1-32bit-0.3.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libaudiofile1-debuginfo-32bit-0.3.6-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "audiofile / audiofile-debuginfo / audiofile-debugsource / etc");
}
