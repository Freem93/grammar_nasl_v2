#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-737.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86864);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/11/13 15:27:58 $");

  script_name(english:"openSUSE Security Update : git (openSUSE-2015-737)");
  script_summary(english:"Check for the openSUSE-2015-737 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Git was updated to fix one security issue.

The following vulnerability was fixed :

  - boo#948969: remote code execution with recursive fetch
    of submodules"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=948969"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected git packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-remote-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gitk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/13");
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

if ( rpm_check(release:"SUSE13.1", reference:"git-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-arch-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-core-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-core-debuginfo-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-cvs-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-daemon-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-daemon-debuginfo-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-debugsource-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-email-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-gui-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-remote-helpers-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-svn-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-svn-debuginfo-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"git-web-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"gitk-1.8.4.5-3.11.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-arch-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-core-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-core-debuginfo-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-cvs-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-daemon-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-daemon-debuginfo-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-debugsource-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-email-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-gui-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-svn-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-svn-debuginfo-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"git-web-2.1.4-16.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"gitk-2.1.4-16.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git / git-arch / git-core / git-core-debuginfo / git-cvs / etc");
}
