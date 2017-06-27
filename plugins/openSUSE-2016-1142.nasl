#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1142.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93851);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id("CVE-2016-5177", "CVE-2016-5178");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-2016-1142)");
  script_summary(english:"Check for the openSUSE-2016-1142 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update Chromium 53.0.2785.143 fixes the following issues
(boo#1002140)

  - CVE-2016-5177: Use after free in V8

  - CVE-2016-5178: Various fixes from internal audits

The following bugfix changes are included :

  - Export GDK_BACKEND=x11 before starting chromium,
    ensuring that it's started as an Xwayland client
    (boo#1001135).

  - Changes to Sandbox to fix crashers on tumbleweed
    (boo#999091)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002140"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999091"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");
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

if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-53.0.2785.143-128.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromedriver-debuginfo-53.0.2785.143-128.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-53.0.2785.143-128.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-debuginfo-53.0.2785.143-128.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-gnome-53.0.2785.143-128.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-desktop-kde-53.0.2785.143-128.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-53.0.2785.143-128.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"chromium-ffmpegsumo-debuginfo-53.0.2785.143-128.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromedriver-53.0.2785.143-79.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromedriver-debuginfo-53.0.2785.143-79.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-53.0.2785.143-79.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-debuginfo-53.0.2785.143-79.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-desktop-gnome-53.0.2785.143-79.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-desktop-kde-53.0.2785.143-79.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-ffmpegsumo-53.0.2785.143-79.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"chromium-ffmpegsumo-debuginfo-53.0.2785.143-79.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
