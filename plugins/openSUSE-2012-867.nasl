#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-867.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74848);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-5139", "CVE-2012-5140", "CVE-2012-5141", "CVE-2012-5142", "CVE-2012-5143", "CVE-2012-5144");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2012:1682-1)");
  script_summary(english:"Check for the openSUSE-2012-867 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to 25.0.1362

  - Security fixes (bnc#794075) :

  - CVE-2012-5139: Use-after-free with visibility events

  - CVE-2012-5140: Use-after-free in URL loader

  - CVE-2012-5141: Limit Chromoting client plug-in
    instantiation.

  - CVE-2012-5142: Crash in history navigation.

  - CVE-2012-5143: Integer overflow in PPAPI image buffers

  - CVE-2012-5144: Stack corruption in AAC decoding

  - Fixed garbled header and footer text in print preview.
    [Issue: 152893]

  - Fixed extension action badges with long text. [Issue:
    160069]

  - Disable find if constrained window is shown. [Issue:
    156969]

  - Enable fullscreen for apps windows. [Issue: 161246]

  - Fixed broken profile with system-wide installation and
    UserDataDir & DiskCacheDir policy. [Issue: 161336]

  - Fixed stability crashes like 158747, 159437, 149139,
    160914, 160401, 161858, 158747, 156878

  - Fixed graphical corruption in Dust. [Issue: 155258]

  - Fixed scrolling issue. [Issue: 163553]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-12/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794075"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/20");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-debuginfo-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-ffmpegsumo-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-ffmpegsumo-debuginfo-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-25.0.1362.0-1.47.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-debuginfo-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debuginfo-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debugsource-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-gnome-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-kde-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-debuginfo-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-25.0.1362.0-1.27.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-debuginfo-25.0.1362.0-1.27.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
