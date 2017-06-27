#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-135.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75257);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-6641", "CVE-2013-6643", "CVE-2013-6644", "CVE-2013-6645", "CVE-2013-6646", "CVE-2013-6649", "CVE-2013-6650");
  script_bugtraq_id(64805, 64981, 65168, 65172);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:0243-1)");
  script_summary(english:"Check for the openSUSE-2014-135 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to version 32.0.1700.102: Stable channel update :

  - Security Fixes :

  - CVE-2013-6649: Use-after-free in SVG images

  - CVE-2013-6650: Memory corruption in V8

  - and 12 other fixes

  - Other :

  - Mouse Pointer disappears after exiting full-screen mode

  - Drag and drop files into Chromium may not work properly

  - Quicktime Plugin crashes in Chromium

  - Chromium becomes unresponsive

  - Trackpad users may not be able to scroll horizontally

  - Scrolling does not work in combo box

  - Chromium does not work with all CSS minifiers such as
    whitespace around a media query's `and` keyword

  - Update to Chromium 32.0.1700.77 Stable channel update :

  - Security fixes :

  - CVE-2013-6646: Use-after-free in web workers

  - CVE-2013-6641: Use-after-free related to forms

  - CVE-2013-6643: Unprompted sync with an attacker&rsquo;s
    Google account

  - CVE-2013-6645: Use-after-free related to speech input
    elements

  - CVE-2013-6644: Various fixes from internal audits,
    fuzzing and other initiatives

  - Other :

  - Tab indicators for sound, webcam and casting 

  - Automatically blocking malware files 

  - Lots of under the hood changes for stability and
    performance 

  - Remove patch chromium-fix-chromedriver-build.diff as
    that chromedriver is fixed upstream

  - Updated ExcludeArch to exclude aarch64, ppc, ppc64 and
    ppc64le. This is based on missing build requires
    (valgrind, v8, etc)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861013"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/08");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-debuginfo-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debuginfo-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debugsource-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-gnome-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-kde-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-debuginfo-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-debuginfo-32.0.1700.102-1.25.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-32.0.1700.102-17.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-debuginfo-32.0.1700.102-17.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
