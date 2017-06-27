#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-845.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74839);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/26 05:42:54 $");

  script_cve_id("CVE-2012-5130", "CVE-2012-5131", "CVE-2012-5132", "CVE-2012-5133", "CVE-2012-5134", "CVE-2012-5135", "CVE-2012-5136", "CVE-2012-5137", "CVE-2012-5138");

  script_name(english:"openSUSE Security Update : Chromium (openSUSE-SU-2012:1637-1)");
  script_summary(english:"Check for the openSUSE-2012-845 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 25.0.1343

  - Security Fixes (bnc#791234 and bnc#792154) :

  - CVE-2012-5131: Corrupt rendering in the Apple OSX driver
    for Intel GPUs

  - CVE-2012-5133: Use-after-free in SVG filters.

  - CVE-2012-5130: Out-of-bounds read in Skia

  - CVE-2012-5132: Browser crash with chunked encoding

  - CVE-2012-5134: Buffer underflow in libxml.

  - CVE-2012-5135: Use-after-free with printing.

  - CVE-2012-5136: Bad cast in input element handling.

  - CVE-2012-5138: Incorrect file path handling

  - CVE-2012-5137: Use-after-free in media source handling

  - Correct build so that proprietary codecs can be used
    when the chromium-ffmpeg package is installed

  - Update to 25.0.1335

  - {gtk} Fixed <input> selection renders white text on
    white background in apps. (Issue: 158422)

  - Fixed translate infobar button to show selected
    language. (Issue: 155350)

  - Fixed broken Arabic language. (Issue: 158978)

  - Fixed pre-rendering if the preference is disabled at
    start up. (Issue: 159393)

  - Fixed JavaScript rendering issue. (Issue: 159655)

  - No further indications in the ChangeLog

  - Updated V8 - 3.14.5.0

  - Bookmarks are now searched by their title while typing
    into the omnibox with matching bookmarks being shown in
    the autocomplete suggestions pop-down list. Matching is
    done by prefix.

  - Fixed chromium issues 155871, 154173, 155133.

  - Removed patch chomium-ffmpeg-no-pkgconfig.patch

  - Building now internal libffmpegsumo.so based on the
    standard chromium ffmpeg codecs

  - Add a configuration file (/etc/default/chromium) where
    we can indicate flags for the chromium-browser.

  - add explicit buildrequire on libbz2-devel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-12/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792154"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Chromium packages."
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-debuginfo-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-ffmpegsumo-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-ffmpegsumo-debuginfo-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-25.0.1343.0-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-debuginfo-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debuginfo-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debugsource-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-gnome-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-kde-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-debuginfo-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-25.0.1343.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-debuginfo-25.0.1343.0-1.23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium");
}
