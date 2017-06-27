#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-72.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75155);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2012-5145", "CVE-2012-5146", "CVE-2012-5147", "CVE-2012-5148", "CVE-2012-5149", "CVE-2012-5150", "CVE-2012-5152", "CVE-2012-5153", "CVE-2012-5154", "CVE-2013-0830", "CVE-2013-0831", "CVE-2013-0832", "CVE-2013-0833", "CVE-2013-0834", "CVE-2013-0835", "CVE-2013-0836", "CVE-2013-0837", "CVE-2013-0838");
  script_bugtraq_id(59413, 59423);
  script_osvdb_id(89072, 89073, 89074, 89075, 89076, 89078, 89079, 89080, 89086, 89087, 89088, 89089, 89090, 89091, 89092, 89093, 89094, 89095);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2013:0236-1)");
  script_summary(english:"Check for the openSUSE-2013-72 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to 26.0.1383

  - Security fixes (bnc#798326)

  - CVE-2012-5145: Use-after-free in SVG layout

  - CVE-2012-5146: Same origin policy bypass with malformed
    URL

  - CVE-2012-5147: Use-after-free in DOM handling

  - CVE-2012-5148: Missing filename sanitization in
    hyphenation support

  - CVE-2012-5149: Integer overflow in audio IPC handling

  - CVE-2012-5150: Use-after-free when seeking video

  - CVE-2012-5152: Out-of-bounds read when seeking video

  - CVE-2012-5153: Out-of-bounds stack access in v8.

  - CVE-2012-5154: Integer overflow in shared memory
    allocation

  - CVE-2013-0830: Missing NUL termination in IPC.

  - CVE-2013-0831: Possible path traversal from extension
    process

  - CVE-2013-0832: Use-after-free with printing.

  - CVE-2013-0833: Out-of-bounds read with printing.

  - CVE-2013-0834: Out-of-bounds read with glyph handling

  - CVE-2013-0835: Browser crash with geolocation

  - CVE-2013-0836: Crash in v8 garbage collection. 

  - CVE-2013-0837: Crash in extension tab handling.

  - CVE-2013-0838: Tighten permissions on shared memory
    segments

  - Set up Google API keys, see
    http://www.chromium.org/developers/how-tos/api-keys . #
    Note: these are for openSUSE Chromium builds ONLY!!
    (Setup was done based on indication from Pawel Hajdan)

  - Change the default setting for password-store to basic.
    (bnc#795860)

  - Fixes from Update to 25.0.1352

  - Fixed garbled header and footer text in print preview. 

  - Fixed broken profile with system-wide installation and 

  - Fixed stability crashes like 158747, 159437, 149139,
    160914, 

  - Add a configuration file (/etc/default/chromium) where
    we can indicate flags for the chromium-browser.

  - {gtk} Fixed <input> selection renders white text on
    white 

  - Fixed translate infobar button to show selected
    language. 

  - Update to 25.0.1329

  - No further indications in the ChangeLog

  - Update to 25.0.1319

  - No further indications in the Changelog

  - Update to 24.0.1308

  - Updated V8 - 3.14.5.0

  - Bookmarks are now searched by their title while typing
    into the omnibox with matching bookmarks being shown in
    the autocomplete suggestions pop-down list. Matching is
    done by prefix.

  - Fixed chromium issues 155871, 154173, 155133.

  - No further indications in the ChangeLog.

  - Update to 24.0.1283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.chromium.org/developers/how-tos/api-keys"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=795860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798326"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
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

if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-debuginfo-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-ffmpegsumo-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-ffmpegsumo-debuginfo-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-26.0.1383.0-1.51.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-debuginfo-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debuginfo-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debugsource-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-gnome-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-kde-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-ffmpegsumo-debuginfo-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-26.0.1383.0-1.31.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-debuginfo-26.0.1383.0-1.31.1") ) flag++;

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
