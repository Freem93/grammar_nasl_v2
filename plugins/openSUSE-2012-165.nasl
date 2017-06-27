#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-165.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74570);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-3031", "CVE-2011-3032", "CVE-2011-3033", "CVE-2011-3034", "CVE-2011-3035", "CVE-2011-3036", "CVE-2011-3037", "CVE-2011-3038", "CVE-2011-3039", "CVE-2011-3040", "CVE-2011-3041", "CVE-2011-3042", "CVE-2011-3043", "CVE-2011-3044", "CVE-2011-3046", "CVE-2011-3047");

  script_name(english:"openSUSE Security Update : chromium / v8 (openSUSE-SU-2012:0374-1)");
  script_summary(english:"Check for the openSUSE-2012-165 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in chromium :

  - Update to 19.0.1066

  - Fixed Chrome install/update resets Google search
    preferences (Issue: 105390)

  - Don't trigger accelerated compositing on 3D CSS when
    using swiftshader (Issue: 116401)

  - Fixed a GPU crash (Issue: 116096)

  - More fixes for Back button frequently hangs (Issue:
    93427)

  - Bastion now works (Issue: 116285)

  - Fixed Composited layer sorting irregularity with
    accelerated canvas (Issue: 102943)

  - Fixed Composited layer sorting irregularity with
    accelerated canvas (Issue: 102943)

  - Fixed Google Feedback causes render process to use too
    much memory (Issue: 114489)

  - Fixed after upgrade, some pages are rendered as blank
    (Issue: 109888)

  - Fixed Pasting text into a single-line text field
    shouldn't keep literal newlines (Issue: 106551)

  - Security Fixes :

  - Critical CVE-2011-3047: Errant plug-in load and GPU
    process memory corruption

  - Critical CVE-2011-3046: UXSS and bad history navigation.

  - Update to 19.0.1060

  - Fixed NTP signed in state is missing (Issue: 112676)

  - Fixed gmail seems to redraw itself (all white)
    occasionally (Issue: 111263)

  - Focus 'OK' button on JavaScript dialogs (Issue: 111015)

  - Fixed Back button frequently hangs (Issue: 93427)

  - Increase the buffer size to fix muted playback rate
    (Issue: 108239)

  - Fixed Empty span with line-height renders with non-zero
    height (Issue: 109811)

  - Marked the Certum Trusted Network CA as an issuer of
    extended-validation (EV) certificates.

  - Fixed importing of bookmarks, history, etc. from Firefox
    10+.

  - Fixed issues - 114001, 110785, 114168, 114598, 111663,
    113636, 112676

  - Fixed several crashes (Issues: 111376, 108688, 114391)

  - Fixed Firefox browser in Import Bookmarks and Settings
    drop-down (Issue: 114476)

  - Sync: Sessions aren't associating pre-existing tabs
    (Issue: 113319)

  - Fixed All 'Extensions' make an entry under the 'NTP
    Apps' page (Issue: 113672)

  - Security Fixes (bnc#750407) :

  - High CVE-2011-3031: Use-after-free in v8 element
    wrapper.

  - High CVE-2011-3032: Use-after-free in SVG value
    handling.

  - High CVE-2011-3033: Buffer overflow in the Skia drawing
    library.

  - High CVE-2011-3034: Use-after-free in SVG document
    handling.

  - High CVE-2011-3035: Use-after-free in SVG use handling.

  - High CVE-2011-3036: Bad cast in line box handling.

  - High CVE-2011-3037: Bad casts in anonymous block
    splitting.

  - High CVE-2011-3038: Use-after-free in multi-column
    handling.

  - High CVE-2011-3039: Use-after-free in quote handling.

  - High CVE-2011-3040: Out-of-bounds read in text handling.

  - High CVE-2011-3041: Use-after-free in class attribute
    handling.

  - High CVE-2011-3042: Use-after-free in table section
    handling.

  - High CVE-2011-3043: Use-after-free in flexbox with
    floats.

  - High CVE-2011-3044: Use-after-free with SVG animation
    elements.

Changes in v8 :

  - Update to 3.9.13.0

  - Add code kind check before preparing for OSR. (issue
    1900, 115073)

  - Pass zone explicitly to zone-allocation on x64 and ARM.
    (issue 1802)

  - Port string construct stub to x64. (issue 849)

  - Performance and stability improvements on all platforms."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-03/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751738"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium / v8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/14");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"chromium-19.0.1066.0-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-19.0.1066.0-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-19.0.1066.0-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-19.0.1066.0-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-19.0.1066.0-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-19.0.1066.0-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-19.0.1066.0-1.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-3.9.13.0-1.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-debuginfo-3.9.13.0-1.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-debugsource-3.9.13.0-1.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-devel-3.9.13.0-1.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-private-headers-devel-3.9.13.0-1.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium / chromium-debuginfo / chromium-debugsource / etc");
}
