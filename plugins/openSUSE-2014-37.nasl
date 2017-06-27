#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-37.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75366);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-2906", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909", "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913", "CVE-2013-2914", "CVE-2013-2915", "CVE-2013-2916", "CVE-2013-2917", "CVE-2013-2918", "CVE-2013-2919", "CVE-2013-2920", "CVE-2013-2921", "CVE-2013-2922", "CVE-2013-2923", "CVE-2013-2924", "CVE-2013-2925", "CVE-2013-2926", "CVE-2013-2927", "CVE-2013-2928", "CVE-2013-2931", "CVE-2013-6621", "CVE-2013-6622", "CVE-2013-6623", "CVE-2013-6624", "CVE-2013-6625", "CVE-2013-6626", "CVE-2013-6627", "CVE-2013-6628", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6631", "CVE-2013-6632", "CVE-2013-6634", "CVE-2013-6635", "CVE-2013-6636", "CVE-2013-6637", "CVE-2013-6638", "CVE-2013-6639", "CVE-2013-6640");

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:0065-1)");
  script_summary(english:"Check for the openSUSE-2014-37 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to Chromium 31.0.1650.63 Stable channel update :

  - Security fixes :

  - CVE-2013-6634: Session fixation in sync related to 302
    redirects

  - CVE-2013-6635: Use-after-free in editing

  - CVE-2013-6636: Address bar spoofing related to modal
    dialogs

  - CVE-2013-6637: Various fixes from internal audits,
    fuzzing and other initiatives.

  - CVE-2013-6638: Buffer overflow in v8

  - CVE-2013-6639: Out of bounds write in v8.

  - CVE-2013-6640: Out of bounds read in v8

  - and 12 other security fixes.

  - Remove the build flags to build according to the Chrome
    ffmpeg branding and the proprietary codecs. (bnc#847971)

  - Update to Chromium 31.0.1650.57 Stable channel update :

  - Security Fixes :

  - CVE-2013-6632: Multiple memory corruption issues.

  - Update to Chromium 31.0.1650.48 Stable Channel update :

  - Security fixes :

  - CVE-2013-6621: Use after free related to speech input
    elements..

  - CVE-2013-6622: Use after free related to media elements. 

  - CVE-2013-6623: Out of bounds read in SVG.

  - CVE-2013-6624: Use after free related to
    &ldquo;id&rdquo; attribute strings.

  - CVE-2013-6625: Use after free in DOM ranges.

  - CVE-2013-6626: Address bar spoofing related to
    interstitial warnings.

  - CVE-2013-6627: Out of bounds read in HTTP parsing.

  - CVE-2013-6628: Issue with certificates not being checked
    during TLS renegotiation.

  - CVE-2013-2931: Various fixes from internal audits,
    fuzzing and other initiatives.

  - CVE-2013-6629: Read of uninitialized memory in libjpeg
    and libjpeg-turbo.

  - CVE-2013-6630: Read of uninitialized memory in
    libjpeg-turbo.

  - CVE-2013-6631: Use after free in libjingle.

  - Added patch chromium-fix-chromedriver-build.diff to fix
    the chromedriver build

  - Enable ARM build for Chromium. 

  - Added patches chromium-arm-webrtc-fix.patch,
    chromium-fix-arm-icu.patch and
    chromium-fix-arm-sysroot.patch to resolve ARM specific
    build issues

  - Update to Chromium 30.0.1599.114 Stable Channel update:
    fix build for 32bit systems

  - Drop patch chromium-fix-chromedriver-build.diff. This is
    now fixed upstream

  - For openSUSE versions lower than 13.1, build against the
    in-tree libicu

  - Update to Chromium 30.0.1599.101

  - Security Fixes :

  + CVE-2013-2925: Use after free in XHR

  + CVE-2013-2926: Use after free in editing

  + CVE-2013-2927: Use after free in forms.

  + CVE-2013-2928: Various fixes from internal audits,
    fuzzing and other initiatives.

  - Update to Chromium 30.0.1599.66

  - Easier searching by image 

  - A number of new apps/extension APIs 

  - Lots of under the hood changes for stability and
    performance

  - Security fixes :

  + CVE-2013-2906: Races in Web Audio

  + CVE-2013-2907: Out of bounds read in Window.prototype
    object

  + CVE-2013-2908: Address bar spoofing related to the
    &ldquo;204 No Content&rdquo; status code

  + CVE-2013-2909: Use after free in inline-block rendering

  + CVE-2013-2910: Use-after-free in Web Audio

  + CVE-2013-2911: Use-after-free in XSLT

  + CVE-2013-2912: Use-after-free in PPAPI

  + CVE-2013-2913: Use-after-free in XML document parsing

  + CVE-2013-2914: Use after free in the Windows color
    chooser dialog

  + CVE-2013-2915: Address bar spoofing via a malformed
    scheme

  + CVE-2013-2916: Address bar spoofing related to the
    &ldquo;204 No Content&rdquo; status code

  + CVE-2013-2917: Out of bounds read in Web Audio

  + CVE-2013-2918: Use-after-free in DOM

  + CVE-2013-2919: Memory corruption in V8

  + CVE-2013-2920: Out of bounds read in URL parsing

  + CVE-2013-2921: Use-after-free in resource loader

  + CVE-2013-2922: Use-after-free in template element

  + CVE-2013-2923: Various fixes from internal audits,
    fuzzing and other initiatives 

  + CVE-2013-2924: Use-after-free in ICU. Upstream bug"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854473"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/07");
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

if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-31.0.1650.63-13.7") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-debuginfo-31.0.1650.63-13.7") ) flag++;

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
