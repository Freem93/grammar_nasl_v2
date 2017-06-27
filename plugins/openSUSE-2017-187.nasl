#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-187.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96940);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/15 21:22:53 $");

  script_cve_id("CVE-2017-5373", "CVE-2017-5374", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5377", "CVE-2017-5378", "CVE-2017-5379", "CVE-2017-5380", "CVE-2017-5381", "CVE-2017-5382", "CVE-2017-5383", "CVE-2017-5384", "CVE-2017-5385", "CVE-2017-5386", "CVE-2017-5387", "CVE-2017-5388", "CVE-2017-5389", "CVE-2017-5390", "CVE-2017-5391", "CVE-2017-5392", "CVE-2017-5393", "CVE-2017-5394", "CVE-2017-5395", "CVE-2017-5396");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2017-187)");
  script_summary(english:"Check for the openSUSE-2017-187 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox to version 51.0.1 fixes security issues
and bugs.

These security issues were fixed :

  - CVE-2017-5375: Excessive JIT code allocation allows
    bypass of ASLR and DEP (bmo#1325200, boo#1021814)

  - CVE-2017-5376: Use-after-free in XSL (bmo#1311687,
    boo#1021817) CVE-2017-5377: Memory corruption with
    transforms to create gradients in Skia (bmo#1306883,
    boo#1021826)

  - CVE-2017-5378: Pointer and frame data leakage of
    JavaScript objects (bmo#1312001, bmo#1330769,
    boo#1021818)

  - CVE-2017-5379: Use-after-free in Web Animations
    (bmo#1309198,boo#1021827)

  - CVE-2017-5380: Potential use-after-free during DOM
    manipulations (bmo#1322107, boo#1021819)

  - CVE-2017-5390: Insecure communication methods in
    Developer Tools JSON viewer (bmo#1297361, boo#1021820)

  - CVE-2017-5389: WebExtensions can install additional
    add-ons via modified host requests (bmo#1308688,
    boo#1021828)

  - CVE-2017-5396: Use-after-free with Media Decoder
    (bmo#1329403, boo#1021821)

  - CVE-2017-5381: Certificate Viewer exporting can be used
    to navigate and save to arbitrary filesystem locations
    (bmo#1017616, boo#1021830)

  - CVE-2017-5382: Feed preview can expose privileged
    content errors and exceptions (bmo#1295322, boo#1021831)

  - CVE-2017-5383: Location bar spoofing with unicode
    characters (bmo#1323338, bmo#1324716, boo#1021822)

  - CVE-2017-5384: Information disclosure via Proxy
    Auto-Config (PAC) (bmo#1255474, boo#1021832)

  - CVE-2017-5385: Data sent in multipart channels ignores
    referrer-policy response headers (bmo#1295945,
    boo#1021833)

  - CVE-2017-5386: WebExtensions can use data: protocol to
    affect other extensions (bmo#1319070, boo#1021823)

  - CVE-2017-5391: Content about: pages can load privileged
    about: pages (bmo#1309310, boo#1021835)

  - CVE-2017-5393: Remove addons.mozilla.org CDN from
    whitelist for mozAddonManager (bmo#1309282, boo#1021837)

  - CVE-2017-5387: Disclosure of local file existence
    through TRACK tag error messages (bmo#1295023,
    boo#1021839)

  - CVE-2017-5388: WebRTC can be used to generate a large
    amount of UDP traffic for DDOS attacks (bmo#1281482,
    boo#1021840)

  - CVE-2017-5374: Memory safety bugs (boo#1021841)

  - CVE-2017-5373: Memory safety bugs (boo#1021824)

These non-security issues in MozillaFirefox were fixed :

  - Added support for FLAC (Free Lossless Audio Codec)
    playback

  - Added support for WebGL 2

  - Added Georgian (ka) and Kabyle (kab) locales

  - Support saving passwords for forms without 'submit'
    events

  - Improved video performance for users without GPU
    acceleration

  - Zoom indicator is shown in the URL bar if the zoom level
    is not at default level

  - View passwords from the prompt before saving them

  - Remove Belarusian (be) locale

  - Use Skia for content rendering (Linux)

  - Improve recognition of LANGUAGE env variable
    (boo#1017174)

  - Multiprocess incompatibility did not correctly register
    with some add-ons (bmo#1333423)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021841"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");
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

if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-branding-upstream-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-debugsource-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-devel-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-translations-common-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-translations-other-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-51.0.1-50.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-51.0.1-50.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
