#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-937.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92746);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/10/28 21:03:37 $");

  script_cve_id("CVE-2016-0718", "CVE-2016-2830", "CVE-2016-2835", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5250", "CVE-2016-5251", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5255", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5260", "CVE-2016-5261", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265", "CVE-2016-5266", "CVE-2016-5268");

  script_name(english:"openSUSE Security Update : MozillaFirefox / mozilla-nss (openSUSE-2016-937)");
  script_summary(english:"Check for the openSUSE-2016-937 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 48.0 to fix security issues, bugs, and
deliver various improvements.

The following major changes are included :

  - Process separation (e10s) is enabled for some users

  - Add-ons that have not been verified and signed by
    Mozilla will not load

  - WebRTC enhancements

  - The media parser has been redeveloped using the Rust
    programming language

  - better Canvas performance with speedy Skia support

  - Now requires NSS 3.24

The following security issues were fixed: (boo#991809)

  - CVE-2016-2835/CVE-2016-2836: Miscellaneous memory safety
    hazards

  - CVE-2016-2830: Favicon network connection can persist
    when page is closed

  - CVE-2016-2838: Buffer overflow rendering SVG with
    bidirectional content

  - CVE-2016-2839: Cairo rendering crash due to memory
    allocation issue with FFmpeg 0.10

  - CVE-2016-5251: Location bar spoofing via data URLs with
    malformed/invalid mediatypes

  - CVE-2016-5252: Stack underflow during 2D graphics
    rendering

  - CVE-2016-0718: Out-of-bounds read during XML parsing in
    Expat library

  - CVE-2016-5254: Use-after-free when using alt key and
    toplevel menus

  - CVE-2016-5255: Crash in incremental garbage collection
    in JavaScript

  - CVE-2016-5258: Use-after-free in DTLS during WebRTC
    session shutdown

  - CVE-2016-5259: Use-after-free in service workers with
    nested sync events

  - CVE-2016-5260: Form input type change from password to
    text can store plain text password in session restore
    file

  - CVE-2016-5261: Integer overflow in WebSockets during
    data buffering

  - CVE-2016-5262: Scripts on marquee tag can execute in
    sandboxed iframes

  - CVE-2016-2837: Buffer overflow in ClearKey Content
    Decryption Module (CDM) during video playback

  - CVE-2016-5263: Type confusion in display transformation

  - CVE-2016-5264: Use-after-free when applying SVG effects

  - CVE-2016-5265: Same-origin policy violation using local
    HTML file and saved shortcut file

  - CVE-2016-5266: Information disclosure and local file
    manipulation through drag and drop

  - CVE-2016-5268: Spoofing attack through text injection
    into internal error pages

  - CVE-2016-5250: Information disclosure through Resource
    Timing API during page navigation

The following non-security changes are included :

  - The AppData description and screenshots were updated.

  - Fix Firefox crash on startup on i586 (boo#986541)

  - The Selenium WebDriver may have caused Firefox to crash
    at startup

  - fix build issues with gcc/binutils combination used in
    Leap 42.2 (boo#984637)

  - Fix running on 48bit va aarch64 (boo#984126)

  - fix XUL dialog button order under KDE session
    (boo#984403)

Mozilla NSS was updated to 3.24 as a dependency.

Changes in mozilla-nss :

  - NSS softoken updated with latest NIST guidance

  - NSS softoken updated to allow NSS to run in FIPS Level 1
    (no password)

  - Various added and deprecated functions 

  - Remove most code related to SSL v2, including the
    ability to actively send a SSLv2-compatible client
    hello.

  - Protect against the Cachebleed attack.

  - Disable support for DTLS compression.

  - Improve support for TLS 1.3. This includes support for
    DTLS 1.3. (experimental)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986541"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991809"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / mozilla-nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/05");
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

if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-48.0-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-48.0-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-48.0-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-48.0-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-48.0-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-48.0-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-48.0-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-48.0-74.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-debuginfo-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-debuginfo-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-debuginfo-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debuginfo-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debugsource-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-devel-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-debuginfo-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-debuginfo-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.24-37.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-48.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-branding-upstream-48.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-buildsymbols-48.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debuginfo-48.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debugsource-48.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-devel-48.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-common-48.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-other-48.0-27.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-debuginfo-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-debuginfo-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-debuginfo-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debuginfo-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debugsource-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-devel-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-debuginfo-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-debuginfo-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.24-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.24-21.1") ) flag++;

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
