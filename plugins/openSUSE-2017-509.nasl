#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-509.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99649);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/05/22 13:36:33 $");

  script_cve_id("CVE-2017-5429", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5449", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467");

  script_name(english:"openSUSE Security Update : Mozilla Firefox (openSUSE-2017-509)");
  script_summary(english:"Check for the openSUSE-2017-509 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to Firefox 52.1.0esr.

The following vulnerabilities were fixed (bsc#1035082) :

  - CVE-2017-5443: Out-of-bounds write during BinHex
    decoding

  - CVE-2017-5429: Memory safety bugs fixed in Firefox 53,
    Firefox ESR 45.9, and Firefox ESR 52.1

  - CVE-2017-5464: Memory corruption with accessibility and
    DOM manipulation

  - CVE-2017-5465: Out-of-bounds read in ConvolvePixel

  - CVE-2017-5466: Origin confusion when reloading isolated
    data:text/html URL

  - CVE-2017-5467: Memory corruption when drawing Skia
    content

  - CVE-2017-5460: Use-after-free in frame selection

  - CVE-2017-5461: Out-of-bounds write in Base64 encoding in
    NSS

  - CVE-2017-5448: Out-of-bounds write in ClearKeyDecryptor

  - CVE-2017-5449: Crash during bidirectional unicode
    manipulation with animation

  - CVE-2017-5446: Out-of-bounds read when HTTP/2 DATA
    frames are sent with incorrect data

  - CVE-2017-5447: Out-of-bounds read during glyph
    processing

  - CVE-2017-5444: Buffer overflow while parsing
    application/http-index-format content

The package is now following the ESR 52 branch :

  - Enable plugin support by default

  - service workers are disabled by default

  - push notifications are disabled by default

  - WebAssembly (wasm) is disabled

  - Less use of multiprocess architecture Electrolysis
    (e10s)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035082"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");
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

if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-52.1.0-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-branding-upstream-52.1.0-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-52.1.0-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.1.0-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.1.0-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-devel-52.1.0-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-translations-common-52.1.0-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-translations-other-52.1.0-61.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-52.1.0-57.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-52.1.0-57.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-52.1.0-57.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-52.1.0-57.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-52.1.0-57.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-52.1.0-57.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-52.1.0-57.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-52.1.0-57.6.1") ) flag++;

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
