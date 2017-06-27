#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-344.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(97747);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/17 15:25:03 $");

  script_cve_id("CVE-2017-5398", "CVE-2017-5399", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410", "CVE-2017-5412", "CVE-2017-5413", "CVE-2017-5414", "CVE-2017-5415", "CVE-2017-5416", "CVE-2017-5417", "CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5420", "CVE-2017-5421", "CVE-2017-5422", "CVE-2017-5426", "CVE-2017-5427");

  script_name(english:"openSUSE Security Update : MozillaFirefox / mozilla-nss (openSUSE-2017-344)");
  script_summary(english:"Check for the openSUSE-2017-344 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox and mozilla-nss fixes the following
issues :

MozillaFirefox was updated to Firefox 52.0 (boo#1028391)

  - requires NSS >= 3.28.3

  - Pages containing insecure password fields now display a
    warning directly within username and password fields.

  - Send and open a tab from one device to another with Sync

  - Removed NPAPI support for plugins other than Flash.
    Silverlight, Java, Acrobat and the like are no longer
    supported.

  - Removed Battery Status API to reduce fingerprinting of
    users by trackers

  - MFSA 2017-05 CVE-2017-5400: asm.js JIT-spray bypass of
    ASLR and DEP (bmo#1334933) CVE-2017-5401: Memory
    Corruption when handling ErrorResult (bmo#1328861)
    CVE-2017-5402: Use-after-free working with events in
    FontFace objects (bmo#1334876) CVE-2017-5403:
    Use-after-free using addRange to add range to an
    incorrect root object (bmo#1340186) CVE-2017-5404:
    Use-after-free working with ranges in selections
    (bmo#1340138) CVE-2017-5406: Segmentation fault in Skia
    with canvas operations (bmo#1306890) CVE-2017-5407:
    Pixel and history stealing via floating-point timing
    side channel with SVG filters (bmo#1336622)
    CVE-2017-5410: Memory corruption during JavaScript
    garbage collection incremental sweeping (bmo#1330687)
    CVE-2017-5408: Cross-origin reading of video captions in
    violation of CORS (bmo#1313711) CVE-2017-5412: Buffer
    overflow read in SVG filters (bmo#1328323)
    CVE-2017-5413: Segmentation fault during bidirectional
    operations (bmo#1337504) CVE-2017-5414: File picker can
    choose incorrect default directory (bmo#1319370)
    CVE-2017-5415: Addressbar spoofing through blob URL
    (bmo#1321719) CVE-2017-5416: Null dereference crash in
    HttpChannel (bmo#1328121) CVE-2017-5417: Addressbar
    spoofing by draging and dropping URLs (bmo#791597)
    CVE-2017-5426: Gecko Media Plugin sandbox is not started
    if seccomp-bpf filter is running (bmo#1257361)
    CVE-2017-5427: Non-existent chrome.manifest file loaded
    during startup (bmo#1295542) CVE-2017-5418: Out of
    bounds read when parsing HTTP digest authorization
    responses (bmo#1338876) CVE-2017-5419: Repeated
    authentication prompts lead to DOS attack (bmo#1312243)
    CVE-2017-5420: Javascript: URLs can obfuscate addressbar
    location (bmo#1284395) CVE-2017-5405: FTP response codes
    can cause use of uninitialized values for ports
    (bmo#1336699) CVE-2017-5421: Print preview spoofing
    (bmo#1301876) CVE-2017-5422: DOS attack by using
    view-source: protocol repeatedly in one hyperlink
    (bmo#1295002) CVE-2017-5399: Memory safety bugs fixed in
    Firefox 52 CVE-2017-5398: Memory safety bugs fixed in
    Firefox 52 and Firefox ESR 45.8

mozilla-nss was updated to NSS 3.28.3

  - This is a patch release to fix binary compatibility
    issues. NSS version 3.28, 3.28.1 and 3.28.2 contained
    changes that were in violation with the NSS
    compatibility promise. ECParams, which is part of the
    public API of the freebl/softokn parts of NSS, had been
    changed to include an additional attribute. That size
    increase caused crashes or malfunctioning with
    applications that use that data structure directly, or
    indirectly through ECPublicKey, ECPrivateKey,
    NSSLOWKEYPublicKey, NSSLOWKEYPrivateKey, or potentially
    other data structures that reference ECParams. The
    change has been reverted to the original state in bug
    bmo#1334108. SECKEYECPublicKey had been extended with a
    new attribute, named 'encoding'. If an application
    passed type SECKEYECPublicKey to NSS (as part of
    SECKEYPublicKey), the NSS library read the uninitialized
    attribute. With this NSS release
    SECKEYECPublicKey.encoding is deprecated. NSS no longer
    reads the attribute, and will always set it to
    ECPoint_Undefined. See bug bmo#1340103.

  - requires NSPR >= 4.13.1

  - update to NSS 3.28.2 This is a stability and
    compatibility release. Below is a summary of the
    changes.

  - Fixed a NSS 3.28 regression in the signature scheme
    flexibility that causes connectivity issues between iOS
    8 clients and NSS servers with ECDSA certificates
    (bmo#1334114)

  - Fixed a possible crash on some Windows systems
    (bmo#1323150)

  - Fixed a compatibility issue with TLS clients that do not
    provide a list of supported key exchange groups
    (bmo#1330612)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028391"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / mozilla-nss packages."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");
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

if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-52.0-55.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-branding-upstream-52.0-55.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-buildsymbols-52.0-55.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debuginfo-52.0-55.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debugsource-52.0-55.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-devel-52.0-55.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-common-52.0-55.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-other-52.0-55.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-accessibility-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-demo-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-devel-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-headless-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-javadoc-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-src-1.8.0.121-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debugsource-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-devel-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-branding-upstream-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-debugsource-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-devel-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-translations-common-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-translations-other-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-52.0-55.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-src-1.8.0.121-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfreebl3-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libfreebl3-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsoftokn3-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libsoftokn3-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-certs-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-certs-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-debugsource-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-devel-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-sysinit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-sysinit-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-tools-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"mozilla-nss-tools-debuginfo-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.28.3-38.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.28.3-38.1") ) flag++;

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
