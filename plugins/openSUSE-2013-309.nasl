#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-309.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74965);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/10 14:11:56 $");

  script_cve_id("CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800", "CVE-2013-1620");
  script_osvdb_id(89848, 91874, 91875, 91879, 91880, 91881, 91882, 91883, 91885, 91886);

  script_name(english:"openSUSE Security Update : Mozilla Firefox and others (openSUSE-SU-2013:0630-1)");
  script_summary(english:"Check for the openSUSE-2013-309 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla suite received security and bugfix updates :

Mozilla Firefox was updated to version 20.0. Mozilla Thunderbird was
updated to version 17.0.5. Mozilla SeaMonkey was updated to version
17.0.5. Mozilla XULRunner was updated to version 17.0.5. mozilla-nss
was updated to version 3.14.3. mozilla-nspr was updated to version
4.9.6.

mozilla-nspr was updated to version 4.9.6 :

  - aarch64 support

  - added PL_SizeOfArenaPoolExcludingPool function
    (bmo#807883)

  - Auto detect android api version for x86 (bmo#782214)

  - Initialize Windows CRITICAL_SECTIONs without debug info
    and with nonzero spin count (bmo#812085) Previous update
    to version 4.9.5

  - bmo#634793: define NSPR's exact-width integer types
    PRInt{N} and PRUint{N} types to match the <stdint.h>
    exact-width integer types int{N}_t and uint{N}_t.

  - bmo#782815: passing 'int *' to parameter of type
    'unsigned int *' in setsockopt().

  - bmo#822932: Port bmo#802527 (NDK r8b support for x86) to
    NSPR.

  - bmo#824742: NSPR shouldn't require librt on Android.

  - bmo#831793: data race on lib->refCount in
    PR_UnloadLibrary.

mozilla-nss was updated to version 3.14.3 :

  - disable tests with expired certificates

  - add SEC_PKCS7VerifyDetachedSignatureAtTime using patch
    from mozilla tree to fulfill Firefox 21 requirements

  - No new major functionality is introduced in this
    release. This release is a patch release to address
    CVE-2013-1620 (bmo#822365)

  - 'certutil -a' was not correctly producing ASCII output
    as requested. (bmo#840714)

  - NSS 3.14.2 broke compilation with older versions of
    sqlite that lacked the SQLITE_FCNTL_TEMPFILENAME file
    control. NSS 3.14.3 now properly compiles when used with
    older versions of sqlite (bmo#837799) - remove
    system-sqlite.patch

  - add arm aarch64 support

  - added system-sqlite.patch (bmo#837799)

  - do not depend on latest sqlite just for a #define

  - enable system sqlite usage again

  - update to 3.14.2

  - required for Firefox >= 20

  - removed obsolete nssckbi update patch

  - MFSA 2013-40/CVE-2013-0791 (bmo#629816) Out-of-bounds
    array read in CERT_DecodeCertPackage

  - disable system sqlite usage since we depend on 3.7.15
    which is not provided in any openSUSE distribution

  - add nss-sqlitename.patch to avoid any name clash

Changes in MozillaFirefox :

  - update to Firefox 20.0 (bnc#813026)

  - requires NSPR 4.9.5 and NSS 3.14.3

  - MFSA 2013-30/CVE-2013-0788/CVE-2013-0789 Miscellaneous
    memory safety hazards

  - MFSA 2013-31/CVE-2013-0800 (bmo#825721) Out-of-bounds
    write in Cairo library

  - MFSA 2013-35/CVE-2013-0796 (bmo#827106) WebGL crash with
    Mesa graphics driver on Linux

  - MFSA 2013-36/CVE-2013-0795 (bmo#825697) Bypass of SOW
    protections allows cloning of protected nodes

  - MFSA 2013-37/CVE-2013-0794 (bmo#626775) Bypass of
    tab-modal dialog origin disclosure

  - MFSA 2013-38/CVE-2013-0793 (bmo#803870) Cross-site
    scripting (XSS) using timed history navigations

  - MFSA 2013-39/CVE-2013-0792 (bmo#722831) Memory
    corruption while rendering grayscale PNG images

  - use GStreamer 1.0 starting with 12.3
    (mozilla-gstreamer-1.patch)

  - build fixes for armv7hl :

  - disable debug build as armv7hl does not have enough
    memory

  - disable webrtc on armv7hl as it is non-compiling

Changes in MozillaThunderbird :

  - update to Thunderbird 17.0.5 (bnc#813026)

  - requires NSPR 4.9.5 and NSS 3.14.3

  - MFSA 2013-30/CVE-2013-0788/CVE-2013-0789 Miscellaneous
    memory safety hazards

  - MFSA 2013-31/CVE-2013-0800 (bmo#825721) Out-of-bounds
    write in Cairo library

  - MFSA 2013-35/CVE-2013-0796 (bmo#827106) WebGL crash with
    Mesa graphics driver on Linux

  - MFSA 2013-36/CVE-2013-0795 (bmo#825697) Bypass of SOW
    protections allows cloning of protected nodes

  - MFSA 2013-38/CVE-2013-0793 (bmo#803870) Cross-site
    scripting (XSS) using timed history navigations

Changes in seamonkey :

  - update to SeaMonkey 2.17 (bnc#813026)

  - requires NSPR 4.9.5 and NSS 3.14.3

  - MFSA 2013-30/CVE-2013-0788/CVE-2013-0789 Miscellaneous
    memory safety hazards

  - MFSA 2013-31/CVE-2013-0800 (bmo#825721) Out-of-bounds
    write in Cairo library

  - MFSA 2013-35/CVE-2013-0796 (bmo#827106) WebGL crash with
    Mesa graphics driver on Linux

  - MFSA 2013-36/CVE-2013-0795 (bmo#825697) Bypass of SOW
    protections allows cloning of protected nodes

  - MFSA 2013-37/CVE-2013-0794 (bmo#626775) Bypass of
    tab-modal dialog origin disclosure

  - MFSA 2013-38/CVE-2013-0793 (bmo#803870) Cross-site
    scripting (XSS) using timed history navigations

  - MFSA 2013-39/CVE-2013-0792 (bmo#722831) Memory
    corruption while rendering grayscale PNG images

  - use GStreamer 1.0 starting with 12.3
    (mozilla-gstreamer-1.patch)

Changes in xulrunner :

  - update to 17.0.5esr (bnc#813026)

  - requires NSPR 4.9.5 and NSS 3.14.3

  - MFSA 2013-30/CVE-2013-0788 Miscellaneous memory safety
    hazards

  - MFSA 2013-31/CVE-2013-0800 (bmo#825721) Out-of-bounds
    write in Cairo library

  - MFSA 2013-35/CVE-2013-0796 (bmo#827106) WebGL crash with
    Mesa graphics driver on Linux

  - MFSA 2013-36/CVE-2013-0795 (bmo#825697) Bypass of SOW
    protections allows cloning of protected nodes

  - MFSA 2013-37/CVE-2013-0794 (bmo#626775) Bypass of
    tab-modal dialog origin disclosure

  - MFSA 2013-38/CVE-2013-0793 (bmo#803870) Cross-site
    scripting (XSS) using timed history navigations"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813026"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox and others packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-irc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:seamonkey-venkman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/04");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-20.0-2.70.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-20.0-2.70.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-20.0-2.70.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-20.0-2.70.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-20.0-2.70.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-20.0-2.70.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-20.0-2.70.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-20.0-2.70.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-buildsymbols-17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debuginfo-17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-debugsource-17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-devel-debuginfo-17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-common-17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaThunderbird-translations-other-17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-1.5.1+17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"enigmail-debuginfo-1.5.1+17.0.5-33.59.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreebl3-debuginfo-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libsoftokn3-debuginfo-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-js-debuginfo-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-4.9.6-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-debuginfo-4.9.6-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-debugsource-4.9.6-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nspr-devel-4.9.6-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-certs-debuginfo-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debuginfo-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-debugsource-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-devel-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-sysinit-debuginfo-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mozilla-nss-tools-debuginfo-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-2.17-2.61.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debuginfo-2.17-2.61.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-debugsource-2.17-2.61.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-dom-inspector-2.17-2.61.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-irc-2.17-2.61.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-common-2.17-2.61.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-translations-other-2.17-2.61.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"seamonkey-venkman-2.17-2.61.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-buildsymbols-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debuginfo-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-debugsource-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"xulrunner-devel-debuginfo-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.6-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.6-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.14.3-9.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-32bit-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.5-2.65.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-20.0-2.41.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-upstream-20.0-2.41.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-buildsymbols-20.0-2.41.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debuginfo-20.0-2.41.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debugsource-20.0-2.41.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-devel-20.0-2.41.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-common-20.0-2.41.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-other-20.0-2.41.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-debuginfo-17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.5.1+17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-debuginfo-1.5.1+17.0.5-49.39.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfreebl3-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfreebl3-debuginfo-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsoftokn3-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsoftokn3-debuginfo-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-debuginfo-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-4.9.6-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-debuginfo-4.9.6-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-debugsource-4.9.6-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-devel-4.9.6-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-certs-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-certs-debuginfo-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-debuginfo-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-debugsource-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-devel-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-sysinit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-sysinit-debuginfo-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-tools-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-tools-debuginfo-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-buildsymbols-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debuginfo-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debugsource-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-debuginfo-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.6-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.6-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.14.3-2.19.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-32bit-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.5-2.38.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-20.0-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-20.0-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-20.0-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-20.0-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-20.0-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-20.0-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-20.0-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-20.0-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-buildsymbols-17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debuginfo-17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debugsource-17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-debuginfo-17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-common-17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-other-17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-1.5.1+17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-debuginfo-1.5.1+17.0.5-61.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-debuginfo-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-debuginfo-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-js-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-js-debuginfo-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-4.9.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debuginfo-4.9.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debugsource-4.9.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-devel-4.9.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-debuginfo-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debuginfo-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debugsource-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-devel-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-debuginfo-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-debuginfo-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-buildsymbols-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-debuginfo-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-debugsource-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-devel-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-devel-debuginfo-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.9.6-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.14.3-1.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xulrunner-32bit-17.0.5-1.8.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.5-1.8.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox and others");
}
