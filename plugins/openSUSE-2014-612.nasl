#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-612.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(78818);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/12/07 05:48:41 $");

  script_cve_id("CVE-2014-1554", "CVE-2014-1574", "CVE-2014-1575", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1580", "CVE-2014-1581", "CVE-2014-1582", "CVE-2014-1583", "CVE-2014-1584", "CVE-2014-1585", "CVE-2014-1586");

  script_name(english:"openSUSE Security Update : firefox / mozilla-nspr / mozilla-nss (openSUSE-SU-2014:1344-1)");
  script_summary(english:"Check for the openSUSE-2014-612 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to Firefox 33.0 (bnc#900941) New features :

  - OpenH264 support (sandboxed)

  - Enhanced Tiles

  - Improved search experience through the location bar

  - Slimmer and faster JavaScript strings

  - New CSP (Content Security Policy) backend

  - Support for connecting to HTTP proxy over HTTPS

  - Improved reliability of the session restoration

  - Proprietary window.crypto properties/functions removed
    Security :

  - MFSA 2014-74/CVE-2014-1574/CVE-2014-1575 Miscellaneous
    memory safety hazards

  - MFSA 2014-75/CVE-2014-1576 (bmo#1041512) Buffer overflow
    during CSS manipulation

  - MFSA 2014-76/CVE-2014-1577 (bmo#1012609) Web Audio
    memory corruption issues with custom waveforms

  - MFSA 2014-77/CVE-2014-1578 (bmo#1063327) Out-of-bounds
    write with WebM video

  - MFSA 2014-78/CVE-2014-1580 (bmo#1063733) Further
    uninitialized memory use during GIF rendering

  - MFSA 2014-79/CVE-2014-1581 (bmo#1068218) Use-after-free
    interacting with text directionality

  - MFSA 2014-80/CVE-2014-1582/CVE-2014-1584 (bmo#1049095,
    bmo#1066190) Key pinning bypasses

  - MFSA 2014-81/CVE-2014-1585/CVE-2014-1586 (bmo#1062876,
    bmo#1062981) Inconsistent video sharing within iframe

  - MFSA 2014-82/CVE-2014-1583 (bmo#1015540) Accessing
    cross-origin objects via the Alarms API (only relevant
    for installed web apps)

  - requires NSPR 4.10.7

  - requires NSS 3.17.1

  - removed obsolete patches :

  - mozilla-ppc.patch

  - mozilla-libproxy-compat.patch

  - added basic appdata information

  - update to SeaMonkey 2.30 (bnc#900941)

  - venkman debugger removed from application and therefore
    obsolete package seamonkey-venkman

  - MFSA 2014-74/CVE-2014-1574/CVE-2014-1575 Miscellaneous
    memory safety hazards

  - MFSA 2014-75/CVE-2014-1576 (bmo#1041512) Buffer overflow
    during CSS manipulation

  - MFSA 2014-76/CVE-2014-1577 (bmo#1012609) Web Audio
    memory corruption issues with custom waveforms

  - MFSA 2014-77/CVE-2014-1578 (bmo#1063327) Out-of-bounds
    write with WebM video

  - MFSA 2014-78/CVE-2014-1580 (bmo#1063733) Further
    uninitialized memory use during GIF rendering

  - MFSA 2014-79/CVE-2014-1581 (bmo#1068218) Use-after-free
    interacting with text directionality

  - MFSA 2014-80/CVE-2014-1582/CVE-2014-1584 (bmo#1049095,
    bmo#1066190) Key pinning bypasses

  - MFSA 2014-81/CVE-2014-1585/CVE-2014-1586 (bmo#1062876,
    bmo#1062981) Inconsistent video sharing within iframe

  - MFSA 2014-82/CVE-2014-1583 (bmo#1015540) Accessing
    cross-origin objects via the Alarms API (only relevant
    for installed web apps)

  - requires NSPR 4.10.7

  - requires NSS 3.17.1

  - removed obsolete patches :

  - mozilla-ppc.patch

  - mozilla-libproxy-compat.patch

Changes in mozilla-nss :

  - update to 3.17.1 (bnc#897890)

  - Change library's signature algorithm default to SHA256

  - Add support for draft-ietf-tls-downgrade-scsv

  - Add clang-cl support to the NSS build system

  - Implement TLS 1.3 :

  - Part 1. Negotiate TLS 1.3

  - Part 2. Remove deprecated cipher suites andcompression.

  - Add support for little-endian powerpc64

  - update to 3.17

  - required for Firefox 33 New functionality :

  - When using ECDHE, the TLS server code may be configured
    to generate a fresh ephemeral ECDH key for each
    handshake, by setting the SSL_REUSE_SERVER_ECDHE_KEY
    socket option to PR_FALSE. The
    SSL_REUSE_SERVER_ECDHE_KEY option defaults to PR_TRUE,
    which means the server's ephemeral ECDH key is reused
    for multiple handshakes. This option does not affect the
    TLS client code, which always generates a fresh
    ephemeral ECDH key for each handshake. New Macros

  - SSL_REUSE_SERVER_ECDHE_KEY Notable Changes :

  - The manual pages for the certutil and pp tools have been
    updated to document the new parameters that had been
    added in NSS 3.16.2.

  - On Windows, the new build variable USE_STATIC_RTL can be
    used to specify the static C runtime library should be
    used. By default the dynamic C runtime library is used.
    Changes in mozilla-nspr :

  - update to version 4.10.7

  - bmo#836658: VC11+ defaults to SSE2 builds by default.

  - bmo#979278: TSan: data race
    nsprpub/pr/src/threads/prtpd.c:103
    PR_NewThreadPrivateIndex.

  - bmo#1026129: Replace some manual declarations of MSVC
    intrinsics with #include <intrin.h>.

  - bmo#1026469: Use AC_CHECK_LIB instead of
    MOZ_CHECK_PTHREADS. Skip compiler checks when using
    MSVC, even when $CC is not literally 'cl'.

  - bmo#1034415: NSPR hardcodes the C compiler to cl on
    Windows.

  - bmo#1042408: Compilation fix for Android > API level 19.

  - bmo#1043082: NSPR's build system hardcodes -MD."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1012609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1015540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1026129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1026469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1034415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1041512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1042408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1043082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1049095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1062876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1062981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1063327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1063733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1063971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1066190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1068218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=836658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=979278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=894370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=896624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=901213"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox / mozilla-nspr / mozilla-nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-33.0-1.90.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-33.0-1.90.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-33.0-1.90.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-33.0-1.90.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-33.0-1.90.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-33.0-1.90.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-33.0-1.90.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-33.0-1.90.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-debuginfo-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-debuginfo-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-4.10.7-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debuginfo-4.10.7-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debugsource-4.10.7-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-devel-4.10.7-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-debuginfo-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debuginfo-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debugsource-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-devel-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-debuginfo-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-debuginfo-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-2.30-1.61.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debuginfo-2.30-1.61.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debugsource-2.30-1.61.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-dom-inspector-2.30-1.61.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-irc-2.30-1.61.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-common-2.30-1.61.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-other-2.30-1.61.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.7-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.17.1-1.59.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.17.1-1.59.1") ) flag++;

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
