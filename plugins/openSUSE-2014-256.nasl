#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-256.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75307);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/06 15:36:33 $");

  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2014:0448-1)");
  script_summary(english:"Check for the openSUSE-2014-256 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 28.0, receiving enhancements,
bug and security fixes. Mozilla NSPR was updated to 4.10.4 receiving
enhancements, bug and security fixes. Mozilla NSS was updated to
3.15.5 receiving enhancements, bug and security fixes.

Changes in MozillaFirefox :

  - update to Firefox 28.0 (bnc#868603)

  - MFSA 2014-15/CVE-2014-1493/CVE-2014-1494 Miscellaneous
    memory safety hazards

  - MFSA 2014-17/CVE-2014-1497 (bmo#966311) Out of bounds
    read during WAV file decoding

  - MFSA 2014-18/CVE-2014-1498 (bmo#935618)
    crypto.generateCRMFRequest does not validate type of key

  - MFSA 2014-19/CVE-2014-1499 (bmo#961512) Spoofing attack
    on WebRTC permission prompt

  - MFSA 2014-20/CVE-2014-1500 (bmo#956524) onbeforeunload
    and JavaScript navigation DOS

  - MFSA 2014-22/CVE-2014-1502 (bmo#972622) WebGL content
    injection from one domain to rendering in another

  - MFSA 2014-23/CVE-2014-1504 (bmo#911547) Content Security
    Policy for data: documents not preserved by session
    restore

  - MFSA 2014-26/CVE-2014-1508 (bmo#963198) Information
    disclosure through polygon rendering in MathML

  - MFSA 2014-27/CVE-2014-1509 (bmo#966021) Memory
    corruption in Cairo during PDF font rendering

  - MFSA 2014-28/CVE-2014-1505 (bmo#941887) SVG filters
    information disclosure through feDisplacementMap

  - MFSA 2014-29/CVE-2014-1510/CVE-2014-1511 (bmo#982906,
    bmo#982909) Privilege escalation using
    WebIDL-implemented APIs

  - MFSA 2014-30/CVE-2014-1512 (bmo#982957) Use-after-free
    in TypeObject

  - MFSA 2014-31/CVE-2014-1513 (bmo#982974) Out-of-bounds
    read/write through neutering ArrayBuffer objects

  - MFSA 2014-32/CVE-2014-1514 (bmo#983344) Out-of-bounds
    write through TypedArrayObject after neutering

  - requires NSPR 4.10.3 and NSS 3.15.5

  - new build dependency (and recommends) :

  - libpulse

  - JS math correctness issue (bmo#941381)

Changes in mozilla-nspr :

  - update to version 4.10.4

  - bmo#767759: Add support for new x32 abi

  - bmo#844784: Thread data race in PR_EnterMonitor

  - bmo#939786: data race
    nsprpub/pr/src/pthreads/ptthread.c:137 _pt_root

  - bmo#958796: Users of _beginthreadex that set a custom
    stack size may not be getting the behavior they want

  - bmo#963033: AArch64 support update for NSPR

  - bmo#969061:&#9;Incorrect end-of-list test when iterating
    over a PRCList in prcountr.c and prtrace.c

  - bmo#971152: IPv6 detection on linux depends on
    availability of /proc/net/if_inet6

  - update to version 4.10.3

  - bmo#749849: ensure we'll free the thread-specific data
    key.

  - bmo#941461: don't compile android with unaligned memory
    access.

  - bmo#932398: Add PR_SyncMemMap, a portable version of
    msync/FlushViewOfFile.

  - bmo#952621: Fix a thread-unsafe access to lock->owner in
    PR_Lock.

  - bmo#957458: Fix several bugs in the lock rank checking
    code.

  - bmo#936320: Use an alternative test for IPv6 support on
    Linux to avoid opening a socket.

Changes in mozilla-nss :

  - update to 3.15.5

  - required for Firefox 28

  - export FREEBL_LOWHASH to get the correct default headers
    (bnc#865539) New functionality

  - Added support for the TLS application layer protocol
    negotiation (ALPN) extension. Two SSL socket options,
    SSL_ENABLE_NPN and SSL_ENABLE_ALPN, can be used to
    control whether NPN or ALPN (or both) should be used for
    application layer protocol negotiation.

  - Added the TLS padding extension. The extension type
    value is 35655, which may change when an official
    extension type value is assigned by IANA. NSS
    automatically adds the padding extension to ClientHello
    when necessary.

  - Added a new macro CERT_LIST_TAIL, defined in certt.h,
    for getting the tail of a CERTCertList. Notable Changes

  - bmo#950129: Improve the OCSP fetching policy when
    verifying OCSP responses

  - bmo#949060: Validate the iov input argument (an array of
    PRIOVec structures) of ssl_WriteV (called via
    PR_Writev). Applications should still take care when
    converting struct iov to PRIOVec because the iov_len
    members of the two structures have different types
    (size_t vs. int). size_t is unsigned and may be larger
    than int."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868603"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-28.0-1.56.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-28.0-1.56.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-28.0-1.56.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-28.0-1.56.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-28.0-1.56.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-28.0-1.56.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-28.0-1.56.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-28.0-1.56.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-debuginfo-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-debuginfo-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-4.10.4-1.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debuginfo-4.10.4-1.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debugsource-4.10.4-1.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-devel-4.10.4-1.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-debuginfo-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debuginfo-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debugsource-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-devel-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-debuginfo-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-debuginfo-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.4-1.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.4-1.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.15.5-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-28.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-28.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-28.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-28.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-28.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-28.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-28.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-28.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-4.10.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debuginfo-4.10.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debugsource-4.10.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-devel-4.10.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.15.5-16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.15.5-16.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
