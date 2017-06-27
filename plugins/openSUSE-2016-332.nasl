#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-332.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89913);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2016-1950", "CVE-2016-1952", "CVE-2016-1953", "CVE-2016-1954", "CVE-2016-1955", "CVE-2016-1956", "CVE-2016-1957", "CVE-2016-1958", "CVE-2016-1959", "CVE-2016-1960", "CVE-2016-1961", "CVE-2016-1962", "CVE-2016-1963", "CVE-2016-1964", "CVE-2016-1965", "CVE-2016-1966", "CVE-2016-1967", "CVE-2016-1968", "CVE-2016-1970", "CVE-2016-1971", "CVE-2016-1972", "CVE-2016-1973", "CVE-2016-1974", "CVE-2016-1975", "CVE-2016-1976", "CVE-2016-1977", "CVE-2016-1979", "CVE-2016-2790", "CVE-2016-2791", "CVE-2016-2792", "CVE-2016-2793", "CVE-2016-2794", "CVE-2016-2795", "CVE-2016-2796", "CVE-2016-2797", "CVE-2016-2798", "CVE-2016-2799", "CVE-2016-2800", "CVE-2016-2801", "CVE-2016-2802");

  script_name(english:"openSUSE Security Update : MozillaFirefox / mozilla-nspr / mozilla-nss (openSUSE-2016-332)");
  script_summary(english:"Check for the openSUSE-2016-332 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for MozillaFirefox, mozilla-nspr, mozilla-nss fixes the
following issues :

MozillaFirefox was updated to Firefox 45.0 (boo#969894)

  - requires NSPR 4.12 / NSS 3.21.1

  - Instant browser tab sharing through Hello

  - Synced Tabs button in button bar

  - Tabs synced via Firefox Accounts from other devices are
    now shown in dropdown area of Awesome Bar when searching

  - Introduce a new preference (network.dns.blockDotOnion)
    to allow blocking .onion at the DNS level

  - Tab Groups (Panorama) feature removed

  - MFSA 2016-16/CVE-2016-1952/CVE-2016-1953 Miscellaneous
    memory safety hazards

  - MFSA 2016-17/CVE-2016-1954 (bmo#1243178) Local file
    overwriting and potential privilege escalation through
    CSP reports

  - MFSA 2016-18/CVE-2016-1955 (bmo#1208946) CSP reports
    fail to strip location information for embedded iframe
    pages

  - MFSA 2016-19/CVE-2016-1956 (bmo#1199923) Linux video
    memory DOS with Intel drivers

  - MFSA 2016-20/CVE-2016-1957 (bmo#1227052) Memory leak in
    libstagefright when deleting an array during MP4
    processing

  - MFSA 2016-21/CVE-2016-1958 (bmo#1228754) Displayed page
    address can be overridden

  - MFSA 2016-22/CVE-2016-1959 (bmo#1234949) Service Worker
    Manager out-of-bounds read in Service Worker Manager

  - MFSA 2016-23/CVE-2016-1960/ZDI-CAN-3545 (bmo#1246014)
    Use-after-free in HTML5 string parser

  - MFSA 2016-24/CVE-2016-1961/ZDI-CAN-3574 (bmo#1249377)
    Use-after-free in SetBody

  - MFSA 2016-25/CVE-2016-1962 (bmo#1240760) Use-after-free
    when using multiple WebRTC data channels

  - MFSA 2016-26/CVE-2016-1963 (bmo#1238440) Memory
    corruption when modifying a file being read by
    FileReader

  - MFSA 2016-27/CVE-2016-1964 (bmo#1243335) Use-after-free
    during XML transformations

  - MFSA 2016-28/CVE-2016-1965 (bmo#1245264) Addressbar
    spoofing though history navigation and Location protocol
    property

  - MFSA 2016-29/CVE-2016-1967 (bmo#1246956) Same-origin
    policy violation using perfomance.getEntries and history
    navigation with session restore

  - MFSA 2016-30/CVE-2016-1968 (bmo#1246742) Buffer overflow
    in Brotli decompression

  - MFSA 2016-31/CVE-2016-1966 (bmo#1246054) Memory
    corruption with malicious NPAPI plugin

  - MFSA 2016-32/CVE-2016-1970/CVE-2016-1971/CVE-2016-1975/
    CVE-2016-1976/CVE-2016-1972 WebRTC and LibVPX
    vulnerabilities found through code inspection

  - MFSA 2016-33/CVE-2016-1973 (bmo#1219339) Use-after-free
    in GetStaticInstance in WebRTC

  - MFSA 2016-34/CVE-2016-1974 (bmo#1228103) Out-of-bounds
    read in HTML parser following a failed allocation

  - MFSA 2016-35/CVE-2016-1950 (bmo#1245528) Buffer overflow
    during ASN.1 decoding in NSS (fixed by requiring 3.21.1)

  - MFSA 2016-36/CVE-2016-1979 (bmo#1185033) Use-after-free
    during processing of DER encoded keys in NSS (fixed by
    requiring 3.21.1)

  - MFSA 2016-37/CVE-2016-1977/CVE-2016-2790/CVE-2016-2791/
    CVE-2016-2792/CVE-2016-2793/CVE-2016-2794/CVE-2016-2795/
    CVE-2016-2796/CVE-2016-2797/CVE-2016-2798/CVE-2016-2799/
    CVE-2016-2800/CVE-2016-2801/CVE-2016-2802 Font
    vulnerabilities in the Graphite 2 library

mozilla-nspr was updated to version 4.12

  - added a PR_GetEnvSecure function, which attempts to
    detect if the program is being executed with elevated
    privileges, and returns NULL if detected. It is
    recommended to use this function in general purpose
    library code.

  - fixed a memory allocation bug related to the PR_*printf
    functions

  - exported API PR_DuplicateEnvironment, which had already
    been added in NSPR 4.10.9

  - added support for FreeBSD aarch64

  - several minor correctness and compatibility fixes

mozilla-nss was updated to NSS 3.21.1 (bmo#969894)

  - required for Firefox 45.0

  - MFSA 2016-35/CVE-2016-1950 (bmo#1245528) Buffer overflow
    during ASN.1 decoding in NSS (fixed by requiring 3.21.1)

  - MFSA 2016-36/CVE-2016-1979 (bmo#1185033) Use-after-free
    during processing of DER encoded keys in NSS (fixed by
    requiring 3.21.1)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969894"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / mozilla-nspr / mozilla-nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");
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

if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-45.0-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-45.0-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-45.0-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-45.0-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-45.0-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-45.0-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-45.0-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-45.0-65.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-debuginfo-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-debuginfo-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-4.12-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-debuginfo-4.12-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-debugsource-4.12-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-devel-4.12-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-debuginfo-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debuginfo-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debugsource-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-devel-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-debuginfo-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-debuginfo-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.12-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.21.1-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-45.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-branding-upstream-45.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-buildsymbols-45.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debuginfo-45.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debugsource-45.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-devel-45.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-common-45.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-other-45.0-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-debuginfo-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-debuginfo-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nspr-4.12-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nspr-debuginfo-4.12-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nspr-debugsource-4.12-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nspr-devel-4.12-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-debuginfo-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debuginfo-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debugsource-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-devel-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-debuginfo-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-debuginfo-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.12-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.12-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.21.1-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.21.1-12.1") ) flag++;

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
