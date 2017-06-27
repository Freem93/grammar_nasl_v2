#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-718.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86807);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-4513", "CVE-2015-4514", "CVE-2015-4515", "CVE-2015-4518", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7183", "CVE-2015-7185", "CVE-2015-7186", "CVE-2015-7187", "CVE-2015-7188", "CVE-2015-7189", "CVE-2015-7190", "CVE-2015-7191", "CVE-2015-7192", "CVE-2015-7193", "CVE-2015-7194", "CVE-2015-7195", "CVE-2015-7196", "CVE-2015-7197", "CVE-2015-7198", "CVE-2015-7199", "CVE-2015-7200");

  script_name(english:"openSUSE Security Update : MozillaFirefox / mozilla-nspr / mozilla-nss / etc (openSUSE-2015-718)");
  script_summary(english:"Check for the openSUSE-2015-718 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 42.0, fixing bugs and security
issues. Mozilla xulrunner was updated to xulrunner 38.4.0. SeaMonkey
was updated to 2.39.

New features in Mozilla Firefox :

  - Private Browsing with Tracking Protection blocks certain
    Web elements that could be used to record your behavior
    across sites

  - Control Center that contains site security and privacy
    controls

  - Login Manager improvements

  - WebRTC improvements

  - Indicator added to tabs that play audio with one-click
    muting

  - Media Source Extension for HTML5 video available for all
    sites

Security fixes :

  - MFSA 2015-116/CVE-2015-4513/CVE-2015-4514 Miscellaneous
    memory safety hazards

  - MFSA 2015-117/CVE-2015-4515 (bmo#1046421) Information
    disclosure through NTLM authentication

  - MFSA 2015-118/CVE-2015-4518 (bmo#1182778, bmo#1136692)
    CSP bypass due to permissive Reader mode whitelist

  - MFSA 2015-119/CVE-2015-7185 (bmo#1149000) (Android only)
    Firefox for Android addressbar can be removed after
    fullscreen mode

  - MFSA 2015-120/CVE-2015-7186 (bmo#1193027) (Android only)
    Reading sensitive profile files through local HTML file
    on Android

  - MFSA 2015-121/CVE-2015-7187 (bmo#1195735) disabling
    scripts in Add-on SDK panels has no effect

  - MFSA 2015-122/CVE-2015-7188 (bmo#1199430) Trailing
    whitespace in IP address hostnames can bypass
    same-origin policy

  - MFSA 2015-123/CVE-2015-7189 (bmo#1205900) Buffer
    overflow during image interactions in canvas

  - MFSA 2015-124/CVE-2015-7190 (bmo#1208520) (Android only)
    Android intents can be used on Firefox for Android to
    open privileged files

  - MFSA 2015-125/CVE-2015-7191 (bmo#1208956) (Android only)
    XSS attack through intents on Firefox for Android

  - MFSA 2015-126/CVE-2015-7192 (bmo#1210023) (OS X only)
    Crash when accessing HTML tables with accessibility
    tools on OS X

  - MFSA 2015-127/CVE-2015-7193 (bmo#1210302) CORS preflight
    is bypassed when non-standard Content-Type headers are
    received

  - MFSA 2015-128/CVE-2015-7194 (bmo#1211262) Memory
    corruption in libjar through zip files

  - MFSA 2015-129/CVE-2015-7195 (bmo#1211871) Certain
    escaped characters in host of Location-header are being
    treated as non-escaped

  - MFSA 2015-130/CVE-2015-7196 (bmo#1140616) JavaScript
    garbage collection crash with Java applet

  - MFSA 2015-131/CVE-2015-7198/CVE-2015-7199/CVE-2015-7200
    (bmo#1188010, bmo#1204061, bmo#1204155) Vulnerabilities
    found through code inspection

  - MFSA 2015-132/CVE-2015-7197 (bmo#1204269) Mixed content
    WebSocket policy bypass through workers

  - MFSA 2015-133/CVE-2015-7181/CVE-2015-7182/CVE-2015-7183
    (bmo#1202868, bmo#1205157) NSS and NSPR memory
    corruption issues (fixed in mozilla-nspr and mozilla-nss
    packages)

mozilla-nspr was updated to 4.10.10 :

  - MFSA 2015-133/CVE-2015-7183 (bmo#1205157) memory
    corruption issues

This update includes the update to version 4.10.9

  - bmo#1021167: Leak of |poll_list| on failure in
    _MW_PollInternal

  - bmo#1030692: Make compiling nspr on windows possible
    again.

  - bmo#1088790: dosprint() doesn't support %zu and other
    size formats

  - bmo#1130787: prtime.h does not compile with MSVC's /Za
    (ISO C/C++ conformance) option

  - bmo#1153610: MIPS64: Add support for n64 ABI

  - bmo#1156029: Teach clang-analyzer about PR_ASSERT

  - bmo#1160125: MSVC version detection is broken CC is set
    to a wrapper (like sccache)

  - bmo#1163346: Add NSPR support for FreeBSD mips/mips64

  - bmo#1169185: Add support for OpenRISC (or1k)

  - bmo:1174749: Remove configure block for iOS that uses
    MACOS_SDK_DIR

  - bmo#1174781: PR_GetInheritedFD can use uninitialized
    variables

mozilla-nss was updated to 3.20.1 :

  - requires NSPR 4.10.10

  - MFSA 2015-133/CVE-2015-7181/CVE-2015-7182 (bmo#1192028,
    bmo#1202868) memory corruption issues

  - Install the static libfreebl.a that is needed in order
    to link Sun elliptical curves provider in Java 7.

This includes the update of Mozilla NSS to NSS 3.20 New 
functionality :

  - The TLS library has been extended to support DHE
    ciphersuites in server applications. New Functions :

  - SSL_DHEGroupPrefSet - Configure the set of
    allowed/enabled DHE group parameters that can be used by
    NSS for a server socket.

  - SSL_EnableWeakDHEPrimeGroup - Enable the use of weak DHE
    group parameters that are smaller than the library
    default's minimum size. New Types :

  - SSLDHEGroupType - Enumerates the set of DHE parameters
    embedded in NSS that can be used with function
    SSL_DHEGroupPrefSet. New Macros :

  - SSL_ENABLE_SERVER_DHE - A socket option user to enable
    or disable DHE ciphersuites for a server socket. Notable
    Changes :

  - For backwards compatibility reasons, the server side
    implementation of the TLS library keeps all DHE
    ciphersuites disabled by default. They can be enabled
    with the new socket option SSL_ENABLE_SERVER_DHE and the
    SSL_OptionSet or the SSL_OptionSetDefault API.

  - The server side implementation of the TLS implementation
    does not support session tickets when using a DHE
    ciphersuite (see bmo#1174677).

  - Support for the following ciphersuites has been added :

  - TLS_DHE_DSS_WITH_AES_128_GCM_SHA256

  - TLS_DHE_DSS_WITH_AES_128_CBC_SHA256

  - TLS_DHE_DSS_WITH_AES_256_CBC_SHA256

  - By default, the server side TLS implementation will use
    DHE parameters with a size of 2048 bits when using DHE
    ciphersuites.

  - NSS embeds fixed DHE parameters sized 2048, 3072, 4096,
    6144 and 8192 bits, which were copied from version 08 of
    the Internet-Draft 'Negotiated Finite Field
    Diffie-Hellman Ephemeral Parameters for TLS', Appendix
    A.

  - A new API SSL_DHEGroupPrefSet has been added to NSS,
    which allows a server application to select one or
    multiple of the embedded DHE parameters as the preferred
    parameters. The current implementation of NSS will
    always use the first entry in the array that is passed
    as a parameter to the SSL_DHEGroupPrefSet API. In future
    versions of the TLS implementation, a TLS client might
    signal a preference for certain DHE parameters, and the
    NSS TLS server side implementation might select a
    matching entry from the set of parameters that have been
    configured as preferred on the server side.

  - NSS optionally supports the use of weak DHE parameters
    with DHE ciphersuites to support legacy clients. In
    order to enable this support, the new API
    SSL_EnableWeakDHEPrimeGroup must be used. Each time this
    API is called for the first time in a process, a fresh
    set of weak DHE parameters will be randomly created,
    which may take a long amount of time. Please refer to
    the comments in the header file that declares the
    SSL_EnableWeakDHEPrimeGroup API for additional details.

  - The size of the default PQG parameters used by certutil
    when creating DSA keys has been increased to use 2048
    bit parameters.

  - The selfserv utility has been enhanced to support the
    new DHE features.

  - NSS no longer supports C compilers that predate the ANSI
    C standard (C89).

It also includes the update to NSS 3.19.3; certstore updates only

  - The following CA certificates were removed

  - Buypass Class 3 CA 1

  - T&Uuml;RKTRUST Elektronik Sertifika Hizmet
    Sa&#x11F;lay&#x131;c&#x131;s&#x131;

  - SG TRUST SERVICES RACINE

  - TC TrustCenter Universal CA I

  - TC TrustCenter Class 2 CA II

  - The following CA certificate had the Websites trust bit
    turned off

  - ComSign Secured CA

  - The following CA certificates were added

  - T&Uuml;RKTRUST Elektronik Sertifika Hizmet
    Sa&#x11F;lay&#x131;c&#x131;s&#x131; H5

  - T&Uuml;RKTRUST Elektronik Sertifika Hizmet
    Sa&#x11F;lay&#x131;c&#x131;s&#x131; H6

  - Certinomis - Root CA

  - The version number of the updated root CA list has been
    set to 2.5

  - Install blapi.h and algmac.h that are needed in order to
    build Sun elliptical curves provider in Java 7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=952810"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / mozilla-nspr / mozilla-nss / etc packages."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-42.0-94.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-42.0-94.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-42.0-94.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-42.0-94.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-42.0-94.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-42.0-94.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-42.0-94.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-42.0-94.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-4.10.10-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debuginfo-4.10.10-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-debugsource-4.10.10-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nspr-devel-4.10.10-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-2.39-59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debuginfo-2.39-59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-debugsource-2.39-59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-dom-inspector-2.39-59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-irc-2.39-59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-common-2.39-59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"seamonkey-translations-other-2.39-59.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.10-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.10-25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.20.1-62.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-42.0-50.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-42.0-50.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-42.0-50.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-42.0-50.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-42.0-50.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-42.0-50.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-42.0-50.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-42.0-50.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libfreebl3-debuginfo-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libsoftokn3-debuginfo-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-4.10.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-debuginfo-4.10.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-debugsource-4.10.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nspr-devel-4.10.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-certs-debuginfo-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debuginfo-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-debugsource-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-devel-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-sysinit-debuginfo-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mozilla-nss-tools-debuginfo-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-2.39-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-debuginfo-2.39-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-debugsource-2.39-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-dom-inspector-2.39-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-irc-2.39-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-translations-common-2.39-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"seamonkey-translations-other-2.39-23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.10-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.20.1-19.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-42.0-3.5") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-branding-upstream-42.0-3.5") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-buildsymbols-42.0-3.5") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debuginfo-42.0-3.5") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-debugsource-42.0-3.5") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-devel-42.0-3.5") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-common-42.0-3.5") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"MozillaFirefox-translations-other-42.0-3.5") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libfreebl3-debuginfo-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libsoftokn3-debuginfo-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nspr-4.10.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nspr-debuginfo-4.10.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nspr-debugsource-4.10.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nspr-devel-4.10.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-certs-debuginfo-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debuginfo-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-debugsource-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-devel-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-sysinit-debuginfo-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mozilla-nss-tools-debuginfo-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-2.39-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-debuginfo-2.39-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-debugsource-2.39-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-dom-inspector-2.39-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-irc-2.39-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-translations-common-2.39-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"seamonkey-translations-other-2.39-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xulrunner-38.4.0-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xulrunner-debuginfo-38.4.0-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xulrunner-debugsource-38.4.0-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xulrunner-devel-38.4.0-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.20.1-3.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xulrunner-32bit-38.4.0-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-38.4.0-3.2") ) flag++;

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
