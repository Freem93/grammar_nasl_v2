#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1248-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100151);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/12 13:30:58 $");

  script_cve_id("CVE-2016-1950", "CVE-2016-2834", "CVE-2016-8635", "CVE-2016-9574", "CVE-2017-5429", "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435", "CVE-2017-5436", "CVE-2017-5437", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440", "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444", "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5448", "CVE-2017-5459", "CVE-2017-5460", "CVE-2017-5461", "CVE-2017-5462", "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5469");
  script_osvdb_id(135603, 139466, 139467, 139468, 139469, 147522, 151245, 151246, 151247, 151476, 155950, 155951, 155952, 155953, 155955, 155956, 155957, 155958, 155959, 155960, 155961, 155962, 155963, 155964, 155965, 155966, 155967, 155968, 155972, 155976, 155992, 155999, 156051, 156052, 156053, 156054, 156055, 156056, 156057, 156058, 156059, 156139);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : MozillaFirefox, mozilla-nss, mozilla-nspr, java-1_8_0-openjdk (SUSE-SU-2017:1248-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the Firefox ESR release 45.9. Mozilla
NSS was updated to support TLS 1.3 (close to release draft) and
various new ciphers, PRFs, Diffie Hellman key agreement and support
for more hashes. Security issues fixed in Firefox (bsc#1035082)

  - MFSA 2017-11/CVE-2017-5469: Potential Buffer overflow in
    flex-generated code

  - MFSA 2017-11/CVE-2017-5429: Memory safety bugs fixed in
    Firefox 53, Firefox ESR 45.9, and Firefox ESR 52.1

  - MFSA 2017-11/CVE-2017-5439: Use-after-free in nsTArray
    Length() during XSLT processing

  - MFSA 2017-11/CVE-2017-5438: Use-after-free in nsAutoPtr
    during XSLT processing

  - MFSA 2017-11/CVE-2017-5437: Vulnerabilities in Libevent
    library

  - MFSA 2017-11/CVE-2017-5436: Out-of-bounds write with
    malicious font in Graphite 2

  - MFSA 2017-11/CVE-2017-5435: Use-after-free during
    transaction processing in the editor

  - MFSA 2017-11/CVE-2017-5434: Use-after-free during focus
    handling

  - MFSA 2017-11/CVE-2017-5433: Use-after-free in SMIL
    animation functions

  - MFSA 2017-11/CVE-2017-5432: Use-after-free in text input
    selection

  - MFSA 2017-11/CVE-2017-5464: Memory corruption with
    accessibility and DOM manipulation

  - MFSA 2017-11/CVE-2017-5465: Out-of-bounds read in
    ConvolvePixel

  - MFSA 2017-11/CVE-2017-5460: Use-after-free in frame
    selection

  - MFSA 2017-11/CVE-2017-5448: Out-of-bounds write in
    ClearKeyDecryptor

  - MFSA 2017-11/CVE-2017-5446: Out-of-bounds read when
    HTTP/2 DATA frames are sent with incorrect data

  - MFSA 2017-11/CVE-2017-5447: Out-of-bounds read during
    glyph processing

  - MFSA 2017-11/CVE-2017-5444: Buffer overflow while
    parsing application/http-index-format content

  - MFSA 2017-11/CVE-2017-5445: Uninitialized values used
    while parsing application/http-index-format content

  - MFSA 2017-11/CVE-2017-5442: Use-after-free during style
    changes

  - MFSA 2017-11/CVE-2017-5443: Out-of-bounds write during
    BinHex decoding

  - MFSA 2017-11/CVE-2017-5440: Use-after-free in
    txExecutionState destructor during XSLT processing

  - MFSA 2017-11/CVE-2017-5441: Use-after-free with
    selection during scroll events

  - MFSA 2017-11/CVE-2017-5459: Buffer overflow in WebGL
    Mozilla NSS was updated to 3.29.5, bringing new features
    and fixing bugs :

  - Update to NSS 3.29.5 :

  - MFSA 2017-11/CVE-2017-5461: Rare crashes in the base 64
    decoder and encoder were fixed.

  - MFSA 2017-11/CVE-2017-5462: A carry over bug in the RNG
    was fixed.

  - CVE-2016-9574: Remote DoS during session handshake when
    using SessionTicket extention and ECDHE-ECDSA
    (bsc#1015499).

  - requires NSPR >= 4.13.1

  - Update to NSS 3.29.3

  - enables TLS 1.3 by default

  - Fixed a bug in hash computation (and build with GCC 7
    which complains about shifts of boolean values).
    (bsc#1030071, bmo#1348767)

  - Update to NSS 3.28.3 This is a patch release to fix
    binary compatibility issues.

  - Update to NSS 3.28.1 This is a patch release to update
    the list of root CA certificates.

  - The following CA certificates were Removed CN = Buypass
    Class 2 CA 1 CN = Root CA Generalitat Valenciana OU =
    RSA Security 2048 V3

  - The following CA certificates were Added OU = AC RAIZ
    FNMT-RCM CN = Amazon Root CA 1 CN = Amazon Root CA 2 CN
    = Amazon Root CA 3 CN = Amazon Root CA 4 CN = LuxTrust
    Global Root 2 CN = Symantec Class 1 Public Primary
    Certification Authority - G4 CN = Symantec Class 1
    Public Primary Certification Authority - G6 CN =
    Symantec Class 2 Public Primary Certification Authority
    - G4 CN = Symantec Class 2 Public Primary Certification
    Authority - G6

  - The version number of the updated root CA list has been
    set to 2.11

  - Update to NSS 3.28 New functionality :

  - NSS includes support for TLS 1.3 draft -18. This
    includes a number of improvements to TLS 1.3 :

  - The signed certificate timestamp, used in certificate
    transparency, is supported in TLS 1.3.

  - Key exporters for TLS 1.3 are supported. This includes
    the early key exporter, which can be used if 0-RTT is
    enabled. Note that there is a difference between TLS 1.3
    and key exporters in older versions of TLS. TLS 1.3 does
    not distinguish between an empty context and no context.

  - The TLS 1.3 (draft) protocol can be enabled, by defining
    NSS_ENABLE_TLS_1_3=1 when building NSS.

  - NSS includes support for the X25519 key exchange
    algorithm, which is supported and enabled by default in
    all versions of TLS. Notable Changes :

  - NSS can no longer be compiled with support for
    additional elliptic curves. This was previously possible
    by replacing certain NSS source files.

  - NSS will now detect the presence of tokens that support
    additional elliptic curves and enable those curves for
    use in TLS. Note that this detection has a one-off
    performance cost, which can be avoided by using the
    SSL_NamedGroupConfig function to limit supported groups
    to those that NSS provides.

  - PKCS#11 bypass for TLS is no longer supported and has
    been removed.

  - Support for 'export' grade SSL/TLS cipher suites has
    been removed.

  - NSS now uses the signature schemes definition in TLS
    1.3. This also affects TLS 1.2. NSS will now only
    generate signatures with the combinations of hash and
    signature scheme that are defined in TLS 1.3, even when
    negotiating TLS 1.2.

  - This means that SHA-256 will only be used with P-256
    ECDSA certificates, SHA-384 with P-384 certificates, and
    SHA-512 with P-521 certificates. SHA-1 is permitted (in
    TLS 1.2 only) with any certificate for backward
    compatibility reasons.

  - NSS will now no longer assume that default signature
    schemes are supported by a peer if there was no commonly
    supported signature scheme.

  - NSS will now check if RSA-PSS signing is supported by
    the token that holds the private key prior to using it
    for TLS.

  - The certificate validation code contains checks to no
    longer trust certificates that are issued by old WoSign
    and StartCom CAs after October 21, 2016. This is
    equivalent to the behavior that Mozilla will release
    with Firefox 51.

  - Update to NSS 3.27.2

  - Fixed SSL_SetTrustAnchors leaks (bmo#1318561)

  - raised the minimum softokn/freebl version to 3.28 as
    reported in (boo#1021636)

  - Update to NSS 3.26.2 New Functionality :

  - the selfserv test utility has been enhanced to support
    ALPN (HTTP/1.1) and 0-RTT

  - added support for the System-wide crypto policy
    available on Fedora Linux see
    http://fedoraproject.org/wiki/Changes/CryptoPolicy

  - introduced build flag NSS_DISABLE_LIBPKIX that allows
    compilation of NSS without the libpkix library Notable
    Changes :

  - The following CA certificate was Added CN = ISRG Root X1

  - NPN is disabled and ALPN is enabled by default

  - the NSS test suite now completes with the experimental
    TLS 1.3 code enabled

  - several test improvements and additions, including a
    NIST known answer test Changes in 3.26.2

  - MD5 signature algorithms sent by the server in
    CertificateRequest messages are now properly ignored.
    Previously, with rare server configurations, an MD5
    signature algorithm might have been selected for client
    authentication and caused the client to abort the
    connection soon after.

  - Update to NSS 3.25 New functionality :

  - Implemented DHE key agreement for TLS 1.3

  - Added support for ChaCha with TLS 1.3

  - Added support for TLS 1.2 ciphersuites that use SHA384
    as the PRF

  - In previous versions, when using client authentication
    with TLS 1.2, NSS only supported certificate_verify
    messages that used the same signature hash algorithm as
    used by the PRF. This limitation has been removed.
    Notable changes :

  - An SSL socket can no longer be configured to allow both
    TLS 1.3 and SSLv3

  - Regression fix: NSS no longer reports a failure if an
    application attempts to disable the SSLv2 protocol.

  - The list of trusted CA certificates has been updated to
    version 2.8

  - The following CA certificate was Removed Sonera Class1
    CA

  - The following CA certificates were Added Hellenic
    Academic and Research Institutions RootCA 2015 Hellenic
    Academic and Research Institutions ECC RootCA 2015
    Certplus Root CA G1 Certplus Root CA G2 OpenTrust Root
    CA G1 OpenTrust Root CA G2 OpenTrust Root CA G3

  - Update to NSS 3.24 New functionality :

  - NSS softoken has been updated with the latest National
    Institute of Standards and Technology (NIST) guidance
    (as of 2015) :

  - Software integrity checks and POST functions are
    executed on shared library load. These checks have been
    disabled by default, as they can cause a performance
    regression. To enable these checks, you must define
    symbol NSS_FORCE_FIPS when building NSS.

  - Counter mode and Galois/Counter Mode (GCM) have checks
    to prevent counter overflow.

  - Additional CSPs are zeroed in the code.

  - NSS softoken uses new guidance for how many Rabin-Miller
    tests are needed to verify a prime based on prime size.

  - NSS softoken has also been updated to allow NSS to run
    in FIPS Level 1 (no password). This mode is triggered by
    setting the database password to the empty string. In
    FIPS mode, you may move from Level 1 to Level 2 (by
    setting an appropriate password), but not the reverse.

  - A SSL_ConfigServerCert function has been added for
    configuring SSL/TLS server sockets with a certificate
    and private key. Use this new function in place of
    SSL_ConfigSecureServer,
    SSL_ConfigSecureServerWithCertChain,
    SSL_SetStapledOCSPResponses, and
    SSL_SetSignedCertTimestamps. SSL_ConfigServerCert
    automatically determines the certificate type from the
    certificate and private key. The caller is no longer
    required to use SSLKEAType explicitly to select a 'slot'
    into which the certificate is configured (which
    incorrectly identifies a key agreement type rather than
    a certificate). Separate functions for configuring
    Online Certificate Status Protocol (OCSP) responses or
    Signed Certificate Timestamps are not needed, since
    these can be added to the optional
    SSLExtraServerCertData struct provided to
    SSL_ConfigServerCert. Also, partial support for RSA
    Probabilistic Signature Scheme (RSA-PSS) certificates
    has been added. Although these certificates can be
    configured, they will not be used by NSS in this
    version.

  - Deprecate the member attribute authAlgorithm of type
    SSLCipherSuiteInfo. Instead, applications should use the
    newly added attribute authType.

  - Add a shared library (libfreeblpriv3) on Linux platforms
    that define FREEBL_LOWHASH.

  - Remove most code related to SSL v2, including the
    ability to actively send a SSLv2-compatible client
    hello. However, the server-side implementation of the
    SSL/TLS protocol still supports processing of received
    v2-compatible client hello messages.

  - Disable (by default) NSS support in optimized builds for
    logging SSL/TLS key material to a logfile if the
    SSLKEYLOGFILE environment variable is set. To enable the
    functionality in optimized builds, you must define the
    symbol NSS_ALLOW_SSLKEYLOGFILE when building NSS.

  - Update NSS to protect it against the Cachebleed attack.

  - Disable support for DTLS compression.

  - Improve support for TLS 1.3. This includes support for
    DTLS 1.3. Note that TLS 1.3 support is experimental and
    not suitable for production use.

  - Update to NSS 3.23 New functionality :

  - ChaCha20/Poly1305 cipher and TLS cipher suites now
    supported

  - Experimental-only support TLS 1.3 1-RTT mode (draft-11).
    This code is not ready for production use. Notable
    changes :

  - The list of TLS extensions sent in the TLS handshake has
    been reordered to increase compatibility of the Extended
    Master Secret with with servers

  - The build time environment variable NSS_ENABLE_ZLIB has
    been renamed to NSS_SSL_ENABLE_ZLIB

  - The build time environment variable
    NSS_DISABLE_CHACHAPOLY was added, which can be used to
    prevent compilation of the ChaCha20/Poly1305 code.

  - The following CA certificates were Removed

  - Staat der Nederlanden Root CA

  - NetLock Minositett Kozjegyzoi (Class QA)
    Tanusitvanykiado

  - NetLock Kozjegyzoi (Class A) Tanusitvanykiado

  - NetLock Uzleti (Class B) Tanusitvanykiado

  - NetLock Expressz (Class C) Tanusitvanykiado

  - VeriSign Class 1 Public PCA - G2

  - VeriSign Class 3 Public PCA

  - VeriSign Class 3 Public PCA - G2

  - CA Disig

  - The following CA certificates were Added

  + SZAFIR ROOT CA2

  + Certum Trusted Network CA 2

  - The following CA certificate had the Email trust bit
    turned on

  + Actalis Authentication Root CA Security fixes :

  - CVE-2016-2834: Memory safety bugs (boo#983639)
    MFSA-2016-61 bmo#1206283 bmo#1221620 bmo#1241034
    bmo#1241037

  - Update to NSS 3.22.3

  - Increase compatibility of TLS extended master secret,
    don't send an empty TLS extension last in the handshake
    (bmo#1243641)

  - Fixed a heap-based buffer overflow related to the
    parsing of certain ASN.1 structures. An attacker could
    create a specially crafted certificate which, when
    parsed by NSS, would cause a crash or execution of
    arbitrary code with the permissions of the user.
    (CVE-2016-1950, bmo#1245528)

  - Update to NSS 3.22.2 New functionality :

  - RSA-PSS signatures are now supported (bmo#1215295)

  - Pseudorandom functions based on hashes other than SHA-1
    are now supported

  - Enforce an External Policy on NSS from a config file
    (bmo#1009429)

  - CVE-2016-8635: Fix for DH small subgroup confinement
    attack (bsc#1015547) Mozilla NSPR was updated to version
    4.13.1: The previously released version 4.13 had changed
    pipes to be nonblocking by default, and as a
    consequence, PollEvent was changed to not block on
    clear. The NSPR development team received reports that
    these changes caused regressions in some applications
    that use NSPR, and it has been decided to revert the
    changes made in NSPR 4.13. NSPR 4.13.1 restores the
    traditional behavior of pipes and PollEvent. Mozilla
    NSPR update to version 4.13 had these changes :

  - PL_strcmp (and others) were fixed to return consistent
    results when one of the arguments is NULL.

  - PollEvent was fixed to not block on clear.

  - Pipes are always nonblocking.

  - PR_GetNameForIdentity: added thread safety lock and
    bound checks.

  - Removed the PLArena freelist.

  - Avoid some integer overflows.

  - fixed several comments. This update also contains
    java-1_8_0-openjdk that needed to be rebuilt against the
    new mozilla-nss version.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://fedoraproject.org/wiki/Changes/CryptoPolicy"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1035082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8635.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9574.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5436.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5437.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5443.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5445.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5447.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5448.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5460.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5462.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5464.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5465.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5469.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171248-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2ea3260"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-748=1

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2017-748=1

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-748=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-748=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-748=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-748=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-748=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-748=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-748=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debuginfo-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-debugsource-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"MozillaFirefox-translations-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-devel-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-hmac-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-hmac-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debuginfo-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debugsource-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debugsource-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-tools-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-tools-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libfreebl3-hmac-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libsoftokn3-hmac-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nspr-debuginfo-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-certs-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debuginfo-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-debugsource-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-devel-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"MozillaFirefox-translations-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-hmac-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-hmac-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debuginfo-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debugsource-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-devel-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debugsource-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-devel-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-tools-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-tools-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfreebl3-hmac-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsoftokn3-hmac-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nspr-debuginfo-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-certs-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debugsource-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-translations-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-demo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-devel-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libfreebl3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libfreebl3-hmac-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-hmac-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-debugsource-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-certs-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-tools-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libfreebl3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libfreebl3-hmac-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-hmac-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-debugsource-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"MozillaFirefox-translations-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libfreebl3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libfreebl3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsoftokn3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nspr-debugsource-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-tools-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-debugsource-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-translations-45.9.0esr-105.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.121-23.4")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfreebl3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfreebl3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfreebl3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nspr-debugsource-4.13.1-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-certs-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-debugsource-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-sysinit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-tools-3.29.5-57.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"mozilla-nss-tools-debuginfo-3.29.5-57.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / mozilla-nss / mozilla-nspr / java-1_8_0-openjdk");
}
