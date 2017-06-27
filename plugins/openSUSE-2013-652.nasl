#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-652.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75122);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:20:15 $");

  script_cve_id("CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1704", "CVE-2013-1705", "CVE-2013-1708", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1711", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717");

  script_name(english:"openSUSE Security Update : MozillaFirefox / MozillaThunderbird / mozilla-nspr / etc (openSUSE-SU-2013:1348-1)");
  script_summary(english:"Check for the openSUSE-2013-652 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes in seamonkey :

  - update to SeaMonkey 2.20 (bnc#833389)

  - MFSA 2013-63/CVE-2013-1701/CVE-2013-1702 Miscellaneous
    memory safety hazards

  - MFSA 2013-64/CVE-2013-1704 (bmo#883313) Use after free
    mutating DOM during SetBody

  - MFSA 2013-65/CVE-2013-1705 (bmo#882865) Buffer underflow
    when generating CRMF requests

  - MFSA 2013-67/CVE-2013-1708 (bmo#879924) Crash during WAV
    audio file decoding

  - MFSA 2013-68/CVE-2013-1709 (bmo#838253) Document URI
    misrepresentation and masquerading

  - MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests
    allow for code execution and XSS attacks

  - MFSA 2013-70/CVE-2013-1711 (bmo#843829) Bypass of
    XrayWrappers using XBL Scopes

  - MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal
    used for validating URI for some JavaScript components

  - MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin
    bypass with web workers and XMLHttpRequest

  - MFSA 2013-75/CVE-2013-1717 (bmo#406541, bmo#738397)
    Local Java applets may read contents of local file
    system

  - requires NSPR 4.10 and NSS 3.15

  - removed obsolete seamonkey-shared-nss-db.patch

Changes in seamonkey :

  - update to SeaMonkey 2.20 (bnc#833389)

  - MFSA 2013-63/CVE-2013-1701/CVE-2013-1702 Miscellaneous
    memory safety hazards

  - MFSA 2013-64/CVE-2013-1704 (bmo#883313) Use after free
    mutating DOM during SetBody

  - MFSA 2013-65/CVE-2013-1705 (bmo#882865) Buffer underflow
    when generating CRMF requests

  - MFSA 2013-67/CVE-2013-1708 (bmo#879924) Crash during WAV
    audio file decoding

  - MFSA 2013-68/CVE-2013-1709 (bmo#838253) Document URI
    misrepresentation and masquerading

  - MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests
    allow for code execution and XSS attacks

  - MFSA 2013-70/CVE-2013-1711 (bmo#843829) Bypass of
    XrayWrappers using XBL Scopes

  - MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal
    used for validating URI for some JavaScript components

  - MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin
    bypass with web workers and XMLHttpRequest

  - MFSA 2013-75/CVE-2013-1717 (bmo#406541, bmo#738397)
    Local Java applets may read contents of local file
    system

  - requires NSPR 4.10 and NSS 3.15

  - removed obsolete seamonkey-shared-nss-db.patch

Changes in xulrunner :

  - update to 17.0.8esr (bnc#833389)

  - MFSA 2013-63/CVE-2013-1701 Miscellaneous memory safety
    hazards

  - MFSA 2013-68/CVE-2013-1709 (bmo#838253) Document URI
    misrepresentation and masquerading

  - MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests
    allow for code execution and XSS attacks

  - MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal
    used for validating URI for some JavaScript components

  - MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin
    bypass with web workers and XMLHttpRequest

  - MFSA 2013-75/CVE-2013-1717 (bmo#406541, bmo#738397)
    Local Java applets may read contents of local file
    system

Changes in xulrunner :

  - update to 17.0.8esr (bnc#833389)

  - MFSA 2013-63/CVE-2013-1701 Miscellaneous memory safety
    hazards

  - MFSA 2013-68/CVE-2013-1709 (bmo#838253) Document URI
    misrepresentation and masquerading

  - MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests
    allow for code execution and XSS attacks

  - MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal
    used for validating URI for some JavaScript components

  - MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin
    bypass with web workers and XMLHttpRequest

  - MFSA 2013-75/CVE-2013-1717 (bmo#406541, bmo#738397)
    Local Java applets may read contents of local file
    system

Changes in MozillaThunderbird :

  - update to Thunderbird 17.0.8 (bnc#833389)

  - MFSA 2013-63/CVE-2013-1701 Miscellaneous memory safety
    hazards

  - MFSA 2013-68/CVE-2013-1709 (bmo#838253) Document URI
    misrepresentation and masquerading

  - MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests
    allow for code execution and XSS attacks

  - MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal
    used for validating URI for some JavaScript components

  - MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin
    bypass with web workers and XMLHttpRequest

  - MFSA 2013-75/CVE-2013-1717 (bmo#406541, bmo#738397)
    Local Java applets may read contents of local file
    system

  - update Enigmail to 1.5.2

  - bugfix release

Changes in MozillaThunderbird :

  - update to Thunderbird 17.0.8 (bnc#833389)

  - MFSA 2013-63/CVE-2013-1701 Miscellaneous memory safety
    hazards

  - MFSA 2013-68/CVE-2013-1709 (bmo#838253) Document URI
    misrepresentation and masquerading

  - MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests
    allow for code execution and XSS attacks

  - MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal
    used for validating URI for some JavaScript components

  - MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin
    bypass with web workers and XMLHttpRequest

  - MFSA 2013-75/CVE-2013-1717 (bmo#406541, bmo#738397)
    Local Java applets may read contents of local file
    system

  - update Enigmail to 1.5.2

  - bugfix release

Changes in mozilla-nss :

  - fix 32bit requirement, it's without () actually

  - update to 3.15.1

  - TLS 1.2 (RFC 5246) is supported. HMAC-SHA256 cipher
    suites (RFC 5246 and RFC 5289) are supported, allowing
    TLS to be used without MD5 and SHA-1. Note the following
    limitations: The hash function used in the signature for
    TLS 1.2 client authentication must be the hash function
    of the TLS 1.2 PRF, which is always SHA-256 in NSS
    3.15.1. AES GCM cipher suites are not yet supported.

  - some bugfixes and improvements

  - require libnssckbi instead of mozilla-nss-certs so
    p11-kit can conflict with the latter (fate#314991)

  - update to 3.15

  - Packaging

  + removed obsolete patches

  - nss-disable-expired-testcerts.patch

  - bug-834091.patch

  - New Functionality

  + Support for OCSP Stapling (RFC 6066, Certificate Status
    Request) has been added for both client and server
    sockets. TLS client applications may enable this via a
    call to SSL_OptionSetDefault(SSL_ENABLE_OCSP_STAPLING,
    PR_TRUE);

  + Added function SECITEM_ReallocItemV2. It replaces
    function SECITEM_ReallocItem, which is now declared as
    obsolete.

  + Support for single-operation (eg: not multi-part)
    symmetric key encryption and decryption, via
    PK11_Encrypt and PK11_Decrypt.

  + certutil has been updated to support creating name
    constraints extensions.

  - New Functions in ssl.h SSL_PeerStapledOCSPResponse -
    Returns the server's stapled OCSP response, when used
    with a TLS client socket that negotiated the
    status_request extension. SSL_SetStapledOCSPResponses -
    Set's a stapled OCSP response for a TLS server socket to
    return when clients send the status_request extension.
    in ocsp.h CERT_PostOCSPRequest - Primarily intended for
    testing, permits the sending and receiving of raw OCSP
    request/responses. in secpkcs7.h
    SEC_PKCS7VerifyDetachedSignatureAtTime - Verifies a
    PKCS#7 signature at a specific time other than the
    present time. in xconst.h
    CERT_EncodeNameConstraintsExtension - Matching function
    for CERT_DecodeNameConstraintsExtension, added in NSS
    3.10. in secitem.h SECITEM_AllocArray SECITEM_DupArray
    SECITEM_FreeArray SECITEM_ZfreeArray - Utility functions
    to handle the allocation and deallocation of
    SECItemArrays SECITEM_ReallocItemV2 - Replaces
    SECITEM_ReallocItem, which is now obsolete.
    SECITEM_ReallocItemV2 better matches caller
    expectations, in that it updates item->len on
    allocation. For more details of the issues with
    SECITEM_ReallocItem, see Bug 298649 and Bug 298938. in
    pk11pub.h PK11_Decrypt - Performs decryption as a single
    PKCS#11 operation (eg: not multi-part). This is
    necessary for AES-GCM. PK11_Encrypt - Performs
    encryption as a single PKCS#11 operation (eg: not
    multi-part). This is necessary for AES-GCM.

  - New Types in secitem.h SECItemArray - Represents a
    variable-length array of SECItems.

  - New Macros in ssl.h SSL_ENABLE_OCSP_STAPLING - Used with
    SSL_OptionSet to configure TLS client sockets to request
    the certificate_status extension (eg: OCSP stapling)
    when set to PR_TRUE

  - Notable changes

  + SECITEM_ReallocItem is now deprecated. Please consider
    using SECITEM_ReallocItemV2 in all future code.

  + The list of root CA certificates in the nssckbi module
    has been updated.

  + The default implementation of SSL_AuthCertificate has
    been updated to add certificate status responses stapled
    by the TLS server to the OCSP cache.

  - a lot of bugfixes

  - Add Source URL, see https://en.opensuse.org/SourceUrls

Changes in mozilla-nss :

  - fix 32bit requirement, it's without () actually

  - update to 3.15.1

  - TLS 1.2 (RFC 5246) is supported. HMAC-SHA256 cipher
    suites (RFC 5246 and RFC 5289) are supported, allowing
    TLS to be used without MD5 and SHA-1. Note the following
    limitations: The hash function used in the signature for
    TLS 1.2 client authentication must be the hash function
    of the TLS 1.2 PRF, which is always SHA-256 in NSS
    3.15.1. AES GCM cipher suites are not yet supported.

  - some bugfixes and improvements

  - require libnssckbi instead of mozilla-nss-certs so
    p11-kit can conflict with the latter (fate#314991)

  - update to 3.15

  - Packaging

  + removed obsolete patches

  - nss-disable-expired-testcerts.patch

  - bug-834091.patch

  - New Functionality

  + Support for OCSP Stapling (RFC 6066, Certificate Status
    Request) has been added for both client and server
    sockets. TLS client applications may enable this via a
    call to SSL_OptionSetDefault(SSL_ENABLE_OCSP_STAPLING,
    PR_TRUE);

  + Added function SECITEM_ReallocItemV2. It replaces
    function SECITEM_ReallocItem, which is now declared as
    obsolete.

  + Support for single-operation (eg: not multi-part)
    symmetric key encryption and decryption, via
    PK11_Encrypt and PK11_Decrypt.

  + certutil has been updated to support creating name
    constraints extensions.

  - New Functions in ssl.h SSL_PeerStapledOCSPResponse -
    Returns the server's stapled OCSP response, when used
    with a TLS client socket that negotiated the
    status_request extension. SSL_SetStapledOCSPResponses -
    Set's a stapled OCSP response for a TLS server socket to
    return when clients send the status_request extension.
    in ocsp.h CERT_PostOCSPRequest - Primarily intended for
    testing, permits the sending and receiving of raw OCSP
    request/responses. in secpkcs7.h
    SEC_PKCS7VerifyDetachedSignatureAtTime - Verifies a
    PKCS#7 signature at a specific time other than the
    present time. in xconst.h
    CERT_EncodeNameConstraintsExtension - Matching function
    for CERT_DecodeNameConstraintsExtension, added in NSS
    3.10. in secitem.h SECITEM_AllocArray SECITEM_DupArray
    SECITEM_FreeArray SECITEM_ZfreeArray - Utility functions
    to handle the allocation and deallocation of
    SECItemArrays SECITEM_ReallocItemV2 - Replaces
    SECITEM_ReallocItem, which is now obsolete.
    SECITEM_ReallocItemV2 better matches caller
    expectations, in that it updates item->len on
    allocation. For more details of the issues with
    SECITEM_ReallocItem, see Bug 298649 and Bug 298938. in
    pk11pub.h PK11_Decrypt - Performs decryption as a single
    PKCS#11 operation (eg: not multi-part). This is
    necessary for AES-GCM. PK11_Encrypt - Performs
    encryption as a single PKCS#11 operation (eg: not
    multi-part). This is necessary for AES-GCM.

  - New Types in secitem.h SECItemArray - Represents a
    variable-length array of SECItems.

  - New Macros in ssl.h SSL_ENABLE_OCSP_STAPLING - Used with
    SSL_OptionSet to configure TLS client sockets to request
    the certificate_status extension (eg: OCSP stapling)
    when set to PR_TRUE

  - Notable changes

  + SECITEM_ReallocItem is now deprecated. Please consider
    using SECITEM_ReallocItemV2 in all future code.

  + The list of root CA certificates in the nssckbi module
    has been updated.

  + The default implementation of SSL_AuthCertificate has
    been updated to add certificate status responses stapled
    by the TLS server to the OCSP cache.

  - a lot of bugfixes

  - Add Source URL, see https://en.opensuse.org/SourceUrls

Changes in mozilla-nspr :

  - update to version 4.10

  - bmo#844513: Add AddressSanitizer (ASan) memory check
    annotations to PLArena.

  - bmo#849089: Simple changes to make NSPR's configure.in
    work with the current version of autoconf.

  - bmo#856196: Fix compiler warnings and clean up code in
    NSPR 4.10.

  - bmo#859066: Fix warning in
    nsprpub/pr/src/misc/prnetdb.c.

  - bmo#859830: Deprecate ANDROID_VERSION in favor of
    android/api-level.h.

  - bmo#861434: Make PR_SetThreadPriority() change
    priorities relatively to the main process instead of
    using absolute values on Linux.

  - bmo#871064L: _PR_InitThreads() should not call
    PR_SetThreadPriority.

Changes in mozilla-nspr :

  - update to version 4.10

  - bmo#844513: Add AddressSanitizer (ASan) memory check
    annotations to PLArena.

  - bmo#849089: Simple changes to make NSPR's configure.in
    work with the current version of autoconf.

  - bmo#856196: Fix compiler warnings and clean up code in
    NSPR 4.10.

  - bmo#859066: Fix warning in
    nsprpub/pr/src/misc/prnetdb.c.

  - bmo#859830: Deprecate ANDROID_VERSION in favor of
    android/api-level.h.

  - bmo#861434: Make PR_SetThreadPriority() change
    priorities relatively to the main process instead of
    using absolute values on Linux.

  - bmo#871064L: _PR_InitThreads() should not call
    PR_SetThreadPriority.

Changes in MozillaFirefox :

  - update to Firefox 23.0 (bnc#833389)

  - MFSA 2013-63/CVE-2013-1701/CVE-2013-1702 Miscellaneous
    memory safety hazards

  - MFSA 2013-64/CVE-2013-1704 (bmo#883313) Use after free
    mutating DOM during SetBody

  - MFSA 2013-65/CVE-2013-1705 (bmo#882865) Buffer underflow
    when generating CRMF requests

  - MFSA 2013-67/CVE-2013-1708 (bmo#879924) Crash during WAV
    audio file decoding

  - MFSA 2013-68/CVE-2013-1709 (bmo#838253) Document URI
    misrepresentation and masquerading

  - MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests
    allow for code execution and XSS attacks

  - MFSA 2013-70/CVE-2013-1711 (bmo#843829) Bypass of
    XrayWrappers using XBL Scopes

  - MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal
    used for validating URI for some JavaScript components

  - MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin
    bypass with web workers and XMLHttpRequest

  - MFSA 2013-75/CVE-2013-1717 (bmo#406541, bmo#738397)
    Local Java applets may read contents of local file
    system

  - requires NSPR 4.10 and NSS 3.15

  - fix build on ARM (/-g/ matches /-grecord-switches/)

Changes in MozillaFirefox :

  - update to Firefox 23.0 (bnc#833389)

  - MFSA 2013-63/CVE-2013-1701/CVE-2013-1702 Miscellaneous
    memory safety hazards

  - MFSA 2013-64/CVE-2013-1704 (bmo#883313) Use after free
    mutating DOM during SetBody

  - MFSA 2013-65/CVE-2013-1705 (bmo#882865) Buffer underflow
    when generating CRMF requests

  - MFSA 2013-67/CVE-2013-1708 (bmo#879924) Crash during WAV
    audio file decoding

  - MFSA 2013-68/CVE-2013-1709 (bmo#838253) Document URI
    misrepresentation and masquerading

  - MFSA 2013-69/CVE-2013-1710 (bmo#871368) CRMF requests
    allow for code execution and XSS attacks

  - MFSA 2013-70/CVE-2013-1711 (bmo#843829) Bypass of
    XrayWrappers using XBL Scopes

  - MFSA 2013-72/CVE-2013-1713 (bmo#887098) Wrong principal
    used for validating URI for some JavaScript components

  - MFSA 2013-73/CVE-2013-1714 (bmo#879787) Same-origin
    bypass with web workers and XMLHttpRequest

  - MFSA 2013-75/CVE-2013-1717 (bmo#406541, bmo#738397)
    Local Java applets may read contents of local file
    system

  - requires NSPR 4.10 and NSS 3.15

  - fix build on ARM (/-g/ matches /-grecord-switches/)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://en.opensuse.org/SourceUrls"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox / MozillaThunderbird / mozilla-nspr / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox toString console.time Privileged Javascript Injection');
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-23.0-2.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-upstream-23.0-2.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-buildsymbols-23.0-2.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debuginfo-23.0-2.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debugsource-23.0-2.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-devel-23.0-2.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-common-23.0-2.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-other-23.0-2.55.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-buildsymbols-17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debuginfo-17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-debugsource-17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-devel-debuginfo-17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-common-17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaThunderbird-translations-other-17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-1.5.2+17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"enigmail-debuginfo-1.5.2+17.0.8-49.51.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfreebl3-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfreebl3-debuginfo-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsoftokn3-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libsoftokn3-debuginfo-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-js-debuginfo-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-4.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-debuginfo-4.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-debugsource-4.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nspr-devel-4.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-certs-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-certs-debuginfo-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-debuginfo-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-debugsource-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-devel-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-sysinit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-sysinit-debuginfo-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-tools-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"mozilla-nss-tools-debuginfo-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-2.20-2.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debuginfo-2.20-2.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-debugsource-2.20-2.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-dom-inspector-2.20-2.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-irc-2.20-2.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-common-2.20-2.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-translations-other-2.20-2.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"seamonkey-venkman-2.20-2.46.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-buildsymbols-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debuginfo-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-debugsource-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xulrunner-devel-debuginfo-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfreebl3-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsoftokn3-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.15.1-2.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-32bit-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.8-2.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-23.0-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-23.0-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-23.0-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-23.0-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-23.0-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-23.0-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-23.0-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-23.0-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-buildsymbols-17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debuginfo-17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debugsource-17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-debuginfo-17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-common-17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-other-17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-1.5.2+17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"enigmail-debuginfo-1.5.2+17.0.8-61.21.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-debuginfo-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-debuginfo-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-js-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-js-debuginfo-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-4.10-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debuginfo-4.10-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-debugsource-4.10-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nspr-devel-4.10-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-debuginfo-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debuginfo-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debugsource-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-devel-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-debuginfo-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-debuginfo-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-2.20-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debuginfo-2.20-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-debugsource-2.20-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-dom-inspector-2.20-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-irc-2.20-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-common-2.20-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-translations-other-2.20-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"seamonkey-venkman-2.20-1.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-buildsymbols-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-debuginfo-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-debugsource-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-devel-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xulrunner-devel-debuginfo-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-js-32bit-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-js-debuginfo-32bit-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nspr-debuginfo-32bit-4.10-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.15.1-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xulrunner-32bit-17.0.8-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xulrunner-debuginfo-32bit-17.0.8-1.24.1") ) flag++;

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
