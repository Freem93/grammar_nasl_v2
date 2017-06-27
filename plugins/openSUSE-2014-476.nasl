#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-476.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76959);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/05 23:53:27 $");

  script_cve_id("CVE-2014-1544", "CVE-2014-1547", "CVE-2014-1548", "CVE-2014-1549", "CVE-2014-1550", "CVE-2014-1552", "CVE-2014-1555", "CVE-2014-1556", "CVE-2014-1557", "CVE-2014-1558", "CVE-2014-1559", "CVE-2014-1560", "CVE-2014-1561");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2014-476)");
  script_summary(english:"Check for the openSUSE-2014-476 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to version 31 to fix various security
issues and bugs :

  - MFSA 2014-56/CVE-2014-1547/CVE-2014-1548 Miscellaneous
    memory safety hazards

  - MFSA 2014-57/CVE-2014-1549 (bmo#1020205) Buffer overflow
    during Web Audio buffering for playback

  - MFSA 2014-58/CVE-2014-1550 (bmo#1020411) Use-after-free
    in Web Audio due to incorrect control message ordering

  - MFSA 2014-60/CVE-2014-1561 (bmo#1000514, bmo#910375)
    Toolbar dialog customization event spoofing

  - MFSA 2014-61/CVE-2014-1555 (bmo#1023121) Use-after-free
    with FireOnStateChange event

  - MFSA 2014-62/CVE-2014-1556 (bmo#1028891) Exploitable
    WebGL crash with Cesium JavaScript library

  - MFSA 2014-63/CVE-2014-1544 (bmo#963150) Use-after-free
    while when manipulating certificates in the trusted
    cache (solved with NSS 3.16.2 requirement)

  - MFSA 2014-64/CVE-2014-1557 (bmo#913805) Crash in Skia
    library when scaling high quality images

  - MFSA 2014-65/CVE-2014-1558/CVE-2014-1559/CVE-2014-1560
    (bmo#1015973, bmo#1026022, bmo#997795) Certificate
    parsing broken by non-standard character encoding

  - MFSA 2014-66/CVE-2014-1552 (bmo#985135) IFRAME sandbox
    same-origin access through redirect

Mozilla-nss was updated to 3.16.3: New Functions :

  - CERT_GetGeneralNameTypeFromString (This function was
    already added in NSS 3.16.2, however, it wasn't declared
    in a public header file.) Notable Changes :

  - The following 1024-bit CA certificates were removed

  - Entrust.net Secure Server Certification Authority

  - GTE CyberTrust Global Root

  - ValiCert Class 1 Policy Validation Authority

  - ValiCert Class 2 Policy Validation Authority

  - ValiCert Class 3 Policy Validation Authority

  - Additionally, the following CA certificate was removed
    as requested by the CA :

  - TDC Internet Root CA

  - The following CA certificates were added :

  - Certification Authority of WoSign

  - CA &#x6C83;&#x901A;&#x6839;&#x8BC1;&#x4E66;

  - DigiCert Assured ID Root G2

  - DigiCert Assured ID Root G3

  - DigiCert Global Root G2

  - DigiCert Global Root G3

  - DigiCert Trusted Root G4

  - QuoVadis Root CA 1 G3

  - QuoVadis Root CA 2 G3

  - QuoVadis Root CA 3 G3

  - The Trust Bits were changed for the following CA
    certificates

  - Class 3 Public Primary Certification Authority

  - Class 3 Public Primary Certification Authority

  - Class 2 Public Primary Certification Authority - G2

  - VeriSign Class 2 Public Primary Certification Authority
    - G3

  - AC Ra&iacute;z Certic&aacute;mara S.A.

  - NetLock Uzleti (Class B) Tanusitvanykiado

  - NetLock Expressz (Class C) Tanusitvanykiado changes in
    3.16.2 New functionality :

  - DTLS 1.2 is supported.

  - The TLS application layer protocol negotiation (ALPN)
    extension is also supported on the server side.

  - RSA-OEAP is supported. Use the new PK11_PrivDecrypt and
    PK11_PubEncrypt functions with the CKM_RSA_PKCS_OAEP
    mechanism.

  - New Intel AES assembly code for 32-bit and 64-bit
    Windows, contributed by Shay Gueron and Vlad Krasnov of
    Intel. Notable Changes :

  - The btoa command has a new command-line option -w
    suffix, which causes the output to be wrapped in
    BEGIN/END lines with the given suffix

  - The certutil commands supports additionals types of
    subject alt name extensions.

  - The certutil command supports generic certificate
    extensions, by loading binary data from files, which
    have been prepared using external tools, or which have
    been extracted from other existing certificates and
    dumped to file.

  - The certutil command supports three new certificate
    usage specifiers.

  - The pp command supports printing UTF-8 (-u).

  - On Linux, NSS is built with the -ffunction-sections
    -fdata-sections compiler flags and the --gc-sections
    linker flag to allow unused functions to be discarded.
    changes in 3.16.1 New functionality :

  - Added the 'ECC' flag for modutil to select the module
    used for elliptic curve cryptography (ECC) operations.
    New Macros

  - PUBLIC_MECH_ECC_FLAG a public mechanism flag for
    elliptic curve cryptography (ECC) operations

  - SECMOD_ECC_FLAG an NSS-internal mechanism flag for
    elliptic curve cryptography (ECC) operations. This macro
    has the same numeric value as PUBLIC_MECH_ECC_FLAG.
    Notable Changes :

  - Imposed name constraints on the French government root
    CA ANSSI (DCISS)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887746"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/01");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-31.0-1.72.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-31.0-1.72.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-31.0-1.72.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-31.0-1.72.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-31.0-1.72.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-31.0-1.72.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-31.0-1.72.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-31.0-1.72.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfreebl3-debuginfo-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libsoftokn3-debuginfo-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-certs-debuginfo-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debuginfo-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-debugsource-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-devel-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-sysinit-debuginfo-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"mozilla-nss-tools-debuginfo-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.16.3-1.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-31.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-31.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-31.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-31.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-31.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-31.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-31.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-31.0-33.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreebl3-debuginfo-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libsoftokn3-debuginfo-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-certs-debuginfo-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debuginfo-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-debugsource-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-devel-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-sysinit-debuginfo-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"mozilla-nss-tools-debuginfo-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreebl3-debuginfo-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libsoftokn3-debuginfo-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-certs-debuginfo-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-debuginfo-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.16.3-27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-debuginfo-32bit-3.16.3-27.1") ) flag++;

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
