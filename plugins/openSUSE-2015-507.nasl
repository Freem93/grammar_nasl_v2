#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-507.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(84998);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2014-3570", "CVE-2014-3572", "CVE-2014-8176", "CVE-2014-8275", "CVE-2015-0205", "CVE-2015-0206", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1792", "CVE-2015-4000");

  script_name(english:"openSUSE Security Update : libressl (openSUSE-2015-507) (Logjam)");
  script_summary(english:"Check for the openSUSE-2015-507 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libressl was updated to version 2.2.1 to fix 16 security issues.

LibreSSL is a fork of OpenSSL. Because of that CVEs affecting OpenSSL
often also affect LibreSSL.

These security issues were fixed :

  - CVE-2014-3570: The BN_sqr implementation in OpenSSL
    before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before
    1.0.1k did not properly calculate the square of a BIGNUM
    value, which might make it easier for remote attackers
    to defeat cryptographic protection mechanisms via
    unspecified vectors, related to crypto/bn/asm/mips.pl,
    crypto/bn/asm/x86_64-gcc.c, and crypto/bn/bn_asm.c
    (bsc#912296).

  - CVE-2014-3572: The ssl3_get_key_exchange function in
    s3_clnt.c in OpenSSL before 0.9.8zd, 1.0.0 before
    1.0.0p, and 1.0.1 before 1.0.1k allowed remote SSL
    servers to conduct ECDHE-to-ECDH downgrade attacks and
    trigger a loss of forward secrecy by omitting the
    ServerKeyExchange message (bsc#912015).

  - CVE-2015-1792: The do_free_upto function in
    crypto/cms/cms_smime.c in OpenSSL before 0.9.8zg, 1.0.0
    before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before
    1.0.2b allowed remote attackers to cause a denial of
    service (infinite loop) via vectors that trigger a NULL
    value of a BIO data structure, as demonstrated by an
    unrecognized X.660 OID for a hash function (bsc#934493).

  - CVE-2014-8275: OpenSSL before 0.9.8zd, 1.0.0 before
    1.0.0p, and 1.0.1 before 1.0.1k did not enforce certain
    constraints on certificate data, which allowed remote
    attackers to defeat a fingerprint-based
    certificate-blacklist protection mechanism by including
    crafted data within a certificate's unsigned portion,
    related to crypto/asn1/a_verify.c,
    crypto/dsa/dsa_asn1.c, crypto/ecdsa/ecs_vrf.c, and
    crypto/x509/x_all.c (bsc#912018).

  - CVE-2015-0209: Use-after-free vulnerability in the
    d2i_ECPrivateKey function in crypto/ec/ec_asn1.c in
    OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1
    before 1.0.1m, and 1.0.2 before 1.0.2a might allowed
    remote attackers to cause a denial of service (memory
    corruption and application crash) or possibly have
    unspecified other impact via a malformed Elliptic Curve
    (EC) private-key file that is improperly handled during
    import (bsc#919648).

  - CVE-2015-1789: The X509_cmp_time function in
    crypto/x509/x509_vfy.c in OpenSSL before 0.9.8zg, 1.0.0
    before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before
    1.0.2b allowed remote attackers to cause a denial of
    service (out-of-bounds read and application crash) via a
    crafted length field in ASN1_TIME data, as demonstrated
    by an attack against a server that supports client
    authentication with a custom verification callback
    (bsc#934489).

  - CVE-2015-1788: The BN_GF2m_mod_inv function in
    crypto/bn/bn_gf2m.c in OpenSSL before 0.9.8s, 1.0.0
    before 1.0.0e, 1.0.1 before 1.0.1n, and 1.0.2 before
    1.0.2b did not properly handle ECParameters structures
    in which the curve is over a malformed binary polynomial
    field, which allowed remote attackers to cause a denial
    of service (infinite loop) via a session that used an
    Elliptic Curve algorithm, as demonstrated by an attack
    against a server that supports client authentication
    (bsc#934487).

  - CVE-2015-1790: The PKCS7_dataDecodefunction in
    crypto/pkcs7/pk7_doit.c in OpenSSL before 0.9.8zg, 1.0.0
    before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before
    1.0.2b allowed remote attackers to cause a denial of
    service (NULL pointer dereference and application crash)
    via a PKCS#7 blob that used ASN.1 encoding and lacks
    inner EncryptedContent data (bsc#934491).

  - CVE-2015-0287: The ASN1_item_ex_d2i function in
    crypto/asn1/tasn_dec.c in OpenSSL before 0.9.8zf, 1.0.0
    before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before
    1.0.2a did not reinitialize CHOICE and ADB data
    structures, which might allowed attackers to cause a
    denial of service (invalid write operation and memory
    corruption) by leveraging an application that relies on
    ASN.1 structure reuse (bsc#922499).

  - CVE-2015-0286: The ASN1_TYPE_cmp function in
    crypto/asn1/a_type.c in OpenSSL before 0.9.8zf, 1.0.0
    before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before
    1.0.2a did not properly perform boolean-type
    comparisons, which allowed remote attackers to cause a
    denial of service (invalid read operation and
    application crash) via a crafted X.509 certificate to an
    endpoint that used the certificate-verification feature
    (bsc#922496).

  - CVE-2015-0289: The PKCS#7 implementation in OpenSSL
    before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1 before
    1.0.1m, and 1.0.2 before 1.0.2a did not properly handle
    a lack of outer ContentInfo, which allowed attackers to
    cause a denial of service (NULL pointer dereference and
    application crash) by leveraging an application that
    processes arbitrary PKCS#7 data and providing malformed
    data with ASN.1 encoding, related to
    crypto/pkcs7/pk7_doit.c and crypto/pkcs7/pk7_lib.c
    (bsc#922500).

  - CVE-2015-0288: The X509_to_X509_REQ function in
    crypto/x509/x509_req.c in OpenSSL before 0.9.8zf, 1.0.0
    before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before
    1.0.2a might allowed attackers to cause a denial of
    service (NULL pointer dereference and application crash)
    via an invalid certificate key (bsc#920236).

  - CVE-2014-8176: The dtls1_clear_queues function in
    ssl/d1_lib.c in OpenSSL before 0.9.8za, 1.0.0 before
    1.0.0m, and 1.0.1 before 1.0.1h frees data structures
    without considering that application data can arrive
    between a ChangeCipherSpec message and a Finished
    message, which allowed remote DTLS peers to cause a
    denial of service (memory corruption and application
    crash) or possibly have unspecified other impact via
    unexpected application data (bsc#934494).

  - CVE-2015-4000: The TLS protocol 1.2 and earlier, when a
    DHE_EXPORT ciphersuite is enabled on a server but not on
    a client, did not properly convey a DHE_EXPORT choice,
    which allowed man-in-the-middle attackers to conduct
    cipher-downgrade attacks by rewriting a ClientHello with
    DHE replaced by DHE_EXPORT and then rewriting a
    ServerHello with DHE_EXPORT replaced by DHE, aka the
    'Logjam' issue (bsc#931600).

  - CVE-2015-0205: The ssl3_get_cert_verify function in
    s3_srvr.c in OpenSSL 1.0.0 before 1.0.0p and 1.0.1
    before 1.0.1k accepts client authentication with a
    Diffie-Hellman (DH) certificate without requiring a
    CertificateVerify message, which allowed remote
    attackers to obtain access without knowledge of a
    private key via crafted TLS Handshake Protocol traffic
    to a server that recognizes a Certification Authority
    with DH support (bsc#912293).

  - CVE-2015-0206: Memory leak in the dtls1_buffer_record
    function in d1_pkt.c in OpenSSL 1.0.0 before 1.0.0p and
    1.0.1 before 1.0.1k allowed remote attackers to cause a
    denial of service (memory consumption) by sending many
    duplicate records for the next epoch, leading to failure
    of replay detection (bsc#912292)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=931600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=934494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=937891"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libressl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcrypto34-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libressl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libssl33-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtls4-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libcrypto34-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libcrypto34-debuginfo-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-debuginfo-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-debugsource-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libressl-devel-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssl33-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libssl33-debuginfo-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtls4-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtls4-debuginfo-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcrypto34-32bit-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libcrypto34-debuginfo-32bit-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libressl-devel-32bit-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssl33-32bit-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libssl33-debuginfo-32bit-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtls4-32bit-2.2.1-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtls4-debuginfo-32bit-2.2.1-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcrypto34 / libcrypto34-32bit / libcrypto34-debuginfo / etc");
}
