#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-289.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(89091);
  script_version("$Revision: 2.14 $");
  script_cvs_date("$Date: 2016/10/13 14:27:28 $");

  script_cve_id("CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0702", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800");

  script_name(english:"openSUSE Security Update : openssl (openSUSE-2016-289) (DROWN)");
  script_summary(english:"Check for the openSUSE-2016-289 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes various security issues :

Security issues fixed :

  - CVE-2016-0800 aka the 'DROWN' attack (bsc#968046):
    OpenSSL was vulnerable to a cross-protocol attack that
    could lead to decryption of TLS sessions by using a
    server supporting SSLv2 and EXPORT cipher suites as a
    Bleichenbacher RSA padding oracle.

    This update changes the openssl library to :

  - Disable SSLv2 protocol support by default. This can be
    overridden by setting the environment variable
    'OPENSSL_ALLOW_SSL2' or by using SSL_CTX_clear_options
    using the SSL_OP_NO_SSLv2 flag.

    Note that various services and clients had already
    disabled SSL protocol 2 by default previously.

  - Disable all weak EXPORT ciphers by default. These can be
    reenabled if required by old legacy software using the
    environment variable 'OPENSSL_ALLOW_EXPORT'.

  - CVE-2016-0702 aka the 'CacheBleed' attack. (bsc#968050)
    Various changes in the modular exponentation code were
    added that make sure that it is not possible to recover
    RSA secret keys by analyzing cache-bank conflicts on the
    Intel Sandy-Bridge microarchitecture.

    Note that this was only exploitable if the malicious
    code was running on the same hyper threaded Intel Sandy
    Bridge processor as the victim thread performing
    decryptions.

  - CVE-2016-0705 (bnc#968047): A double free() bug in the
    DSA ASN1 parser code was fixed that could be abused to
    facilitate a denial-of-service attack.

  - CVE-2016-0797 (bnc#968048): The BN_hex2bn() and
    BN_dec2bn() functions had a bug that could result in an
    attempt to de-reference a NULL pointer leading to
    crashes. This could have security consequences if these
    functions were ever called by user applications with
    large untrusted hex/decimal data. Also, internal usage
    of these functions in OpenSSL uses data from config
    files or application command line arguments. If user
    developed applications generated config file data based
    on untrusted data, then this could have had security
    consequences as well.

  - CVE-2016-0798 (bnc#968265) The SRP user database lookup
    method SRP_VBASE_get_by_user() had a memory leak that
    attackers could abuse to facility DoS attacks. To
    mitigate the issue, the seed handling in
    SRP_VBASE_get_by_user() was disabled even if the user
    has configured a seed. Applications are advised to
    migrate to SRP_VBASE_get1_by_user().

  - CVE-2016-0799 (bnc#968374) On many 64 bit systems, the
    internal fmtstr() and doapr_outch() functions could
    miscalculate the length of a string and attempt to
    access out-of-bounds memory locations. These problems
    could have enabled attacks where large amounts of
    untrusted data is passed to the BIO_*printf functions.
    If applications use these functions in this way then
    they could have been vulnerable. OpenSSL itself uses
    these functions when printing out human-readable dumps
    of ASN.1 data. Therefore applications that print this
    data could have been vulnerable if the data is from
    untrusted sources. OpenSSL command line applications
    could also have been vulnerable when they print out
    ASN.1 data, or if untrusted data is passed as command
    line arguments. Libssl is not considered directly
    vulnerable.

  - CVE-2015-3197 (bsc#963415): The SSLv2 protocol did not
    block disabled ciphers.

Note that the March 1st 2016 release also references following CVEs
that were fixed by us with CVE-2015-0293 in 2015 :

  - CVE-2016-0703 (bsc#968051): This issue only affected
    versions of OpenSSL prior to March 19th 2015 at which
    time the code was refactored to address vulnerability
    CVE-2015-0293. It would have made the above 'DROWN'
    attack much easier.

  - CVE-2016-0704 (bsc#968053): 'Bleichenbacher oracle in
    SSLv2' This issue only affected versions of OpenSSL
    prior to March 19th 2015 at which time the code was
    refactored to address vulnerability CVE-2015-0293. It
    would have made the above 'DROWN' attack much easier.

Also the following bug was fixed :

  - Ensure that OpenSSL doesn't fall back to the default
    digest algorithm (SHA1) in case a non-FIPS algorithm was
    negotiated while running in FIPS mode. Instead, OpenSSL
    will refuse the session. (bnc#958501)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968374"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_0_0-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/03");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libopenssl-devel-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl1_0_0-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl1_0_0-debuginfo-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libopenssl1_0_0-hmac-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openssl-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openssl-debuginfo-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openssl-debugsource-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl-devel-32bit-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libopenssl1_0_0-hmac-32bit-1.0.1i-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenssl-devel / libopenssl-devel-32bit / libopenssl1_0_0 / etc");
}
