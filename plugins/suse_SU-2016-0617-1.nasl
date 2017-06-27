#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0617-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(89076);
  script_version("$Revision: 2.21 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0702", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800");
  script_bugtraq_id(73232);
  script_osvdb_id(119757, 133715, 134973, 135095, 135096, 135121, 135149, 135150, 135151, 135152, 135153);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssl (SUSE-SU-2016:0617-1) (DROWN)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl fixes various security issues and bugs :

Security issues fixed :

  - CVE-2016-0800 aka the 'DROWN' attack (bsc#968046):
    OpenSSL was vulnerable to a cross-protocol attack that
    could lead to decryption of TLS sessions by using a
    server supporting SSLv2 and EXPORT cipher suites as a
    Bleichenbacher RSA padding oracle.

    This update changes the openssl library to :

  - Disable SSLv2 protocol support by default.

    This can be overridden by setting the environment
    variable 'OPENSSL_ALLOW_SSL2' or by using
    SSL_CTX_clear_options using the SSL_OP_NO_SSLv2 flag.

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

Bugs fixed :

  - Avoid running OPENSSL_config twice. This avoids breaking
    engine loading. (bsc#952871)

  - Ensure that OpenSSL doesn't fall back to the default
    digest algorithm (SHA1) in case a non-FIPS algorithm was
    negotiated while running in FIPS mode. Instead, OpenSSL
    will refuse the digest. (bnc#958501)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0703.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0800.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160617-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ee18e5c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-352=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-352=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-352=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-debuginfo-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-hmac-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-debuginfo-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openssl-debugsource-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-32bit-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libopenssl1_0_0-hmac-32bit-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-debuginfo-1.0.1i-27.13.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"openssl-debugsource-1.0.1i-27.13.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
