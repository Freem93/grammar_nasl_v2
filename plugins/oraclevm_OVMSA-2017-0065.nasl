#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0065.
#

include("compat.inc");

if (description)
{
  script_id(99568);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id("CVE-2016-1950");
  script_osvdb_id(135603);

  script_name(english:"OracleVM 3.3 / 3.4 : nss / nss-util (OVMSA-2017-0065)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

nss

  - Added nss-vendor.patch to change vendor

  - Temporarily disable some tests until expired
    PayPalEE.cert is renewed

  - Rebase to 3.28.4

  - Fix crash with tstclnt -W

  - Adjust gtests to run with our old softoken and
    downstream patches

  - Avoid cipher suite ordering change, spotted by Hubert
    Kario

  - Rebase to 3.28.3

  - Remove upstreamed moz-1282627-rh-1294606.patch,
    moz-1312141-rh-1387811.patch, moz-1315936.patch, and
    moz-1318561.patch

  - Remove no longer necessary nss-duplicate-ciphers.patch

  - Disable X25519 and exclude tests using it

  - Catch failed ASN1 decoding of RSA keys, by Kamil Dudka
    (#1427481)

  - Update expired PayPalEE.cert

  - Disable unsupported test cases in ssl_gtests

  - Adjust the sslstress.txt filename so that it matches
    with the disableSSL2tests patch ported from RHEL 7

  - Exclude SHA384 and CHACHA20_POLY1305 ciphersuites from
    stress tests

  - Don't add gtests and ssl_gtests to nss_tests, unless
    gtests are enabled

  - Add patch to fix SSL CA name leaks, taken from NSS
    3.27.2 release

  - Add patch to fix bash syntax error in tests/ssl.sh

  - Add patch to remove duplicate ciphersuites entries in
    sslinfo.c

  - Add patch to abort selfserv/strsclnt/tstclnt on
    non-parsable version range

  - Build with support for SSLKEYLOGFILE

  - Update fix_multiple_open patch to fix regression in
    openldap client

  - Remove pk11_genobj_leak patch, which caused crash with
    Firefox

  - Add comment in the policy file to preserve the last
    empty line

  - Disable SHA384 ciphersuites when
    CKM_TLS12_KEY_AND_MAC_DERIVE is not provided by
    softoken  this superseds check_hash_impl patch

  - Fix problem in check_hash_impl patch

  - Add patch to check if hash algorithms are backed by a
    token

  - Add patch to disable
    TLS_ECDHE_[RSA,ECDSA]_WITH_AES_128_CBC_SHA256, which
    have never enabled in the past

  - Add upstream patch to fix a crash. Mozilla #1315936

  - Disable the use of RSA-PSS with SSL/TLS. #1390161

  - Use updated upstream patch for RH bug 1387811

  - Added upstream patches to fix RH bugs 1057388, 1294606,
    1387811

  - Enable gtests when requested

  - Rebase to NSS 3.27.1

  - Remove nss-646045.patch, which is not necessary

  - Remove p-disable-md5-590364-reversed.patch, which is
    no-op here, because the patched code is removed later in
    %setup

  - Remove disable_hw_gcm.patch, which is no-op here,
    because the patched code is removed later in %setup.
    Also remove NSS_DISABLE_HW_GCM setting, which was only
    required for RHEL 5

  - Add Bug-1001841-disable-sslv2-libssl.patch and
    Bug-1001841-disable-sslv2-tests.patch, which completedly
    disable EXPORT ciphersuites. Ported from RHEL 7

  - Remove disable-export-suites-tests.patch, which is
    covered by Bug-1001841-disable-sslv2-tests.patch

  - Remove nss-ca-2.6-enable-legacy.patch, as we decided to
    not allow 1024 legacy CA certificates

  - Remove ssl-server-min-key-sizes.patch, as we decided to
    support DH key size greater than 1023 bits

  - Remove nss-init-ss-sec-certs-null.patch, which appears
    to be no-op, as it clears memory area allocated with
    PORT_ZAlloc

  - Remove nss-disable-sslv2-libssl.patch,
    nss-disable-sslv2-tests.patch, sslauth-no-v2.patch, and
    nss-sslstress-txt-ssl3-lower-value-in-range.patch as
    SSLv2 is already disabled in upstream

  - Remove fix-nss-test-filtering.patch, which is fixed in
    upstream

  - Add nss-check-policy-file.patch from Fedora

  - Install policy config in
    /etc/pki/nss-legacy/nss-rhel6.config

nss-util

  - Rebase to NSS 3.28.4 to accommodate base64 encoding fix

  - Rebase to NSS 3.28.3

  - Package new header eccutil.h

  - Tolerate policy file without last empty line

  - Add missing source files

  - Rebase to NSS 3.26.0

  - Remove upstreamed patch for (CVE-2016-1950)

  - Remove p-disable-md5-590364-reversed.patch for bug
    1335915"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-April/000682.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3652e035"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-April/000683.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97bdc28b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"nss-3.28.4-1.0.1.el6_9")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-sysinit-3.28.4-1.0.1.el6_9")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-tools-3.28.4-1.0.1.el6_9")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-util-3.28.4-1.el6_9")) flag++;

if (rpm_check(release:"OVS3.4", reference:"nss-3.28.4-1.0.1.el6_9")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-sysinit-3.28.4-1.0.1.el6_9")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-tools-3.28.4-1.0.1.el6_9")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-util-3.28.4-1.el6_9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-sysinit / nss-tools / nss-util");
}
