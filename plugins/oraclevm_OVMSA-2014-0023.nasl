#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0023.
#

include("compat.inc");

if (description)
{
  script_id(79540);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2014-1568");
  script_bugtraq_id(63736, 63737, 63738, 70116, 72178);
  script_osvdb_id(99746, 99747, 99748, 112036);

  script_name(english:"OracleVM 3.3 : nss (OVMSA-2014-0023)");
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

  - Replace expired PayPal test certificate that breaks the
    build

  - Resolves: Bug 1145431 - (CVE-2014-1568)

  - Resolves: Bug 1145431 - (CVE-2014-1568)

  - Removed listed but unused patches detected by the
    rpmdiff test

  - Resolves: Bug 1099619

  - Update some patches on account of the rebase

  - Resolves: Bug 1099619

  - Backport nss-3.12.6 upstream fix required by Firefox 31

  - Resolves: Bug 1099619

  - Remove two unused patches and apply a needed one that
    was missed

  - Resolves: Bug 1112136 - Rebase nss in RHEL 6.5.Z to NSS
    3.16.1

  - Update to nss-3.16.1

  - Resolves: Bug 1112136 - Rebase nss in RHEL 6.5.Z to NSS
    3.16.1

  - Make pem's derEncodingsMatch function work with
    encrypted keys

  - Resolves: Bug 1048713 - [PEM] active FTPS with encrypted
    client key ends up with
    SSL_ERROR_TOKEN_INSERTION_REMOVAL

  - Remove unused patches

  - Resolves: Bug 1048713

  - Resolves: Bug 1048713 - [PEM] active FTPS with encrypted
    client key ends up with
    SSL_ERROR_TOKEN_INSERTION_REMOVAL

  - Revoke trust in one mis-issued anssi certificate

  - Resolves: Bug 1042685 - nss: Mis-issued ANSSI/DCSSI
    certificate (MFSA 2013-117) [rhel-6.6]

  - Enable patch with fix for deadlock in trust domain lock
    and object lock

  - Resolves: Bug 1036477 - deadlock in trust domain lock
    and object lock

  - Disable hw gcm on rhel-5 based build environments where
    OS lacks support

  - Rollback changes to build nss without softokn until Bug
    689919 is approved

  - Cipher suite was run as part of the nss-softokn build

  - Update to NSS_3_15_3_RTM

  - Resolves: Bug 1032470 - CVE-2013-5605 CVE-2013-5606
    (CVE-2013-1741)

  - Using export NSS_DISABLE_HW_GCM=1 to deal with some
    problemmatic build systems

  - Resolves: rhbz#1016044 - nss.s390: primary link for
    libnssckbi.so must be /usr/lib64/libnssckbi.so

  - Add s390x and ia64 to the %define multilib_arches list
    used for defining alt_ckbi

  - Resolves: rhbz#1016044 - nss.s390: primary link for
    libnssckbi.so must be /usr/lib64/libnssckbi.so

  - Add zero default value to DISABLETEST check and fix the
    TEST_FAILURES check and reporting

  - Resolves: rhbz#990631 - file permissions of
    pkcs11.txt/secmod.db must be kept when modified by NSS

  - Related: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for
    FF 24.x)

  - Add a zero default value to the DISABLETEST and
    TEST_FAILURES checks

  - Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1
    (for FF 24.x)

  - Fix the test for zero failures in the %check section

  - Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1
    (for FF 24.x)

  - Restore a mistakenly removed patch

  - Resolves: rhbz#961659 - SQL backend does not reload
    certificates

  - Rebuild for the pem module to link with freel from
    nss-softokn-3.14.3-6.el6

  - Related: rhbz#993441 - NSS needs to conform to new FIPS
    standard. 

  - Related: rhbz#1010224 - NSS 3.15 breaks SSL in OpenLDAP
    clients

  - Don't require nss-softokn-fips

  - Resolves: rhbz#993441 - NSS needs to conform to new FIPS
    standard. 

  - Additional syntax fixes in
    nss-versus-softoken-test.patch

  - Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1
    (for FF 24.x)

  - Fix all.sh test for which application was last build by
    updating nss-versus-softoken-test.path

  - Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1
    (for FF 24.x)

  - Disable the cipher suite already run as part of the
    nss-softokn build

  - Resolves: rhbz#993441 - NSS needs to conform to new FIPS
    standard. 

  - Require nss-softokn-fips

  - Resolves: rhbz#993441 - NSS needs to conform to new FIPS
    standard. 

  - Require nspr-4.10.0

  - Related: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1 (for
    FF 24.x)

  - Fix relative path in %check section to prevent
    undetected test failures

  - Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1
    (for FF 24.x)

  - Rebase to NSS_3.15.1_RTM

  - Resolves: rhbz#1002645 - Rebase RHEL 6 to NSS 3.15.1
    (for FF 24.x)

  - Update patches on account of the shallow tree with the
    rebase to 3.15.1

  - Update the pem module sources nss-pem-20130405.tar.bz2
    with latest patches applied

  - Remove patches rendered obsolete by the nss rebase and
    the updated nss-pem sources

  - Enable the iquote.patch to access newly introduced types

  - Do not hold issuer certificate handles in the crl cache

  - Resolves: rhbz#961659 - SQL backend does not reload
    certificates

  - Resolves: rhbz#977341 - nss-tools certutil -H does not
    list all options

  - Resolves: rhbz#702083 - don't require unique file
    basenames

  - Fix race condition in cert code related to smart cards

  - Resolves: rhbz#903017 - Firefox hang when CAC/PIV smart
    card certificates are viewed in the certificate manager

  - Configure libnssckbi.so to use the alternatives system
    in order to prepare for a drop in replacement. Please
    ensure that older packages that don't use the
    alternatives system for libnssckbi.so have a smaller
    n-v-r.

  - Syncup with uptream changes for aes gcm and ecc suiteb

  - Enable ecc support for suite b

  - Apply several upstream AES GCM fixes

  - Use the pristine nss upstream sources with ecc included

  - Export NSS_ENABLE_ECC=1 in both the build and the check
    sections

  - Make failed requests for unsupoprted ssl pkcs 11 bypass
    non fatal

  - Resolves: rhbz#882408 - NSS_NO_PKCS11_BYPASS must
    preserve ABI

  - Related: rhbz#918950 - rebase nss to 3.14.3

nss-softokn

  - Adjust patch to be compatible with legacy softokn API.

  - Resolves: Bug 1145431 - (CVE-2014-1568)

  - Resolves: Bug 1145431 - (CVE-2014-1568)

  - Skip calls to CHECK_FORK in [C & NSC]_GetFunctionList

  - Resolves: Bug 1082900 - Admin server segfault when
    configuration DS configured on SSL port

  - Add workaround to %check unset DISPLAY section for
    RHEL-5 based build machines where kernel lacks support
    for hardware GCM

  - back out -fips package changes

  - Enable new packaging but don't apply nss-fips-post.patch

  - Related: rhbz#1008513 - Unable to login in fips mode

  - Fix the PR_Access stub to actually access the correct
    permissions

  - Resolves: rhbz#1008513 - Unable to login in fips mode

  - Run the lowhash tests

  - Require nspr-4.0.0 and nss-util-3.15.1

  - create -fips packages

  - patch submitted by Bob Relyea

  - fix the script that splits softoken off from nss

  - patch nss/cmd/lib/basicutil.c to build against
    nss-util-3.15.1

  - Resolves: rhbz#993441 - NSS needs to conform to new FIPS
    standard. 

  - Resolves: rhbz#976572 - Pick up various upstream GCM
    code fixes applied since nss-3.14.3 was released

  - Display cpuifo as part of the tests and make
    NSS_DISABLE_HW_GCM the environment variable to test for

  - When appling the patches use a backup file suffix that
    better describes the patch purpose

  - Enable ECC support for suite b and add upstream fixes
    for aec gcm

  - Use the unstripped upstream sources with ecc support

  - Limit the ECC support to suite b

  - Apply several upstream aes gcm fixes

  - Rename macros EC_MIN_KEY_BITS and EC_MAX_KEY_BITS per
    upstream

  - Resolves: rhbz#960208 - Enable ECC in nss-softoken

  - Related: rhbz#919172

nss-util

  - Resolves: bug 1145431 - (CVE-2014-1568)

  - Update to nss-3.16.1

  - Resolves: rhbz#1112136

  - Update to NSS_3_15_3_RTM

  - Resolves: rhbz#1032470 - CVE-2013-5605 CVE-2013-5606
    (CVE-2013-1741)

  - Preserve existing permissions when replacing existing
    pkcs11.txt file, but keep strict default permissions for
    new files

  - Resolves: rhbz#990631 - file permissions of
    pkcs11.txt/secmod.db must be kept when modified by NSS"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-September/000225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26f1db89"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"nss-3.16.1-7.0.1.el6_5")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-softokn-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-softokn-freebl-3.14.3-12.el6_5")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-sysinit-3.16.1-7.0.1.el6_5")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-tools-3.16.1-7.0.1.el6_5")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-util-3.16.1-2.el6_5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-softokn / nss-softokn-freebl / nss-sysinit / nss-tools / etc");
}
