#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0066.
#

include("compat.inc");

if (description)
{
  script_id(91747);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2014-1568", "CVE-2015-2721", "CVE-2015-2730", "CVE-2015-7181", "CVE-2015-7182", "CVE-2016-1950");
  script_bugtraq_id(63736, 63737, 63738, 70116, 72178, 75541);
  script_osvdb_id(99746, 99747, 99748, 112036, 124092, 124105, 129797, 129798, 135603);

  script_name(english:"OracleVM 3.2 : nss (OVMSA-2016-0066)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Fix SSL_DH_MIN_P_BITS in more places.

  - Keep SSL_DH_MIN_P_BITS at 768 as in the previously
    released build.

  - Run SSL tests

  - Add compatility patches to prevent regressions

  - Ensure all ssl.sh tests are executed

  - Rebase to nss 3.21

  - Resolves: Bug 1297944 - Rebase RHEL 5.11.z to NSS 3.21
    in preparation for Firefox 45

  - Actually apply the fix for CVE-2016-1950 from NSS
    3.19.2.3 ...

  - Include the fix for CVE-2016-1950 from NSS 3.19.2.3

  - Resolves: Bug 1269354 - CVE-2015-7182 (CVE-2015-7181)

  - Rebase nss to 3.19.1

  - Pick up upstream fix for client auth. regression caused
    by 3.19.1

  - Revert upstream change to minimum key sizes

  - Remove patches that rendered obsolote by the rebase

  - Update existing patches on account of the rebase

  - Pick up upstream patch from nss-3.19.1

  - Resolves: Bug 1236954 - CVE-2015-2730 NSS: ECDSA
    signature validation fails to handle some signatures
    correctly (MFSA 2015-64)

  - Resolves: Bug 1236967 - CVE-2015-2721 NSS: incorrectly
    permited skipping of ServerKeyExchange (MFSA 2015-71)

  - On RHEL 6.x keep the TLS version defaults unchanged.

  - Update to CKBI 2.4 from NSS 3.18.1 (the only change in
    NSS 3.18.1)

  - Copy PayPalICA.cert and PayPalRootCA.cert to
    nss/tests/libpkix/certs

  - Resolves: Bug 1200905 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-5.11]

  - Update and reeneable nss-646045.patch on account of the
    rebase

  - Enable additional ssl test cycles and document why some
    aren't enabled

  - Resolves: Bug 1200905 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-5.11]

  - Fix shell syntax error on nss/tests/all.sh

  - Resolves: Bug 1200905 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-5.11]

  - Replace expired PayPal test certificate that breaks the
    build

  - Resolves: Bug 1200905 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-5.11]

  - Resolves: Bug 1200905 - Rebase nss to 3.18 for Firefox
    38 ESR [RHEL-5.11]

  - Resolves: Bug 1158159 - Upgrade to NSS 3.16.2.3 for
    Firefox 31.3

  - Adjust softokn patch to be compatible with legacy
    softokn API.

  - Resolves: Bug 1145430 - (CVE-2014-1568)

  - Add patches published with NSS 3.16.2.1

  - Resolves: Bug 1145430 - (CVE-2014-1568)

  - Backport nss-3.12.6 upstream fix required by Firefox 31
    ESR

  - Resolves: Bug 1110860

  - Rebase to nss-3.16.1 for FF31

  - Resolves: Bug 1110860 - Rebase nss in RHEL 5.11 to NSS
    3.16.1, required for FF 31

  - Remove unused and obsolete patches

  - Related: Bug 1032468

  - Improve shell code for error detection on %check section

  - Resolves: Bug 1035281 - Suboptimal shell code in
    nss.spec

  - Revoke trust in one mis-issued anssi certificate

  - Resolves: Bug 1042684 - nss: Mis-issued ANSSI/DCSSI
    certificate (MFSA 2013-117)

  - Pick up corrections made in the rhel-10.Z branch, remove
    an unused patch

  - Resolves: rhbz#1032468 - CVE-2013-5605 CVE-2013-5606
    (CVE-2013-1741) nss: various flaws [rhel-5.11]

  - Remove unused patch and retag for update to nss-3.15.3

  - Resolves: rhbz#1032468 - CVE-2013-5605 CVE-2013-5606
    (CVE-2013-1741) nss: various flaws [rhel-5.11]

  - Update to nss-3.15.3

  - Resolves: rhbz#1032468 - CVE-2013-5605 CVE-2013-5606
    (CVE-2013-1741) nss: various flaws [rhel-5.11]

  - Remove unused patches

  - Resolves: rhbz#1002642 - Rebase RHEL 5 to NSS 3.15.1
    (for FF 24.x)

  - Rebase to nss-3.15.1

  - Resolves: rhbz#1002642 - Rebase RHEL 5 to NSS 3.15.1
    (for FF 24.x)

  - Resolves: rhbz#1015864 - [Regression] NSS no longer
    trusts MD5 certificates

  - Split %check section tests in two: freebl/softoken and
    rest of nss tests

  - Adjust various patches and spec file steps on account of
    the rebase

  - Add various patches and remove obsoleted ones on account
    of the rebase

  - Renumber patches so freeb/softoken ones match the
    corresponding ones in rhel-6 nss-softokn

  - Make the freebl sources identical to the corresponding
    ones for rhel-6.5

  - Related: rhbz#987131

  - Adjust the patches to complete the syncup with upstrean
    nss

  - Use NSS_DISABLE_HW_GCM on the patch as we do on the spec
    file

  - Ensure softoken/freebl code is the same on nss side as
    on the softoken side

  - Related: rhbz#987131

  - Add disable_hw_gcm.patch and in the spec file export
    NSS_DISABLE_HW_GCM=1

  - Disable HW GCM on RHEL-5 as the older kernel lacks
    support for it

  - Related: rhbz#987131

  - Related: rhbz#987131 - Display cpuifo as part of the
    tests

  - Resolves: rhbz#987131 - Pick up various upstream GCM
    code fixes applied since nss-3.14.3 was released

  - Roll back to 79c87e69caa7454cbcf5f8161a628c538ff3cab3

  - Peviously added patch hasn't solved the sporadic core
    dumps

  - Related: rhbz#983766 - nssutil_ReadSecmodDB leaks memory

  - Resolves: rhbz#983766 - nssutil_ReadSecmodDB leaks
    memory

  - Add patch to get rid of sporadic blapitest core dumps

  - Restore 'export NO_FORK_CHECK=1' required for binary
    compatibility on RHEL-5

  - Remove an unused patch

  - Resolves: rhbz#918948 - [RFE][RHEL5] Rebase to
    nss-3.14.3

  - Resolves: rhbz#807419 - nss-tools certutil -H does not
    list all options

  - Apply upstream fixes for ecc enabling and aes gcm

  - Rename two macros EC_MIN_KEY_BITS and EC_MAX_KEY_BITS
    per upstream

  - Apply several upstream AES GCM fixes

  - Resolves: rhbz#960241 - Enable ECC in nss and freebl

  - Resolves: rhbz#918948 - [RFE][RHEL5]

  - Enable ECC support limited to suite b

  - Export NSS_ENABLE_ECC=1 in the %check section to
    properly test ecc

  - Resolves: rhbz#960241 - Enable ECC in nss and freebl

  - Define -DNO_FORK_CHECK when compiling softoken for ABI
    compatibility

  - Resolves: rhbz#918948 - [RFE][RHEL5] Rebase to
    nss-3.14.3 to fix the lucky-13 issue

  - Remove obsolete nss-nochktest.patch

  - Related: rhbz#960241 - Enable ECC in nss and freebl

  - Enable ECC by using the unstripped sources

  - Resolves: rhbz#960241 - Enable ECC in nss and freebl

  - Fix rpmdiff test reported failures and remove other
    unwanted changes

  - Resolves: rhbz#918948 - [RFE][RHEL5] Rebase to
    nss-3.14.3 to fix the lucky-13 issue

  - Mon Apr 22 2013 Elio Maldonado - 3.14.3-3

  - Update to NSS_3_14_3_RTM

  - Rework the rebase to preserve needed idiosynchracies

  - Ensure we install frebl/softoken from the extra build
    tree

  - Don't include freebl static library or its private
    headers

  - Add patch to deal with system sqlite not being recent
    enough

  - Don't install nss-sysinit nor sharedb

  - Resolves: rhbz#918948 - [RFE][RHEL5] Rebase to
    nss-3.14.3 to fix the lucky-13 issue

  - Mon Apr 01 2013 Elio Maldonado - 3.14.3-2

  - Restore the freebl-softoken source tar ball updated to
    3.14.3

  - Renumbering of some sources for clarity

  - Resolves: rhbz#918948 - [RFE][RHEL5] Rebase to
    nss-3.14.3 to fix the lucky-13 issue

  - Update to NSS_3_14_3_RTM

  - Resolves: rhbz#918948 - [RFE][RHEL5] Rebase to
    nss-3.14.3 to fix the lucky-13 issue

  - Resolves: rhbz#891150 - Dis-trust TURKTRUST mis-issued
    *.google.com certificate

  - Update to NSS_3_13_6_RTM

  - Resolves: rhbz#883788 - [RFE] [RHEL5] Rebase to NSS >=
    3.13.6

  - Resolves: rhbz#820684

  - Fix last entry in attrFlagsArray to be
    [NAME_SIZE(unextractable), PK11_ATTR_UNEXTRACTABLE]

  - Resolves: rhbz#820684

  - Enable certutil handle user supplied flags for PKCS #11
    attributes.

  - This will enable certutil to generate keys in fussy
    hardware tokens.

  - fix an error in the patch meta-information area (no code
    change)

  - Related: rhbz#830304 - Fix ia64 / i386 multilib nss
    install failure

  - Remove no longer needed %pre and %preun scriplets meant
    for nss updates from RHEL-5.0

  - Related: rhbz#830304 - Fix the changes to the %post line

  - Having multiple commands requires that /sbin/lconfig be
    the beginning of the scriptlet

  - Resolves: rhbz#830304 - Fix multilib and scriptlet
    problems

  - Fix %post and %postun lines per packaging guildelines

  - Add %[?_isa] to tools Requires: per packaging guidelines

  - Fix explicit-lib-dependency zlib error reported by
    rpmlint

  - Resolves: rhbz#830304 - Remove unwanted change to
    nss.pc.in

  - Update to NSS_3_13_5_RTM

  - Resolves: rhbz#830304 - Update RHEL 5.x to NSS 3.13.5
    and NSPR 4.9.1 for Mozilla 10.0.6

  - Resolves: rhbz#797939 - Protect NSS_Shutdown from
    clients that fail to initialize nss

  - Resolves: Bug 788039 - retagging to prevent update
    problems

  - Resolves: Bug 788039 - rebase nss to make firefox 10 LTS
    rebase possible

  - Update to 4.8.9

  - Resolves: Bug 713373 - File descriptor leak after
    service httpd reload

  - Don't initialize nss if already initialized or if there
    are no dbs

  - Retagging for a Y-stream version higher than the
    RHEL-5-7-Z branch

  - Retagging to keep the n-v-r as high as that for the
    RHEL-5-7-Z branch

  - Update builtins certs to those from NSSCKBI_1_88_RTM

  - Plug file descriptor leaks on httpd reloads

  - Update builtins certs to those from NSSCKBI_1_87_RTM

  - Update builtins certs to those from NSSCKBI_1_86_RTM

  - Update builtins certs to NSSCKBI_1_85_RTM

  - Update to 3.12.10

  - Fix libcrmf hard-coded maximum size for wrapped private
    keys

  - Update builtin certs to NSS_3.12.9_WITH_CKBI_1_82_RTM
    via a patch

  - Update builtin certs to those from
    NSS_3.12.9_WITH_CKBI_1_82_RTM

  - Update to 3.12.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000488.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"nss-3.21.0-6.el5_11")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss");
}
