#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0065.
#

include("compat.inc");

if (description)
{
  script_id(91746);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2013-1741", "CVE-2013-5605", "CVE-2013-5606", "CVE-2015-7183");
  script_bugtraq_id(63736, 63737, 63738);
  script_osvdb_id(99746, 99747, 99748, 129799);

  script_name(english:"OracleVM 3.2 : nspr (OVMSA-2016-0065)");
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

  - Rebase to NSPR 4.11

  - Resolves: Bug 1297943 - Rebase RHEL 5.11.z to NSPR 4.11
    in preparation for Firefox 45

  - Resolves: Bug 1269359 - (CVE-2015-7183)

  - nspr: heap-buffer overflow in PL_ARENA_ALLOCATE can lead
    to crash (under ASAN), potential memory corruption
    [rhel-5.11.z]

  - Rebase to nspr-4.10.8

  - Resolves: Bug 1200921 - Rebase nspr to 4.10.8 for
    Firefox 38 ESR 

  - Rebase to nspr-4.10.6

  - Resolves: Bug 1110857 - Rebase nspr in RHEL 5.11 to NSPR
    4.10.6 for FF31

  - Retagging

  - Resolves: rhbz#1032468

  - Remove an unused patch

  - Resolves: rhbz#1032468 - CVE-2013-5605 CVE-2013-5606
    (CVE-2013-1741) nss: various flaws [rhel-5.11]

  - Update to nspr-4.10.2

  - Resolves: rhbz#1032468 - CVE-2013-5605 CVE-2013-5606
    (CVE-2013-1741) nss: various flaws [rhel-5.11]

  - Retagging to fix an inconsitency in the release tags

  - Resolves: rhbz#1002641 - Rebase RHEL 5 to NSPR 4.10 (for
    FF 24.x)

  - Rebase to nspr-4.10.0

  - Resolves: rhbz#1002641 - Rebase RHEL 5 to NSPR 4.10 (for
    FF 24.x)

  - Resolves: rhbz#737704 - Fix spec file test script typo
    and enable running the test suites

  - Resolves: rhbz#919183 - Rebase to nspr-4.9.5

  - Resolves: rhbz#883777- [RFE] Rebase nspr to 4.9.2 due to
    Firefox 17 ESR

  - Resolves: rhbz#633519 - pthread_key_t leak and memory
    corruption

  - Resolves: rhbz#831654 - Fix %post and %postun

  - Updated License: to MPLv2.0 per upstream

  - Resolves: rhbz#831654 - Pick up fixes from the rhel-5.8
    branch

  - Regenerated nspr-config-pc.patch passes the the rpmdiff
    tests

  - Resolves: rhbz#831654 - restore top section of
    nspr-config-pc.patch

  - Needed to prevent multilib regressions

  - Resolves: rhbz#831654 - revert unwanted changes to
    nspr.pc

  - Change@/nspr4 to@ in the patch

  - Update to NSPR_4_9_1_RTM

  - Resolves: rhbz#831654

  - rebuilt

  - Resolves: Bug 772945 - [RFE] Async update nspr to make
    firefox 10 LTS rebase possible

  - Update to 4.8.9

  - Bumping the relase tag so it's higher than the one in
    5.7-z

  - Update to 4.8.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000485.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nspr package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nspr");
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
if (rpm_check(release:"OVS3.2", reference:"nspr-4.11.0-1.el5_11")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr");
}
