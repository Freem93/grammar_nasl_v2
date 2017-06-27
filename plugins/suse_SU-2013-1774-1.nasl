#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1774-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83602);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-1432", "CVE-2013-1442", "CVE-2013-1918", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4369", "CVE-2013-4370", "CVE-2013-4371", "CVE-2013-4375", "CVE-2013-4416");
  script_bugtraq_id(59615, 60799, 62630, 62708, 62710, 62930, 62931, 62932, 62934, 62935, 63404);
  script_osvdb_id(92983, 94600, 97770, 97954, 97955, 98287, 98288, 98289, 98290, 98332, 99072);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : Xen (SUSE-SU-2013:1774-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN has been updated to version 4.2.3 c/s 26170, fixing various bugs
and security issues.

  - CVE-2013-4416: XSA-72: Fixed ocaml xenstored that
    mishandled oversized message replies

  - CVE-2013-4355: XSA-63: Fixed information leaks through
    I/O instruction emulation

  - CVE-2013-4361: XSA-66: Fixed information leak through
    fbld instruction emulation

  - CVE-2013-4368: XSA-67: Fixed information leak through
    outs instruction emulation

  - CVE-2013-4369: XSA-68: Fixed possible null dereference
    when parsing vif ratelimiting info

  - CVE-2013-4370: XSA-69: Fixed misplaced free in ocaml
    xc_vcpu_getaffinity stub

  - CVE-2013-4371: XSA-70: Fixed use-after-free in
    libxl_list_cpupool under memory pressure

  - CVE-2013-4375: XSA-71: xen: qemu disk backend (qdisk)
    resource leak

  - CVE-2013-1442: XSA-62: Fixed information leak on AVX
    and/or LWP capable CPUs

  - CVE-2013-1432: XSA-58: Page reference counting error due
    to XSA-45/CVE-2013-1918 fixes.

Various bugs have also been fixed :

  - Boot failure with xen kernel in UEFI mode with error 'No
    memory for trampoline' (bnc#833483)

  - Improvements to block-dmmd script (bnc#828623)

  - MTU size on Dom0 gets reset when booting DomU with e1000
    device (bnc#840196)

  - In HP's UEFI x86_64 platform and with xen environment,
    in booting stage, xen hypervisor will panic.
    (bnc#833251)

  - Xen: migration broken from xsave-capable to
    xsave-incapable host (bnc#833796)

  - In xen, 'shutdown -y 0 -h' cannot power off system
    (bnc#834751)

  - In HP's UEFI x86_64 platform with xen environment, xen
    hypervisor will panic on multiple blades nPar.
    (bnc#839600)

  - vcpus not started after upgrading Dom0 from SLES 11 SP2
    to SP3 (bnc#835896)

  - SLES 11 SP3 Xen security patch does not automatically
    update UEFI boot binary (bnc#836239)

  - Failed to setup devices for vm instance when start
    multiple vms simultaneously (bnc#824676)

  - SLES 9 SP4 guest fails to start after upgrading to SLES
    11 SP3 (bnc#817799)

  - Various upstream fixes have been included.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=44263de6887ab03471056913790a1e0e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6759046d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1432.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4361.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4369.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4370.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4371.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4416.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/817799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/824676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/828623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/833251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/833483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/833796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/834751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/835896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/836239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/839596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/839600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/840196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/840592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/841766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/842515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/845520"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131774-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f72f7687"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-xen-201310-8479

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-xen-201310-8479

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-xen-201310-8479

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Xen");
}
