#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70969);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/26 00:30:55 $");

  script_cve_id("CVE-2013-1432", "CVE-2013-1442", "CVE-2013-1918", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2211", "CVE-2013-4329", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4369", "CVE-2013-4370", "CVE-2013-4371", "CVE-2013-4375", "CVE-2013-4416");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : Xen (SAT Patch Numbers 8478 / 8479)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN has been updated to version 4.2.3 c/s 26170, fixing various bugs
and security issues.

  - XSA-72: Fixed ocaml xenstored that mishandled oversized
    message replies. (CVE-2013-4416)

  - XSA-63: Fixed information leaks through I/O instruction
    emulation. (CVE-2013-4355)

  - XSA-66: Fixed information leak through fbld instruction
    emulation. (CVE-2013-4361)

  - XSA-67: Fixed information leak through outs instruction
    emulation. (CVE-2013-4368)

  - XSA-68: Fixed possible null dereference when parsing vif
    ratelimiting info. (CVE-2013-4369)

  - XSA-69: Fixed misplaced free in ocaml
    xc_vcpu_getaffinity stub. (CVE-2013-4370)

  - XSA-70: Fixed use-after-free in libxl_list_cpupool under
    memory pressure. (CVE-2013-4371)

  - XSA-71: xen: qemu disk backend (qdisk) resource leak.
    (CVE-2013-4375)

  - XSA-62: Fixed information leak on AVX and/or LWP capable
    CPUs. (CVE-2013-1442)

  - XSA-58: Page reference counting error due to
    XSA-45/CVE-2013-1918 fixes. Various bugs have also been
    fixed:. (CVE-2013-1432)

  - Boot failure with xen kernel in UEFI mode with error 'No
    memory for trampoline'. (bnc#833483)

  - Improvements to block-dmmd script. (bnc#828623)

  - MTU size on Dom0 gets reset when booting DomU with e1000
    device. (bnc#840196)

  - In HP's UEFI x86_64 platform and with xen environment,
    in booting stage, xen hypervisor will panic.
    (bnc#833251)

  - Xen: migration broken from xsave-capable to
    xsave-incapable host. (bnc#833796)

  - In xen, 'shutdown -y 0 -h' cannot power off system.
    (bnc#834751)

  - In HP's UEFI x86_64 platform with xen environment, xen
    hypervisor will panic on multiple blades nPar.
    (bnc#839600)

  - vcpus not started after upgrading Dom0 from SLES 11 SP2
    to SP3. (bnc#835896)

  - SLES 11 SP3 Xen security patch does not automatically
    update UEFI boot binary. (bnc#836239)

  - Failed to setup devices for vm instance when start
    multiple vms simultaneously. (bnc#824676)

  - SLES 9 SP4 guest fails to start after upgrading to SLES
    11 SP3. (bnc#817799)

  - Various upstream fixes have been included."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845520"
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
    value:"http://support.novell.com/security/cve/CVE-2013-2194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2211.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4329.html"
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
    attribute:"solution", 
    value:"Apply SAT patch number 8478 / 8479 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-libs-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-tools-domU-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-libs-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-tools-domU-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-doc-html-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-doc-pdf-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-libs-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-libs-32bit-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-tools-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-tools-domU-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-libs-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-tools-domU-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_02_3.0.93_0.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.6_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-libs-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-tools-domU-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-doc-html-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-doc-pdf-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.3_02_3.0.93_0.8-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-libs-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-libs-32bit-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-tools-4.2.3_02-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-tools-domU-4.2.3_02-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
