#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:3083-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(95761);
  script_version("$Revision: 3.9 $");
  script_cvs_date("$Date: 2017/02/01 15:30:45 $");

  script_cve_id("CVE-2016-7777", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-7995", "CVE-2016-8576", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9377", "CVE-2016-9378", "CVE-2016-9379", "CVE-2016-9380", "CVE-2016-9381", "CVE-2016-9382", "CVE-2016-9383", "CVE-2016-9385", "CVE-2016-9386", "CVE-2016-9637");
  script_osvdb_id(145043, 145066, 145163, 145167, 145316, 145385, 145695, 145697, 146244, 146245, 147621, 147622, 147623, 147652, 147653, 147655, 147656, 147657, 147658, 148308);
  script_xref(name:"IAVB", value:"2016-B-0149");
  script_xref(name:"IAVB", value:"2016-B-0190");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : xen (SUSE-SU-2016:3083-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen to version 4.5.5 fixes several issues. These
security issues were fixed :

  - CVE-2016-9637: ioport array overflow allowing a
    malicious guest administrator can escalate their
    privilege to that of the host (bsc#1011652)

  - CVE-2016-9386: x86 null segments were not always treated
    as unusable allowing an unprivileged guest user program
    to elevate its privilege to that of the guest operating
    system. Exploit of this vulnerability is easy on Intel
    and more complicated on AMD (bsc#1009100)

  - CVE-2016-9382: x86 task switch to VM86 mode was
    mis-handled, allowing a unprivileged guest process to
    escalate its privilege to that of the guest operating
    system on AMD hardware. On Intel hardware a malicious
    unprivileged guest process can crash the guest
    (bsc#1009103)

  - CVE-2016-9385: x86 segment base write emulation lacked
    canonical address checks, allowing a malicious guest
    administrator to crash the host (bsc#1009104)

  - CVE-2016-9383: The x86 64-bit bit test instruction
    emulation was broken, allowing a guest to modify
    arbitrary memory leading to arbitray code execution
    (bsc#1009107)

  - CVE-2016-9378: x86 software interrupt injection was
    mis-handled, allowing an unprivileged guest user to
    crash the guest (bsc#1009108)

  - CVE-2016-9377: x86 software interrupt injection was
    mis-handled, allowing an unprivileged guest user to
    crash the guest (bsc#1009108)

  - CVE-2016-9381: Improper processing of shared rings
    allowing guest administrators take over the qemu
    process, elevating their privilege to that of the qemu
    process (bsc#1009109)

  - CVE-2016-9380: Delimiter injection vulnerabilities in
    pygrub allowed guest administrators to obtain the
    contents of sensitive host files or delete the files
    (bsc#1009111)

  - CVE-2016-9379: Delimiter injection vulnerabilities in
    pygrub allowed guest administrators to obtain the
    contents of sensitive host files or delete the files
    (bsc#1009111)

  - CVE-2016-7777: Xen did not properly honor CR0.TS and
    CR0.EM, which allowed local x86 HVM guest OS users to
    read or modify FPU, MMX, or XMM register state
    information belonging to arbitrary tasks on the guest by
    modifying an instruction while the hypervisor is
    preparing to emulate it (bsc#1000106)

  - CVE-2016-8910: The rtl8139_cplus_transmit function in
    hw/net/rtl8139.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and CPU
    consumption) by leveraging failure to limit the ring
    descriptor count (bsc#1007157)

  - CVE-2016-8909: The intel_hda_xfer function in
    hw/audio/intel-hda.c allowed local guest OS
    administrators to cause a denial of service (infinite
    loop and CPU consumption) via an entry with the same
    value for buffer length and pointer position
    (bsc#1007160).

  - CVE-2016-8667: The rc4030_write function in
    hw/dma/rc4030.c in allowed local guest OS administrators
    to cause a denial of service (divide-by-zero error and
    QEMU process crash) via a large interval timer reload
    value (bsc#1005004)

  - CVE-2016-8669: The serial_update_parameters function in
    hw/char/serial.c allowed local guest OS administrators
    to cause a denial of service (divide-by-zero error and
    QEMU process crash) via vectors involving a value of
    divider greater than baud base (bsc#1005005)

  - CVE-2016-7995: A memory leak in ehci_process_itd allowed
    a privileged user inside guest to DoS the host
    (bsc#1003870).

  - CVE-2016-8576: The xhci_ring_fetch function in
    hw/usb/hcd-xhci.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and QEMU
    process crash) by leveraging failure to limit the number
    of link Transfer Request Blocks (TRB) to process
    (bsc#1004016).

  - CVE-2016-7908: The mcf_fec_do_tx function in
    hw/net/mcf_fec.c did not properly limit the buffer
    descriptor count when transmitting packets, which
    allowed local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) via
    vectors involving a buffer descriptor with a length of 0
    and crafted values in bd.flags (bsc#1003030)

  - CVE-2016-7909: The pcnet_rdra_addr function in
    hw/net/pcnet.c allowed local guest OS administrators to
    cause a denial of service (infinite loop and QEMU
    process crash) by setting the (1) receive or (2)
    transmit descriptor ring length to 0 (bsc#1003032)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7908.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7909.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8576.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8667.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8909.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8910.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9377.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9378.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9379.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9380.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9381.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9382.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9385.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9386.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9637.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20163083-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9867021e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1:zypper in -t
patch SUSE-SLE-SDK-12-SP1-2016-1795=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1795=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1795=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-debugsource-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-doc-html-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.5.5_02_k3.12.67_60.64.18-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.5.5_02_k3.12.67_60.64.18-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-32bit-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-debugsource-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-4.5.5_02_k3.12.67_60.64.18-22.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.5.5_02_k3.12.67_60.64.18-22.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-libs-32bit-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-libs-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.5.5_02-22.3.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"xen-libs-debuginfo-4.5.5_02-22.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
