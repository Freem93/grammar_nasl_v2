#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1745-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93177);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2014-0222", "CVE-2014-3640", "CVE-2014-3689", "CVE-2014-7815", "CVE-2014-9718", "CVE-2015-5278", "CVE-2015-6855", "CVE-2015-7512", "CVE-2015-8345", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8554", "CVE-2015-8555", "CVE-2015-8558", "CVE-2015-8743", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-1714", "CVE-2016-1981", "CVE-2016-2270", "CVE-2016-2271", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841");
  script_bugtraq_id(67357, 67483, 70237, 70997, 70998, 73316);
  script_osvdb_id(106038, 106039, 106040, 106041, 106042, 106045, 106046, 106067, 106983, 111847, 113748, 114397, 120289, 127378, 127493, 130703, 130889, 131399, 131793, 132029, 132032, 132050, 132466, 132467, 132550, 132759, 132798, 133503, 133504, 133524, 134630, 134631, 134693, 134694, 134888, 135279);

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2016:1745-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xen was updated to fix 36 security issues.

These security issues were fixed :

  - CVE-2013-4527: Buffer overflow in hw/timer/hpet.c might
    have allowed remote attackers to execute arbitrary code
    via vectors related to the number of timers
    (bnc#864673).

  - CVE-2013-4529: Buffer overflow in hw/pci/pcie_aer.c
    allowed remote attackers to cause a denial of service
    and possibly execute arbitrary code via a large log_num
    value in a savevm image (bnc#864678).

  - CVE-2013-4530: Buffer overflow in hw/ssi/pl022.c allowed
    remote attackers to cause a denial of service or
    possibly execute arbitrary code via crafted tx_fifo_head
    and rx_fifo_head values in a savevm image (bnc#864682).

  - CVE-2013-4533: Buffer overflow in the pxa2xx_ssp_load
    function in hw/arm/pxa2xx.c allowed remote attackers to
    cause a denial of service or possibly execute arbitrary
    code via a crafted s->rx_level value in a savevm image
    (bsc#864655).

  - CVE-2013-4534: Buffer overflow in hw/intc/openpic.c
    allowed remote attackers to cause a denial of service or
    possibly execute arbitrary code via vectors related to
    IRQDest elements (bsc#864811).

  - CVE-2013-4537: The ssi_sd_transfer function in
    hw/sd/ssi-sd.c allowed remote attackers to execute
    arbitrary code via a crafted arglen value in a savevm
    image (bsc#864391).

  - CVE-2013-4538: Multiple buffer overflows in the
    ssd0323_load function in hw/display/ssd0323.c allowed
    remote attackers to cause a denial of service (memory
    corruption) or possibly execute arbitrary code via
    crafted (1) cmd_len, (2) row, or (3) col values; (4)
    row_start and row_end values; or (5) col_star and
    col_end values in a savevm image (bsc#864769).

  - CVE-2013-4539: Multiple buffer overflows in the
    tsc210x_load function in hw/input/tsc210x.c might have
    allowed remote attackers to execute arbitrary code via a
    crafted (1) precision, (2) nextprecision, (3) function,
    or (4) nextfunction value in a savevm image
    (bsc#864805).

  - CVE-2014-0222: Integer overflow in the qcow_open
    function in block/qcow.c allowed remote attackers to
    cause a denial of service (crash) via a large L2 table
    in a QCOW version 1 image (bsc#877642).

  - CVE-2014-3640: The sosendto function in slirp/udp.c
    allowed local users to cause a denial of service (NULL
    pointer dereference) by sending a udp packet with a
    value of 0 in the source port and address, which
    triggers access of an uninitialized socket (bsc#897654).

  - CVE-2014-3689: The vmware-vga driver
    (hw/display/vmware_vga.c) allowed local guest users to
    write to qemu memory locations and gain privileges via
    unspecified parameters related to rectangle handling
    (bsc#901508).

  - CVE-2014-7815: The set_pixel_format function in ui/vnc.c
    allowed remote attackers to cause a denial of service
    (crash) via a small bytes_per_pixel value (bsc#902737).

  - CVE-2014-9718: The (1) BMDMA and (2) AHCI HBA interfaces
    in the IDE functionality had multiple interpretations of
    a function's return value, which allowed guest OS users
    to cause a host OS denial of service (memory consumption
    or infinite loop, and system crash) via a PRDT with zero
    complete sectors, related to the bmdma_prepare_buf and
    ahci_dma_prepare_buf functions (bsc#928393).

  - CVE-2015-5278: Infinite loop in ne2000_receive()
    function (bsc#945989).

  - CVE-2015-6855: hw/ide/core.c did not properly restrict
    the commands accepted by an ATAPI device, which allowed
    guest users to cause a denial of service or possibly
    have unspecified other impact via certain IDE commands,
    as demonstrated by a WIN_READ_NATIVE_MAX command to an
    empty drive, which triggers a divide-by-zero error and
    instance crash (bsc#945404).

  - CVE-2015-7512: Buffer overflow in the pcnet_receive
    function in hw/net/pcnet.c, when a guest NIC has a
    larger MTU, allowed remote attackers to cause a denial
    of service (guest OS crash) or execute arbitrary code
    via a large packet (bsc#957162).

  - CVE-2015-8345: eepro100: infinite loop in processing
    command block list (bsc#956829).

  - CVE-2015-8504: VNC: floating point exception
    (bsc#958491).

  - CVE-2015-8550: Paravirtualized drivers were incautious
    about shared memory contents (XSA-155) (bsc#957988).

  - CVE-2015-8554: qemu-dm buffer overrun in MSI-X handling
    (XSA-164) (bsc#958007).

  - CVE-2015-8555: Information leak in legacy x86 FPU/XMM
    initialization (XSA-165) (bsc#958009).

  - CVE-2015-8558: Infinite loop in ehci_advance_state
    resulted in DoS (bsc#959005).

  - CVE-2015-8743: ne2000: OOB memory access in ioport r/w
    functions (bsc#960725).

  - CVE-2015-8745: Reading IMR registers lead to a crash via
    assert(2) call (bsc#960707).

  - CVE-2016-1568: AHCI use-after-free vulnerability in aio
    port commands (bsc#961332).

  - CVE-2016-1570: The PV superpage functionality in
    arch/x86/mm.c allowed local PV guests to obtain
    sensitive information, cause a denial of service, gain
    privileges, or have unspecified other impact via a
    crafted page identifier (MFN) to the (1)
    MMUEXT_MARK_SUPER or (2) MMUEXT_UNMARK_SUPER sub-op in
    the HYPERVISOR_mmuext_op hypercall or (3) unknown
    vectors related to page table updates (bsc#960861).

  - CVE-2016-1571: VMX: intercept issue with INVLPG on
    non-canonical address (XSA-168) (bsc#960862).

  - CVE-2016-1714: nvram: OOB r/w access in processing
    firmware configurations (bsc#961691).

  - CVE-2016-1981: e1000 infinite loop in start_xmit and
    e1000_receive_iov routines (bsc#963782).

  - CVE-2016-2270: Xen allowed local guest administrators to
    cause a denial of service (host reboot) via vectors
    related to multiple mappings of MMIO pages with
    different cachability settings (bsc#965315).

  - CVE-2016-2271: VMX when using an Intel or Cyrix CPU,
    allowed local HVM guest users to cause a denial of
    service (guest crash) via vectors related to a
    non-canonical RIP (bsc#965317).

  - CVE-2016-2391: usb: multiple eof_timers in ohci module
    lead to NULL pointer dereference (bsc#967013).

  - CVE-2016-2392: NULL pointer dereference in remote NDIS
    control message handling (bsc#967012).

  - CVE-2016-2538: Integer overflow in remote NDIS control
    message handling (bsc#967969).

  - CVE-2016-2841: ne2000: Infinite loop in ne2000_receive
    (bsc#969350).

  - XSA-166: ioreq handling possibly susceptible to multiple
    read issue (bsc#958523).

These non-security issues were fixed :

  - bsc#954872: script block-dmmd not working as expected

  - bsc#959695: Missing docs for xen

  - bsc#967630: Discrepancy in reported memory size with
    correction XSA-153 for xend

  - bsc#959928: When DomU is in state running xm domstate
    returned nothing

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/877642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/897654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4527.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4529.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4530.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4533.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4534.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0222.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3640.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5278.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6855.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8743.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1570.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1714.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2271.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2391.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2392.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2841.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161745-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af739691"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-xen-12639=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-xen-12639=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_20_3.0.101_0.47.79-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-domU-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-html-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-tools-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_20_3.0.101_0.47.79-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_20_3.0.101_0.47.79-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-libs-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-tools-domU-4.2.5_20-24.9")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_20_3.0.101_0.47.79-24.9")) flag++;


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
