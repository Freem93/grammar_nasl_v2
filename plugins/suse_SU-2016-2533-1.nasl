#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2533-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94269);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/28 15:50:26 $");

  script_cve_id("CVE-2014-3615", "CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4480", "CVE-2016-4952", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258", "CVE-2016-6351", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094", "CVE-2016-7154");
  script_bugtraq_id(69654);
  script_osvdb_id(111030, 136473, 136948, 136949, 137159, 137352, 137353, 138373, 138374, 138720, 138741, 138742, 138951, 138952, 139049, 139050, 139051, 139178, 139179, 139237, 139321, 139322, 139324, 139518, 139575, 139576, 142100, 142140, 142178, 142870, 142871, 142872, 142873, 143254, 143907, 143908, 143909, 143916);
  script_xref(name:"IAVB", value:"2016-B-0118");
  script_xref(name:"IAVB", value:"2016-B-0140");

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2016:2533-1) (Bunker Buster)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes several issues. These security issues were
fixed :

  - CVE-2014-3672: The qemu implementation in libvirt Xen
    allowed local guest OS users to cause a denial of
    service (host disk consumption) by writing to stdout or
    stderr (bsc#981264).

  - CVE-2016-3158: The xrstor function did not properly
    handle writes to the hardware FSW.ES bit when running on
    AMD64 processors, which allowed local guest OS users to
    obtain sensitive register content information from
    another guest by leveraging pending exception and mask
    bits (bsc#973188).

  - CVE-2016-3159: The fpu_fxrstor function in
    arch/x86/i387.c did not properly handle writes to the
    hardware FSW.ES bit when running on AMD64 processors,
    which allowed local guest OS users to obtain sensitive
    register content information from another guest by
    leveraging pending exception and mask bits (bsc#973188).

  - CVE-2016-3710: The VGA module improperly performed
    bounds checking on banked access to video memory, which
    allowed local guest OS administrators to execute
    arbitrary code on the host by changing access modes
    after setting the bank register, aka the 'Dark Portal'
    issue (bsc#978164)

  - CVE-2016-3960: Integer overflow in the x86 shadow
    pagetable code allowed local guest OS users to cause a
    denial of service (host crash) or possibly gain
    privileges by shadowing a superpage mapping
    (bsc#974038).

  - CVE-2016-4001: Buffer overflow in the
    stellaris_enet_receive function, when the Stellaris
    ethernet controller is configured to accept large
    packets, allowed remote attackers to cause a denial of
    service (QEMU crash) via a large packet (bsc#975130).

  - CVE-2016-4002: Buffer overflow in the mipsnet_receive
    function, when the guest NIC is configured to accept
    large packets, allowed remote attackers to cause a
    denial of service (memory corruption and QEMU crash) or
    possibly execute arbitrary code via a packet larger than
    1514 bytes (bsc#975138).

  - CVE-2016-4020: The patch_instruction function did not
    initialize the imm32 variable, which allowed local guest
    OS administrators to obtain sensitive information from
    host stack memory by accessing the Task Priority
    Register (TPR) (bsc#975907)

  - CVE-2016-4037: The ehci_advance_state function in
    hw/usb/hcd-ehci.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and CPU
    consumption) via a circular split isochronous transfer
    descriptor (siTD) list (bsc#976111)

  - CVE-2016-4439: The esp_reg_write function in the 53C9X
    Fast SCSI Controller (FSC) support did not properly
    check command buffer length, which allowed local guest
    OS administrators to cause a denial of service
    (out-of-bounds write and QEMU process crash) or
    potentially execute arbitrary code on the host via
    unspecified vectors (bsc#980716)

  - CVE-2016-4441: The get_cmd function in the 53C9X Fast
    SCSI Controller (FSC) support did not properly check DMA
    length, which allowed local guest OS administrators to
    cause a denial of service (out-of-bounds write and QEMU
    process crash) via unspecified vectors, involving an
    SCSI command (bsc#980724)

  - CVE-2016-4453: The vmsvga_fifo_run function allowed
    local guest OS administrators to cause a denial of
    service (infinite loop and QEMU process crash) via a VGA
    command (bsc#982225)

  - CVE-2016-4454: The vmsvga_fifo_read_raw function allowed
    local guest OS administrators to obtain sensitive host
    memory information or cause a denial of service (QEMU
    process crash) by changing FIFO registers and issuing a
    VGA command, which triggered an out-of-bounds read
    (bsc#982224)

  - CVE-2016-4480: The guest_walk_tables function in
    arch/x86/mm/guest_walk.c in Xen did not properly handle
    the Page Size (PS) page table entry bit at the L4 and L3
    page table levels, which might have allowed local guest
    OS users to gain privileges via a crafted mapping of
    memory (bsc#978295).

  - CVE-2016-4952: Out-of-bounds access issue in
    pvsci_ring_init_msg/data routines (bsc#981276)

  - CVE-2016-4962: The libxl device-handling allowed local
    OS guest administrators to cause a denial of service
    (resource consumption or management facility confusion)
    or gain host OS privileges by manipulating information
    in guest controlled areas of xenstore (bsc#979620)

  - CVE-2016-4963: The libxl device-handling allowed local
    guest OS users with access to the driver domain to cause
    a denial of service (management tool confusion) by
    manipulating information in the backend directories in
    xenstore (bsc#979670)

  - CVE-2016-5105: Stack information leakage while reading
    configuration (bsc#982024)

  - CVE-2016-5106: Out-of-bounds write while setting
    controller properties (bsc#982025)

  - CVE-2016-5107: Out-of-bounds read in
    megasas_lookup_frame() function (bsc#982026)

  - CVE-2016-5126: Heap-based buffer overflow in the
    iscsi_aio_ioctl function allowed local guest OS users to
    cause a denial of service (QEMU process crash) or
    possibly execute arbitrary code via a crafted iSCSI
    asynchronous I/O ioctl call (bsc#982286)

  - CVE-2016-5238: The get_cmd function in hw/scsi/esp.c
    might have allowed local guest OS administrators to
    cause a denial of service (out-of-bounds write and QEMU
    process crash) via vectors related to reading from the
    information transfer buffer in non-DMA mode (bsc#982960)

  - CVE-2016-5337: The megasas_ctrl_get_info function
    allowed local guest OS administrators to obtain
    sensitive host memory information via vectors related to
    reading device control information (bsc#983973)

  - CVE-2016-5338: The (1) esp_reg_read and (2)
    esp_reg_write functions allowed local guest OS
    administrators to cause a denial of service (QEMU
    process crash) or execute arbitrary code on the host via
    vectors related to the information transfer buffer
    (bsc#983984)

  - CVE-2016-5403: virtio: unbounded memory allocation on
    host via guest leading to DoS (XSA-184) (bsc#990923)

  - CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in
    Xen allowed local 32-bit PV guest OS administrators to
    gain host OS privileges by leveraging fast-paths for
    updating pagetable entries (bsc#988675)

  - CVE-2016-6351: The esp_do_dma function in hw/scsi/esp.c,
    when built with ESP/NCR53C9x controller emulation
    support, allowed local guest OS administrators to cause
    a denial of service (out-of-bounds write and QEMU
    process crash) or execute arbitrary code on the host via
    vectors involving DMA read into ESP command buffer
    (bsc#990843).

  - CVE-2016-6833: A use-after-free issue in the VMWARE
    VMXNET3 NIC device support allowed privileged user
    inside guest to crash the Qemu instance resulting in DoS
    (bsc#994775).

  - CVE-2016-6834: A infinite loop during packet
    fragmentation in the VMWARE VMXNET3 NIC device support
    allowed privileged user inside guest to crash the Qemu
    instance resulting in DoS (bsc#994421).

  - CVE-2016-6835: Buffer overflow in the VMWARE VMXNET3 NIC
    device support, causing an OOB read access (bsc#994625).

  - CVE-2016-6836: VMWARE VMXNET3 NIC device allowed
    privileged user inside the guest to leak information. It
    occured while processing transmit(tx) queue, when it
    reaches the end of packet (bsc#994761).

  - CVE-2016-6888: A integer overflow int the VMWARE VMXNET3
    NIC device support, during the initialisation of new
    packets in the device, could have allowed a privileged
    user inside guest to crash the Qemu instance resulting
    in DoS (bsc#994772).

  - CVE-2016-7092: The get_page_from_l3e function in
    arch/x86/mm.c in Xen allowed local 32-bit PV guest OS
    administrators to gain host OS privileges via vectors
    related to L3 recursive pagetables (bsc#995785)

  - CVE-2016-7093: Xen allowed local HVM guest OS
    administrators to overwrite hypervisor memory and
    consequently gain host OS privileges by leveraging
    mishandling of instruction pointer truncation during
    emulation (bsc#995789)

  - CVE-2016-7094: Buffer overflow in Xen allowed local x86
    HVM guest OS administrators on guests running with
    shadow paging to cause a denial of service via a
    pagetable update (bsc#995792)

  - CVE-2016-7154: Use-after-free vulnerability in the FIFO
    event channel code in Xen allowed local guest OS
    administrators to cause a denial of service (host crash)
    and possibly execute arbitrary code or obtain sensitive
    information via an invalid guest frame number
    (bsc#997731). These non-security issues were fixed :

  - bsc#991934: Hypervisor crash in csched_acct

  - bsc#992224: During boot of Xen Hypervisor, failed to get
    contiguous memory for DMA

  - bsc#970135: New virtualization project clock test
    randomly fails on Xen

  - bsc#971949: xl: Support (by ignoring) xl migrate --live.
    xl migrations are always live

  - bsc#990970: Add PMU support for Intel E7-8867 v4 (fam=6,
    model=79)

  - bsc#985503: vif-route broken

  - bsc#978413: PV guest upgrade from sles11sp4 to sles12sp2
    alpha3 failed on sles11sp4 xen host.

  - bsc#986586: Out of memory (oom) during boot on 'modprobe
    xenblk' (non xen kernel)

  - bsc#953339, bsc#953362, bsc#953518, bsc#984981:
    Implement SUSE specific unplug protocol for emulated PCI
    devices in PVonHVM guests to qemu-xen-upstream

  - bsc#958848: HVM guest crash at /usr/src/packages/BUILD/
    xen-4.4.2-testing/obj/default/balloon/balloon.c:407

  - bsc#982695: xen-4.5.2 qemu fails to boot HVM guest from
    xvda

  - bsc#954872: script block-dmmd not working as expected

  - bsc#961600: : poor performance when Xen HVM domU
    configured with max memory > current memory

  - bsc#979035: Restore xm migrate fixes for bsc#955399/
    bsc#955399

  - bsc#963161: Windows VM getting stuck during load while a
    VF is assigned to it

  - bsc#976058: Xen error running simple HVM guest (Post
    Alpha 2 xen+qemu)

  - bsc#957986: Indirect descriptors are not compatible with
    Amazon block backend

  - bsc#973631: AWS EC2 kdump issue

  - bsc#964427: Discarding device blocks failed with
    input/output error

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3672.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3158.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3710.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3712.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3960.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4453.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4454.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4952.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4962.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4963.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5106.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5126.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5238.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5337.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5338.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5403.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6258.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6351.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7154.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162533-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?256ed468"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2016-1476=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2016-1476=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-doc-html-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_04_k3.12.60_52.54-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.4_04_k3.12.60_52.54-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_04-22.22.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.4.4_04-22.22.2")) flag++;


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
