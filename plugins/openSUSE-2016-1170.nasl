#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1170.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94000);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id("CVE-2014-3615", "CVE-2014-3672", "CVE-2015-7512", "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8743", "CVE-2016-1714", "CVE-2016-1981", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4480", "CVE-2016-4952", "CVE-2016-4962", "CVE-2016-4963", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5126", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258", "CVE-2016-6259", "CVE-2016-6351", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094");
  script_xref(name:"IAVB", value:"2016-B-0118");
  script_xref(name:"IAVB", value:"2016-B-0140");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2016-1170) (Bunker Buster)");
  script_summary(english:"Check for the openSUSE-2016-1170 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xen fixes the following issues :

These security issues were fixed :

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

  - CVE-2016-6836: VMWARE VMXNET3 NIC device support was
    leaging information leakage. A privileged user inside
    guest could have used this to leak host memory bytes to
    a guest (boo#994761)

  - CVE-2016-6888: Integer overflow in packet initialisation
    in VMXNET3 device driver. A privileged user inside guest
    could have used this flaw to crash the Qemu instance
    resulting in DoS (bsc#994772)

  - CVE-2016-6833: Use-after-free issue in the VMWARE
    VMXNET3 NIC device support. A privileged user inside
    guest could have used this issue to crash the Qemu
    instance resulting in DoS (boo#994775)

  - CVE-2016-6835: Buffer overflow in the VMWARE VMXNET3 NIC
    device support, causing an OOB read access (bsc#994625)

  - CVE-2016-6834: A infinite loop during packet
    fragmentation in the VMWARE VMXNET3 NIC device support
    allowed privileged user inside guest to crash the Qemu
    instance resulting in DoS (bsc#994421)

  - CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in
    Xen allowed local 32-bit PV guest OS administrators to
    gain host OS privileges by leveraging fast-paths for
    updating pagetable entries (bsc#988675)

  - CVE-2016-6259: Xen did not implement Supervisor Mode
    Access Prevention (SMAP) whitelisting in 32-bit
    exception and event delivery, which allowed local 32-bit
    PV guest OS kernels to cause a denial of service
    (hypervisor and VM crash) by triggering a safety check
    (bsc#988676)

  - CVE-2016-5403: The virtqueue_pop function in
    hw/virtio/virtio.c in QEMU allowed local guest OS
    administrators to cause a denial of service (memory
    consumption and QEMU process crash) by submitting
    requests without waiting for completion (boo#990923)

  - CVE-2016-6351: The esp_do_dma function in hw/scsi/esp.c,
    when built with ESP/NCR53C9x controller emulation
    support, allowed local guest OS administrators to cause
    a denial of service (out-of-bounds write and QEMU
    process crash) or execute arbitrary code on the host via
    vectors involving DMA read into ESP command buffer
    (bsc#990843)

  - CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in
    Xen allowed local 32-bit PV guest OS administrators to
    gain host OS privileges by leveraging fast-paths for
    updating pagetable entries (bsc#988675)

  - CVE-2016-6259: Xen did not implement Supervisor Mode
    Access Prevention (SMAP) whitelisting in 32-bit
    exception and event delivery, which allowed local 32-bit
    PV guest OS kernels to cause a denial of service
    (hypervisor and VM crash) by triggering a safety check
    (bsc#988676)

  - CVE-2016-5337: The megasas_ctrl_get_info function in
    hw/scsi/megasas.c in QEMU allowed local guest OS
    administrators to obtain sensitive host memory
    information via vectors related to reading device
    control information (bsc#983973)

  - CVE-2016-5338: The (1) esp_reg_read and (2)
    esp_reg_write functions in hw/scsi/esp.c in QEMU allowed
    local guest OS administrators to cause a denial of
    service (QEMU process crash) or execute arbitrary code
    on the QEMU host via vectors related to the information
    transfer buffer (bsc#983984)

  - CVE-2016-5238: The get_cmd function in hw/scsi/esp.c in
    QEMU allowed local guest OS administrators to cause a
    denial of service (out-of-bounds write and QEMU process
    crash) via vectors related to reading from the
    information transfer buffer in non-DMA mode (bsc#982960)

  - CVE-2016-4453: The vmsvga_fifo_run function in
    hw/display/vmware_vga.c in QEMU allowed local guest OS
    administrators to cause a denial of service (infinite
    loop and QEMU process crash) via a VGA command
    (bsc#982225)

  - CVE-2016-4454: The vmsvga_fifo_read_raw function in
    hw/display/vmware_vga.c in QEMU allowed local guest OS
    administrators to obtain sensitive host memory
    information or cause a denial of service (QEMU process
    crash) by changing FIFO registers and issuing a VGA
    command, which triggers an out-of-bounds read
    (bsc#982224)

  - CVE-2016-5126: Heap-based buffer overflow in the
    iscsi_aio_ioctl function in block/iscsi.c in QEMU
    allowed local guest OS users to cause a denial of
    service (QEMU process crash) or possibly execute
    arbitrary code via a crafted iSCSI asynchronous I/O
    ioctl call (bsc#982286)

  - CVE-2016-5105: The megasas_dcmd_cfg_read function in
    hw/scsi/megasas.c in QEMU, when built with MegaRAID SAS
    8708EM2 Host Bus Adapter emulation support, used an
    uninitialized variable, which allowed local guest
    administrators to read host memory via vectors involving
    a MegaRAID Firmware Interface (MFI) command (bsc#982024)

  - CVE-2016-5106: The megasas_dcmd_set_properties function
    in hw/scsi/megasas.c in QEMU, when built with MegaRAID
    SAS 8708EM2 Host Bus Adapter emulation support, allowed
    local guest administrators to cause a denial of service
    (out-of-bounds write access) via vectors involving a
    MegaRAID Firmware Interface (MFI) command (bsc#982025)

  - CVE-2016-5107: The megasas_lookup_frame function in
    QEMU, when built with MegaRAID SAS 8708EM2 Host Bus
    Adapter emulation support, allowed local guest OS
    administrators to cause a denial of service
    (out-of-bounds read and crash) via unspecified vectors
    (bsc#982026)

  - CVE-2016-4963: The libxl device-handling allowed local
    guest OS users with access to the driver domain to cause
    a denial of service (management tool confusion) by
    manipulating information in the backend directories in
    xenstore (bsc#979670)

  - CVE-2016-4962: The libxl device-handling allowed local
    OS guest administrators to cause a denial of service
    (resource consumption or management facility confusion)
    or gain host OS privileges by manipulating information
    in guest controlled areas of xenstore (bsc#979620)

  - CVE-2016-4952: Out-of-bounds access issue in
    pvsci_ring_init_msg/data routines (bsc#981276)

  - CVE-2016-3710: The VGA module improperly performed
    bounds checking on banked access to video memory, which
    allowed local guest OS administrators to execute
    arbitrary code on the host by changing access modes
    after setting the bank register, aka the 'Dark Portal'
    issue (bsc#978164)

  - CVE-2014-3672: The qemu implementation in libvirt Xen
    allowed local guest OS users to cause a denial of
    service (host disk consumption) by writing to stdout or
    stderr (bsc#981264)

  - CVE-2016-4441: The get_cmd function in the 53C9X Fast
    SCSI Controller (FSC) support did not properly check DMA
    length, which allowed local guest OS administrators to
    cause a denial of service (out-of-bounds write and QEMU
    process crash) via unspecified vectors, involving an
    SCSI command (bsc#980724)

  - CVE-2016-4439: The esp_reg_write function in the 53C9X
    Fast SCSI Controller (FSC) support did not properly
    check command buffer length, which allowed local guest
    OS administrators to cause a denial of service
    (out-of-bounds write and QEMU process crash) or
    potentially execute arbitrary code on the host via
    unspecified vectors (bsc#980716)

  - CVE-2016-3960: Integer overflow in the x86 shadow
    pagetable code allowed local guest OS users to cause a
    denial of service (host crash) or possibly gain
    privileges by shadowing a superpage mapping (bsc#974038)

  - CVE-2016-3158: The xrstor function did not properly
    handle writes to the hardware FSW.ES bit when running on
    AMD64 processors, which allowed local guest OS users to
    obtain sensitive register content information from
    another guest by leveraging pending exception and mask
    bits (bsc#973188)

  - CVE-2016-3159: The fpu_fxrstor function in
    arch/x86/i387.c did not properly handle writes to the
    hardware FSW.ES bit when running on AMD64 processors,
    which allowed local guest OS users to obtain sensitive
    register content information from another guest by
    leveraging pending exception and mask bits (bsc#973188)

  - CVE-2016-4037: The ehci_advance_state function in
    hw/usb/hcd-ehci.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and CPU
    consumption) via a circular split isochronous transfer
    descriptor (siTD) list (bsc#976111)

  - CVE-2016-4020: The patch_instruction function did not
    initialize the imm32 variable, which allowed local guest
    OS administrators to obtain sensitive information from
    host stack memory by accessing the Task Priority
    Register (TPR) (bsc#975907)

  - CVE-2016-4001: Buffer overflow in the
    stellaris_enet_receive function, when the Stellaris
    ethernet controller is configured to accept large
    packets, allowed remote attackers to cause a denial of
    service (QEMU crash) via a large packet (bsc#975130)

  - CVE-2016-4002: Buffer overflow in the mipsnet_receive
    function, when the guest NIC is configured to accept
    large packets, allowed remote attackers to cause a
    denial of service (memory corruption and QEMU crash) or
    possibly execute arbitrary code via a packet larger than
    1514 bytes (bsc#975138)

  - CVE-2016-4480: The guest_walk_tables function in
    arch/x86/mm/guest_walk.c in Xen did not properly handle
    the Page Size (PS) page table entry bit at the L4 and L3
    page table levels, which might have allowed local guest
    OS users to gain privileges via a crafted mapping of
    memory (bsc#978295)

These non-security issues were fixed :

  - boo#991934: xen hypervisor crash in csched_acct

  - boo#992224: During boot of Xen Hypervisor, Failed to get
    contiguous memory for DMA from Xen

  - boo#955104: Virsh reports error 'one or more references
    were leaked after disconnect from hypervisor' when
    'virsh save' failed due to 'no response from client
    after 6 keepalive messages'

  - boo#959552: Migration of HVM guest leads into libvirt
    segmentation fault

  - boo#993665: Migration of xen guests finishes in: One or
    more references were leaked after disconnect from the
    hypervisor

  - boo#959330: Guest migrations using virsh results in
    error 'Internal error: received hangup / error event on
    socket'

  - boo#990500: VM virsh migration fails with keepalive
    error: ':virKeepAliveTimerInternal:143 : No response
    from client'

  - boo#953518: Unplug also SCSI disks in
    qemu-xen-traditional for upstream unplug protocol

  - boo#953518: xen_platform: unplug also SCSI disks in
    qemu-xen

  - boo#971949: Support (by ignoring) xl migrate --live. xl
    migrations are always live 

  - boo#970135: New virtualization project clock test
    randomly fails on Xen

  - boo#990970: Add PMU support for Intel E7-8867 v4 (fam=6,
    model=79)

  - boo#985503: vif-route broken

  - boo#961100: Migrate a fv guest from sles12 to sles12sp1
    fails remove patch because it can not fix the bug

  - boo#978413: PV guest upgrade from sles11sp4 to sles12sp2
    alpha3 failed on sles11sp4 xen host.

  - boo#986586: Out of memory (oom) during boot on 'modprobe
    xenblk' (non xen kernel) init.50-hvm-xen_conf

  - boo#900418: Dump cannot be performed on SLES12 XEN

  - boo#953339, boo#953362, boo#953518, boo#984981:
    Implement SUSE specific unplug protocol for emulated PCI
    devices in PVonHVM guests to qemu-xen-upstream 

  - boo#954872: script block-dmmd not working as expected -
    libxl: error: libxl_dm.c (Additional fixes) block-dmmd

  - boo#982695: xen-4.5.2 qemu fails to boot HVM guest from
    xvda 

  - boo#958848: HVM guest crash at /usr/src/packages/BUILD/
    xen-4.4.2-testing/obj/default/balloon/balloon.c:407

  - boo#949889: Fail to install 32-bit paravirt VM under
    SLES12SP1Beta3 XEN

  - boo#954872: script block-dmmd not working as expected -
    libxl: error: libxl_dm.c (another modification)
    block-dmmd

  - boo#961600: Poor performance when Xen HVM domU
    configured with max memory greater than current memory

  - boo#963161: Windows VM getting stuck during load while a
    VF is assigned to it after upgrading to latest
    maintenance updates

  - boo#976058: Xen error running simple HVM guest (Post
    Alpha 2 xen+qemu)

  - boo#961100: Migrate a fv guest from sles12 to sles12sp1
    on xen fails for 'Domain is not running on destination
    host'. qemu-ignore-kvm-tpr-opt-on-migration.patch 

  - boo#973631: AWS EC2 kdump issue

  - boo#964427: Discarding device blocks: failed -
    Input/output error"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=976111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995792"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"xen-debugsource-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-devel-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-libs-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-libs-debuginfo-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-tools-domU-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-tools-domU-debuginfo-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-doc-html-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-kmp-default-4.5.3_10_k4.1.31_30-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.5.3_10_k4.1.31_30-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-libs-32bit-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-tools-4.5.3_10-15.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.5.3_10-15.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen-debugsource / xen-devel / xen-libs-32bit / xen-libs / etc");
}
