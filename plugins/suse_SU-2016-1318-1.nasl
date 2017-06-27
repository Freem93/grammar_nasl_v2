#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1318-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91249);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2013-4527", "CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2014-0222", "CVE-2014-3640", "CVE-2014-3689", "CVE-2014-7815", "CVE-2014-9718", "CVE-2015-1779", "CVE-2015-5278", "CVE-2015-6855", "CVE-2015-7512", "CVE-2015-7549", "CVE-2015-8345", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8554", "CVE-2015-8555", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1568", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2198", "CVE-2016-2270", "CVE-2016-2271", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538");
  script_bugtraq_id(67357, 67483, 70237, 70997, 70998, 73303, 73316);
  script_osvdb_id(106038, 106039, 106040, 106041, 106042, 106045, 106046, 106067, 106983, 111847, 113748, 114397, 119885, 120289, 127378, 127493, 130703, 130889, 131399, 131668, 131793, 131824, 132029, 132032, 132050, 132136, 132210, 132257, 132466, 132467, 132549, 132550, 132759, 132798, 133503, 133504, 133524, 133811, 134630, 134631, 134693, 134694, 134888, 135159);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : xen (SUSE-SU-2016:1318-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xen was updated to fix 46 security issues.

These security issues were fixed :

  - CVE-2013-4527: Buffer overflow in hw/timer/hpet.c might
    have allowed remote attackers to execute arbitrary code
    via vectors related to the number of timers
    (bsc#964746).

  - CVE-2013-4529: Buffer overflow in hw/pci/pcie_aer.c
    allowed remote attackers to cause a denial of service
    and possibly execute arbitrary code via a large log_num
    value in a savevm image (bsc#964929).

  - CVE-2013-4530: Buffer overflow in hw/ssi/pl022.c allowed
    remote attackers to cause a denial of service or
    possibly execute arbitrary code via crafted tx_fifo_head
    and rx_fifo_head values in a savevm image (bsc#964950).

  - CVE-2013-4533: Buffer overflow in the pxa2xx_ssp_load
    function in hw/arm/pxa2xx.c allowed remote attackers to
    cause a denial of service or possibly execute arbitrary
    code via a crafted s->rx_level value in a savevm image
    (bsc#964644).

  - CVE-2013-4534: Buffer overflow in hw/intc/openpic.c
    allowed remote attackers to cause a denial of service or
    possibly execute arbitrary code via vectors related to
    IRQDest elements (bsc#964452).

  - CVE-2013-4537: The ssi_sd_transfer function in
    hw/sd/ssi-sd.c allowed remote attackers to execute
    arbitrary code via a crafted arglen value in a savevm
    image (bsc#962642).

  - CVE-2013-4538: Multiple buffer overflows in the
    ssd0323_load function in hw/display/ssd0323.c allowed
    remote attackers to cause a denial of service (memory
    corruption) or possibly execute arbitrary code via
    crafted (1) cmd_len, (2) row, or (3) col values; (4)
    row_start and row_end values; or (5) col_star and
    col_end values in a savevm image (bsc#962335).

  - CVE-2013-4539: Multiple buffer overflows in the
    tsc210x_load function in hw/input/tsc210x.c might have
    allowed remote attackers to execute arbitrary code via a
    crafted (1) precision, (2) nextprecision, (3) function,
    or (4) nextfunction value in a savevm image
    (bsc#962758).

  - CVE-2014-0222: Integer overflow in the qcow_open
    function in block/qcow.c allowed remote attackers to
    cause a denial of service (crash) via a large L2 table
    in a QCOW version 1 image (bsc#964925).

  - CVE-2014-3640: The sosendto function in slirp/udp.c
    allowed local users to cause a denial of service (NULL
    pointer dereference) by sending a udp packet with a
    value of 0 in the source port and address, which
    triggers access of an uninitialized socket (bsc#965112).

  - CVE-2014-3689: The vmware-vga driver
    (hw/display/vmware_vga.c) allowed local guest users to
    write to qemu memory locations and gain privileges via
    unspecified parameters related to rectangle handling
    (bsc#962611).

  - CVE-2014-7815: The set_pixel_format function in ui/vnc.c
    allowed remote attackers to cause a denial of service
    (crash) via a small bytes_per_pixel value (bsc#962627).

  - CVE-2014-9718: The (1) BMDMA and (2) AHCI HBA interfaces
    in the IDE functionality had multiple interpretations of
    a function's return value, which allowed guest OS users
    to cause a host OS denial of service (memory consumption
    or infinite loop, and system crash) via a PRDT with zero
    complete sectors, related to the bmdma_prepare_buf and
    ahci_dma_prepare_buf functions (bsc#964431).

  - CVE-2015-1779: The VNC websocket frame decoder allowed
    remote attackers to cause a denial of service (memory
    and CPU consumption) via a large (1) websocket payload
    or (2) HTTP headers section (bsc#962632).

  - CVE-2015-5278: Infinite loop in ne2000_receive()
    function (bsc#964947).

  - CVE-2015-6855: hw/ide/core.c did not properly restrict
    the commands accepted by an ATAPI device, which allowed
    guest users to cause a denial of service or possibly
    have unspecified other impact via certain IDE commands,
    as demonstrated by a WIN_READ_NATIVE_MAX command to an
    empty drive, which triggers a divide-by-zero error and
    instance crash (bsc#965156).

  - CVE-2015-7512: Buffer overflow in the pcnet_receive
    function in hw/net/pcnet.c, when a guest NIC has a
    larger MTU, allowed remote attackers to cause a denial
    of service (guest OS crash) or execute arbitrary code
    via a large packet (bsc#962360).

  - CVE-2015-7549: pci: NULL pointer dereference issue
    (bsc#958918).

  - CVE-2015-8345: eepro100: infinite loop in processing
    command block list (bsc#956832).

  - CVE-2015-8504: VNC: floating point exception
    (bsc#958493).

  - CVE-2015-8550: Paravirtualized drivers were incautious
    about shared memory contents (XSA-155) (bsc#957988).

  - CVE-2015-8554: qemu-dm buffer overrun in MSI-X handling
    (XSA-164) (bsc#958007).

  - CVE-2015-8555: Information leak in legacy x86 FPU/XMM
    initialization (XSA-165) (bsc#958009).

  - CVE-2015-8558: Infinite loop in ehci_advance_state
    resulted in DoS (bsc#959006).

  - CVE-2015-8567: vmxnet3: host memory leakage
    (bsc#959387).

  - CVE-2015-8568: vmxnet3: host memory leakage
    (bsc#959387).

  - CVE-2015-8613: SCSI: stack-based buffer overflow in
    megasas_ctrl_get_info (bsc#961358).

  - CVE-2015-8619: Stack based OOB write in hmp_sendkey
    routine (bsc#965269).

  - CVE-2015-8743: ne2000: OOB memory access in ioport r/w
    functions (bsc#960726).

  - CVE-2015-8744: vmxnet3: Incorrect l2 header validation
    lead to a crash via assert(2) call (bsc#960836).

  - CVE-2015-8745: Reading IMR registers lead to a crash via
    assert(2) call (bsc#960707).

  - CVE-2015-8817: OOB access in address_space_rw lead to
    segmentation fault (I) (bsc#969125).

  - CVE-2015-8818: OOB access in address_space_rw lead to
    segmentation fault (II) (bsc#969126).

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
    firmware configurations (bsc#961692).

  - CVE-2016-1922: NULL pointer dereference in vapic_write()
    (bsc#962321).

  - CVE-2016-1981: e1000 infinite loop in start_xmit and
    e1000_receive_iov routines (bsc#963783).

  - CVE-2016-2198: EHCI NULL pointer dereference in
    ehci_caps_write (bsc#964415).

  - CVE-2016-2270: Xen allowed local guest administrators to
    cause a denial of service (host reboot) via vectors
    related to multiple mappings of MMIO pages with
    different cachability settings (bsc#965315).

  - CVE-2016-2271: VMX when using an Intel or Cyrix CPU,
    allowed local HVM guest users to cause a denial of
    service (guest crash) via vectors related to a
    non-canonical RIP (bsc#965317).

  - CVE-2016-2391: usb: multiple eof_timers in ohci module
    lead to NULL pointer dereference (bsc#967101).

  - CVE-2016-2392: NULL pointer dereference in remote NDIS
    control message handling (bsc#967090).

  - CVE-2016-2538: Integer overflow in remote NDIS control
    message handling (bsc#968004).

  - XSA-166: ioreq handling possibly susceptible to multiple
    read issue (bsc#958523).

These non-security issues were fixed :

  - bsc#954872: script block-dmmd not working as expected

  - bsc#963923: domain weights not honored when sched-credit
    tslice is reduced

  - bsc#959695: Missing docs for xen

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956832"
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
    value:"https://bugzilla.suse.com/958493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960836"
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
    value:"https://bugzilla.suse.com/961358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965269"
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
    value:"https://bugzilla.suse.com/967090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969126"
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
    value:"https://www.suse.com/security/cve/CVE-2015-1779.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-7549.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-8567.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8613.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8743.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8744.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8818.html"
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
    value:"https://www.suse.com/security/cve/CVE-2016-1922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2198.html"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161318-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d670117c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-779=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-779=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-779=1

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-doc-html-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_02_k3.12.55_52.42-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.4_02_k3.12.55_52.42-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_02_k3.12.55_52.42-22.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.4_02_k3.12.55_52.42-22.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.4_02-22.19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.4_02-22.19.1")) flag++;


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
