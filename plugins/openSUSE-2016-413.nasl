#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-413.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90260);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2013-4533", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2014-0222", "CVE-2014-3689", "CVE-2014-7815", "CVE-2014-9718", "CVE-2015-1779", "CVE-2015-5278", "CVE-2015-6855", "CVE-2015-7512", "CVE-2015-8345", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1570", "CVE-2016-1714", "CVE-2016-1981", "CVE-2016-2198", "CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538");

  script_name(english:"openSUSE Security Update : xen (openSUSE-2016-413)");
  script_summary(english:"Check for the openSUSE-2016-413 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xen was updated to fix 26 security issues.

These security issues were fixed :

  - CVE-2013-4533: Buffer overflow in the pxa2xx_ssp_load
    function in hw/arm/pxa2xx.c allowed remote attackers to
    cause a denial of service or possibly execute arbitrary
    code via a crafted s->rx_level value in a savevm image
    (bsc#864655).

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

  - CVE-2015-1779: The VNC websocket frame decoder allowed
    remote attackers to cause a denial of service (memory
    and CPU consumption) via a large (1) websocket payload
    or (2) HTTP headers section (bsc#924018).

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

  - CVE-2015-8613: SCSI: stack based buffer overflow in
    megasas_ctrl_get_info (bsc#961358).

  - CVE-2015-8619: Stack based OOB write in hmp_sendkey
    routine (bsc#960334).

  - CVE-2015-8743: ne2000: OOB memory access in ioport r/w
    functions (bsc#960725).

  - CVE-2015-8744: vmxnet3: Incorrect l2 header validation
    lead to a crash via assert(2) call (bsc#960835).

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

  - CVE-2016-1714: nvram: OOB r/w access in processing
    firmware configurations (bsc#961691).

  - CVE-2016-1981: e1000 infinite loop in start_xmit and
    e1000_receive_iov routines (bsc#963782).

  - CVE-2016-2198: EHCI NULL pointer dereference in
    ehci_caps_write (bsc#964413).

  - CVE-2016-2391: usb: multiple eof_timers in ohci module
    lead to NULL pointer dereference (bsc#967013).

  - CVE-2016-2392: NULL pointer dereference in remote NDIS
    control message handling (bsc#967012).

  - CVE-2016-2538: Integer overflow in remote NDIS control
    message handling (bsc#967969).

These non-security issues were fixed :

  - bsc#954872: script block-dmmd not working as expected 

  - bsc#957698: DOM0 can't bring up on Dell PC

  - bsc#963923: domain weights not honored when sched-credit
    tslice is reduced

  - bsc#959332: SLES12SP1 PV guest is unreachable when
    restored or migrated

  - bsc#959695: Missing docs for xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=864391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=864655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=864769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=864805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=877642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=901508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=924018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=928393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967969"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
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

if ( rpm_check(release:"SUSE42.1", reference:"xen-debugsource-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-devel-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-libs-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-libs-debuginfo-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-tools-domU-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"xen-tools-domU-debuginfo-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-doc-html-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-kmp-default-4.5.2_06_k4.1.15_8-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.5.2_06_k4.1.15_8-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-libs-32bit-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-tools-4.5.2_06-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.5.2_06-12.1") ) flag++;

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
