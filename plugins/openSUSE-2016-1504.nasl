#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1504.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(96129);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/27 14:30:01 $");

  script_cve_id("CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7422", "CVE-2016-7466", "CVE-2016-7907", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-7994", "CVE-2016-7995", "CVE-2016-8576", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8667", "CVE-2016-8668", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2016-1504)");
  script_summary(english:"Check for the openSUSE-2016-1504 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu to version 2.6.2 fixes the several issues.

These security issues were fixed :

  - CVE-2016-7161: Heap-based buffer overflow in the
    .receive callback of xlnx.xps-ethernetlite in QEMU (aka
    Quick Emulator) allowed attackers to execute arbitrary
    code on the QEMU host via a large ethlite packet
    (bsc#1001151).

  - CVE-2016-7170: OOB stack memory access when processing
    svga command (bsc#998516).

  - CVE-2016-7466: xhci memory leakage during device unplug
    (bsc#1000345).

  - CVE-2016-7422: NULL pointer dereference in
    virtqueu_map_desc (bsc#1000346).

  - CVE-2016-7908: The mcf_fec_do_tx function in
    hw/net/mcf_fec.c did not properly limit the buffer
    descriptor count when transmitting packets, which
    allowed local guest OS administrators to cause a denial
    of service (infinite loop and QEMU process crash) via
    vectors involving a buffer descriptor with a length of 0
    and crafted values in bd.flags (bsc#1002550).

  - CVE-2016-7995: Memory leak in ehci_process_itd
    (bsc#1003612).

  - CVE-2016-8576: The xhci_ring_fetch function in
    hw/usb/hcd-xhci.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and QEMU
    process crash) by leveraging failure to limit the number
    of link Transfer Request Blocks (TRB) to process
    (bsc#1003878).

  - CVE-2016-8578: The v9fs_iov_vunmarshal function in
    fsdev/9p-iov-marshal.c allowed local guest OS
    administrators to cause a denial of service (NULL
    pointer dereference and QEMU process crash) by sending
    an empty string parameter to a 9P operation
    (bsc#1003894).

  - CVE-2016-9105: Memory leakage in v9fs_link
    (bsc#1007494).

  - CVE-2016-8577: Memory leak in the v9fs_read function in
    hw/9pfs/9p.c allowed local guest OS administrators to
    cause a denial of service (memory consumption) via
    vectors related to an I/O read operation (bsc#1003893).

  - CVE-2016-9106: Memory leakage in v9fs_write
    (bsc#1007495).

  - CVE-2016-8669: The serial_update_parameters function in
    hw/char/serial.c allowed local guest OS administrators
    to cause a denial of service (divide-by-zero error and
    QEMU process crash) via vectors involving a value of
    divider greater than baud base (bsc#1004707).

  - CVE-2016-7909: The pcnet_rdra_addr function in
    hw/net/pcnet.c allowed local guest OS administrators to
    cause a denial of service (infinite loop and QEMU
    process crash) by setting the (1) receive or (2)
    transmit descriptor ring length to 0 (bsc#1002557).

  - CVE-2016-9101: eepro100 memory leakage whern unplugging
    a device (bsc#1007391).

  - CVE-2016-8668: The rocker_io_writel function in
    hw/net/rocker/rocker.c allowed local guest OS
    administrators to cause a denial of service
    (out-of-bounds read and QEMU process crash) by
    leveraging failure to limit DMA buffer size
    (bsc#1004706).

  - CVE-2016-8910: The rtl8139_cplus_transmit function in
    hw/net/rtl8139.c allowed local guest OS administrators
    to cause a denial of service (infinite loop and CPU
    consumption) by leveraging failure to limit the ring
    descriptor count (bsc#1006538).

  - CVE-2016-8909: The intel_hda_xfer function in
    hw/audio/intel-hda.c allowed local guest OS
    administrators to cause a denial of service (infinite
    loop and CPU consumption) via an entry with the same
    value for buffer length and pointer position
    (bsc#1006536).

  - CVE-2016-7994: Memory leak in
    virtio_gpu_resource_create_2d (bsc#1003613).

  - CVE-2016-9104: Integer overflow leading to OOB access in
    9pfs (bsc#1007493).

  - CVE-2016-8667: The rc4030_write function in
    hw/dma/rc4030.c allowed local guest OS administrators to
    cause a denial of service (divide-by-zero error and QEMU
    process crash) via a large interval timer reload value
    (bsc#1004702).

  - CVE-2016-7907: The pcnet_rdra_addr function in
    hw/net/pcnet.c allowed local guest OS administrators to
    cause a denial of service (infinite loop and QEMU
    process crash) by setting the (1) receive or (2)
    transmit descriptor ring length to 0 (bsc#1002549).

These non-security issues were fixed :

  - Change kvm-supported.txt to be per-architecture
    documentation, stored in the package documentation
    directory of each per-arch package (bsc#1005353).

  - Update support doc to include current ARM64 (AArch64)
    support stance (bsc#1005374).

  - Fix migration failure when snapshot also has been done
    (bsc#1008148).

  - Change package post script udevadm trigger calls to be
    device specific (bsc#1002116).

  - Add qmp-commands.txt documentation file back in. It was
    inadvertently dropped.

  - Add an x86 cpu option (l3-cache) to specify that an L3
    cache is present and another option (cpuid-0xb) to
    enable the cpuid 0xb leaf (bsc#1007769).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006536"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/316228"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"qemu-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-arm-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-arm-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-curl-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-curl-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-dmg-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-dmg-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-iscsi-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-iscsi-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-ssh-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-ssh-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-debugsource-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-extra-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-extra-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-guest-agent-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-guest-agent-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ipxe-1.0.0-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-kvm-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-lang-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-debugsource-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ppc-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ppc-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-s390-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-s390-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-seabios-1.9.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-sgabios-8-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-testsuite-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-tools-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-tools-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-vgabios-1.9.1-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-x86-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-x86-debuginfo-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"qemu-block-rbd-2.6.2-23.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.6.2-23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
