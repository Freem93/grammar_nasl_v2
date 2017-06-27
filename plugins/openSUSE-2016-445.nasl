#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-445.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90482);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2003-1604", "CVE-2015-1339", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7884", "CVE-2015-8104", "CVE-2015-8709", "CVE-2015-8767", "CVE-2015-8785", "CVE-2015-8787", "CVE-2015-8812", "CVE-2016-0723", "CVE-2016-2069", "CVE-2016-2184", "CVE-2016-2383", "CVE-2016-2384");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-445)");
  script_summary(english:"Check for the openSUSE-2016-445 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.1 kernel was updated to 4.1.20 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2015-1339: A memory leak in cuse could be used to
    exhaust kernel memory. (bsc#969356).

  - CVE-2015-7799: The slhc_init function in
    drivers/net/slip/slhc.c in the Linux kernel did not
    ensure that certain slot numbers are valid, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) via a crafted
    PPPIOCSMAXCID ioctl call (bnc#949936 951638).

  - CVE-2015-7872: The key_gc_unused_keys function in
    security/keys/gc.c in the Linux kernel allowed local
    users to cause a denial of service (OOPS) via crafted
    keyctl commands (bnc#951440).

  - CVE-2015-7884: The vivid_fb_ioctl function in
    drivers/media/platform/vivid/vivid-osd.c in the Linux
    kernel did not initialize a certain structure member,
    which allowed local users to obtain sensitive
    information from kernel memory via a crafted application
    (bnc#951626).

  - CVE-2015-8104: The KVM subsystem in the Linux kernel
    allowed guest OS users to cause a denial of service
    (host OS panic or hang) by triggering many #DB (aka
    Debug) exceptions, related to svm.c (bnc#954404).

  - CVE-2015-8709: kernel/ptrace.c in the Linux kernel
    mishandled uid and gid mappings, which allowed local
    users to gain privileges by establishing a user
    namespace, waiting for a root process to enter that
    namespace with an unsafe uid or gid, and then using the
    ptrace system call. NOTE: the vendor states 'there is no
    kernel bug here (bnc#959709).

  - CVE-2015-8767: net/sctp/sm_sideeffect.c in the Linux
    kernel did not properly manage the relationship between
    a lock and a socket, which allowed local users to cause
    a denial of service (deadlock) via a crafted sctp_accept
    call. (bsc#961509)

  - CVE-2015-8785: The fuse_fill_write_pages function in
    fs/fuse/file.c in the Linux kernel allowed local users
    to cause a denial of service (infinite loop) via a
    writev system call that triggers a zero length for the
    first segment of an iov (bnc#963765).

  - CVE-2015-8787: The nf_nat_redirect_ipv4 function in
    net/netfilter/nf_nat_redirect.c in the Linux kernel
    allowed remote attackers to cause a denial of service
    (NULL pointer dereference and system crash) or possibly
    have unspecified other impact by sending certain IPv4
    packets to an incompletely configured interface, a
    related issue to CVE-2003-1604 (bnc#963931).

  - CVE-2015-8812: A flaw was found in the CXGB3 kernel
    driver when the network was considered congested. The
    kernel would incorrectly misinterpret the congestion as
    an error condition and incorrectly free/clean up the
    skb. When the device would then send the skb's queued,
    these structures would be referenced and may panic the
    system or allow an attacker to escalate privileges in a
    use-after-free scenario. (bsc#966437).

  - CVE-2016-0723: Race condition in the tty_ioctl function
    in drivers/tty/tty_io.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (use-after-free and
    system crash) by making a TIOCGETD ioctl call during
    processing of a TIOCSETD ioctl call (bnc#961500).

  - CVE-2016-2069: When Linux invalidated a paging structure
    that is not in use locally, it could, in principle, race
    against another CPU that is switching to a process that
    uses the paging structure in question. (bsc#963767)

  - CVE-2016-2184: A malicious USB device could cause a
    kernel crash in the alsa usb-audio driver. (bsc#971125)

  - CVE-2016-2383: Incorrect branch fixups for eBPF allow
    arbitrary read of kernel memory. (bsc#966684)

  - CVE-2016-2384: A malicious USB device could cause a
    kernel crash in the alsa usb-audio driver. (bsc#966693)

The following non-security bugs were fixed :

  - alsa: hda - Apply clock gate workaround to Skylake, too
    (bsc#966137).

  - alsa: hda - disable dynamic clock gating on Broxton
    before reset (bsc#966137).

  - alsa: hda - Fix playback noise with 24/32 bit sample
    size on BXT (bsc#966137).

  - alsa: seq: Fix double port list deletion (bsc#968018).

  - alsa: seq: Fix leak of pool buffer at concurrent writes
    (bsc#968018).

  - alsa: timer: Fix race between stop and interrupt
    (bsc#968018).

  - alsa: timer: Fix wrong instance passed to slave
    callbacks (bsc#968018).

  - arm64: Add workaround for Cavium erratum 27456.

  - arm64: Backport arm64 patches from SLE12-SP1-ARM

  - btrfs: teach backref walking about backrefs with
    underflowed (bsc#966259).

  - cgroup kabi fix for 4.1.19.

  - config: Disable CONFIG_DDR. CONFIG_DDR is selected
    automatically by drivers which need it.

  - config: Disable MFD_TPS65218 The TPS65218 is a power
    management IC for 32-bit ARM systems.

  - config: Modularize NF_REJECT_IPV4/V6 There is no reason
    why these helper modules should be built-in when the
    rest of netfilter is built as modules.

  - config: Update x86 config files: Enable Intel RAPL This
    driver is useful when power caping is needed. It was
    enabled in the SLE kernel 2 years ago.

  - Delete patches.fixes/bridge-module-get-put.patch. As
    discussed in
    http://lists.opensuse.org/opensuse-kernel/2015-11/msg000
    46.html

  - drm/i915: Fix double unref in intelfb_alloc failure path
    (boo#962866, boo#966179).

  - drm/i915: Fix failure paths around initial fbdev
    allocation (boo#962866, boo#966179).

  - drm/i915: Pin the ifbdev for the info->system_base GGTT
    mmapping (boo#962866, boo#966179).

  - e1000e: Avoid divide by zero error (bsc#965125).

  - e1000e: fix division by zero on jumbo MTUs (bsc#965125).

  - e1000e: fix systim issues (bsc#965125).

  - e1000e: Fix tight loop implementation of systime read
    algorithm (bsc#965125).

  - ibmvnic: Fix ibmvnic_capability struct.

  - intel: Disable Skylake support in intel_idle driver
    again (boo#969582) This turned out to bring a regression
    on some machines, unfortunately. It should be addressed
    in the upstream at first.

  - intel_idle: allow idle states to be freeze-mode specific
    (boo#969582).

  - intel_idle: Skylake Client Support (boo#969582).

  - intel_idle: Skylake Client Support - updated
    (boo#969582).

  - libceph: fix scatterlist last_piece calculation
    (bsc#963746).

  - lio: Add LIO clustered RBD backend (fate#318836)

  - net kabi fixes for 4.1.19.

  - numa patches updated to v15

  - ocfs2: fix dlmglue deadlock issue(bnc#962257)

  - pci: thunder: Add driver for ThunderX-pass{1,2} on-chip
    devices

  - pci: thunder: Add PCIe host driver for ThunderX
    processors

  - sd: Optimal I/O size is in bytes, not sectors
    (boo#961263).

  - sd: Reject optimal transfer length smaller than page
    size (boo#961263).

  - series.conf: move cxgb3 patch to network drivers section"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-kernel/2015-11/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=814440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=884701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=953527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=962977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971125"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
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

if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-html-4.1.20-11.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-pdf-4.1.20-11.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-macros-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-4.1.20-11.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-debugsource-4.1.20-11.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-xen-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-vanilla-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-syms-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-devel-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debugsource-4.1.20-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-devel-4.1.20-11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-base-debuginfo / etc");
}
