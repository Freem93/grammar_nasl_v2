#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-753.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(91736);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2013-7446", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-3134", "CVE-2016-3672", "CVE-2016-3955", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4557", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4581", "CVE-2016-4805", "CVE-2016-4951", "CVE-2016-5244");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-753)");
  script_summary(english:"Check for the openSUSE-2016-753 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.1 kernel was updated to 4.1.26 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2016-1583: Prevent the usage of mmap when the lower
    file system does not allow it. This could have lead to
    local privilege escalation when ecryptfs-utils was
    installed and /sbin/mount.ecryptfs_private was setuid
    (bsc#983143).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relies on the write system
    call, which allows local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface.
    (bsc#979548)

  - CVE-2016-4805: Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network
    namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions. (bsc#980371).

  - CVE-2016-4951: The tipc_nl_publ_dump function in
    net/tipc/socket.c in the Linux kernel did not verify
    socket existence, which allowed local users to cause a
    denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact via a
    dumpit operation. (bsc#981058).

  - CVE-2016-5244: An information leak vulnerability in
    function rds_inc_info_copy of file net/rds/recv.c was
    fixed that might have leaked kernel stack data.
    (bsc#983213).

  - CVE-2016-4580: The x25_negotiate_facilities function in
    net/x25/x25_facilities.c in the Linux kernel did not
    properly initialize a certain data structure, which
    allowed attackers to obtain sensitive information from
    kernel stack memory via an X.25 Call Request.
    (bsc#981267).

  - CVE-2016-0758: Tags with indefinite length could have
    corrupted pointers in asn1_find_indefinite_length
    (bsc#979867).

  - CVE-2016-2053: The asn1_ber_decoder function in
    lib/asn1_decoder.c in the Linux kernel allowed attackers
    to cause a denial of service (panic) via an ASN.1 BER
    file that lacks a public key, leading to mishandling by
    the public_key_verify_signature function in
    crypto/asymmetric_keys/public_key.c (bnc#963762).

  - CVE-2013-7446: Use-after-free vulnerability in
    net/unix/af_unix.c in the Linux kernel allowed local
    users to bypass intended AF_UNIX socket permissions or
    cause a denial of service (panic) via crafted epoll_ctl
    calls (bnc#955654).

  - CVE-2016-3134: The netfilter subsystem in the Linux
    kernel did not validate certain offset fields, which
    allowed local users to gain privileges or cause a denial
    of service (heap memory corruption) via an
    IPT_SO_SET_REPLACE setsockopt call (bnc#971126).

  - CVE-2016-3672: The arch_pick_mmap_layout function in
    arch/x86/mm/mmap.c in the Linux kernel did not properly
    randomize the legacy base address, which made it easier
    for local users to defeat the intended restrictions on
    the ADDR_NO_RANDOMIZE flag, and bypass the ASLR
    protection mechanism for a setuid or setgid program, by
    disabling stack-consumption resource limits
    (bnc#974308).

  - CVE-2016-4482: A kernel information leak in the usbfs
    devio connectinfo was fixed, which could expose kernel
    stack memory to userspace. (bnc#978401).

  - CVE-2016-4485: A kernel information leak in llc was
    fixed (bsc#978821).

  - CVE-2016-4486: A kernel information leak in rtnetlink
    was fixed, where 4 uninitialized bytes could leak to
    userspace (bsc#978822).

  - CVE-2016-4557: A use-after-free via double-fdput in
    replace_map_fd_with_map_ptr() was fixed, which could
    allow privilege escalation (bsc#979018).

  - CVE-2016-4565: When the 'rdma_ucm' infiniband module is
    loaded, local attackers could escalate their privileges
    (bsc#979548).

  - CVE-2016-4569: A kernel information leak in the ALSA
    timer via events via snd_timer_user_tinterrupt that
    could leak information to userspace was fixed
    (bsc#979213).

  - CVE-2016-4578: A kernel information leak in the ALSA
    timer via events that could leak information to
    userspace was fixed (bsc#979879).

  - CVE-2016-4581: If the first propogated mount copy was
    being a slave it could oops the kernel (bsc#979913)

The following non-security bugs were fixed :

  - ALSA: hda - Add dock support for ThinkPad X260
    (boo#979278).

  - ALSA: hda - Apply fix for white noise on Asus N550JV,
    too (boo#979278).

  - ALSA: hda - Asus N750JV external subwoofer fixup
    (boo#979278).

  - ALSA: hda - Fix broken reconfig (boo#979278).

  - ALSA: hda - Fix headphone mic input on a few Dell ALC293
    machines (boo#979278).

  - ALSA: hda - Fix subwoofer pin on ASUS N751 and N551
    (boo#979278).

  - ALSA: hda - Fix white noise on Asus N750JV headphone
    (boo#979278).

  - ALSA: hda - Fix white noise on Asus UX501VW headset
    (boo#979278).

  - ALSA: hda/realtek - Add ALC3234 headset mode for
    Optiplex 9020m (boo#979278).

  - ALSA: hda/realtek - New codecs support for
    ALC234/ALC274/ALC294 (boo#979278).

  - ALSA: hda/realtek - New codec support of ALC225
    (boo#979278).

  - ALSA: hda/realtek - Support headset mode for ALC225
    (boo#979278).

  - ALSA: pcxhr: Fix missing mutex unlock (boo#979278).

  - ALSA: usb-audio: Quirk for yet another Phoenix Audio
    devices (v2) (boo#979278).

  - bluetooth: fix power_on vs close race (bsc#966849).

  - bluetooth: vhci: fix open_timeout vs. hdev race
    (bsc#971799,bsc#966849).

  - bluetooth: vhci: Fix race at creating hci device
    (bsc#971799,bsc#966849).

  - bluetooth: vhci: purge unhandled skbs
    (bsc#971799,bsc#966849).

  - btrfs: do not use src fd for printk (bsc#980348).

  - btrfs: fix crash/invalid memory access on fsync when
    using overlayfs (bsc#977198)

  - drm: qxl: Workaround for buggy user-space (bsc#981344).

  - enic: set netdev->vlan_features (bsc#966245).

  - fs: add file_dentry() (bsc#977198).

  - IB/IPoIB: Do not set skb truesize since using one
    linearskb (bsc#980657).

  - input: i8042 - lower log level for 'no controller'
    message (bsc#945345).

  - kabi: Add kabi/severities entries to ignore sound/hda/*,
    x509_*, efivar_validate, file_open_root and dax_fault

  - kabi: Add some fixups (module, pci_dev, drm, fuse and
    thermal)

  - kabi: file_dentry changes (bsc#977198).

  - kABI fixes for 4.1.22

  - mm/page_alloc.c: calculate 'available' memory in a
    separate function (bsc#982239).

  - net: disable fragment reassembly if high_thresh is zero
    (bsc#970506).

  - of: iommu: Silence misleading warning.

  - pstore_register() error handling was wrong -- it tried
    to release lock before it's acquired, causing spinlock /
    preemption imbalance. - usb: quirk to stop runtime PM
    for Intel 7260 (bnc#984460).

  - Revert 'usb: hub: do not clear BOS field during reset
    device' (boo#979728).

  - usb: core: hub: hub_port_init lock controller instead of
    bus (bnc#978073).

  - usb: preserve kABI in address0 locking (bnc#978073).

  - usb: usbip: fix potential out-of-bounds write
    (bnc#975945).

  - USB: xhci: Add broken streams quirk for Frescologic
    device id 1009 (bnc#982712).

  - virtio_balloon: do not change memory amount visible via
    /proc/meminfo (bsc#982238).

  - virtio_balloon: export 'available' memory to balloon
    statistics (bsc#982239)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984460"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BPF Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
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

if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-html-4.1.26-21.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-pdf-4.1.26-21.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-macros-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-xen-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-vanilla-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-syms-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-devel-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debugsource-4.1.26-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-devel-4.1.26-21.1") ) flag++;

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
