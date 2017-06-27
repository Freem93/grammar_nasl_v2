#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-794.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80153);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/22 14:33:18 $");

  script_cve_id("CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-8133", "CVE-2014-9090", "CVE-2014-9322");

  script_name(english:"openSUSE Security Update : Linux Kernel (openSUSE-SU-2014:1678-1)");
  script_summary(english:"Check for the openSUSE-2014-794 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.2 kernel was updated to version 3.16.7.

These security issues were fixed :

  - CVE-2014-9322: A local privilege escalation in the
    x86_64 32bit compatibility signal handling was fixed,
    which could be used by local attackers to crash the
    machine or execute code. (bnc#910251)

  - CVE-2014-9090: The do_double_fault function in
    arch/x86/kernel/traps.c in the Linux kernel did not
    properly handle faults associated with the Stack Segment
    (SS) segment register, which allowed local users to
    cause a denial of service (panic) via a modify_ldt
    system call, as demonstrated by sigreturn_32 in the
    linux-clock-tests test suite. (bnc#907818)

  - CVE-2014-8133: Insufficient validation of TLS register
    usage could leak information from the kernel stack to
    userspace. (bnc#909077)

  - CVE-2014-3673: The SCTP implementation in the Linux
    kernel through 3.17.2 allowed remote attackers to cause
    a denial of service (system crash) via a malformed
    ASCONF chunk, related to net/sctp/sm_make_chunk.c and
    net/sctp/sm_statefuns.c (bnc#902346, bnc#902349).

  - CVE-2014-3687: The sctp_assoc_lookup_asconf_ack function
    in net/sctp/associola.c in the SCTP implementation in
    the Linux kernel through 3.17.2 allowed remote attackers
    to cause a denial of service (panic) via duplicate
    ASCONF chunks that triggered an incorrect uncork within
    the side-effect interpreter (bnc#902349).

  - CVE-2014-3688: The SCTP implementation in the Linux
    kernel before 3.17.4 allowed remote attackers to cause a
    denial of service (memory consumption) by triggering a
    large number of chunks in an association's output queue,
    as demonstrated by ASCONF probes, related to
    net/sctp/inqueue.c and net/sctp/sm_statefuns.c
    (bnc#902351).

  - CVE-2014-7826: kernel/trace/trace_syscalls.c in the
    Linux kernel through 3.17.2 did not properly handle
    private syscall numbers during use of the ftrace
    subsystem, which allowed local users to gain privileges
    or cause a denial of service (invalid pointer
    dereference) via a crafted application (bnc#904013).

  - CVE-2014-7841: The sctp_process_param function in
    net/sctp/sm_make_chunk.c in the SCTP implementation in
    the Linux kernel before 3.17.4, when ASCONF is used,
    allowed remote attackers to cause a denial of service
    (NULL pointer dereference and system crash) via a
    malformed INIT chunk (bnc#905100).

These non-security issues were fixed :

  - ahci: Check and set 64-bit DMA mask for platform AHCI
    driver (bnc#902632).

  - ahci/xgene: Remove logic to set 64-bit DMA mask
    (bnc#902632).

  - ahci_xgene: Skip the PHY and clock initialization if
    already configured by the firmware (bnc#902632).

  - ALSA: hda - Add mute LED control for Lenovo Ideapad Z560
    (bnc#665315).

  - ALSA: hda/realtek - Add alc_update_coef*_idx() helper
    (bnc#905068).

  - ALSA: hda/realtek - Change EAPD to verb control
    (bnc#905068).

  - ALSA: hda/realtek - Optimize alc888_coef_init()
    (bnc#905068).

  - ALSA: hda/realtek - Restore default value for ALC668
    (bnc#905068).

  - ALSA: hda/realtek - Update Initial AMP for EAPD control
    (bnc#905068).

  - ALSA: hda/realtek - Update restore default value for
    ALC282 (bnc#905068).

  - ALSA: hda/realtek - Update restore default value for
    ALC283 (bnc#905068).

  - ALSA: hda/realtek - Use alc_write_coef_idx() in
    alc269_quanta_automake() (bnc#905068).

  - ALSA: hda/realtek - Use tables for batch COEF
    writes/updtes (bnc#905068).

  - ALSA: usb-audio: Do not resubmit pending URBs at MIDI
    error recovery.

  - arm64: Add architectural support for PCI (bnc#902632).

  - arm64: adjust el0_sync so that a function can be called
    (bnc#902632).

  - arm64: Do not call enable PCI resources when specify
    PCI_PROBE_ONLY (bnc#902632).

  - arm64: dts: Add X-Gene reboot driver dts node
    (bnc#902632).

  - arm64/efi: efistub: cover entire static mem footprint in
    PE/COFF .text (bnc#902632).

  - arm64/efi: efistub: do not abort if base of DRAM is
    occupied (bnc#902632).

  - arm64: fix bug for reloading FPSIMD state after cpu
    power off (bnc#902632).

  - arm64: fix VTTBR_BADDR_MASK (bnc#902632).

  - arm64: fpsimd: fix a typo in fpsimd_save_partial_state
    ENDPROC (bnc#902632).

  - arm64/mustang: Disable sgenet and xgenet (bnc#902632).

  - arm64: Select reboot driver for X-Gene platform
    (bnc#902632).

  - arm: Add APM Mustang network driver (bnc#902632).

  - arm/arm64: KVM: Fix and refactor unmap_range
    (bnc#902632).

  - arm: Define PCI_IOBASE as the base of virtual PCI IO
    space (bnc#902632).

  - asm-generic/io.h: Fix ioport_map() for
    !CONFIG_GENERIC_IOMAP (bnc#902632).

  - ax88179_178a: fix bonding failure (bsc#908253).

  - btrfs: Fix and enhance merge_extent_mapping() to insert
    best fitted extent map.

  - btrfs: fix crash of btrfs_release_extent_buffer_page.

  - btrfs: fix invalid leaf slot access in
    btrfs_lookup_extent().

  - btrfs: fix kfree on list_head in
    btrfs_lookup_csums_range error cleanup.

  - btrfs: fix lockups from btrfs_clear_path_blocking.

  - btrfs: fix race that makes btrfs_lookup_extent_info miss
    skinny extent items.

  - btrfs: Fix the wrong condition judgment about subset
    extent map.

  - btrfs: fix wrong accounting of raid1 data profile in
    statfs.

  - btrfs: send, do not delay dir move if there is a new
    parent inode.

  - config: armv7hl: Disable CONFIG_USB_MUSB_TUSB6010
    (bnc#906914).

  - cpufreq: arm_big_little: fix module license spec
    (bnc#902632).

  - Delete patches.rpmify/chipidea-clean-up-dependencies
    (bnc#903986).

  - Disable Exynos cpufreq modules.

  - drivers/net/fddi/skfp/h/skfbi.h: Remove useless
    PCI_BASE_2ND macros (bnc#902632).

  - drm/i915: Keep vblank interrupts enabled while
    enabling/disabling planes (bnc#904097).

  - drm: Implement O_NONBLOCK support on /dev/dri/cardN
    (bnc#904097).

  - drm/nv50/disp: fix dpms regression on certain boards
    (bnc#902728).

  - drm/radeon: add locking around atombios scratch space
    usage (bnc#904932).

  - drm/radeon: add missing crtc unlock when setting up the
    MC (bnc#904932).

  - drm/radeon/dpm: disable ulv support on SI (bnc#904932).

  - drm/radeon: fix endian swapping in vbios fetch for tdp
    table (bnc#904932).

  - drm/radeon: fix speaker allocation setup (bnc#904932).

  - drm/radeon: initialize sadb to NULL in the audio code
    (bnc#904932).

  - drm/radeon: make sure mode init is complete in
    bandwidth_update (bnc#904932).

  - drm/radeon: report disconnected for LVDS/eDP with PX if
    ddc fails (bnc#904417).

  - drm/radeon: set correct CE ram size for CIK
    (bnc#904932).

  - drm/radeon: Use drm_malloc_ab instead of kmalloc_array
    (bnc#904932).

  - drm/radeon: use gart for DMA IB tests (bnc#904932).

  - drm/radeon: use gart memory for DMA ring tests
    (bnc#904932).

  - drm/tilcdc: Fix the error path in tilcdc_load()
    (bko#86071).

  - hp_accel: Add support for HP ZBook 15 (bnc#905329).

  - ideapad-laptop: Change Lenovo Yoga 2 series rfkill
    handling (bnc#904289).

  - Input: i8042 - also set the firmware id for MUXed ports
    (bnc#897112).

  - Input: psmouse - add psmouse_matches_pnp_id helper
    function (bnc#897112).

  - Input: psmouse - add support for detecting FocalTech
    PS/2 touchpads (bnc#897112).

  - Input: synaptics - add min/max quirk for Lenovo T440s
    (bnc#903748).

  - irqchip: gic: preserve gic V2 bypass bits in cpu ctrl
    register (bnc#902632).

  - iwlwifi: dvm: drop non VO frames when flushing
    (bnc#900786).

  - KEYS: Allow special keys (eg. DNS results) to be
    invalidated by CAP_SYS_ADMIN (bnc#904717).

  - KEYS: Fix stale key registration at error path
    (bnc#908163).

  - KEYS: Fix the size of the key description passed to/from
    userspace (bnc#904717).

  - KEYS: Increase root_maxkeys and root_maxbytes sizes
    (bnc#904717).

  - KEYS: request_key() should reget expired keys rather
    than give EKEYEXPIRED (bnc#904717).

  - KEYS: Simplify KEYRING_SEARCH_{NO,DO}_STATE_CHECK flags
    (bnc#904717).

  - KVM: ARM: Add arm,gic-400 compatible support
    (bnc#902632).

  - KVM: ARM: Hack to enable VGIC mapping on 64k PAGE_SIZE
    kernels (bnc#902633).

  - Limit xgbe a0 driver to arm64

  - net/xgbe: Add A0 silicon support (bnc#902632).

  - of/pci: Add pci_get_new_domain_nr() and
    of_get_pci_domain_nr() (bnc#902632).

  - of/pci: Add pci_register_io_range() and
    pci_pio_to_address() (bnc#902632).

  - of/pci: Add support for parsing PCI host bridge
    resources from DT (bnc#902632).

  - of/pci: Fix the conversion of IO ranges into IO
    resources (bnc#902632).

  - of/pci: Move of_pci_range_to_resource() to of/address.c
    (bnc#902632).

  - parport: parport_pc, do not remove parent devices early
    (bnc#856659).

  - PCI: Add generic domain handling (bnc#902632).

  - PCI: Add pci_remap_iospace() to map bus I/O resources
    (bnc#902632).

  - PCI: xgene: Add APM X-Gene PCIe driver (bnc#902632).

  - power: reset: Add generic SYSCON register mapped reset
    (bnc#902632).

  - power: reset: Remove X-Gene reboot driver (bnc#902632).

  - quirk for Lenovo Yoga 3: no rfkill switch (bnc#904289).

  - reiserfs: destroy allocated commit workqueue.

  - rtc: ia64: allow other architectures to use EFI RTC
    (bnc#902632).

  - scripts/tags.sh: Do not specify kind-spec for emacs
    ctags/etags.

  - scripts/tags.sh: fix DEFINE_HASHTABLE in emacs case.

  - tags.sh: Fixup regex definition for etags.

  - ttusb-dec: buffer overflow in ioctl (bnc#905739).

  - usb: Add support for Synopsis H20AHB EHCI host
    controller (bnc#902632).

  - usb: fix hcd h20ahb driver depends (bnc#902632).

  - usb: uvc: add a quirk for Dell XPS M1330 webcam
    (bnc#904539).

  - usb: uvc: Fix destruction order in uvc_delete()
    (bnc#897736)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=665315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=856659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=897736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910251"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-macros-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-3.16.7-7.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-debugsource-3.16.7-7.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-3.16.7-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-xen-3.16.7-7.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-vanilla-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-syms-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.16.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-devel-3.16.7-7.1") ) flag++;

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
