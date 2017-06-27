#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59125);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-3104", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-4308", "CVE-2007-4573", "CVE-2007-4997", "CVE-2007-5904", "CVE-2007-6063");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 4745)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - The sysfs_readdir function in the Linux kernel 2.6
    allows local users to cause a denial of service (kernel
    OOPS) by dereferencing a NULL pointer to an inode in a
    dentry. (CVE-2007-3104)

  - A 2 byte buffer underflow in the ieee80211 stack was
    fixed, which might be used by attackers in the local
    WLAN reach to crash the machine. (CVE-2007-4997)

  - The CIFS filesystem, when Unix extension support is
    enabled, did not honor the umask of a process, which
    allowed local users to gain privileges. (CVE-2007-3740)

  - It was possible for local user to become root by
    exploiting a bug in the IA32 system call emulation. This
    problem affects the x86_64 platform only, on all
    distributions. (CVE-2007-4573)

    This problem was fixed for regular kernels, but had not
    been fixed for the XEN kernels. This update fixes the
    problem also for the XEN kernels.

  - The (1) aac_cfg_open and (2) aac_compat_ioctl functions
    in the SCSI layer ioctl path in aacraid did not check
    permissions for ioctls, which might have allowed local
    users to cause a denial of service or gain privileges.
    (CVE-2007-4308)

  - The Linux kernel checked the wrong global variable for
    the CIFS sec mount option, which might allow remote
    attackers to spoof CIFS network traffic that the client
    configured for security signatures, as demonstrated by
    lack of signing despite sec=ntlmv2i in a SetupAndX
    request. (CVE-2007-3843)

  - Multiple buffer overflows in CIFS VFS in the Linux
    kernel allowed remote attackers to cause a denial of
    service (crash) and possibly execute arbitrary code via
    long SMB responses that trigger the overflows in the
    SendReceive function. (CVE-2007-5904)

    This requires the attacker to mis-present / replace a
    CIFS server the client machine is connected to.

  - Buffer overflow in the isdn_net_setcfg function in
    isdn_net.c in the Linux kernel allowed local users to
    have an unknown impact via a crafted argument to the
    isdn_ioctl function. (CVE-2007-6063)

and the following non security bugs :

-

patches.drivers/pci-delete-ACPI-hook-from-pci_set_power_stat e.patch:
Delete ACPI hook from pci_set_power_state() [#162320] Still execute
the code on Lenovo ThinkPads (or USB ports do not work anymore after
suspend [#329232]

  - patches.drivers/alsa-post-sp1-hda-probe-blacklist:
    [ALSA] hda-intel - Add probe_mask blacklist [#172330]

  - patches.drivers/alsa-post-sp1-hda-robust-probe: [ALSA]
    hda-intel - Improve HD-audio codec probing robustness
    [#172330]

  - patches.arch/i386-hpet-lost-interrupts-fix.patch:
    Backport i386 hpet lost interrupts code [#257035]

  - patches.fixes/megaraid_mbox-dell-cerc-support: Dell CERC
    support for megaraid_mbox [#267134]

  - patches.fixes/nfsv4-MAXNAME-fix.diff: knfsd: query
    filesystem for NFSv4 getattr of FATTR4_MAXNAME [#271803]
    -

patches.drivers/ide-amd74xx-add-ignore_enablebits-parameter: amd74xx:
add ignore_enable_bits module parameter [#272786]

  - patches.fixes/legacy-pty-count-kernel-parm.patch: Add a
    kernel boot parameter to overwrite the legacy PTY count.
    The default value of 64 is insufficient occasionally
    [#277846]

  - patches.fixes/lockd-grant-shutdown: Stop GRANT callback
    from crashing if NFS server has been stopped. [#292478]

  - Kernel update to 2.6.16.54 [#298719] including (among
    others) :

  - lots of md fixes

  - fix of sparc bugs

  - fix of TCP handling of SACK in bidirectional flows

  - fix of MCA bus matching

  - fix of PPC issues :

  - Fix osize too small errors when decoding mppe.

  - Fix output buffer size in ppp_decompress_frame(). -

patches.fixes/assign-task_struct.exit_code-before-taskstats_
exit.patch: Assign task_struct.exit_code before taskstats_exit()
[#307504]

  - patches.fixes/bonding_no_addrconf_for_bond_slaves:
    bonding / ipv6: no addrconf for slaves separately from
    master. [#310254]

  - patches.fixes/bonding_support_carrier_state_for_master:
    bonding: support carrier state for master [#310254] -

patches.fixes/fix-sys-devices-system-node-node0-meminfo-from

-having-anonpages-wrapped.patch: fix
/sys/devices/system/node/node0/meminfo from having anonpages wrapped
[#310744] -

patches.fixes/nfs-remove-bogus-cache-change-attribute-check. diff fix
bogus cache change to make data available immediately, on direct write
[#325877] -

patches.fixes/tcp-send-ACKs-each-2nd-received-segment.patch: Send ACKs
each 2nd received segment. This fixes a problem where the tcp cubic
congestion algorithm was too slow in converging [#327848]

  - patches.drivers/libata-fix-spindown: libata: fix disk
    spindown on shutdown [#330722]

  - patches.fixes/scsi-reset-resid: busy status on tape
    write results in incorrect residual [#330926]

  - patches.fixes/condense-output-of-show_free_areas.patch:
    Condense output of show_free_areas() [#331251]

  - patches.arch/powernowk8_family_freq_from_fiddid.patch:
    To find the frequency given the fid and did is family
    dependent. [#332722]

  - patches.fixes/tcp-saner-thash_entries-default.patch:
    Limit the size of the TCP established hash to 512k
    entries by default [#333273]

  - patches.drivers/alsa-emu10k1-spdif-mem-fix: [ALSA]
    emu10k1 - Fix memory corruption [#333314]

  - patches.drivers/alsa-post-sp1-hda-stac-error-fix: [ALSA]
    Fix error probing with STAC codecs [#333320] -

    patches.fixes/qla2xxx-avoid-duplicate-pci_disable_device
    : Fixup patch to not refer to stale pointer [#333542]

  - large backport of dm-crypt fixes: [#333905]

  - patches.fixes/dm-disable_barriers.diff: dm: disable
    barriers. -

patches.fixes/dm-crypt-restructure_for_workqueue_change.diff -

patches.fixes/dm-crypt-restructure_write_processing.diff

  - patches.fixes/dm-crypt-move_io_to_workqueue.diff

  - patches.fixes/dm-crypt-use_private_biosets.diff

  - patches.fixes/dm-crypt-fix_call_to_clone_init.diff -

patches.fixes/dm-crypt-fix_avoid_cloned_bio_ref_after_free.d iff

  - patches.fixes/dm-crypt-fix_remove_first_clone.diff -

patches.fixes/dm-crypt-use_smaller_bvecs_in_clones.diff -

patches.fixes/dm-crypt-fix_panic_on_large_request.diff

  - patches.fixes/initramfs-fix-cpio-hardlink-check.patch:
    initramfs: fix CPIO hardlink check [#334612]

  - patches.drivers/lpfc-8.1.10.12-update: driver update to
    fix severe issues in lpfc 8.1.10.9 driver [#334630]
    [#342044]

  - patches.fixes/nfs-direct-io-fix-1: NFS: Fix error
    handling in nfs_direct_write_result() [#336200]

  - patches.fixes/nfs-direct-io-fix-2: NFS: Fix a refcount
    leakage in O_DIRECT [#336200]

  - add patches.drivers/ibmvscsi-migration-login.patch
    prohibit IO during adapter login process [#337980]

  - patches.arch/acpi_thinkpad_brightness_fix.patch: Take
    care of latest Lenovo ThinkPad brightness control
    [#338274] [#343660]

  - patches.fixes/ramdisk-2.6.23-corruption_fix.diff: rd:
    fix data corruption on memory pressure [#338643] -

    patches.fixes/fc_transport-remove-targets-on-host-remove
    : memory use after free error in mptfc [#338730] -

patches.fixes/ipmi-ipmi_msghandler.c-fix-a-memory-leak.patch : IPMI:
ipmi_msghandler.c: fix a memory leak [#339413]

  - add patches.arch/ppc-pseries-rtas_ibm_suspend_me.patch
    fix multiple bugs in rtas_ibm_suspend_me code [#339927]

  - patches.fixes/nfsacl-retval.diff: knfsd: fix spurious
    EINVAL errors on first access of new filesystem
    [#340873]

  - patches.fixes/avm-fix-capilib-locking: [ISDN] Fix random
    hard freeze with AVM cards. [#341894]

  - patches.fixes/ipv6_rh_processing_fix: [IPV6]: Restore
    semantics of Routing Header processing [#343100]

  - The following set of XEN fixes has been applied:
    [#343612]

  - patches.xen/14280-net-fake-carrier-flag.patch: netfront:
    Better fix for netfront_tx_slot_available().

  - patches.xen/14893-copy-more-skbs.patch: netback: Copy
    skbuffs that are presented to the start_xmit() function.

  - patches.xen/157-netfront-skb-deref.patch: net front:
    Avoid deref'ing skb after it is potentially freed.

  - patches.xen/263-xfs-unmap.patch: xfs: eagerly remove
    vmap mappings to avoid upsetting Xen.

  - patches.xen/xen-i386-set-fixmap: i386/PAE: avoid
    temporarily inconsistent pte-s.

  - patches.xen/xen-isa-dma: Suppress all use of ISA DMA on
    Xen.

  - patches.xen/xen-x86-panic-smp,

  - patches.xen/xen-netback-alloc,

  - patches.xen/xen-split-pt-lock,

  - patches.xen/137-netfront-copy-release.patch,

  - patches.xen/141-driver-autoload.patch,

  - patches.xen/xen-balloon-max-target,

  - patches.xen/xen-balloon-min,

  - patches.xen/xen-i386-highpte,

  - patches.xen/xen-intel-agp,

  - patches.xen/xen-multicall-check,

  - patches.xen/xen-x86-dcr-fallback,

  - patches.xen/xen-x86-pXX_val,

  - patches.xen/xen-x86-performance: Adjust.

  - patches.arch/acpi_backport_video.c.patch: Backport video
    driver from 2.6.23-rc9 [#343660]

  - patches.arch/acpi_find_bcl_support.patch: Store
    brightness/video functionality of ACPI provided by BIOS
    [#343660]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3740.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-3843.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4308.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4997.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-5904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-6063.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4745.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-smp-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-debug-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-kdump-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-smp-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.16.54-0.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.16.54-0.2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
