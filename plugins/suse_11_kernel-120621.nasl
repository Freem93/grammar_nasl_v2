#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64176);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/10/28 10:42:46 $");

  script_cve_id("CVE-2011-4131", "CVE-2012-2119", "CVE-2012-2136", "CVE-2012-2373", "CVE-2012-2375", "CVE-2012-2390");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 6453 / 6457)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.34, fixing
a lot of bugs and security issues.

The update from Linux kernel 3.0.31 to 3.0.34 also fixes various bugs
not listed here.

The following security issues have been fixed :

  - Local attackers could trigger an overflow in
    sock_alloc_send_pksb(), potentially crashing the machine
    or escalate privileges. (CVE-2012-2136)

  - A memory leak in transparent hugepages on mmap failure
    could be used by local attacker to run the machine out
    of memory (local denial of service). (CVE-2012-2390)

  - A malicious guest driver could overflow the host stack
    by passing a long descriptor, so potentially crashing
    the host system or escalating privileges on the host.
    (CVE-2012-2119)

  - Malicious NFS server could crash the clients when more
    than 2 GETATTR bitmap words are returned in response to
    the FATTR4_ACL attribute requests, only incompletely
    fixed by CVE-2011-4131. (CVE-2012-2375)

The following non-security bugs have been fixed :

Hyper-V :

  - storvsc: Properly handle errors from the host.
    (bnc#747404)

  - HID: hid-hyperv: Do not use hid_parse_report() directly.

  - HID: hyperv: Set the hid drvdata correctly.

  - drivers/hv: Get rid of an unnecessary check in
    vmbus_prep_negotiate_resp().

  - drivers/hv: util: Properly handle version negotiations.

  - hv: fix return type of hv_post_message().

  - net/hyperv: Add flow control based on hi/low watermark.

  - usb/net: rndis: break out <1/rndis.h> defines. only
    net/hyperv part

  - usb/net: rndis: remove ambiguous status codes. only
    net/hyperv part

  - usb/net: rndis: merge command codes. only net/hyperv
    part

  - net/hyperv: Adding cancellation to ensure rndis filter
    is closed.

  - update hv drivers to 3.4-rc1, requires new 
hv_kvp_daemon :

  - drivers: hv: kvp: Add/cleanup connector defines.

  - drivers: hv: kvp: Move the contents of hv_kvp.h to
    hyperv.h.

  - net/hyperv: Convert camel cased variables in
    rndis_filter.c to lower cases.

  - net/hyperv: Correct the assignment in
    netvsc_recv_callback().

  - net/hyperv: Remove the unnecessary memset in
    rndis_filter_send().

  - drivers: hv: Cleanup the kvp related state in hyperv.h.

  - tools: hv: Use hyperv.h to get the KVP definitions.

  - drivers: hv: kvp: Cleanup the kernel/user protocol.

  - drivers: hv: Increase the number of VCPUs supported in
    the guest.

  - net/hyperv: Fix data corruption in
    rndis_filter_receive().

  - net/hyperv: Add support for vlan trunking from guests.

  - Drivers: hv: Add new message types to enhance KVP.

  - Drivers: hv: Support the newly introduced KVP messages
    in the driver.

  - Tools: hv: Fully support the new KVP verbs in the user
    level daemon.

  - Tools: hv: Support enumeration from all the pools.

  - net/hyperv: Fix the code handling tx busy.

  - patches.suse/suse-hv-pata_piix-ignore-disks.patch
    replace our version of this patch with upstream variant:
    ata_piix: defer disks to the Hyper-V drivers by default
    libata: add a host flag to ignore detected ATA devices.

Btrfs :

  - btrfs: more module message prefixes.

  - vfs: re-implement writeback_inodes_sb(_nr)_if_idle() and
    rename them

  - btrfs: flush all the dirty pages if
    try_to_writeback_inodes_sb_nr() fails

  - vfs: re-implement writeback_inodes_sb(_nr)_if_idle() and
    rename them

  - btrfs: fix locking in btrfs_destroy_delayed_refs

  - btrfs: wake up transaction waiters when aborting a
    transaction

  - btrfs: abort the transaction if the commit fails

  - btrfs: fix btrfs_destroy_marked_extents

  - btrfs: unlock everything properly in the error case for
    nocow

  - btrfs: fix return code in drop_objectid_items

  - btrfs: check to see if the inode is in the log before
    fsyncing

  - btrfs: pass locked_page into
    extent_clear_unlock_delalloc if theres an error

  - btrfs: check the return code of btrfs_save_ino_cache

  - btrfs: do not update atime for RO snapshots
    (FATE#306586).

  - btrfs: convert the inode bit field to use the actual bit
    operations

  - btrfs: fix deadlock when the process of delayed refs
    fails

  - btrfs: stop defrag the files automatically when doin
    readonly remount or umount

  - btrfs: avoid memory leak of extent state in error
    handling routine

  - btrfs: make sure that we have made everything in pinned
    tree clean

  - btrfs: destroy the items of the delayed inodes in error
    handling routine

  - btrfs: ulist realloc bugfix

  - btrfs: bugfix in btrfs_find_parent_nodes

  - btrfs: bugfix: ignore the wrong key for indirect tree
    block backrefs

  - btrfs: avoid buffer overrun in btrfs_printk

  - btrfs: fall back to non-inline if we do not have enough
    space

  - btrfs: NUL-terminate path buffer in DEV_INFO ioctl
    result

  - btrfs: avoid buffer overrun in mount option handling

  - btrfs: do not do balance in readonly mode

  - btrfs: fix the same inode id problem when doing auto
    defragment

  - btrfs: fix wrong error returned by adding a device

  - btrfs: use fastpath in extent state ops as much as
    possible Misc :

  - tcp: drop SYN+FIN messages. (bnc#765102)

  - mm: avoid swapping out with swappiness==0 (swappiness).

  - thp: avoid atomic64_read in pmd_read_atomic for 32bit
    PAE. (bnc#762991)

  - paravirt: Split paravirt MMU ops (bnc#556135,
    bnc#754690, FATE#306453).

  - paravirt: Only export pv_mmu_ops symbol if PARAVIRT_MMU

  - parvirt: Stub support KABI for KVM_MMU (bnc#556135,
    bnc#754690, FATE#306453).

  - tmpfs: implement NUMA node interleaving. (bnc#764209)

  - synaptics-hp-clickpad: Fix the detection of LED on the
    recent HP laptops. (bnc#765524)

  - supported.conf: mark xt_AUDIT as supported. (bnc#765253)

  - mm: pmd_read_atomic: fix 32bit PAE pmd walk vs
    pmd_populate SMP race condition. (bnc#762991 /
    CVE-2012-2373)

  - xhci: Do not free endpoints in xhci_mem_cleanup().
    (bnc#763307)

  - xhci: Fix invalid loop check in xhci_free_tt_info().
    (bnc#763307)

  - drm: Skip too big EDID extensions. (bnc#764900)

  - drm/i915: Add HP EliteBook to LVDS-temporary-disable
    list. (bnc#763717)

  - hwmon: (fam15h_power) Increase output resolution.
    (bnc#759336)

  - hwmon: (k10temp) Add support for AMD Trinity CPUs.
    (bnc#759336)

  - rpm/kernel-binary.spec.in: Own the right -kdump initrd.
    (bnc#764500)

  - memcg: prevent from OOM with too many dirty pages.

  - dasd: re-prioritize partition detection message
    (bnc#764091,LTC#81617).

  - kernel: pfault task state race (bnc#764091,LTC#81724).

  - kernel: clear page table for sw large page emulation
    (bnc#764091,LTC#81933).

  - USB: fix bug of device descriptor got from superspeed
    device. (bnc#761087)

  - xfrm: take net hdr len into account for esp payload size
    calculation. (bnc#759545)

  - st: clean up dev cleanup in st_probe. (bnc#760806)

  - st: clean up device file creation and removal.
    (bnc#760806)

  - st: get rid of scsi_tapes array. (bnc#760806)

  - st: raise device limit. (bnc#760806)

  - st: Use static class attributes. (bnc#760806)

  - mm: Optimize put_mems_allowed() usage (VM performance).

  - cifs: fix oops while traversing open file list (try #4).
    (bnc#756050)

  - scsi: Fix dm-multipath starvation when scsi host is
    busy. (bnc#763485)

  - dasd: process all requests in the device tasklet.
    (bnc#763267)

  - rt2x00:Add RT539b chipset support. (bnc#760237)

  - kabi/severities: Ignore changes in
    drivers/net/wireless/rt2x00, these are just exports used
    among the rt2x00 modules.

  - rt2800: radio 3xxx: reprogram only lower bits of RF_R3.
    (bnc#759805)

  - rt2800: radio 3xxx: program RF_R1 during channel switch.
    (bnc#759805)

  - rt2800: radio 3xxxx: channel switch RX/TX calibration
    fixes. (bnc#759805)

  - rt2x00: Avoid unnecessary uncached. (bnc#759805)

  - rt2x00: Introduce sta_add/remove callbacks. (bnc#759805)

  - rt2x00: Add WCID to crypto struct. (bnc#759805)

  - rt2x00: Add WCID to HT TX descriptor. (bnc#759805)

  - rt2x00: Move bssidx calculation into its own function.
    (bnc#759805)

  - rt2x00: Make use of sta_add/remove callbacks in rt2800.
    (bnc#759805)

  - rt2x00: Forbid aggregation for STAs not programmed into
    the hw. (bnc#759805)

  - rt2x00: handle spurious pci interrupts. (bnc#759805)

  - rt2800: disable DMA after firmware load.

  - rt2800: radio 3xxx: add channel switch calibration
    routines. (bnc#759805)

  - rpm/kernel-binary.spec.in: Obsolete ath3k, as it is now
    in the tree.

  - floppy: remove floppy-specific O_EXCL handling.
    (bnc#757315)

  - floppy: convert to delayed work and single-thread wq.
    (bnc#761245)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=735909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2119.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2373.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2390.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 6453 / 6457 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-default-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-source-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-devel-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-source-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-syms-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-trace-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-trace-base-3.0.34-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-trace-devel-3.0.34-0.7.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
