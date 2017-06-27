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
  script_id(64179);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2012-2745");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 6923 / 6926 / 6931)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.42 which
fixes various bugs and security issues.

The following security issues have been fixed :

  - A denial of service in key management was fixed. (This
    was fixed in 3.0.28 already, but is listed here.) Some
    more security and bug fixes might already be part of the
    3.0.42 stable kernel release which is included here.
    (CVE-2012-2745)

The following non security issues have been fixed :

BTRFS :

  - btrfs: allow setting NOCOW for a zero sized file via
    ioctl

  - btrfs: fix a bug of per-file nocow

  - btrfs: fix the missing error information in
    create_pending_snapshot()

  - btrfs: fix off-by-one in file clone

  - btrfs: move transaction aborts to the point of failure

  - btrfs: fix unnecessary warning when the fragments make
    the space alloc fail

  - btrfs: return EPERM upon rmdir on a subvolume

  - btrfs: cleanup for duplicated code in find_free_extent

  - btrfs: cleanup fs_info->hashers

  - btrfs: use vfree instead of kfree

  - btrfs: fix error path in create_pending_snapshot()

  - btrfs: fix file extent discount problem in the, snapshot

  - btrfs: fix full backref problem when inserting shared
    block reference

  - btrfs: fix wrong size for the reservation of the,
    snapshot creation

  - btrfs: fix error handling in delete_block_group_cache()

  - btrfs: polish names of kmem caches

  - btrfs: update last trans if we do not update the inode

  - btrfs: fix possible corruption when fsyncing written
    prealloced extents

  - btrfs: set journal_info in async trans commit worker

  - btrfs: fix a bug in parsing return value in logical
    resolve

  - btrfs: use helper for logical resolve

  - btrfs: use larger limit for translation of logical to
    inode

  - btrfs: use a slab for ordered extents allocation

  - btrfs: fix unprotected ->log_batch

  - btrfs: output more information when aborting a unused
    transaction handle

  - btrfs: fix wrong size for the reservation when doing,
    file pre-allocation

  - btrfs: cleanup for unused ref cache stuff

  - btrfs: fix a misplaced address operator in a condition

  - btrfs: fix that error value is changed by mistake

  - btrfs: fix second lock in btrfs_delete_delayed_items()

  - btrfs: increase the size of the free space cache

  - btrfs: fix enospc problems when deleting a subvol

  - btrfs: fix wrong mtime and ctime when creating snapshots

  - btrfs: fix race in run_clustered_refs S/390 :

  - zfcp: remove invalid reference to list iterator
    variable. (bnc#779461)

  - zfcp: Make trace record tags unique
    (bnc#780012,LTC#84941).

  - zfcp: Do not wakeup while suspended
    (bnc#780012,LTC#84816).

  - zfcp: restore refcount check on port_remove
    (bnc#780012,LTC#84942).

  - zfcp: No automatic port_rescan on events
    (bnc#780012,LTC#84817).

  - dasd: System hang after all channel were lost
    (bnc#780012,LTC#85025).

  - Added patches.arch/s390-54-01-hypfs-missing-files.patch
    to series.conf. (bnc#769407)

  - dasd: set and unset TIMEOUT flag automatically.
    (bnc#768084)

  - kernel: incorrect task size after fork of a 31 bit
    process (bnc#772407,LTC#83674).

  - patches.arch/s390-55-03-crst-table-downgrade.patch:
    Deleted due to 31bit compile error. ALSA :

  - ALSA: hda - Add mic-mute LED control for HP laptop.
    (bnc#779330)

  - ALSA: hda - Add 3stack-automute model to AD1882 codec
    (bnc#775373). Wireless :

  - rt2x00: Remove incorrect led blink. (bnc#774902)

  - Revert 'rt2x00: handle spurious pci interrupts'.
    (bnc#774902)

  - rt2x00: Mark active channels survey data as 'in use'.
    (bnc#774902)

  - rt2x00: Convert big if-statements to switch-statements.
    (bnc#774902)

  - rt2800: zero MAC_SYS_CTRL bits during BBP and MAC reset.
    (bnc#774902)

  - rt2800lib: fix wrong -128dBm when signal is stronger
    than -12dBm. (bnc#774902)

  - rt2800: document RF_R03 register bits [7:4].
    (bnc#774902)

  - rt2x00: Introduce concept of driver data in struct
    rt2x00_dev. (bnc#774902)

  - rt2x00: Use struct rt2x00_dev driver data in
    rt2800{pci,usb}. (bnc#774902)

  - rt2x00: fix a possible NULL pointer dereference.
    (bnc#774902)

  - rt2x00:Add VCO recalibration. (bnc#774902)

  - rt2x00:Add RT5372 chipset support. (bnc#774902)

  - rt2x00: Set IEEE80211_HW_REPORTS_TX_ACK_STATUS in
    rt2800. (bnc#774902)

  - rt2800: introduce wpdma_disable function. (bnc#774902)

  - rt2800: initialize queues before giving up due to DMA
    error. (bnc#774902)

  - rt2800: zero registers of unused TX rings. (bnc#774902)

  - wireless: rt2x00: rt2800pci add more RT539x ids.
    (bnc#774902)

  - rt2x00:Add RT5392 chipset support. (bnc#774902)

  -
    patches.fixes/0012-rt2x00-Add-RT5372-chipset-support.pat
    ch: Fix typo.

  - rt2800: Add documentation on MCU requests. (bnc#744198)

  - rt2800pci: Fix 'Error - MCU request failed' during
    initialization. (bnc#744198) Packaging :

  - rpm/kernel-binary.spec.in: Temporarily disable icecream
    builds until miscompilation is resolved. (bnc#763954 /
    bnc#773831)

  - rpm/kernel-binary.spec.in: add Conflicts for older
    hyper-v hv_kvp_daemon (bnc#770763) the kernel-user
    interface changed, old binaries will busyloop with newer
    kernel

  - rpm/kernel-binary.spec.in: Do not run debugedit -i, use
    eu-unstrip to retrieve the build-id instead.
    (bnc#768504)

  - rpm/kernel-binary.spec.in: Fix Obsoletes: tag for the
    SLE11-SP1 realtek-r8192ce_pci-kmp package. Misc

  - patches.suse/no-partition-scan: Implement
    'no_partition_scan' commandline option (FATE#303697).

  - vfs: dcache: use DCACHE_DENTRY_KILLED instead of
    DCACHE_DISCONNECTED in d_kill(). (bnc#779699)

  - igb: convert to ndo_fix_features. (bnc#777269)

  - igb: do vlan cleanup. (bnc#777269)

  - tcp: flush DMA queue before sk_wait_data if rcv_wnd is
    zero. (bnc#777024)

  - drm: Export drm_probe_ddc(). (bnc#780461)

  - drm/dp: Update DPCD defines. (bnc#780461)

  - drm/i915/dp: Be smarter about connection sense for
    branch devices. (bnc#780461)

  - drm/i915/dp: Fetch downstream port info if needed during
    DPCD fetch. (bnc#780461)

  - md: fix so that GET_ARRAY_INFO and GET_DISK_INFO fail
    correctly when array has not 'raid_disks' count yet.

  - sched: Fix ancient race in do_exit(). (bnc#781018)

  - sched: fix divide by zero in thread_group/task_times().
    (bnc#761774)

  - sched: fix migration thread runtime bogosity.
    (bnc#773688, bnc#769251)

  - megaraid_sas: boot hangs up while LD is offline issue.
    (bnc#698102)

  - memcg: warn on deeper hierarchies with use_hierarchy==0.
    (bnc#781134)

  - scsi_dh_alua: Retry the check-condition in case Mode
    Parameters Changed. (bnc#772473)

  - scsi: update scsi.h with SYNCHRONIZE_CACHE_16
    (FATE#313550,bnc#769195).

  - sd: Reshuffle init_sd to avoid crash. (bnc#776787)

  - st: remove st_mutex. (bnc#773007)

  - cifs: Assume passwords are encoded according to
    iocharset (try #2). (bnc#731035)

  - drm/fb-helper: delay hotplug handling when partially
    bound. (bnc#778822)

  - drm/fb helper: do not call drm_crtc_helper_set_config.
    (bnc#778822)

  - patches.drivers/drm-Skip-too-big-EDID-extensions:
    Delete. Fixed in firmware, so no longer needed.
    (bnc#764900)

  - drm/i915: Fix backlight control for systems which have
    bl polarity reversed. (bnc#766156)

  - patches.kernel.org/patch-3.0.27-28: Update references.
    (bnc#770695 / CVE-2012-2745)

  - xen/x86-64: fix hypercall page unwind info.

  - patches.xen/xen3-patch-3.0.40-41: Linux 3.0.41.

  - Refresh other Xen patches. (bnc#776019)

  - e1000e: clear REQ and GNT in EECD (82571 &amp;&amp;
    82572). (bnc#762099)

  - bonding: add some slack to arp monitoring time limits.
    (bnc#776095)

  - patches.arch/x2apic_opt_out.patch: Refresh. (bnc#778082)

  - x86, mce: Do not call del_timer_sync() in IRQ context.
    (bnc#776896)

  - cpufreq / ACPI: Fix not loading acpi-cpufreq driver
    regression. (bnc#766654)

  - ida: Update references. (bnc#740291)

  - audit: do not free_chunk() after fsnotify_add_mark().
    (bnc#762214)

  - audit: fix refcounting in audit-tree. (bnc#762214)

  - mlx4_en: map entire pages to increase throughput.

  - usb: Add support for root hub port status CAS.
    (bnc#774289)

  - fs,reiserfs: unlock superblock before calling
    reiserfs_quota_on_mount(). (bnc#772786)

  - reiserfs: fix deadlock with nfs racing on create/lookup.
    (bnc#762693)

  - NFS: Slow down state manager after an unhandled error.
    (bnc#774973)

  - nfs: increase number of permitted callback connections.
    (bnc#771706)

  - Freezer / sunrpc / NFS: do not allow TASK_KILLABLE
    sleeps to block the freezer. (bnc#775182)

  - powerpc/pseries: Support lower minimum entitlement for
    virtual processors. (bnc#775984)

  - powerpc: Disable /dev/port interface on systems without
    an ISA bridge. (bnc#754670)

  - ocfs2: Add a missing journal credit in
    ocfs2_link_credits() -v2. (bnc#773320)

  - block: do not artificially constrain max_sectors for
    stacking drivers. (bnc#774073)

  - bnx2x: Clear MDC/MDIO warning message. (bnc#769035)

  - bnx2x: Fix BCM57810-KR AN speed transition. (bnc#769035)

  - bnx2x: Fix BCM57810-KR FC. (bnc#769035)

  - bnx2x: Fix BCM578x0-SFI pre-emphasis settings.
    (bnc#769035)

  - bnx2x: Fix link issue for BCM8727 boards. (bnc#769035)

  - bnx2x: PFC fix. (bnc#769035)

  - bnx2x: fix checksum validation. (bnc#769035)

  - bnx2x: fix panic when TX ring is full. (bnc#769035)

  - bnx2x: previous driver unload revised. (bnc#769035)

  - bnx2x: remove WARN_ON. (bnc#769035)

  - bnx2x: update driver version. (bnc#769035)

  - xhci: Fix a logical vs bitwise AND bug. (bnc#772427)

  - xhci: Switch PPT ports to EHCI on shutdown. (bnc#772427)

  - xhci: definitions of register definitions to preserve
    kABI. (bnc#772427)

  - xhci: Introduce a private switchback method to preserve
    kABI. (bnc#772427)

  - config.conf: Drop reference to a s390 vanilla config
    that does not exist.

  - block: eliminate potential for infinite loop in
    blkdev_issue_discard. (bnc#773319)

  - Fix cosmetic (but worrisome to users) stop class
    accounting bug.

  - bluetooth: Another vendor specific ID for BCM20702A0
    [0a5c:21f1]. (bnc#774612)

  - memcg: further prevent OOM with too many dirty pages.
    (bnc#763198)

  -
    patches.fixes/mm-consider-PageReclaim-for-sync-reclaim.p
    atch: Refresh to match the upstream version.

  - tmpfs: optimize clearing when writing (VM Performance).

  - tmpfs: distribute interleave better across nodes.
    (bnc#764209)

  -
    patches.fixes/tmpfs-implement-NUMA-node-interleaving.pat
    ch: dropped in favor of the upstream patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=753617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2745.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 6923 / 6926 / 6931 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.42-0.7.3")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.42-0.7.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
