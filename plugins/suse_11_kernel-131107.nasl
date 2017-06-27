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
  script_id(71034);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/20 15:05:37 $");

  script_cve_id("CVE-2013-2206");

  script_name(english:"SuSE 11.3 Security Update : Linux kernel (SAT Patch Numbers 8524 / 8525 / 8528)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to
version 3.0.101 and also includes various other bug and security
fixes.

The following features have been added :

  - Drivers: hv: Support handling multiple VMBUS versions
    (FATE#314665).

  - Drivers: hv: Save and export negotiated vmbus version
    (FATE#314665).

  - Drivers: hv: Move vmbus version definitions to hyperv.h
    (FATE#314665). The following security issue has been
    fixed :

  - The sctp_sf_do_5_2_4_dupcook function in
    net/sctp/sm_statefuns.c in the SCTP implementation in
    the Linux kernel did not properly handle associations
    during the processing of a duplicate COOKIE ECHO chunk,
    which allowed remote attackers to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact via crafted SCTP
    traffic. (bnc#826102). (CVE-2013-2206)

The following non-security bugs have been fixed :

  - mm, memcg: introduce own oom handler to iterate only
    over its own threads.

  - mm, memcg: move all oom handling to memcontrol.c.

  - mm, oom: avoid looping when chosen thread detaches its
    mm.

  - mm, oom: fold oom_kill_task() into oom_kill_process().

  - mm, oom: introduce helper function to process threads
    during scan.

  - mm, oom: reduce dependency on tasklist_lock (Reduce
    tasklist_lock hold times). (bnc#821259)

  - mm: do not walk all of system memory during show_mem
    (Reduce tasklist_lock hold times). (bnc#821259)

  - iommu/vt-d: add quirk for broken interrupt remapping on
    55XX chipsets. (bnc#844513)

  - x86/iommu/vt-d: Expand interrupt remapping quirk to
    cover x58 chipset. (bnc#844513)

  - iommu/vt-d: Only warn about broken interrupt remapping.
    (bnc#844513)

  - iommu: Remove stack trace from broken irq remapping
    warning. (bnc#844513)

  - intel-iommu: Fix leaks in pagetable freeing.
    (bnc#841402)

  - Revert aer_recover_queue() __GENKSYMS__ hack, add a fake
    symset with the previous value instead. (bnc#847721)

  - i2c: ismt: initialize DMA buffer. (bnc#843753)

  - powerpc/irq: Run softirqs off the top of the irq stack.
    (bnc#847319)

  - quirks: add touchscreen that is dazzeled by remote
    wakeup. (bnc#835930)

  - kernel: sclp console hangs (bnc#841498, LTC#95711).

  - tty/hvc_iucv: Disconnect IUCV connection when lowering
    DTR (bnc#839973,LTC#97595).

  - tty/hvc_console: Add DTR/RTS callback to handle HUPCL
    control (bnc#839973,LTC#97595).

  - softirq: reduce latencies. (bnc#797526)

  - X.509: Remove certificate date checks. (bnc#841656)

  - config/debug: Enable FSCACHE_DEBUG and CACHEFILES_DEBUG.
    (bnc#837372)

  - splice: fix racy pipe->buffers uses. (bnc#827246)

  - blktrace: fix race with open trace files and directory
    removal. (bnc#832292)

  - rcu: Do not trigger false positive RCU stall detection.
    (bnc#834204)

  - kernel: allow program interruption filtering in user
    space (bnc#837596, LTC#97332).

  - Audit: do not print error when LSMs disabled.
    (bnc#842057)

  - SUNRPC: close a rare race in xs_tcp_setup_socket.
    (bnc#794824)

  - Btrfs: fix negative qgroup tracking from owner
    accounting. (bnc#821948)

  - cifs: fill TRANS2_QUERY_FILE_INFO ByteCount fields.
    (bnc#804950)

  - NFS: make nfs_flush_incompatible more generous.
    (bnc#816099)

  - xfs: growfs: use uncached buffers for new headers.
    (bnc#842604)

  - NFS: do not try to use lock state when we hold a
    delegation. (bnc#831029)

  - NFS: nfs_lookup_revalidate(): fix a leak. (bnc#828894)

  - fs: do_add_mount()/umount -l races. (bnc#836801)

  - xfs: avoid double-free in xfs_attr_node_addname.

  - xfs: Check the return value of xfs_buf_get().
    (bnc#842604)

  - iscsi: do not hang in endless loop if no targets
    present. (bnc#841094)

  - scsi_dh_alua: Allow get_alua_data() to return NULL.
    (bnc#839407)

  - cifs: revalidate directories instiantiated via FIND_ in
    order to handle DFS referrals. (bnc#831143)

  - cifs: do not instantiate new dentries in readdir for
    inodes that need to be revalidated immediately.
    (bnc#831143)

  - cifs: rename cifs_readdir_lookup to cifs_prime_dcache
    and make it void return. (bnc#831143)

  - cifs: get rid of blind d_drop() in readdir. (bnc#831143)

  - cifs: cleanup cifs_filldir. (bnc#831143)

  - cifs: on send failure, readjust server sequence number
    downward. (bnc#827966)

  - cifs: adjust sequence number downward after signing
    NT_CANCEL request. (bnc#827966)

  - cifs: on send failure, readjust server sequence number
    downward. (bnc#827966)

  - cifs: adjust sequence number downward after signing
    NT_CANCEL request. (bnc#827966)

  - reiserfs: fix race with flush_used_journal_lists and
    flush_journal_list. (bnc#837803)

  - reiserfs: remove useless flush_old_journal_lists.

  - lib/radix-tree.c: make radix_tree_node_alloc() work
    correctly within interrupt. (bnc#763463)

  - md: Throttle number of pending write requests in
    md/raid10. (bnc#833858)

  - dm: ignore merge_bvec for snapshots when safe.
    (bnc#820848)

  - ata: Set proper SK when CK_COND is set. (bnc#833588)

  - Btrfs: abort unlink trans in missed error case.

  - Btrfs: add all ioctl checks before user change for quota
    operations.

  - Btrfs: add a rb_tree to improve performance of ulist
    search.

  - Btrfs: add btrfs_fs_incompat helper.

  - Btrfs: add ioctl to wait for qgroup rescan completion.

  - Btrfs: add log message stubs.

  - Btrfs: add missing error checks to add_data_references.

  - Btrfs: add missing error code to BTRFS_IOC_INO_LOOKUP
    handler.

  - Btrfs: add missing error handling to read_tree_block.

  - Btrfs: add missing mounting options in
    btrfs_show_options().

  - Btrfs: add sanity checks regarding to parsing mount
    options.

  - Btrfs: add some missing iput()s in btrfs_orphan_cleanup.

  - Btrfs: add tree block level sanity check.

  - Btrfs: allocate new chunks if the space is not enough
    for global rsv.

  - Btrfs: allow file data clone within a file.

  - Btrfs: allow superblock mismatch from older mkfs.

  - Btrfs: annotate quota tree for lockdep.

  - Btrfs: automatic rescan after 'quota enable' command
    (FATE#312751).

  - Btrfs: change how we queue blocks for backref checking.

  - Btrfs: check if leafs parent exists before pushing items
    around.

  - Btrfs: check if we can nocow if we do not have data
    space.

  - Btrfs: check return value of commit when recovering log.

  - Btrfs: clean snapshots one by one.

  - Btrfs: cleanup destroy_marked_extents.

  - Btrfs: cleanup fs roots if we fail to mount.

  - Btrfs: cleanup orphaned root orphan item.

  - Btrfs: cleanup reloc roots properly on error.

  - Btrfs: Cleanup some redundant codes in
    btrfs_lookup_csums_range().

  - Btrfs: clean up transaction abort messages.

  - Btrfs: cleanup unused arguments of btrfs_csum_data.

  - Btrfs: clear received_uuid field for new writable
    snapshots.

  - Btrfs: compare relevant parts of delayed tree refs.

  - Btrfs: cover more error codes in btrfs_decode_error.

  - Btrfs: creating the subvolume qgroup automatically when
    enabling quota.

  - Btrfs: deal with bad mappings in btrfs_map_block.

  - Btrfs: deal with errors in write_dev_supers.

  - Btrfs: deal with free space cache errors while replaying
    log.

  - Btrfs: deprecate subvolrootid mount option.

  - Btrfs: do away with non-whole_page extent I/O.

  - Btrfs: do delay iput in sync_fs.

  - Btrfs: do not clear our orphan item runtime flag on
    eexist.

  - Btrfs: do not continue if out of memory happens.

  - Btrfs: do not offset physical if we are compressed.

  - Btrfs: do not pin while under spin lock.

  - Btrfs: do not abort the current transaction if there is
    no enough space for inode cache.

  - Btrfs: do not allow a subvol to be deleted if it is the
    default subovl.

  - Btrfs: do not BUG_ON() in btrfs_num_copies.

  - Btrfs: do not bug_on when we fail when cleaning up
    transactions.

  - Btrfs: do not call readahead hook until we have read the
    entire eb.

  - Btrfs: do not delete fs_roots until after we cleanup the
    transaction.

  - Btrfs: dont do log_removal in insert_new_root.

  - Btrfs: do not force pages under writeback to finish when
    aborting.

  - Btrfs: do not ignore errors from
    btrfs_run_delayed_items.

  - Btrfs: do not invoke btrfs_invalidate_inodes() in the
    spin lock context.

  - Btrfs: do not miss inode ref items in
    BTRFS_IOC_INO_LOOKUP.

  - Btrfs: do not NULL pointer deref on abort.

  - Btrfs: do not panic if we are trying to drop too many
    refs.

  - Btrfs: do not steal the reserved space from the global
    reserve if their space type is different.

  - Btrfs: do not stop searching after encountering the
    wrong item.

  - Btrfs: do not try and free ebs twice in log replay.

  - Btrfs: do not use global block reservation for inode
    cache truncation.

  - Btrfs: do not wait on ordered extents if we have a trans
    open.

  - Btrfs: Drop inode if inode root is NULL.

  - Btrfs: enhance superblock checks.

  - Btrfs: exclude logged extents before replying when we
    are mixed.

  - Btrfs: explicitly use global_block_rsv for quota_tree.

  - Btrfs: fall back to global reservation when removing
    subvolumes.

  - Btrfs: fix a bug of snapshot-aware defrag to make it
    work on partial extents.

  - Btrfs: fix accessing a freed tree root.

  - Btrfs: fix accessing the root pointer in tree mod log
    functions.

  - Btrfs: fix all callers of read_tree_block.

  - Btrfs: fix a warning when disabling quota.

  - Btrfs: fix a warning when updating qgroup limit.

  - Btrfs: fix backref walking when we hit a compressed
    extent.

  - Btrfs: fix bad extent logging.

  - Btrfs: fix broken nocow after balance.

  - Btrfs: fix confusing edquot happening case.

  - Btrfs: fix double free in the iterate_extent_inodes().

  - Btrfs: fix error handling in btrfs_ioctl_send().

  - Btrfs: fix error handling in make/read block group.

  - Btrfs: fix estale with btrfs send.

  - Btrfs: fix extent buffer leak after backref walking.

  - Btrfs: fix extent logging with O_DIRECT into prealloc.

  - Btrfs: fix file truncation if FALLOC_FL_KEEP_SIZE is
    specified.

  - Btrfs: fix get set label blocking against balance.

  - Btrfs: fix infinite loop when we abort on mount.

  - Btrfs: fix inode leak on kmalloc failure in tree-log.c.

  - Btrfs: fix lockdep warning.

  - Btrfs: fix lock leak when resuming snapshot deletion.

  - Btrfs: fix memory leak of orphan block rsv.

  - Btrfs: fix missing check about ulist_add() in qgroup.c.

  - Btrfs: fix missing check before creating a qgroup
    relation.

  - Btrfs: fix missing check in the btrfs_qgroup_inherit().

  - Btrfs: fix off-by-one in fiemap.

  - Btrfs: fix oops when writing dirty qgroups to disk.

  - Btrfs: fix possible infinite loop in slow caching.

  - Btrfs: fix possible memory leak in replace_path().

  - Btrfs: fix possible memory leak in the
    find_parent_nodes().

  - Btrfs: fix printing of non NULL terminated string.

  - Btrfs: fix qgroup rescan resume on mount.

  - Btrfs: fix reada debug code compilation.

  - Btrfs: fix the error handling wrt orphan items.

  - Btrfs: fix transaction throttling for delayed refs.

  - Btrfs: fix tree mod log regression on root split
    operations.

  - Btrfs: fix unblocked autodefraggers when remount.

  - Btrfs: fix unlock after free on rewinded tree blocks.

  - Btrfs: fix unprotected root node of the subvolumes inode
    rb-tree.

  - Btrfs: fix use-after-free bug during umount.

  - Btrfs: free csums when we are done scrubbing an extent.

  - Btrfs: handle errors returned from get_tree_block_key.

  - Btrfs: handle errors when doing slow caching.

  - Btrfs: hold the tree mod lock in __tree_mod_log_rewind.

  - Btrfs: ignore device open failures in
    __btrfs_open_devices.

  - Btrfs: improve the loop of scrub_stripe.

  - Btrfs: improve the performance of the csums lookup.

  - Btrfs: init relocate extent_io_tree with a mapping.

  - Btrfs: introduce a mutex lock for btrfs quota
    operations.

  - Btrfs: kill some BUG_ONs() in the find_parent_nodes().

  - Btrfs: log ram bytes properly.

  - Btrfs: make __merge_refs() return type be void.

  - Btrfs: make orphan cleanup less verbose.

  - Btrfs: make static code static &amp; remove dead code.

  - Btrfs: make subvol creation/deletion killable in the
    early stages.

  - Btrfs: make sure roots are assigned before freeing their
    nodes.

  - Btrfs: make sure the backref walker catches all refs to
    our extent.

  - Btrfs: make the cleaner complete early when the fs is
    going to be umounted.

  - Btrfs: make the snap/subv deletion end more early when
    the fs is R/O.

  - Btrfs: merge save_error_info helpers into one.

  - Btrfs: move the R/O check out of
    btrfs_clean_one_deleted_snapshot().

  - Btrfs: only do the tree_mod_log_free_eb if this is our
    last ref.

  - Btrfs: only exclude supers in the range of our block
    group.

  - Btrfs: optimize key searches in btrfs_search_slot.

  - Btrfs: optimize the error handle of use_block_rsv().

  - Btrfs: pause the space balance when remounting to R/O.

  - Btrfs: put our inode if orphan cleanup fails.

  - Btrfs: re-add root to dead root list if we stop dropping
    it.

  - Btrfs: read entire device info under lock.

  - Btrfs: release both paths before logging dir/changed
    extents.

  - Btrfs: Release uuid_mutex for shrink during device
    delete.

  - Btrfs: remove almost all of the BUG()s from tree-log.c.

  - Btrfs: remove BUG_ON() in btrfs_read_fs_tree_no_radix().

  - Btrfs: remove ourselves from the cluster list under
    lock.

  - Btrfs: remove some BUG_ONs() when walking backref tree.

  - Btrfs: remove some unnecessary spin_lock usages.

  - Btrfs: remove unnecessary ->s_umount in
    cleaner_kthread().

  - Btrfs: remove unused argument of fixup_low_keys().

  - Btrfs: remove unused gfp mask parameter from
    release_extent_buffer callchain.

  - Btrfs: remove useless copy in quota_ctl.

  - Btrfs: remove warn on in free space cache writeout.

  - Btrfs: rescan for qgroups (FATE#312751).

  - Btrfs: reset ret in record_one_backref.

  - Btrfs: return ENOSPC when target space is full.

  - Btrfs: return errno if possible when we fail to allocate
    memory.

  - Btrfs: return error code in
    btrfs_check_trunc_cache_free_space().

  - Btrfs: return error when we specify wrong start to
    defrag.

  - Btrfs: return free space in cow error path.

  - Btrfs: separate sequence numbers for delayed ref
    tracking and tree mod log.

  - Btrfs: set UUID in root_item for created trees.

  - Btrfs: share stop worker code.

  - Btrfs: simplify unlink reservations.

  - Btrfs: split btrfs_qgroup_account_ref into four
    functions.

  - Btrfs: stop all workers before cleaning up roots.

  - Btrfs: stop using try_to_writeback_inodes_sb_nr to flush
    delalloc.

  - Btrfs: stop waiting on current trans if we aborted.

  - Btrfs: unlock extent range on enospc in compressed
    submit.

  - Btrfs: update drop progress before stopping snapshot
    dropping.

  - Btrfs: update fixups from 3.11

  - Btrfs: update the global reserve if it is empty.

  - Btrfs: use helper to cleanup tree roots.

  - Btrfs: use REQ_META for all metadata IO.

  - Btrfs: use tree_root to avoid edquot when disabling
    quota.

  - Btrfs: use u64 for subvolid when parsing mount options.

  - Btrfs: use unsigned long type for extent state bits.

  - Btrfs: various abort cleanups.

  - Btrfs: wait ordered range before doing direct io.

  - Btrfs: wake up delayed ref flushing waiters on abort.

  - net/mlx4_en: Fix BlueFlame race. (bnc#835684)

  - ipv6: do not call fib6_run_gc() until routing is ready.
    (bnc#836218)

  - ipv6: prevent fib6_run_gc() contention. (bnc#797526)

  - ipv6: update ip6_rt_last_gc every time GC is run.
    (bnc#797526)

  - netfilter: nf_conntrack: use RCU safe kfree for
    conntrack extensions (bnc#827416 bko#60853).

  - netfilter: prevent race condition breaking net reference
    counting. (bnc#835094)

  - net: remove skb_orphan_try(). (bnc#834600)

  - bonding: check bond->vlgrp in bond_vlan_rx_kill_vid().
    (bnc#834905)

  - sctp: deal with multiple COOKIE_ECHO chunks.
    (bnc#826102)

  - mlx4: allow IB_QP_CREATE_USE_GFP_NOFS in
    mlx4_ib_create_qp(). (bnc#822433)

  - drm/i915: disable sound first on intel_disable_ddi.
    (bnc#833151)

  - drm/i915: HDMI/DP - ELD info refresh support for
    Haswell. (bnc#833151)

  - drm/cirrus: This is a cirrus version of Egbert Eichs
    patch for mgag200. (bnc#808079)

  - drm/i915: Disable GGTT PTEs on GEN6+ suspend.
    (bnc#800875)

  - drm/i915/hsw: Disable L3 caching of atomic memory
    operations. (bnc#800875)

  - ALSA: hda - Re-setup HDMI pin and audio infoframe on
    stream switches. (bnc#833151)

  - vmxnet3: prevent div-by-zero panic when ring resizing
    uninitialized dev. (bnc#833321)

  - mvsas: add support for 9480 device id. (bnc#843950)

  - r8169: fix argument in rtl_hw_init_8168g.
    (bnc#845352,bnc#842820)

  - r8169: support RTL8168G. (bnc#845352,bnc#842820)

  - r8169: abstract out loop conditions.
    (bnc#845352,bnc#842820)

  - r8169: mdio_ops signature change.
    (bnc#845352,bnc#842820)

  - thp: reduce khugepaged freezing latency (khugepaged
    blocking suspend-to-ram (bnc#825291)).

  - bnx2x: Change to D3hot only on removal. (bnc#838448)

  - megaraid_sas: Disable controller reset for ppc.
    (bnc#841050)

  - scsi_dh_alua: simplify alua_check_sense(). (bnc#843642)

  - scsi_dh_alua: Fix missing close brace in
    alua_check_sense. (bnc#843642)

  - scsi_dh_alua: retry command on 'mode parameter changed'
    sense code. (bnc#843645)

  - scsi_dh_alua: invalid state information for 'optimized'
    paths. (bnc#843445)

  - scsi_dh_alua: reattaching device handler fails with
    'Error 15'. (bnc#843429)

  - Drivers: hv: util: Fix a bug in version negotiation code
    for util services. (bnc#828714)

  - Drivers: hv: util: Correctly support ws2008R2 and
    earlier. (bnc#838346)

  - Drivers: hv: vmbus: Do not attempt to negoatiate a new
    version prematurely.

  - Drivers: hv: util: Correctly support ws2008R2 and
    earlier. (bnc#838346)

  - Drivers: hv: vmbus: Terminate vmbus version negotiation
    on timeout.

  - Drivers: hv: vmbus: Fix a bug in the handling of channel
    offers.

  - Drivers: hv: util: Fix a bug in version negotiation code
    for util services. (bnc#828714)

  - Drivers: hv: balloon: Initialize the transaction ID just
    before sending the packet.

  - Drivers: hv: util: Fix a bug in util version negotiation
    code. (bnc#838346)

  - be2net: Check for POST state in suspend-resume sequence.
    (bnc#835189)

  - be2net: bug fix on returning an invalid nic descriptor.
    (bnc#835189)

  - be2net: provision VF resources before enabling SR-IOV.
    (bnc#835189)

  - be2net: Fix firmware download for Lancer. (bnc#835189)

  - be2net: Fix to use version 2 of cq_create for SkyHawk-R
    devices. (bnc#835189)

  - be2net: Use GET_FUNCTION_CONFIG V1 cmd. (bnc#835189)

  - be2net: Avoid flashing BE3 UFI on BE3-R chip.
    (bnc#835189)

  - be2net: Use TXQ_CREATE_V2 cmd. (bnc#835189)

  - writeback: Do not sync data dirtied after sync start.
    (bnc#833820)

  - elousb: some systems cannot stomach work around.
    (bnc#840830,bnc#830985)

  - bounce: allow use of bounce pool via config option
    (Bounce memory pool initialisation (bnc#836347)).

  - block: initialize the bounce pool if high memory may be
    added later (Bounce memory pool initialisation
    (bnc#836347)).

  - bio-integrity: track owner of integrity payload.
    (bnc#831380)

  - xhci: Fix spurious wakeups after S5 on Haswell.
    (bnc#833097)

  - s390/cio: handle unknown pgroup state
    (bnc#837741,LTC#97048).

  - s390/cio: export vpm via sysfs (bnc#837741,LTC#97048).

  - s390/cio: skip broken paths (bnc#837741,LTC#97048).

  - s390/cio: dont abort verification after missing irq
    (bnc#837741,LTC#97048).

  - cio: add message for timeouts on internal I/O
    (bnc#837741,LTC#97048).

  - series.conf: disable XHCI ring expansion patches because
    on machines with large memory they cause a starvation
    problem. (bnc#833635)

  - Update EC2 config files (STRICT_DEVMEM off, bnc#843732).

  - Fixed Xen guest freezes. (bnc#829682, bnc#842063)

  - tools: hv: Improve error logging in VSS daemon.

  - tools: hv: Check return value of poll call.

  - tools: hv: Check return value of setsockopt call.

  - Tools: hv: fix send/recv buffer allocation.

  - Tools: hv: check return value of daemon to fix compiler
    warning.

  - Tools: hv: in kvp_set_ip_info free mac_addr right after
    usage.

  - Tools: hv: check return value of system in
    hv_kvp_daemon.

  - Tools: hv: correct payload size in netlink_send.

  - Tools: hv: use full nlmsghdr in netlink_send.

  - rpm/old-flavors, rpm/mkspec: Add version information to
    obsolete flavors. (bnc#821465)

  - rpm/kernel-binary.spec.in: Move the xenpae obsolete to
    the old-flavors file.

  - rpm/old-flavors: Convert the old-packages.conf file to a
    flat list.

  - rpm/mkspec: Adjust.

  - rpm/old-packages.conf: Delete.

  - rpm/old-packages.conf: Drop bogus obsoletes for 'smp'.
    (bnc#821465)

  - rpm/kernel-binary.spec.in: Make sure that all KMP
    obsoletes are versioned. (bnc#821465)

  - rpm/kernel-binary.spec.in: Remove unversioned
    provides/obsoletes for packages that were only seen in
    openSUSE releases up to 11.0. . (bnc#821465)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=832292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=838346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=838448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=843950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=844513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2206.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8524 / 8525 / 8528 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/22");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-extra-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-source-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-syms-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.3_02_3.0.101_0.8-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.3_02_3.0.101_0.8-0.7.9")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.3_02_3.0.101_0.8-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-source-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-syms-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.3_02_3.0.101_0.8-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.3_02_3.0.101_0.8-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"kernel-default-man-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.3_02_3.0.101_0.8-0.7.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
