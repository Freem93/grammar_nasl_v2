#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-1034.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74878);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/20 15:05:36 $");

  script_cve_id("CVE-2013-0914", "CVE-2013-1059", "CVE-2013-1819", "CVE-2013-1929", "CVE-2013-1979", "CVE-2013-2141", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2546", "CVE-2013-2547", "CVE-2013-2548", "CVE-2013-2634", "CVE-2013-2635", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3226", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3230", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3233", "CVE-2013-3234", "CVE-2013-3235", "CVE-2013-3301", "CVE-2013-4162");
  script_bugtraq_id(58301, 58382, 58426, 58597, 58908, 59055, 59377, 59380, 59381, 59382, 59383, 59387, 59388, 59389, 59390, 59393, 59394, 59396, 59397, 59538, 60254, 60341, 60375, 60409, 60410, 60715, 60874, 60893, 60922, 60953, 61411);
  script_osvdb_id(90904, 90960, 91271, 91505, 91506, 91565, 91566, 92027, 92656, 92657, 92660, 92661, 92662, 92663, 92664, 92665, 92666, 92667, 92668, 92669, 92850, 92978, 93907, 94026, 94033, 94034, 94035, 94456, 94698, 94793, 94796, 94853, 95614);

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2013:1971-1)");
  script_summary(english:"Check for the openSUSE-2013-1034 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux Kernel was updated to fix various security issues and bugs.

  - sctp: Use correct sideffect command in duplicate cookie
    handling (bnc#826102, CVE-2013-2206).

  - Drivers: hv: util: Fix a bug in util version negotiation
    code (bnc#838346).

  - vmxnet3: prevent div-by-zero panic when ring resizing
    uninitialized dev (bnc#833321).

  - md/raid1,5,10: Disable WRITE SAME until a recovery
    strategy is in place (bnc#813889).

  - netback: don't disconnect frontend when seeing oversize
    packet (bnc#823342).

  - netfront: reduce gso_max_size to account for max TCP
    header.

  - netfront: fix kABI after 'reduce gso_max_size to account
    for max TCP header'.

  - backends: Check for insane amounts of requests on the
    ring.

  - Refresh other Xen patches (bnc#804198, bnc#814211,
    bnc#826374).

  - Fix TLB gather virtual address range invalidation corner
    cases (TLB gather memory corruption).

  - mm: fix the TLB range flushed when __tlb_remove_page()
    runs out of slots (TLB gather memory corruption).

  - bnx2x: protect different statistics flows (bnc#814336).

  - Drivers: hv: util: Fix a bug in version negotiation code
    for util services (bnc#828714).

  - kabi/severities: Ignore changes in drivers/hv

  - e1000e: workaround DMA unit hang on I218 (bnc#834647).

  - e1000e: unexpected 'Reset adapter' message when cable
    pulled (bnc#834647).

  - e1000e: 82577: workaround for link drop issue
    (bnc#834647).

  - e1000e: helper functions for accessing EMI registers
    (bnc#834647).

  - atl1c: Fix misuse of netdev_alloc_skb in refilling rx
    ring (bnc#812116).

  - reiserfs: Fixed double unlock in reiserfs_setattr
    failure path.

  - reiserfs: locking, release lock around quota operations
    (bnc#815320).

  - reiserfs: locking, handle nested locks properly
    (bnc#815320).

  - reiserfs: locking, push write lock out of xattr code
    (bnc#815320).

  - af_key: fix info leaks in notify messages (bnc#827749
    CVE-2013-2234).

  - af_key: initialize satype in key_notify_policy_flush()
    (bnc#828119 CVE-2013-2237).

  - kernel/signal.c: stop info leak via the tkill and the
    tgkill syscalls (bnc#823267 CVE-2013-2141).

  - b43: stop format string leaking into error msgs
    (bnc#822579 CVE-2013-2852).

  - net: fix incorrect credentials passing (bnc#816708
    CVE-2013-1979).

  - tipc: fix info leaks via msg_name in
    recv_msg/recv_stream (bnc#816668 CVE-2013-3235).

  - rose: fix info leak via msg_name in rose_recvmsg()
    (bnc#816668 CVE-2013-3234).

  - NFC: llcp: fix info leaks via msg_name in
    llcp_sock_recvmsg() (bnc#816668 CVE-2013-3233).

  - netrom: fix info leak via msg_name in nr_recvmsg()
    (bnc#816668 CVE-2013-3232).

  - llc: Fix missing msg_namelen update in llc_ui_recvmsg()
    (bnc#816668 CVE-2013-3231).

  - l2tp: fix info leak in l2tp_ip6_recvmsg() (bnc#816668
    CVE-2013-3230).

  - iucv: Fix missing msg_namelen update in
    iucv_sock_recvmsg() (bnc#816668 CVE-2013-3229).

  - irda: Fix missing msg_namelen update in
    irda_recvmsg_dgram() (bnc#816668 CVE-2013-3228).

  - caif: Fix missing msg_namelen update in
    caif_seqpkt_recvmsg() (bnc#816668 CVE-2013-3227).

  - Bluetooth: RFCOMM - Fix missing msg_namelen update in
    rfcomm_sock_recvmsg() (bnc#816668 CVE-2013-3226).

  - Bluetooth: fix possible info leak in bt_sock_recvmsg()
    (bnc#816668 CVE-2013-3224).

  - ax25: fix info leak via msg_name in ax25_recvmsg()
    (bnc#816668 CVE-2013-3223).

  - atm: update msg_namelen in vcc_recvmsg() (bnc#816668
    CVE-2013-3222).

  - ipv6: call udp_push_pending_frames when uncorking a
    socket with (bnc#831058, CVE-2013-4162).

  - tracing: Fix possible NULL pointer dereferences
    (bnc#815256 CVE-2013-3301).

  - tg3: fix length overflow in VPD firmware parsing
    (bnc#813733 CVE-2013-1929).

  - dcbnl: fix various netlink info leaks (bnc#810473
    CVE-2013-2634).

  - rtnl: fix info leak on RTM_GETLINK request for VF
    devices (bnc#810473 CVE-2013-2635).

  - crypto: user - fix info leaks in report API (bnc#809906
    CVE-2013-2546 CVE-2013-2547 CVE-2013-2548).

  - kernel/signal.c: use __ARCH_HAS_SA_RESTORER instead of
    SA_RESTORER (bnc#808827 CVE-2013-0914).

  - signal: always clear sa_restorer on execve (bnc#808827
    CVE-2013-0914).

  - signal: Define __ARCH_HAS_SA_RESTORER so we know whether
    to clear sa_restorer (bnc#808827 CVE-2013-0914).

  - ipv6: ip6_sk_dst_check() must not assume ipv6 dst
    (bnc#827750, CVE-2013-2232).

  - xfs: fix _xfs_buf_find oops on blocks beyond the
    filesystem end (CVE-2013-1819 bnc#807471).

  - blk: avoid divide-by-zero with zero discard granularity
    (bnc#832615).

  - dlm: check the write size from user (bnc#831956).

  - drm/i915: Serialize almost all register access
    (bnc#823633).

  - drm/i915: initialize gt_lock early with other spin locks
    (bnc#801341).

  - drm/i915: fix up gt init sequence fallout (bnc#801341).

  - drm/nouveau/hwmon: s/fan0/fan1/.

  - Drivers: hv: balloon: Do not post pressure status if
    interrupted (bnc#829539).

  - drm/i915: Clear FORCEWAKE when taking over from BIOS
    (bnc#801341).

  - drm/i915: Apply alignment restrictions on scanout
    surfaces for VT-d (bnc#818561).

  - fs/notify/inode_mark.c: make
    fsnotify_find_inode_mark_locked() static (bnc#807188).

  - fsnotify: change locking order (bnc#807188).

  - fsnotify: dont put marks on temporary list when clearing
    marks by group (bnc#807188).

  - fsnotify: introduce locked versions of
    fsnotify_add_mark() and fsnotify_remove_mark()
    (bnc#807188).

  - fsnotify: pass group to fsnotify_destroy_mark()
    (bnc#807188).

  - fsnotify: use a mutex instead of a spinlock to protect a
    groups mark list (bnc#807188).

  - fanotify: add an extra flag to mark_remove_from_mask
    that indicates wheather a mark should be destroyed
    (bnc#807188).

  - fsnotify: take groups mark_lock before mark lock
    (bnc#807188).

  - fsnotify: use reference counting for groups
    (bnc#807188).

  - fsnotify: introduce fsnotify_get_group() (bnc#807188).

  - inotify, fanotify: replace fsnotify_put_group() with
    fsnotify_destroy_group() (bnc#807188).

  - drm/i915: fix long-standing SNB regression in power
    consumption after resume v2 (bnc#801341).

  - drm/nouveau: use vmalloc for pgt allocation
    (bnc#802347).

  - USB: xhci: correctly enable interrupts (bnc#828191).

  - drm/i915: Resurrect ring kicking for semaphores,
    selectively (bnc#823633,bnc#799516).

  - ALSA: usb-audio: Fix invalid volume resolution for
    Logitech HD Webcam c310 (bnc#821735).

  - ALSA: usb-audio - Fix invalid volume resolution on
    Logitech HD webcam c270 (bnc#821735).

  - config: sync up config options added with btrfs update

  - xfs: xfs: fallback to vmalloc for large buffers in
    xfs_compat_attrlist_by_handle (bnc#818053 bnc#807153).

  - xfs: fallback to vmalloc for large buffers in
    xfs_attrlist_by_handle (bnc#818053 bnc#807153).

  - btrfs: update to v3.10.

  - block: Add bio_end_sector().

  - block: Use bio_sectors() more consistently.

  - btrfs: handle lookup errors after subvol/snapshot
    creation.

  - btrfs: add new ioctl to determine size of compressed
    file (FATE#306586).

  - btrfs: reduce btrfs_path size (FATE#306586).

  - btrfs: simplify move_pages and copy_pages (FATE#306586).

  - Prefix mount messages with btrfs: for clarity
    (FATE#306586).

  - Btrfs: forced readonly when free_log_tree fails
    (FATE#306586).

  - Btrfs: forced readonly when orphan_del fails
    (FATE#306586).

  - btrfs: abort unlink trans in missed error case.

  - btrfs: access superblock via pagecache in
    scan_one_device.

  - Btrfs: account for orphan inodes properly during
    cleanup.

  - Btrfs: add a comment for fs_info->max_inline.

  - Btrfs: add a incompatible format change for smaller
    metadata extent refs.

  - Btrfs: Add a new ioctl to get the label of a mounted
    file system.

  - Btrfs: add a plugging callback to raid56 writes.

  - Btrfs: add a rb_tree to improve performance of ulist
    search.

  - Btrfs: Add a stripe cache to raid56.

  - Btrfs: Add ACCESS_ONCE() to transaction->abort accesses.

  - Btrfs: add all ioctl checks before user change for quota
    operations.

  - Btrfs: add btrfs_scratch_superblock() function.

  - btrfs: add cancellation points to defrag.

  - Btrfs: add code to scrub to copy read data to another
    disk.

  - btrfs: add debug check for extent_io range alignment.

  - Btrfs: add fiemap's flag check.

  - Btrfs: add ioctl to wait for qgroup rescan completion.

  - btrfs: add missing break in btrfs_print_leaf().

  - Btrfs: add new sources for device replace code.

  - btrfs: add 'no file data' flag to btrfs send ioctl.

  - Btrfs: add orphan before truncating pagecache.

  - Btrfs: add path->really_keep_locks.

  - btrfs: add prefix to sanity tests messages.

  - Btrfs: add rw argument to merge_bio_hook().

  - Btrfs: add some free space cache tests.

  - Btrfs: add some missing iput()'s in
    btrfs_orphan_cleanup.

  - Btrfs: add support for device replace ioctls.

  - Btrfs: add tree block level sanity check.

  - Btrfs: add two more find_device() methods.

  - Btrfs: allocate new chunks if the space is not enough
    for global rsv.

  - Btrfs: allow file data clone within a file.

  - Btrfs: allow for selecting only completely empty chunks.

  - Btrfs: allow omitting stream header and end-cmd for
    btrfs send.

  - Btrfs: allow repair code to include target disk when
    searching mirrors.

  - Btrfs: allow running defrag in parallel to
    administrative tasks.

  - Btrfs: allow superblock mismatch from older mkfs.

  - btrfs: annotate intentional switch case fallthroughs.

  - btrfs: annotate quota tree for lockdep.

  - Btrfs: automatic rescan after 'quota enable' command.

  - Btrfs: avoid deadlock on transaction waiting list.

  - Btrfs: avoid double free of fs_info->qgroup_ulist.

  - Btrfs: avoid risk of a deadlock in btrfs_handle_error.

  - Btrfs: bring back balance pause/resume logic.

  - Btrfs: build up error handling for merge_reloc_roots.

  - Btrfs: change core code of btrfs to support the device
    replace operations.

  - Btrfs: changes to live filesystem are also written to
    replacement disk.

  - Btrfs: Check CAP_DAC_READ_SEARCH for
    BTRFS_IOC_INO_PATHS.

  - Btrfs: check for actual acls rather than just xattrs
    when caching no acl.

  - Btrfs: check for NULL pointer in updating reloc roots.

  - Btrfs: check if leaf's parent exists before pushing
    items around.

  - Btrfs: check if we can nocow if we don't have data
    space.

  - Btrfs: check return value of commit when recovering log.

  - Btrfs: check the return value of
    btrfs_run_ordered_operations().

  - Btrfs: check the return value of
    btrfs_start_delalloc_inodes().

  - btrfs: clean snapshots one by one.

  - btrfs: clean up transaction abort messages.

  - Btrfs: cleanup backref search commit root flag stuff.

  - Btrfs: cleanup, btrfs_read_fs_root_no_name() doesn't
    return NULL.

  - Btrfs: cleanup destroy_marked_extents.

  - Btrfs: cleanup: don't check the same thing twice.

  - Btrfs: cleanup duplicated division functions.

  - Btrfs: cleanup for btrfs_btree_balance_dirty.

  - Btrfs: cleanup for btrfs_wait_order_range.

  - btrfs: cleanup for open-coded alignment.

  - Btrfs: cleanup fs roots if we fail to mount.

  - Btrfs: cleanup of function where btrfs_extend_item() is
    called.

  - Btrfs: cleanup of function where fixup_low_keys() is
    called.

  - Btrfs: cleanup orphan reservation if truncate fails.

  - Btrfs: cleanup orphaned root orphan item.

  - Btrfs: cleanup redundant code in btrfs_submit_direct().

  - Btrfs: cleanup scrub bio and worker wait code.

  - Btrfs: cleanup similar code in delayed inode.

  - btrfs: Cleanup some redundant codes in
    btrfs_log_inode().

  - btrfs: Cleanup some redundant codes in
    btrfs_lookup_csums_range().

  - Btrfs: cleanup the code of copy_nocow_pages_for_inode().

  - Btrfs: cleanup the similar code of the fs root read.

  - Btrfs: cleanup to make the function
    btrfs_delalloc_reserve_metadata more logic.

  - Btrfs: cleanup to remove reduplicate code in
    transaction.c.

  - Btrfs: cleanup unnecessary assignment when cleaning up
    all the residual transaction.

  - Btrfs: cleanup unnecessary clear when freeing a
    transaction or a trans handle.

  - Btrfs: cleanup unused arguments.

  - Btrfs: cleanup unused arguments in send.c.

  - Btrfs: cleanup unused arguments of btrfs_csum_data.

  - Btrfs: cleanup unused function.

  - Btrfs: clear received_uuid field for new writable
    snapshots.

  - Btrfs: Cocci spatch 'memdup.spatch'.

  - Btrfs: Cocci spatch 'ptr_ret.spatch'.

  - Btrfs: compare relevant parts of delayed tree refs.

  - Btrfs: copy everything if we've created an inline
    extent.

  - btrfs: cover more error codes in btrfs_decode_error.

  - Btrfs: creating the subvolume qgroup automatically when
    enabling quota.

  - Btrfs: deal with bad mappings in btrfs_map_block.

  - Btrfs: deal with errors in write_dev_supers.

  - Btrfs: deal with free space cache errors while replaying
    log.

  - btrfs: define BTRFS_MAGIC as a u64 value.

  - Btrfs: delete inline extents when we find them during
    logging.

  - Btrfs: delete unused function.

  - Btrfs: delete unused parameter to
    btrfs_read_root_item().

  - btrfs: deprecate subvolrootid mount option.

  - btrfs: device delete to get errors from the kernel.

  - Btrfs: disable qgroup id 0.

  - Btrfs: disallow mutually exclusive admin operations from
    user mode.

  - Btrfs: disallow some operations on the device replace
    target device.

  - btrfs: do away with non-whole_page extent I/O.

  - Btrfs: do delay iput in sync_fs.

  - Btrfs: do not allow logged extents to be merged or
    removed.

  - Btrfs: do not BUG_ON in prepare_to_reloc.

  - Btrfs: do not BUG_ON on aborted situation.

  - Btrfs: do not call file_update_time in aio_write.

  - Btrfs: do not change inode flags in rename.

  - Btrfs: do not continue if out of memory happens.

  - Btrfs: do not delete a subvolume which is in a R/O
    subvolume.

  - Btrfs: do not log extents when we only log new names.

  - Btrfs: do not mark ems as prealloc if we are writing to
    them.

  - Btrfs: do not merge logged extents if we've removed them
    from the tree.

  - Btrfs: do not overcommit if we don't have enough space
    for global rsv.

  - Btrfs: do not pin while under spin lock.

  - Btrfs: do not warn_on io_ctl->cur in io_ctl_map_page.

  - Btrfs: don't abort the current transaction if there is
    no enough space for inode cache.

  - Btrfs: don't add a NULL extended attribute.

  - Btrfs: don't allow degraded mount if too many devices
    are missing.

  - Btrfs: don't allow device replace on RAID5/RAID6.

  - Btrfs: don't auto defrag a file when doing directIO.

  - Btrfs: don't bother copying if we're only logging the
    inode.

  - Btrfs: don't BUG_ON() in btrfs_num_copies.

  - Btrfs: don't call btrfs_qgroup_free if just
    btrfs_qgroup_reserve fails.

  - Btrfs: don't call readahead hook until we have read the
    entire eb.

  - Btrfs: don't delete fs_roots until after we cleanup the
    transaction.

  - Btrfs: don't drop path when printing out tree errors in
    scrub.

  - Btrfs: don't flush the delalloc inodes in the while loop
    if flushoncommit is set.

  - Btrfs: don't force pages under writeback to finish when
    aborting.

  - Btrfs: don't invoke btrfs_invalidate_inodes() in the
    spin lock context.

  - Btrfs: don't memset new tokens.

  - Btrfs: don't NULL pointer deref on abort.

  - Btrfs: don't panic if we're trying to drop too many
    refs.

  - Btrfs: don't re-enter when allocating a chunk.

  - Btrfs: don't start a new transaction when starting sync.

  - Btrfs: don't steal the reserved space from the global
    reserve if their space type is different.

  - btrfs: don't stop searching after encountering the wrong
    item.

  - Btrfs: don't take inode delalloc mutex if we're a free
    space inode.

  - Btrfs: don't traverse the ordered operation list
    repeatedly.

  - Btrfs: Don't trust the superblock label and simply
    printk('%s') it.

  - Btrfs: don't try and free ebs twice in log replay.

  - btrfs: don't try to notify udev about missing devices.

  - Btrfs: don't use global block reservation for inode
    cache truncation.

  - Btrfs: don't wait for all the writers circularly during
    the transaction commit.

  - Btrfs: don't wait on ordered extents if we have a trans
    open.

  - Btrfs: dont do log_removal in insert_new_root.

  - btrfs: Drop inode if inode root is NULL.

  - Btrfs: eliminate a use-after-free in btrfs_balance().

  - Btrfs: enforce min_bytes parameter during extent
    allocation.

  - Btrfs: enhance btrfs structures for device replace
    support.

  - btrfs: enhance superblock checks.

  - btrfs: ensure we don't overrun devices_info in
    __btrfs_alloc_chunk.

  - Btrfs: exclude logged extents before replying when we
    are mixed.

  - Btrfs: explicitly use global_block_rsv for quota_tree.

  - Btrfs: extend the checksum item as much as possible.

  - btrfs: fall back to global reservation when removing
    subvolumes.

  - Btrfs: fill the global reserve when unpinning space.

  - Btrfs: fix a bug of per-file nocow.

  - Btrfs: fix a bug when llseek for delalloc bytes behind
    prealloc extents.

  - Btrfs: fix a build warning for an unused label.

  - Btrfs: fix a deadlock in aborting transaction due to
    ENOSPC.

  - Btrfs: fix a double free on pending snapshots in error
    handling.

  - Btrfs: fix a mismerge in btrfs_balance().

  - Btrfs: fix a regression in balance usage filter.

  - Btrfs: fix a scrub regression in case of write errors.

  - Btrfs: fix a warning when disabling quota.

  - Btrfs: fix a warning when updating qgroup limit.

  - Btrfs: fix accessing a freed tree root.

  - Btrfs: fix accessing the root pointer in tree mod log
    functions.

  - Btrfs: fix all callers of read_tree_block.

  - Btrfs: fix an while-loop of listxattr.

  - Btrfs: fix autodefrag and umount lockup.

  - Btrfs: fix backref walking race with tree deletions.

  - Btrfs: fix bad extent logging.

  - Btrfs: fix broken nocow after balance.

  - btrfs: fix btrfs_cont_expand() freeing IS_ERR em.

  - btrfs: fix btrfs_extend_item() comment.

  - Btrfs: fix BUG() in scrub when first superblock reading
    gives EIO.

  - Btrfs: fix check on same raid type flag twice.

  - Btrfs: fix chunk allocation error handling.

  - Btrfs: fix cleaner thread not working with inode cache
    option.

  - Btrfs: fix cluster alignment for mount -o ssd.

  - btrfs: fix comment typos.

  - Btrfs: fix confusing edquot happening case.

  - Btrfs: fix crash in log replay with qgroups enabled.

  - Btrfs: fix crash regarding to ulist_add_merge.

  - Btrfs: fix deadlock due to unsubmitted.

  - Btrfs: fix double free in the
    btrfs_qgroup_account_ref().

  - Btrfs: fix double free in the iterate_extent_inodes().

  - Btrfs: fix EDQUOT handling in
    btrfs_delalloc_reserve_metadata.

  - Btrfs: fix EIO from btrfs send in is_extent_unchanged
    for punched holes.

  - Btrfs: fix error handling in btrfs_ioctl_send().

  - Btrfs: fix error handling in make/read block group.

  - Btrfs: fix estale with btrfs send.

  - Btrfs: fix extent logging with O_DIRECT into prealloc.

  - Btrfs: fix freeing delayed ref head while still holding
    its mutex.

  - Btrfs: fix freeze vs auto defrag.

  - Btrfs: fix hash overflow handling.

  - Btrfs: fix how we discard outstanding ordered extents on
    abort.

  - Btrfs: fix infinite loop when we abort on mount.

  - Btrfs: fix joining the same transaction handler more
    than 2 times.

  - Btrfs: fix lockdep warning.

  - Btrfs: fix locking on ROOT_REPLACE operations in tree
    mod log.

  - Btrfs: fix lots of orphan inodes when the space is not
    enough.

  - Btrfs: fix max chunk size on raid5/6.

  - Btrfs: fix memory leak in btrfs_create_tree().

  - Btrfs: fix memory leak in name_cache_insert().

  - Btrfs: fix memory leak of log roots.

  - Btrfs: fix memory leak of pending_snapshot->inherit.

  - Btrfs: fix memory patcher through fs_info->qgroup_ulist.

  - btrfs: fix minor typo in comment.

  - btrfs: fix misleading variable name for flags.

  - Btrfs: fix missed transaction->aborted check.

  - Btrfs: fix missing check about ulist_add() in qgroup.c.

  - Btrfs: fix missing check before creating a qgroup
    relation.

  - Btrfs: fix missing check before disabling quota.

  - Btrfs: fix missing check in the btrfs_qgroup_inherit().

  - Btrfs: fix missing deleted items in
    btrfs_clean_quota_tree.

  - Btrfs: fix missing flush when committing a transaction.

  - Btrfs: fix missing i_size update.

  - Btrfs: fix missing log when BTRFS_INODE_NEEDS_FULL_SYNC
    is set.

  - Btrfs: fix missing qgroup reservation before
    fallocating.

  - Btrfs: fix missing release of qgroup reservation in
    commit_transaction().

  - Btrfs: fix missing release of the space/qgroup
    reservation in start_transaction().

  - Btrfs: fix missing reserved space release in error path
    of delalloc reservation.

  - Btrfs: fix missing write access release in
    btrfs_ioctl_resize().

  - Btrfs: fix 'mutually exclusive op is running' error
    code.

  - Btrfs: fix not being able to find skinny extents during
    relocate.

  - Btrfs: fix NULL pointer after aborting a transaction.

  - Btrfs: fix off-by-one error of the reserved size of
    btrfs_allocate().

  - Btrfs: fix off-by-one error of the same page check in
    btrfs_punch_hole().

  - Btrfs: fix off-by-one in fiemap.

  - Btrfs: fix off-by-one in lseek.

  - Btrfs: fix oops when recovering the file data by scrub
    function.

  - Btrfs: fix panic when recovering tree log.

  - Btrfs: fix permissions of empty files not affected by
    umask.

  - Btrfs: fix permissions of empty files not affected by
    umask.

  - Btrfs: fix possible infinite loop in slow caching.

  - Btrfs: fix possible memory leak in replace_path().

  - Btrfs: fix possible memory leak in the
    find_parent_nodes().

  - Btrfs: fix possible stale data exposure.

  - Btrfs: Fix printk and variable name.

  - Btrfs: fix qgroup rescan resume on mount.

  - Btrfs: fix race between mmap writes and compression.

  - Btrfs: fix race between snapshot deletion and getting
    inode.

  - Btrfs: fix race in check-integrity caused by usage of
    bitfield.

  - Btrfs: fix reada debug code compilation.

  - Btrfs: fix remount vs autodefrag.

  - Btrfs: fix repeated delalloc work allocation.

  - Btrfs: fix resize a readonly device.

  - Btrfs: fix several potential problems in
    copy_nocow_pages_for_inode.

  - Btrfs: fix space accounting for unlink and rename.

  - Btrfs: fix space leak when we fail to reserve metadata
    space.

  - btrfs: fix the code comments for LZO compression
    workspace.

  - Btrfs: fix the comment typo for
    btrfs_attach_transaction_barrier.

  - Btrfs: fix the deadlock between the transaction
    start/attach and commit.

  - Btrfs: fix the page that is beyond EOF.

  - Btrfs: fix the qgroup reserved space is released
    prematurely.

  - Btrfs: fix the race between bio and btrfs_stop_workers.

  - Btrfs: fix transaction throttling for delayed refs.

  - Btrfs: fix tree mod log regression on root split
    operations.

  - Btrfs: fix trivial error in btrfs_ioctl_resize().

  - Btrfs: Fix typo in fs/btrfs.

  - Btrfs: fix unblocked autodefraggers when remount.

  - Btrfs: fix unclosed transaction handler when the async
    transaction commitment fails.

  - Btrfs: fix uncompleted transaction.

  - Btrfs: fix unlock after free on rewinded tree blocks.

  - Btrfs: fix unlock order in btrfs_ioctl_resize.

  - Btrfs: fix unlock order in btrfs_ioctl_rm_dev.

  - Btrfs: fix unnecessary while loop when search the free
    space, cache.

  - Btrfs: fix unprotected defragable inode insertion.

  - Btrfs: fix unprotected extent map operation when logging
    file extents.

  - Btrfs: fix unprotected root node of the subvolume's
    inode rb-tree.

  - Btrfs: fix use-after-free bug during umount.

  - btrfs: fix varargs in __btrfs_std_error.

  - Btrfs: fix warning of free_extent_map.

  - Btrfs: fix warning when creating snapshots.

  - Btrfs: fix wrong comment in can_overcommit().

  - Btrfs: fix wrong file extent length.

  - Btrfs: fix wrong handle at error path of
    create_snapshot() when the commit fails.

  - Btrfs: fix wrong max device number for single profile.

  - Btrfs: fix wrong mirror number tuning.

  - Btrfs: fix wrong outstanding_extents when doing DIO
    write.

  - Btrfs: fix wrong reservation of csums.

  - Btrfs: fix wrong reserved space in qgroup during
    snap/subv creation.

  - Btrfs: fix wrong reserved space when deleting a
    snapshot/subvolume.

  - Btrfs: fix wrong return value of btrfs_lookup_csum().

  - Btrfs: fix wrong return value of btrfs_truncate_page().

  - Btrfs: fix wrong return value of
    btrfs_wait_for_commit().

  - Btrfs: fix wrong sync_writers decrement in
    btrfs_file_aio_write().

  - btrfs: fixup/remove module.h usage as required.

  - Btrfs: flush all dirty inodes if writeback can not
    start.

  - Btrfs: free all recorded tree blocks on error.

  - Btrfs: free csums when we're done scrubbing an extent.

  - Btrfs: get better concurrency for snapshot-aware defrag
    work.

  - Btrfs: get right arguments for btrfs_wait_ordered_range.

  - btrfs: get the device in write mode when deleting it.

  - Btrfs: get write access for qgroup operations.

  - Btrfs: get write access for scrub.

  - Btrfs: get write access when doing resize fs.

  - Btrfs: get write access when removing a device.

  - Btrfs: get write access when setting the default
    subvolume.

  - Btrfs: handle a bogus chunk tree nicely.

  - Btrfs: handle errors from btrfs_map_bio() everywhere.

  - Btrfs: handle errors in compression submission path.

  - btrfs: handle errors returned from get_tree_block_key.

  - btrfs: handle null fs_info in btrfs_panic().

  - Btrfs: handle running extent ops with skinny metadata.

  - Btrfs: hold the ordered operations mutex when waiting on
    ordered extents.

  - Btrfs: hold the tree mod lock in __tree_mod_log_rewind.

  - Btrfs: if we aren't committing just end the transaction
    if we error out.

  - btrfs: ignore device open failures in
    __btrfs_open_devices.

  - Btrfs: ignore orphan qgroup relations.

  - Btrfs: implement unlocked dio write.

  - Btrfs: improve the delayed inode throttling.

  - Btrfs: improve the loop of scrub_stripe.

  - Btrfs: improve the noflush reservation.

  - Btrfs: improve the performance of the csums lookup.

  - Btrfs: in scrub repair code, optimize the reading of
    mirrors.

  - Btrfs: in scrub repair code, simplify alloc error
    handling.

  - Btrfs: Include the device in most error printk()s.

  - Btrfs: increase BTRFS_MAX_MIRRORS by one for dev
    replace.

  - btrfs: Init io_lock after cloning btrfs device struct.

  - Btrfs: init relocate extent_io_tree with a mapping.

  - Btrfs: inline csums if we're fsyncing.

  - Btrfs: introduce a btrfs_dev_replace_item type.

  - Btrfs: introduce a mutex lock for btrfs quota
    operations.

  - Btrfs: introduce GET_READ_MIRRORS functionality for
    btrfs_map_block().

  - Btrfs: introduce grab/put functions for the root of the
    fs/file tree.

  - Btrfs: introduce per-subvolume delalloc inode list.

  - Btrfs: introduce per-subvolume ordered extent list.

  - Btrfs: introduce qgroup_ulist to avoid frequently
    allocating/freeing ulist.

  - Btrfs: just flush the delalloc inodes in the source tree
    before snapshot creation.

  - Btrfs: keep track of the extents original block length.

  - Btrfs: kill replicate code in replay_one_buffer.

  - Btrfs: kill some BUG_ONs() in the find_parent_nodes().

  - Btrfs: kill unnecessary arguments in del_ptr.

  - Btrfs: kill unused argument of
    btrfs_pin_extent_for_log_replay.

  - Btrfs: kill unused argument of update_block_group.

  - Btrfs: kill unused arguments of cache_block_group.

  - Btrfs: let allocation start from the right raid type.

  - btrfs: limit fallocate extent reservation to 256MB.

  - Btrfs: limit the global reserve to 512mb.

  - btrfs: list_entry can't return NULL.

  - Btrfs: log changed inodes based on the extent map tree.

  - Btrfs: log ram bytes properly.

  - Btrfs: make __merge_refs() return type be void.

  - Btrfs: make backref walking code handle skinny metadata.

  - Btrfs: make delalloc inodes be flushed by multi-task.

  - Btrfs: make delayed ref lock logic more readable.

  - Btrfs: make ordered extent be flushed by multi-task.

  - Btrfs: make ordered operations be handled by multi-task.

  - btrfs: make orphan cleanup less verbose.

  - Btrfs: make raid attr array more readable.

  - btrfs: make static code static & remove dead code.

  - btrfs: make subvol creation/deletion killable in the
    early stages.

  - Btrfs: make sure nbytes are right after log replay.

  - Btrfs: make sure NODATACOW also gets NODATASUM set.

  - Btrfs: make sure roots are assigned before freeing their
    nodes.

  - Btrfs: make the chunk allocator completely tree
    lockless.

  - Btrfs: make the cleaner complete early when the fs is
    going to be umounted.

  - Btrfs: make the scrub page array dynamically allocated.

  - Btrfs: make the snap/subv deletion end more early when
    the fs is R/O.

  - Btrfs: make the state of the transaction more readable.

  - Btrfs: merge inode_list in __merge_refs.

  - Btrfs: merge pending IO for tree log write back.

  - btrfs: merge save_error_info helpers into one.

  - Btrfs: MOD_LOG_KEY_REMOVE_WHILE_MOVING never change
    node's nritems.

  - btrfs: more open-coded file_inode().

  - Btrfs: move btrfs_truncate_page to btrfs_cont_expand
    instead of btrfs_truncate.

  - Btrfs: move checks in set_page_dirty under DEBUG.

  - Btrfs: move d_instantiate outside the transaction during
    mksubvol.

  - Btrfs: move fs/btrfs/ioctl.h to
    include/uapi/linux/btrfs.h.

  - btrfs: move ifdef around sanity checks out of
    init_btrfs_fs.

  - btrfs: move leak debug code to functions.

  - Btrfs: move some common code into a subfunction.

  - Btrfs: move the R/O check out of
    btrfs_clean_one_deleted_snapshot().

  - btrfs: Notify udev when removing device.

  - Btrfs: only clear dirty on the buffer if it is marked as
    dirty.

  - Btrfs: only do the tree_mod_log_free_eb if this is our
    last ref.

  - Btrfs: only exclude supers in the range of our block
    group.

  - Btrfs: only log the inode item if we can get away with
    it.

  - Btrfs: only unlock and relock if we have to.

  - Btrfs: optimize leaf_space_used.

  - Btrfs: optimize read_block_for_search.

  - Btrfs: optimize reada_for_balance.

  - Btrfs: optimize the error handle of use_block_rsv().

  - Btrfs: optionally avoid reads from device replace source
    drive.

  - Btrfs: pass fs_info instead of root.

  - Btrfs: pass fs_info to btrfs_map_block() instead of
    mapping_tree.

  - Btrfs: Pass fs_info to btrfs_num_copies() instead of
    mapping_tree.

  - Btrfs: pass NULL instead of 0.

  - Btrfs: pass root object into btrfs_ioctl_{start,
    wait}_sync().

  - Btrfs: pause the space balance when remounting to R/O.

  - Btrfs: place ordered operations on a per transaction
    list.

  - Btrfs: prevent qgroup destroy when there are still
    relations.

  - Btrfs: protect devices list with its mutex.

  - Btrfs: protect fs_info->alloc_start.

  - Btrfs: punch hole past the end of the file.

  - Btrfs: put csums on the right ordered extent.

  - Btrfs: put our inode if orphan cleanup fails.

  - Btrfs: put raid properties into global table.

  - btrfs: put some enospc messages under enospc_debug.

  - Btrfs: RAID5 and RAID6.

  - btrfs/raid56: Add missing #include <linux/vmalloc.h>.

  - btrfs: read entire device info under lock.

  - Btrfs: recheck bio against block device when we map the
    bio.

  - Btrfs: record first logical byte in memory.

  - Btrfs: reduce CPU contention while waiting for delayed
    extent operations.

  - Btrfs: reduce lock contention on extent buffer locks.

  - Btrfs: refactor error handling to drop inode in
    btrfs_create().

  - Btrfs: relax the block group size limit for bitmaps.

  - btrfs: remove a printk from scan_one_device.

  - Btrfs: remove almost all of the BUG()'s from tree-log.c.

  - Btrfs: remove btrfs_sector_sum structure.

  - Btrfs: remove btrfs_try_spin_lock.

  - Btrfs: remove BUG_ON() in btrfs_read_fs_tree_no_radix().

  - btrfs: remove cache only arguments from defrag path.

  - Btrfs: remove conflicting check for minimum number of
    devices in raid56.

  - Btrfs: remove deprecated comments.

  - Btrfs: remove extent mapping if we fail to add chunk.

  - Btrfs: remove reduplicate check about root in the
    function btrfs_clean_quota_tree.

  - Btrfs: remove some BUG_ONs() when walking backref tree.

  - Btrfs: remove some unnecessary spin_lock usages.

  - Btrfs: remove the block device pointer from the scrub
    context struct.

  - Btrfs: remove the code for the impossible case in
    cleanup_transaction().

  - Btrfs: Remove the invalid shrink size check up from
    btrfs_shrink_dev().

  - Btrfs: remove the time check in
    btrfs_commit_transaction().

  - btrfs: remove unnecessary cur_trans set before goto loop
    in join_transaction.

  - btrfs: remove unnecessary DEFINE_WAIT() declarations.

  - Btrfs: remove unnecessary dget_parent/dput when creating
    the pending snapshot.

  - Btrfs: remove unnecessary ->s_umount in
    cleaner_kthread().

  - Btrfs: remove unnecessary varient ->num_joined in
    btrfs_transaction structure.

  - Btrfs: remove unused argument of btrfs_extend_item().

  - Btrfs: remove unused argument of fixup_low_keys().

  - Btrfs: remove unused code in btrfs_del_root.

  - Btrfs: remove unused extent io tree ops V2.

  - btrfs: remove unused fd in btrfs_ioctl_send().

  - btrfs: remove unused fs_info from btrfs_decode_error().

  - btrfs: remove unused gfp mask parameter from
    release_extent_buffer callchain.

  - btrfs: remove unused 'item' in
    btrfs_insert_delayed_item().

  - Btrfs: remove unused variable in
    __process_changed_new_xattr().

  - Btrfs: remove unused variable in the
    iterate_extent_inodes().

  - Btrfs: remove useless copy in quota_ctl.

  - Btrfs: remove warn on in free space cache writeout.

  - Btrfs: rename root_times_lock to root_item_lock.

  - Btrfs: rename the scrub context structure.

  - Btrfs: reorder locks and sanity checks in
    btrfs_ioctl_defrag.

  - Btrfs: reorder tree mod log operations in deleting a
    pointer.

  - Btrfs: rescan for qgroups.

  - Btrfs: reset path lock state to zero.

  - Btrfs: restructure btrfs_run_defrag_inodes().

  - Btrfs: return as soon as possible when edquot happens.

  - Btrfs: return EIO if we have extent tree corruption.

  - Btrfs: return ENOMEM rather than use BUG_ON when
    btrfs_alloc_path fails.

  - Btrfs: return errno if possible when we fail to allocate
    memory.

  - Btrfs: return error code in
    btrfs_check_trunc_cache_free_space().

  - Btrfs: return error when we specify wrong start to
    defrag.

  - Btrfs: return free space in cow error path.

  - Btrfs: rework the overcommit logic to be based on the
    total size.

  - Btrfs: save us a read_lock.

  - Btrfs: select XOR_BLOCKS in Kconfig.

  - Btrfs: separate sequence numbers for delayed ref
    tracking and tree mod log.

  - Btrfs: serialize unlocked dio reads with truncate.

  - Btrfs: set/change the label of a mounted file system.

  - Btrfs: set flushing if we're limited flushing.

  - Btrfs: set hole punching time properly.

  - Btrfs: set UUID in root_item for created trees.

  - Btrfs: share stop worker code.

  - btrfs: show compiled-in config features at module load
    time.

  - Btrfs: simplify unlink reservations.

  - Btrfs: skip adding an acl attribute if we don't have to.

  - Btrfs: snapshot-aware defrag.

  - Btrfs: split btrfs_qgroup_account_ref into four
    functions.

  - Btrfs: steal from global reserve if we are cleaning up
    orphans.

  - Btrfs: stop all workers before cleaning up roots.

  - Btrfs: stop using try_to_writeback_inodes_sb_nr to flush
    delalloc.

  - Btrfs: stop waiting on current trans if we aborted.

  - Btrfs: traverse and flush the delalloc inodes once.

  - btrfs: try harder to allocate raid56 stripe cache.

  - Btrfs: unlock extent range on enospc in compressed
    submit.

  - btrfs: unpin_extent_cache: fix the typo and unnecessary
    arguements.

  - Btrfs: unreserve space if our ordered extent fails to
    work.

  - btrfs: update kconfig title.

  - Btrfs: update the global reserve if it is empty.

  - btrfs: update timestamps on truncate().

  - Btrfs: update to use fs_state bit.

  - Btrfs: use a btrfs bioset instead of abusing bio
    internals.

  - Btrfs: use a lock to protect incompat/compat flag of the
    super block.

  - Btrfs: use a percpu to keep track of possibly pinned
    bytes.

  - Btrfs: use bit operation for ->fs_state.

  - Btrfs: use common work instead of delayed work.

  - Btrfs: use ctl->unit for free space calculation instead
    of block_group->sectorsize.

  - Btrfs: use existing align macros in btrfs_allocate().

  - Btrfs: use helper to cleanup tree roots.

  - btrfs: use only inline_pages from extent buffer.

  - Btrfs: use percpu counter for dirty metadata count.

  - Btrfs: use percpu counter for fs_info->delalloc_bytes.

  - btrfs: use rcu_barrier() to wait for bdev puts at
    unmount.

  - Btrfs: use REQ_META for all metadata IO.

  - Btrfs: use reserved space for creating a snapshot.

  - Btrfs: use right range to find checksum for compressed
    extents.

  - Btrfs: use seqlock to protect fs_info->avail_{data,
    metadata, system}_alloc_bits.

  - Btrfs: use set_nlink if our i_nlink is 0.

  - Btrfs: use slabs for auto defrag allocation.

  - Btrfs: use slabs for delayed reference allocation.

  - Btrfs: use the inode own lock to protect its
    delalloc_bytes.

  - Btrfs: use token to avoid times mapping extent buffer.

  - Btrfs: use tokens where we can in the tree log.

  - Btrfs: use tree_root to avoid edquot when disabling
    quota.

  - btrfs: use unsigned long type for extent state bits.

  - Btrfs: use wrapper page_offset.

  - Btrfs: various abort cleanups.

  - Btrfs: wait on ordered extents at the last possible
    moment.

  - Btrfs: wait ordered range before doing direct io.

  - Btrfs: wake up delayed ref flushing waiters on abort.

  - clear chunk_alloc flag on retryable failure.

  - Correct allowed raid levels on balance.

  - Fix misspellings of 'whether' in comments.

  - fs/btrfs: drop if around WARN_ON.

  - fs/btrfs: remove depends on CONFIG_EXPERIMENTAL.

  - fs/btrfs: use WARN.

  - Minor format cleanup.

  - new helper: file_inode(file).

  - Revert 'Btrfs: fix permissions of empty files not
    affected by umask'.

  - Revert 'Btrfs: MOD_LOG_KEY_REMOVE_WHILE_MOVING never
    change node's nritems'.

  - Revert 'Btrfs: reorder tree mod log operations in
    deleting a pointer'.

  - treewide: Fix typo in printk.

  - writeback: remove nr_pages_dirtied arg from
    balance_dirty_pages_ratelimited_nr().

  - drivers/cdrom/cdrom.c: use kzalloc() for failing
    hardware (bnc#824295, CVE-2013-2164).

  - fanotify: info leak in copy_event_to_user()
    (CVE-2013-2148 bnc#823517).

  - block: do not pass disk names as format strings
    (bnc#822575 CVE-2013-2851).

  - libceph: Fix NULL pointer dereference in auth client
    code. (CVE-2013-1059, bnc#826350)

  - Update
    patches.drivers/media-rtl28xxu-01-add-NOXON-DAB-DAB-USB-
    dongle-rev-2.patch (bnc#811882).

  - Update
    patches.drivers/media-rtl28xxu-02-1b80-d3a8-ASUS-My-Cine
    ma-U3100Mini-Pl.patch (bnc#811882).

  - Update
    patches.drivers/media-rtl28xxu-03-add-Gigabyte-U7300-DVB
    -T-Dongle.patch (bnc#811882).

  - Update
    patches.drivers/media-rtl28xxu-04-correct-some-device-na
    mes.patch (bnc#811882).

  - Update
    patches.drivers/media-rtl28xxu-05-Support-Digivox-Mini-H
    D.patch (bnc#811882).

  - Update
    patches.drivers/media-rtl28xxu-06-Add-USB-IDs-for-Compro
    -VideoMate-U620.patch (bnc#811882).

  - Update
    patches.drivers/media-rtl28xxu-07-Add-USB-ID-for-MaxMedi
    a-HU394-T.patch (bnc#811882). Correct the bnc reference.

  - Update
    patches.fixes/block-discard-granularity-might-not-be-pow
    er-of-2.patch (bnc#823797).

  - block: discard granularity might not be power of 2.

  - USB: reset resume quirk needed by a hub (bnc#810144).

  - NFS: Fix keytabless mounts (bnc#817651).

  - ipv4: fix redirect handling for TCP packets
    (bnc#814510).

  - Always include the git commit in KOTD builds This allows
    us not to set it explicitly in builds submitted to the
    official distribution (bnc#821612, bnc#824171).

  - Btrfs: relocate csums properly with prealloc extents.

  - gcc4: disable __compiletime_object_size for GCC 4.6+
    (bnc#837258).

&#9; - ALSA: hda - Add Toshiba Satellite C870 to MSI blacklist
(bnc#833585)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00129.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=810144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=810473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=811882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=817651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=832615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=837258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=838346"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-source-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-source-vanilla-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-syms-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-base-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-debugsource-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-devel-3.7.10-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.7.10-1.24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
