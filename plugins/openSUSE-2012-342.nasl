#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-342.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74658);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/18 04:40:37 $");

  script_cve_id("CVE-2009-4020", "CVE-2010-3873", "CVE-2010-4164", "CVE-2010-4249", "CVE-2011-1083", "CVE-2011-1173", "CVE-2011-2517", "CVE-2011-2700", "CVE-2011-2909", "CVE-2011-2928", "CVE-2011-3619", "CVE-2011-3638", "CVE-2011-4077", "CVE-2011-4086", "CVE-2011-4330", "CVE-2012-0038", "CVE-2012-0044", "CVE-2012-0207", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1146", "CVE-2012-2119", "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2663");

  script_name(english:"openSUSE Security Update : Kernel (openSUSE-SU-2012:0799-1)");
  script_summary(english:"Check for the openSUSE-2012-342 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update of the openSUSE 12.1 kernel fixes lots of bugs and
security issues.

Following issues were fixed :

  - tcp: drop SYN+FIN messages (bnc#765102).

  - net: sock: validate data_len before allocating skb in
    sock_alloc_send_pskb() (bnc#765320, CVE-2012-2136).

  - fcaps: clear the same personality flags as suid when
    fcaps are used (bnc#758260 CVE-2012-2123).

  - macvtap: zerocopy: validate vectors before building skb
    (bnc#758243 CVE-2012-2119).

  - hfsplus: Fix potential buffer overflows (bnc#760902
    CVE-2009-4020).

  - xfrm: take net hdr len into account for esp payload size
    calculation (bnc#759545).

  - ext4: fix undefined behavior in ext4_fill_flex_info()
    (bnc#757278).

  - igb: fix rtnl race in PM resume path (bnc#748859).

  - ixgbe: add missing rtnl_lock in PM resume path
    (bnc#748859).

  - b43: allocate receive buffers big enough for max frame
    len + offset (bnc#717749).

  - xenbus: Reject replies with payload >
    XENSTORE_PAYLOAD_MAX.

  - xenbus_dev: add missing error checks to watch handling.

  - hwmon: (coretemp-xen) Fix TjMax detection for older
    CPUs.

  - hwmon: (coretemp-xen) Relax target temperature range
    check.

  - Refresh other Xen patches.

  - tlan: add cast needed for proper 64 bit operation
    (bnc#756840).

  - dl2k: Tighten ioctl permissions (bnc#758813).

  - [media] cx22702: Fix signal strength.

  - fs: cachefiles: Add support for large files in
    filesystem caching (bnc#747038).

  - bridge: correct IPv6 checksum after pull (bnc#738644).

  - bridge: fix a possible use after free (bnc#738644).

  - bridge: Pseudo-header required for the checksum of
    ICMPv6 (bnc#738644).

  - bridge: mcast snooping, fix length check of snooped
    MLDv1/2 (bnc#738644).

  - PCI/ACPI: Report ASPM support to BIOS if not disabled
    from command line (bnc#714455).

  - ipc/sem.c: fix race with concurrent semtimedop()
    timeouts and IPC_RMID (bnc#756203).

  - drm/i915/crt: Remove 0xa0 probe for VGA.

  - tty_audit: fix tty_audit_add_data live lock on audit
    disabled (bnc#721366).

  - drm/i915: suspend fbdev device around suspend/hibernate
    (bnc#732908).

  - dlm: Do not allocate a fd for peeloff (bnc#729247).

  - sctp: Export sctp_do_peeloff (bnc#729247).

  - i2c-algo-bit: Fix spurious SCL timeouts under heavy
    load.

  - patches.fixes/epoll-dont-limit-non-nested.patch: Don't
    limit non-nested epoll paths (bnc#676204).

  - Update patches.suse/sd_init.mark_majors_busy.patch
    (bnc#744658).

  - igb: Fix for Alt MAC Address feature on 82580 and later
    devices (bnc#746980).

  - mark busy sd majors as allocated (bug#744658).

  - regset: Return -EFAULT, not -EIO, on host-side memory
    fault (bnc# 750079 CVE-2012-1097).

  - regset: Prevent NULL pointer reference on readonly
    regsets (bnc#750079 CVE-2012-1097).

  - mm: memcg: Correct unregistring of events attached to
    the same eventfd (CVE-2012-1146 bnc#750959).

  - befs: Validate length of long symbolic links
    (CVE-2011-2928 bnc#713430).

  - si4713-i2c: avoid potential buffer overflow on si4713
    (CVE-2011-2700 bnc#707332).

  - staging: comedi: fix infoleak to userspace
    (CVE-2011-2909 bnc#711941).

  - hfs: add sanity check for file name length
    (CVE-2011-4330 bnc#731673).

  - cifs: fix dentry refcount leak when opening a FIFO on
    lookup (CVE-2012-1090 bnc#749569).

  - drm: integer overflow in drm_mode_dirtyfb_ioctl()
    (CVE-2012-0044 bnc#740745).

  - xfs: fix acl count validation in xfs_acl_from_disk()
    (CVE-2012-0038 bnc#740703).

  - xfs: validate acl count (CVE-2012-0038 bnc#740703).

  -
    patches.fixes/xfs-fix-possible-memory-corruption-in-xfs_
    readlink: Work around missing xfs_alert().

  - xfs: Fix missing xfs_iunlock() on error recovery path in
    xfs_readlink() (CVE-2011-4077 bnc#726600).

  - xfs: Fix possible memory corruption in xfs_readlink
    (CVE-2011-4077 bnc#726600).

  - ext4: make ext4_split_extent() handle error correctly.

  - ext4: ext4_ext_convert_to_initialized bug found in
    extended FSX testing.

  - ext4: add ext4_split_extent_at() and
    ext4_split_extent().

  - ext4: reimplement convert and split_unwritten
    (CVE-2011-3638 bnc#726045).

  - patches.fixes/epoll-limit-paths.patch: epoll: limit
    paths (bnc#676204 CVE-2011-1083).

  - patches.kabi/epoll-kabi-fix.patch: epoll: hide kabi
    change in struct file (bnc#676204 CVE-2011-1083).

  - NAT/FTP: Fix broken conntrack (bnc#681639 bnc#466279
    bnc#747660).

  - igmp: Avoid zero delay when receiving odd mixture of
    IGMP queries (bnc#740448 CVE-2012-0207).

  - jbd2: clear BH_Delay & BH_Unwritten in
    journal_unmap_buffer (bnc#745832 CVE-2011-4086).

  - AppArmor: fix oops in apparmor_setprocattr (bnc#717209
    CVE-2011-3619).

  - Refresh patches.suse/SoN-22-netvm.patch. Clean and
    *working* patches.

  - Refresh patches.suse/SoN-22-netvm.patch. (bnc#683671)
    Fix an rcu locking imbalance in the receive path
    triggered when using vlans.

  - Fix mangled patch (invalid date) Although accepted by
    `patch`, this is rejected by `git apply`

  - Fix mangled diff lines (leading space tab vs tab)
    Although accepted by `patch`, these are rejected by `git
    apply`

  - jbd/jbd2: validate sb->s_first in
    journal_get_superblock() (bnc#730118).

  - fsnotify: don't BUG in fsnotify_destroy_mark()
    (bnc#689860).

  - Fix
    patches.fixes/x25-Handle-undersized-fragmented-skbs.patc
    h (CVE-2010-3873 bnc#651219).

  - Fix
    patches.fixes/x25-Prevent-skb-overreads-when-checking-ca
    ll-user-da.patch (CVE-2010-3873 bnc#651219).

  - Fix
    patches.fixes/x25-Validate-incoming-call-user-data-lengt
    hs.patch (CVE-2010-3873 bnc#651219).

  - Fix
    patches.fixes/x25-possible-skb-leak-on-bad-facilities.pa
    tch (CVE-2010-3873 bnc#651219 CVE-2010-4164 bnc#653260).

  - Update
    patches.fixes/econet-4-byte-infoleak-to-the-network.patc
    h (bnc#681186 CVE-2011-1173). Fix reference.

  - hwmon: (w83627ehf) Properly report thermal diode
    sensors.

  - nl80211: fix overflow in ssid_len (bnc#703410
    CVE-2011-2517).

  - nl80211: fix check for valid SSID size in scan
    operations (bnc#703410 CVE-2011-2517).

  - x25: Prevent skb overreads when checking call user data
    (CVE-2010-3873 bnc#737624).

  - x25: Handle undersized/fragmented skbs (CVE-2010-3873
    bnc#737624).

  - x25: Validate incoming call user data lengths
    (CVE-2010-3873 bnc#737624).

  - x25: possible skb leak on bad facilities (CVE-2010-3873
    bnc#737624).

  - net: Add a flow_cache_flush_deferred function
    (bnc#737624).

  - xfrm: avoid possible oopse in xfrm_alloc_dst
    (bnc#737624).

  - scm: lower SCM_MAX_FD (bnc#655696 CVE-2010-4249)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-06/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=466279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=683671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=703410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=717209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=717749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=721366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=737624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765320"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-extra-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-extra-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-source-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-source-vanilla-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-syms-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-base-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-base-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-debugsource-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-devel-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-devel-debuginfo-2.6.37.6-0.20.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-1.2-6.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-debuginfo-1.2-6.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-debugsource-1.2-6.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-default-1.2_k2.6.37.6_0.20-6.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-default-debuginfo-1.2_k2.6.37.6_0.20-6.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-desktop-1.2_k2.6.37.6_0.20-6.17.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-desktop-debuginfo-1.2_k2.6.37.6_0.20-6.17.1") ) flag++;

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
