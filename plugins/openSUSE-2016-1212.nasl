#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1212.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94219);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id("CVE-2016-5195", "CVE-2016-7039", "CVE-2016-7425", "CVE-2016-8658", "CVE-2016-8666");
  script_xref(name:"IAVA", value:"2016-A-0306");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-1212) (Dirty COW)");
  script_summary(english:"Check for the openSUSE-2016-1212 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.1 kernel was updated to 4.1.34, fixing bugs and
security issues.

The following security bugs were fixed :

  - CVE-2016-5195: A local privilege escalation using
    MAP_PRIVATE was fixed, which is reportedly exploited in
    the wild (bsc#1004418).

  - CVE-2016-8658: Stack-based buffer overflow in the
    brcmf_cfg80211_start_ap function in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg8021
    1.c in the Linux kernel allowed local users to cause a
    denial of service (system crash) or possibly have
    unspecified other impact via a long SSID Information
    Element in a command to a Netlink socket (bnc#1004462).

  - CVE-2016-7039: The IP stack in the Linux kernel allowed
    remote attackers to cause a denial of service (stack
    consumption and panic) or possibly have unspecified
    other impact by triggering use of the GRO path for large
    crafted packets, as demonstrated by packets that contain
    only VLAN headers, a related issue to CVE-2016-8666
    (bnc#1001486).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

The following non-security bugs were fixed :

  - 9p: use file_dentry() (bsc#1005101).

  - af_unix: Do not set err in unix_stream_read_generic
    unless there was an error (bsc#1005101).

  - alsa: hda - Fix superfluous HDMI jack repoll
    (bsc#1005101).

  - alsa: hda - Turn off loopback mixing as default
    (bsc#1001462).

  - apparmor: add missing id bounds check on dfa
    verification (bsc#1000304).

  - apparmor: check that xindex is in trans_table bounds
    (bsc#1000304).

  - apparmor: do not check for vmalloc_addr if kvzalloc()
    failed (bsc#1000304).

  - apparmor: do not expose kernel stack (bsc#1000304).

  - apparmor: ensure the target profile name is always
    audited (bsc#1000304).

  - apparmor: exec should not be returning ENOENT when it
    denies (bsc#1000304).

  - apparmor: fix audit full profile hname on successful
    load (bsc#1000304).

  - apparmor: fix change_hat not finding hat after policy
    replacement (bsc#1000287).

  - apparmor: fix disconnected bind mnts reconnection
    (bsc#1000304).

  - apparmor: fix log failures for all profiles in a set
    (bsc#1000304).

  - apparmor: fix module parameters can be changed after
    policy is locked (bsc#1000304).

  - apparmor: fix oops in profile_unpack() when policy_db is
    not present (bsc#1000304).

  - apparmor: fix put() parent ref after updating the active
    ref (bsc#1000304).

  - apparmor: fix refcount bug in profile replacement
    (bsc#1000304).

  - apparmor: fix refcount race when finding a child profile
    (bsc#1000304).

  - apparmor: fix replacement bug that adds new child to old
    parent (bsc#1000304).

  - apparmor: fix uninitialized lsm_audit member
    (bsc#1000304).

  - apparmor: fix update the mtime of the profile file on
    replacement (bsc#1000304).

  - apparmor: internal paths should be treated as
    disconnected (bsc#1000304).

  - apparmor: use list_next_entry instead of list_entry_next
    (bsc#1000304).

  - arm: orion5x: Fix legacy get_irqnr_and_base
    (bsc#1005101).

  - batman-adv: Fix memory leak on tt add with invalid vlan
    (bsc#1005101).

  - batman-adv: replace WARN with rate limited output on
    non-existing VLAN (bsc#1005101).

  - blacklist.conf: add some commits (bsc#1005101)

  - blacklist.conf: add unaplicable IB/uverbs commit
    (bsc#1005101)

  - blacklist.conf: Blacklist unsupported architectures

  - blkfront: fix an error path memory leak (luckily none so
    far).

  - blktap2: eliminate deadlock potential from shutdown path
    (bsc#909994).

  - blktap2: eliminate race from deferred work queue
    handling (bsc#911687).

  - btrfs: ensure that file descriptor used with subvol
    ioctls is a dir (bsc#999600).

  - cdc-acm: added sanity checking for probe() (bsc#993891).

  - cgroup: add seq_file forward declaration for struct
    cftype (bsc#1005101).

  - do 'fold checks into iterate_and_advance()' right
    (bsc#972460).

  - drm/i915: Wait up to 3ms for the pcu to ack the cdclk
    change request on SKL (bsc#1005101).

  - drm/rockchip: unset pgoff when mmap'ing gems
    (bsc#1005101).

  - fold checks into iterate_and_advance() (bsc#972460).

  - fs/cifs: cifs_get_root shouldn't use path with tree name
    (bsc#963655, bsc#979681, bsc#1000907).

  - fs/cifs: Compare prepaths when comparing superblocks
    (bsc#799133).

  - fs/cifs: Fix memory leaks in cifs_do_mount()
    (bsc#799133).

  - fs/cifs: Fix regression which breaks DFS mounting
    (bsc#799133).

  - fs/cifs: Move check for prefix path to within
    cifs_get_root() (bsc#799133).

  - hid: multitouch: force retrieving of Win8 signature blob
    (bsc#1005101).

  - input: ALPS - add touchstick support for SS5 hardware
    (bsc#987703).

  - input: ALPS - allow touchsticks to report pressure
    (bsc#987703).

  - input: ALPS - handle 0-pressure 1F events (bsc#987703).

  - input: ALPS - set DualPoint flag for 74 03 28 devices
    (bsc#987703).

  - ipip: Properly mark ipip GRO packets as encapsulated
    (bsc#1001486).

  - ipv6: suppress sparse warnings in IP6_ECN_set_ce()
    (bsc#1005101).

  - kabi: hide name change of napi_gro_cb::udp_mark
    (bsc#1001486).

  - kaweth: fix firmware download (bsc#993890).

  - kaweth: fix oops upon failed memory allocation
    (bsc#993890).

  - kvm: x86: only channel 0 of the i8254 is linked to the
    HPET (bsc#1005101).

  - memcg: fix thresholds for 32b architectures
    (bsc#1005101).

  - msi-x: fix an error path (luckily none so far).

  - netback: fix flipping mode (bsc#996664).

  - netback: fix flipping mode (bsc#996664).

  - netem: fix a use after free (bsc#1005101).

  - net: fix warnings in 'make htmldocs' by moving macro
    definition out of field declaration (bsc#1005101).

  - netfront: linearize SKBs requiring too many slots
    (bsc#991247).

  - netlink: not trim skb for mmaped socket when dump
    (bsc#1005101).

  - net_sched: fix pfifo_head_drop behavior vs backlog
    (bsc#1005101).

  - net_sched: keep backlog updated with qlen (bsc#1005101).

  - nfs: use file_dentry() (bsc#1005101).

  - ovl: fix open in stacked overlay (bsc#1005101).

  - pci: Prevent out of bounds access in numa_node override
    (bsc#1005101).

  - perf/core: Do not leak event in the syscall error path
    (bsc#1005101).

  - perf: Fix PERF_EVENT_IOC_PERIOD deadlock (bsc#1005101).

  - Revive iov_iter_fault_in_multipages_readable() for
    4.1.34.

  - sch_drr: update backlog as well (bsc#1005101).

  - sch_hfsc: always keep backlog updated (bsc#1005101).

  - sch_prio: update backlog as well (bsc#1005101).

  - sch_qfq: keep backlog updated with qlen (bsc#1005101).

  - sch_red: update backlog as well (bsc#1005101).

  - sch_sfb: keep backlog updated with qlen (bsc#1005101).

  - sch_tbf: update backlog as well (bsc#1005101).

  - tpm: fix: return rc when devm_add_action() fails
    (bsc#1005101).

  - tunnels: Do not apply GRO to multiple layers of
    encapsulation (bsc#1001486).

  - Update blacklisting documentation to contain
    path-blacklisting

  - usb: fix typo in wMaxPacketSize validation (bsc#991665).

  - usb: hub: Fix auto-remount of safely removed or ejected
    USB-3 devices (bsc#922634).

  - x86/LDT: Print the real LDT base address (bsc#1005101).

  - x86/PCI: Mark Broadwell-EP Home Agent 1 as having
    non-compliant BARs (bsc#1005101).

  - xenbus: do not bail early from
    xenbus_dev_request_and_reply() (luckily none so far).

  - xenbus: inspect the correct type in
    xenbus_dev_request_and_reply().

  - xen: Fix refcnt regression in xen netback introduced by
    changes made for bug#881008 (bnc#978094)

  - xen: Linux 4.1.28."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=799133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=881008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=996664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999932"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-xen-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lttng-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lttng-modules-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lttng-modules-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lttng-modules-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lttng-modules-kmp-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lttng-modules-kmp-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/24");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-debugsource-1.28-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-kmp-default-1.28_k4.1.34_33-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-kmp-default-debuginfo-1.28_k4.1.34_33-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-kmp-pae-1.28_k4.1.34_33-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-kmp-pae-debuginfo-1.28_k4.1.34_33-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-kmp-pv-1.28_k4.1.34_33-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-kmp-pv-debuginfo-1.28_k4.1.34_33-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-kmp-xen-1.28_k4.1.34_33-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"hdjmod-kmp-xen-debuginfo-1.28_k4.1.34_33-26.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-6.25.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-debuginfo-6.25.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-debugsource-6.25.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-devel-6.25.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-kmp-default-6.25.1_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-kmp-default-debuginfo-6.25.1_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-kmp-pae-6.25.1_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-kmp-pae-debuginfo-6.25.1_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-kmp-pv-6.25.1_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-kmp-pv-debuginfo-6.25.1_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-kmp-xen-6.25.1_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ipset-kmp-xen-debuginfo-6.25.1_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-default-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-html-4.1.34-33.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-docs-pdf-4.1.34-33.3") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-macros-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-build-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-obs-qa-xen-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-source-vanilla-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"kernel-syms-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libipset3-6.25.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libipset3-debuginfo-6.25.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-0.44-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-debuginfo-0.44-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-debugsource-0.44-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-kmp-default-0.44_k4.1.34_33-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-kmp-default-debuginfo-0.44_k4.1.34_33-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-kmp-pae-0.44_k4.1.34_33-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-kmp-pae-debuginfo-0.44_k4.1.34_33-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-kmp-pv-0.44_k4.1.34_33-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"pcfclock-kmp-pv-debuginfo-0.44_k4.1.34_33-268.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-debugsource-20140928-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-default-20140928_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-default-debuginfo-20140928_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-pae-20140928_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-pae-debuginfo-20140928_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-pv-20140928_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-pv-debuginfo-20140928_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-xen-20140928_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"vhba-kmp-xen-debuginfo-20140928_k4.1.34_33-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-ec2-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pae-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-pv-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-vanilla-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"i686", reference:"kernel-xen-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"drbd-8.4.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"drbd-debugsource-8.4.6-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"drbd-kmp-default-8.4.6_k4.1.34_33-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"drbd-kmp-default-debuginfo-8.4.6_k4.1.34_33-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"drbd-kmp-pv-8.4.6_k4.1.34_33-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"drbd-kmp-pv-debuginfo-8.4.6_k4.1.34_33-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"drbd-kmp-xen-8.4.6_k4.1.34_33-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"drbd-kmp-xen-debuginfo-8.4.6_k4.1.34_33-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-ec2-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pae-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-pv-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-vanilla-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-debugsource-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"kernel-xen-devel-4.1.34-33.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"lttng-modules-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"lttng-modules-debugsource-2.7.0-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.7.0_k4.1.34_33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.7.0_k4.1.34_33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"lttng-modules-kmp-pv-2.7.0_k4.1.34_33-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"lttng-modules-kmp-pv-debuginfo-2.7.0_k4.1.34_33-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hdjmod-debugsource / hdjmod-kmp-default / etc");
}
