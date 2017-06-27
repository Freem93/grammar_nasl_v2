#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1227.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94303);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id("CVE-2015-7513", "CVE-2015-8956", "CVE-2016-0823", "CVE-2016-1237", "CVE-2016-5195", "CVE-2016-5696", "CVE-2016-6327", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7117", "CVE-2016-7425", "CVE-2016-8658");
  script_xref(name:"IAVA", value:"2016-A-0306");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-1227) (Dirty COW)");
  script_summary(english:"Check for the openSUSE-2016-1227 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.2 kernel was updated to receive various security and
bugfixes.

The following security bugs were fixed :

  - CVE-2015-8956: The rfcomm_sock_bind function in
    net/bluetooth/rfcomm/sock.c in the Linux kernel allowed
    local users to obtain sensitive information or cause a
    denial of service (NULL pointer dereference) via vectors
    involving a bind system call on a Bluetooth RFCOMM
    socket (bnc#1003925).

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

  - CVE-2016-7117: Use-after-free vulnerability in the
    __sys_recvmmsg function in net/socket.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via vectors involving a recvmmsg system call that
    is mishandled during error processing (bnc#1003077).

  - CVE-2016-0823: The pagemap_open function in
    fs/proc/task_mmu.c in the Linux kernel before 3.19.3, as
    used in Android 6.0.1 before 2016-03-01, allowed local
    users to obtain sensitive physical-address information
    by reading a pagemap file, aka Android internal bug
    25739721 (bnc#994759).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

  - CVE-2016-6327: drivers/infiniband/ulp/srpt/ib_srpt.c in
    the Linux kernel allowed local users to cause a denial
    of service (NULL pointer dereference and system crash)
    by using an ABORT_TASK command to abort a device write
    operation (bnc#994748).

  - CVE-2016-6828: The tcp_check_send_head function in
    include/net/tcp.h in the Linux kernel did not properly
    maintain certain SACK state after a failed data copy,
    which allowed local users to cause a denial of service
    (tcp_xmit_retransmit_queue use-after-free and system
    crash) via a crafted SACK option (bnc#994296).

  - CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel
    did not properly determine the rate of challenge ACK
    segments, which made it easier for man-in-the-middle
    attackers to hijack TCP sessions via a blind in-window
    attack (bnc#989152)

  - CVE-2016-6480: Race condition in the ioctl_send_fib
    function in drivers/scsi/aacraid/commctrl.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds access or system crash) by changing a
    certain size value, aka a 'double fetch' vulnerability
    (bnc#991608).

  - CVE-2015-7513: arch/x86/kvm/x86.c in the Linux kernel
    did not reset the PIT counter values during state
    restoration, which allowed guest OS users to cause a
    denial of service (divide-by-zero error and host OS
    crash) via a zero value, related to the
    kvm_vm_ioctl_set_pit and kvm_vm_ioctl_set_pit2 functions
    (bnc#960689).

  - CVE-2016-1237: nfsd in the Linux kernel allowed local
    users to bypass intended file-permission restrictions by
    setting a POSIX ACL, related to nfs2acl.c, nfs3acl.c,
    and nfs4acl.c (bnc#986570).

The following non-security bugs were fixed :

  - AF_VSOCK: Shrink the area influenced by prepare_to_wait
    (bsc#994520).

  - xen: Fix refcnt regression in xen netback introduced by
    changes made for bug#881008 (bnc#978094)

  - MSI-X: fix an error path (luckily none so far).

  - usb: fix typo in wMaxPacketSize validation (bsc#991665).

  - usb: validate wMaxPacketValue entries in endpoint
    descriptors (bnc#991665).

  - Update
    patches.fixes/0002-nfsd-check-permissions-when-setting-A
    CLs.patch (bsc#986570 CVE#2016-1237).

  - Update
    patches.fixes/0001-posix_acl-Add-set_posix_acl.patch
    (bsc#986570 CVE#2016-1237).

  - apparmor: fix change_hat not finding hat after policy
    replacement (bsc#1000287).

  - arm64: Honor __GFP_ZERO in dma allocations
    (bsc#1004045).

  - arm64: __clear_user: handle exceptions on strb
    (bsc#994752).

  - arm64: dma-mapping: always clear allocated buffers
    (bsc#1004045).

  - arm64: perf: reject groups spanning multiple HW PMUs
    (bsc#1003931).

  - blkfront: fix an error path memory leak (luckily none so
    far).

  - blktap2: eliminate deadlock potential from shutdown path
    (bsc#909994).

  - blktap2: eliminate race from deferred work queue
    handling (bsc#911687).

  - btrfs: ensure that file descriptor used with subvol
    ioctls is a dir (bsc#999600).

  - cdc-acm: added sanity checking for probe() (bsc#993891).

  - kaweth: fix firmware download (bsc#993890).

  - kaweth: fix oops upon failed memory allocation
    (bsc#993890).

  - netback: fix flipping mode (bsc#996664).

  - netback: fix flipping mode (bsc#996664).

  - netfront: linearize SKBs requiring too many slots
    (bsc#991247).

  - nfsd: check permissions when setting ACLs (bsc#986570).

  - posix_acl: Add set_posix_acl (bsc#986570).

  - ppp: defer netns reference release for ppp channel
    (bsc#980371).

  - tunnels: Do not apply GRO to multiple layers of
    encapsulation (bsc#1001486).

  - usb: hub: Fix auto-remount of safely removed or ejected
    USB-3 devices (bsc#922634).

  - x86: suppress lazy MMU updates during vmalloc fault
    processing (bsc#951155).

  - xen-netback-generalize.patch: Fold back into base patch.

  - xen3-patch-2.6.31.patch: Fold back into base patch.

  - xen3-patch-3.12.patch: Fold bac into base patch.

  - xen3-patch-3.15.patch: Fold back into base patch.

  - xen3-patch-3.3.patch: Fold back into base patch.

  - xen3-patch-3.9.patch: Fold bac into base patch.

  - xen3-patch-3.9.patch: Fold back into base patch.

  - xenbus: do not bail early from
    xenbus_dev_request_and_reply() (luckily none so far).

  - xenbus: inspect the correct type in
    xenbus_dev_request_and_reply()."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004045"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=951155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991608"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994759"
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-0.8-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-debugsource-0.8-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-0.8_k3.16.7_45-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-debuginfo-0.8_k3.16.7_45-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-0.8_k3.16.7_45-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-debuginfo-0.8_k3.16.7_45-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-0.8_k3.16.7_45-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-debuginfo-0.8_k3.16.7_45-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-0.8_k3.16.7_45-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-debuginfo-0.8_k3.16.7_45-3.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-2.639-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debuginfo-2.639-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debugsource-2.639-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-2.639_k3.16.7_45-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-debuginfo-2.639_k3.16.7_45-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-2.639_k3.16.7_45-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.16.7_45-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-2.639_k3.16.7_45-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-debuginfo-2.639_k3.16.7_45-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-2.639_k3.16.7_45-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-debuginfo-2.639_k3.16.7_45-14.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-7.0.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debuginfo-7.0.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debugsource-7.0.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-devel-7.0.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-7.0.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-debuginfo-7.0.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-7.0.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-debuginfo-7.0.8-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-7.0.8_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-debuginfo-7.0.8_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-7.0.8_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-debuginfo-7.0.8_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-7.0.8_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-debuginfo-7.0.8_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-7.0.8_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-debuginfo-7.0.8_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-debugsource-1.28-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-1.28_k3.16.7_45-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.16.7_45-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-1.28_k3.16.7_45-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.16.7_45-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-1.28_k3.16.7_45-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.16.7_45-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-1.28_k3.16.7_45-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.16.7_45-18.23.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-6.23-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debuginfo-6.23-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debugsource-6.23-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-devel-6.23-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-6.23_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-debuginfo-6.23_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-6.23_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-debuginfo-6.23_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-6.23_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-debuginfo-6.23_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-6.23_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-debuginfo-6.23_k3.16.7_45-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-macros-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-xen-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-vanilla-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-syms-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-6.23-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-debuginfo-6.23-22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-0.44-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debuginfo-0.44-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debugsource-0.44-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-0.44_k3.16.7_45-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.16.7_45-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-0.44_k3.16.7_45-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.16.7_45-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-0.44_k3.16.7_45-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.16.7_45-260.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-debugsource-20140629-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-20140629_k3.16.7_45-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-debuginfo-20140629_k3.16.7_45-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-20140629_k3.16.7_45-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-debuginfo-20140629_k3.16.7_45-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-20140629_k3.16.7_45-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-debuginfo-20140629_k3.16.7_45-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-20140629_k3.16.7_45-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-debuginfo-20140629_k3.16.7_45-2.22.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-5.0.28_k3.16.7_45-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-source-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-5.0.28-54.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-debugsource-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-devel-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-debuginfo-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-debuginfo-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-2.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debuginfo-2.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debugsource-2.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-2.6_k3.16.7_45-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-debuginfo-2.6_k3.16.7_45-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-2.6_k3.16.7_45-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-debuginfo-2.6_k3.16.7_45-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-2.6_k3.16.7_45-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-debuginfo-2.6_k3.16.7_45-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-2.6_k3.16.7_45-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-debuginfo-2.6_k3.16.7_45-24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-devel-3.16.7-45.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-doc-html-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_05_k3.16.7_45-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.4_05_k3.16.7_45-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-4.4.4_05_k3.16.7_45-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-debuginfo-4.4.4_05_k3.16.7_45-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-4.4.4_05-51.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.4_05-51.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bbswitch / bbswitch-debugsource / bbswitch-kmp-default / etc");
}
