#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62675);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/10/24 13:10:19 $");

  script_cve_id("CVE-2010-4649", "CVE-2011-1044", "CVE-2011-2494", "CVE-2011-4110", "CVE-2012-2136", "CVE-2012-2663", "CVE-2012-2744", "CVE-2012-3400", "CVE-2012-3510");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 8324)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel update fixes various security issues and bugs in the
SUSE Linux Enterprise 10 SP4 kernel.

The following security issues have been fixed :

  - kernel/taskstats.c in the Linux kernel allowed local
    users to obtain sensitive I/O statistics by sending
    taskstats commands to a netlink socket, as demonstrated
    by discovering the length of another users password (a
    side channel attack). (CVE-2011-2494)

  - net/ipv6/netfilter/nf_conntrack_reasm.c in the Linux
    kernel, when the nf_conntrack_ipv6 module is enabled,
    allowed remote attackers to cause a denial of service
    (NULL pointer dereference and system crash) via certain
    types of fragmented IPv6 packets. (CVE-2012-2744)

  - Use-after-free vulnerability in the xacct_add_tsk
    function in kernel/tsacct.c in the Linux kernel allowed
    local users to obtain potentially sensitive information
    from kernel memory or cause a denial of service (system
    crash) via a taskstats TASKSTATS_CMD_ATTR_PID command.
    (CVE-2012-3510)

  - The user_update function in security/keys/user_defined.c
    in the Linux kernel 2.6 allowed local users to cause a
    denial of service (NULL pointer dereference and kernel
    oops) via vectors related to a user-defined key and
    updating a negative key into a fully instantiated key.
    (CVE-2011-4110)

  - The ib_uverbs_poll_cq function in
    drivers/infiniband/core/uverbs_cmd.c in the Linux kernel
    did not initialize a certain response buffer, which
    allowed local users to obtain potentially sensitive
    information from kernel memory via vectors that cause
    this buffer to be only partially filled, a different
    vulnerability than CVE-2010-4649. (CVE-2011-1044)

  - Heap-based buffer overflow in the udf_load_logicalvol
    function in fs/udf/super.c in the Linux kernel allowed
    remote attackers to cause a denial of service (system
    crash) or possibly have unspecified other impact via a
    crafted UDF filesystem. (CVE-2012-3400)

  - The sock_alloc_send_pskb function in net/core/sock.c in
    the Linux kernel did not properly validate a certain
    length value, which allowed local users to cause a
    denial of service (heap-based buffer overflow and system
    crash) or possibly gain privileges by leveraging access
    to a TUN/TAP device. (CVE-2012-2136)

  - A small denial of service leak in dropping syn+fin
    messages was fixed. (CVE-2012-2663)

The following non-security issues have been fixed :

Packaging :

  - kbuild: Fix gcc -x syntax (bnc#773831). NFS :

  - knfsd: An assortment of little fixes to the sunrpc cache
    code. (bnc#767766)

  - knfsd: Unexport cache_fresh and fix a small race.
    (bnc#767766)

  - knfsd: nfsd: do not drop silently on upcall deferral.
    (bnc#767766)

  - knfsd: svcrpc: remove another silent drop from deferral
    code. (bnc#767766)

  - sunrpc/cache: simplify cache_fresh_locked and
    cache_fresh_unlocked. (bnc#767766)

  - sunrpc/cache: recheck cache validity after
    cache_defer_req. (bnc#767766)

  - sunrpc/cache: use list_del_init for the list_head
    entries in cache_deferred_req. (bnc#767766)

  - sunrpc/cache: avoid variable over-loading in
    cache_defer_req. (bnc#767766)

  - sunrpc/cache: allow thread to block while waiting for
    cache update. (bnc#767766)

  - sunrpc/cache: Fix race in sunrpc/cache introduced by
    patch to allow thread to block while waiting for cache
    update. (bnc#767766)

  - sunrpc/cache: Another fix for race problem with sunrpc
    cache deferal. (bnc#767766)

  - knfsd: nfsd: make all exp_finding functions return
    -errnos on err. (bnc#767766)

  - Fix kabi breakage in previous nfsd patch series.
    (bnc#767766)

  - nfsd: Work around incorrect return type for
    wait_for_completion_interruptible_timeout. (bnc#767766)

  - nfs: Fix a potential file corruption issue when writing.
    (bnc#773272)

  - nfs: Allow sync writes to be multiple pages.
    (bnc#763526)

  - nfs: fix reference counting for NFSv4 callback thread.
    (bnc#767504)

  - nfs: flush signals before taking down callback thread.
    (bnc#767504)

  - nfsv4: Ensure nfs_callback_down() calls svc_destroy()
    (bnc#767504). SCSI :

  - SCSI/ch: Check NULL for kmalloc() return. (bnc#783058)

  - drivers/scsi/aic94xx/aic94xx_init.c: correct the size
    argument to kmalloc. (bnc#783058)

  - block: fail SCSI passthrough ioctls on partition
    devices. (bnc#738400)

  - dm: do not forward ioctls from logical volumes to the
    underlying device. (bnc#738400)

  - vmware: Fix VMware hypervisor detection (bnc#777575,
    bnc#770507). S/390 :

  - lgr: Make lgr_page static (bnc#772409,LTC#83520).

  - zfcp: Fix oops in _blk_add_trace()
    (bnc#772409,LTC#83510).

  - kernel: Add z/VM LGR detection (bnc#767277,LTC#RAS1203).

  - be2net: Fix EEH error reset before a flash dump
    completes. (bnc#755546)

  - mptfusion: fix msgContext in mptctl_hp_hostinfo.
    (bnc#767939)

  - PCI: Fix bus resource assignment on 32 bits with 64b
    resources. . (bnc#762581)

  - PCI: fix up setup-bus.c #ifdef. (bnc#762581)

  - x86: powernow-k8: Fix indexing issue. (bnc#758985)

  - net: Fix race condition about network device name
    allocation. (bnc#747576)

XEN :

  - smpboot: adjust ordering of operations.

  - xen/x86-64: provide a memset() that can deal with 4Gb or
    above at a time. (bnc#738528)

  - xen: fix VM_FOREIGN users after c/s 878:eba6fe6d8d53.
    (bnc#760974)

  - xen/gntdev: fix multi-page slot allocation. (bnc#760974)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4649.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2663.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2744.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3400.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3510.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8324.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.99.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.99.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
