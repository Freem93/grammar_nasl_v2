#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0832-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83628);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-0343", "CVE-2013-2888", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-4470", "CVE-2013-4483", "CVE-2013-4588", "CVE-2013-6382", "CVE-2013-6383", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1737", "CVE-2014-1738");
  script_bugtraq_id(58795, 62043, 62044, 62050, 63359, 63445, 63744, 63888, 63889, 64677, 64685, 64686, 64952, 64953, 64954, 67300, 67302);

  script_name(english:"SUSE SLES10 Security Update : kernel (SUSE-SU-2014:0832-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise Server 10 SP3 LTSS received a roll up update
to fix several security and non-security issues.

The following security issues have been fixed :

CVE-2013-0343: The ipv6_create_tempaddr function in
net/ipv6/addrconf.c in the Linux kernel through 3.8 does not properly
handle problems with the generation of IPv6 temporary addresses, which
allows remote attackers to cause a denial of service (excessive
retries and address-generation outage), and consequently obtain
sensitive information, via ICMPv6 Router Advertisement (RA) messages.
(bnc#805226)

CVE-2013-2888: Multiple array index errors in
drivers/hid/hid-core.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11 allow physically
proximate attackers to execute arbitrary code or cause a
denial of service (heap memory corruption) via a crafted
device that provides an invalid Report ID. (bnc#835839)

CVE-2013-2893: The Human Interface Device (HID) subsystem in
the Linux kernel through 3.11, when CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF is enabled,
allows physically proximate attackers to cause a denial of
service (heap-based out-of-bounds write) via a crafted
device, related to (1) drivers/hid/hid-lgff.c, (2)
drivers/hid/hid-lg3ff.c, and (3) drivers/hid/hid-lg4ff.c.
(bnc#835839)

CVE-2013-2897: Multiple array index errors in
drivers/hid/hid-multitouch.c in the Human Interface Device
(HID) subsystem in the Linux kernel through 3.11, when
CONFIG_HID_MULTITOUCH is enabled, allow physically proximate
attackers to cause a denial of service (heap memory
corruption, or NULL pointer dereference and OOPS) via a
crafted device. (bnc#835839)

CVE-2013-4470: The Linux kernel before 3.12, when UDP
Fragmentation Offload (UFO) is enabled, does not properly
initialize certain data structures, which allows local users
to cause a denial of service (memory corruption and system
crash) or possibly gain privileges via a crafted application
that uses the UDP_CORK option in a setsockopt system call
and sends both short and long packets, related to the
ip_ufo_append_data function in net/ipv4/ip_output.c and the
ip6_ufo_append_data function in net/ipv6/ip6_output.c.
(bnc#847672)

CVE-2013-4483: The ipc_rcu_putref function in ipc/util.c in
the Linux kernel before 3.10 does not properly manage a
reference count, which allows local users to cause a denial
of service (memory consumption or system crash) via a
crafted application. (bnc#848321)

CVE-2013-4588: Multiple stack-based buffer overflows in
net/netfilter/ipvs/ip_vs_ctl.c in the Linux kernel before
2.6.33, when CONFIG_IP_VS is used, allow local users to gain
privileges by leveraging the CAP_NET_ADMIN capability for
(1) a getsockopt system call, related to the
do_ip_vs_get_ctl function, or (2) a setsockopt system call,
related to the do_ip_vs_set_ctl function. (bnc#851095)

CVE-2013-6382: Multiple buffer underflows in the XFS
implementation in the Linux kernel through 3.12.1 allow
local users to cause a denial of service (memory corruption)
or possibly have unspecified other impact by leveraging the
CAP_SYS_ADMIN capability for a (1)
XFS_IOC_ATTRLIST_BY_HANDLE or (2)
XFS_IOC_ATTRLIST_BY_HANDLE_32 ioctl call with a crafted
length value, related to the xfs_attrlist_by_handle function
in fs/xfs/xfs_ioctl.c and the xfs_compat_attrlist_by_handle
function in fs/xfs/xfs_ioctl32.c. (bnc#852553)

CVE-2013-6383: The aac_compat_ioctl function in
drivers/scsi/aacraid/linit.c in the Linux kernel before
3.11.8 does not require the CAP_SYS_RAWIO capability, which
allows local users to bypass intended access restrictions
via a crafted ioctl call. (bnc#852558)

CVE-2013-7263: The Linux kernel before 3.12.4 updates
certain length values before ensuring that associated data
structures have been initialized, which allows local users
to obtain sensitive information from kernel stack memory via
a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call,
related to net/ipv4/ping.c, net/ipv4/raw.c, net/ipv4/udp.c,
net/ipv6/raw.c, and net/ipv6/udp.c. (bnc#857643)

CVE-2013-7264: The l2tp_ip_recvmsg function in
net/l2tp/l2tp_ip.c in the Linux kernel before 3.12.4 updates
a certain length value before ensuring that an associated
data structure has been initialized, which allows local
users to obtain sensitive information from kernel stack
memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg
system call. (bnc#857643)

CVE-2013-7265: The pn_recvmsg function in
net/phonet/datagram.c in the Linux kernel before 3.12.4
updates a certain length value before ensuring that an
associated data structure has been initialized, which allows
local users to obtain sensitive information from kernel
stack memory via a (1) recvfrom, (2) recvmmsg, or (3)
recvmsg system call. (bnc#857643)

CVE-2014-1444: The fst_get_iface function in
drivers/net/wan/farsync.c in the Linux kernel before 3.11.7
does not properly initialize a certain data structure, which
allows local users to obtain sensitive information from
kernel memory by leveraging the CAP_NET_ADMIN capability for
an SIOCWANDEV ioctl call. (bnc#858869)

CVE-2014-1445: The wanxl_ioctl function in
drivers/net/wan/wanxl.c in the Linux kernel before 3.11.7
does not properly initialize a certain data structure, which
allows local users to obtain sensitive information from
kernel memory via an ioctl call. (bnc#858870)

CVE-2014-1446: The yam_ioctl function in
drivers/net/hamradio/yam.c in the Linux kernel before 3.12.8
does not initialize a certain structure member, which allows
local users to obtain sensitive information from kernel
memory by leveraging the CAP_NET_ADMIN capability for an
SIOCYAMGCFG ioctl call. (bnc#858872)

CVE-2014-1737: The raw_cmd_copyin function in
drivers/block/floppy.c in the Linux kernel through 3.14.3
does not properly handle error conditions during processing
of an FDRAWCMD ioctl call, which allows local users to
trigger kfree operations and gain privileges by leveraging
write access to a /dev/fd device. (bnc#875798)

CVE-2014-1738: The raw_cmd_copyout function in
drivers/block/floppy.c in the Linux kernel through 3.14.3
does not properly restrict access to certain pointers during
processing of an FDRAWCMD ioctl call, which allows local
users to obtain sensitive information from kernel heap
memory by leveraging write access to a /dev/fd device.
(bnc#875798)

The following bugs have been fixed :

  - kernel: sclp console hangs (bnc#830344, LTC#95711,
    bnc#860304).

  - ia64: Change default PSR.ac from '1' to '0' (Fix erratum
    #237) (bnc#874108).

  - net: Uninline kfree_skb and allow NULL argument
    (bnc#853501).

  - tcp: syncookies: reduce cookie lifetime to 128 seconds
    (bnc#833968).

  - tcp: syncookies: reduce mss table to four values
    (bnc#833968).

  - udp: Fix bogus UFO packet generation (bnc#847672).

  - blkdev_max_block: make private to fs/buffer.c
    (bnc#820338).

  - vfs: avoid 'attempt to access beyond end of device'
    warnings (bnc#820338).

  - vfs: fix O_DIRECT read past end of block device
    (bnc#820338).

  - HID: check for NULL field when setting values
    (bnc#835839).

  - HID: provide a helper for validating hid reports
    (bnc#835839).

  - dl2k: Tighten ioctl permissions (bnc#758813).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=17ddf66eae63aab3af8b2b3bec742669
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3366e92c"
  );
  # http://download.suse.com/patch/finder/?keywords=26314f5d51311e1fdece27b8fcdf804a
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?992a6e07"
  );
  # http://download.suse.com/patch/finder/?keywords=9914353b490102922bc3d08bdf30bacc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?287c54b5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0343.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2897.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6382.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6383.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7264.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7265.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1445.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1737.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1738.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/758813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/820338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/830344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/833968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/835839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/847672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/848321"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/851095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/852558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/853501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/857643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/858872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/860304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/874108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/875798"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140832-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d643af8f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-kdumppae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-vmipae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-kdumppae-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-vmi-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-vmipae-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"kernel-xenpae-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"kernel-default-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"kernel-source-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"kernel-syms-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-debug-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-smp-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-xen-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-kdumppae-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.123.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.123.1")) flag++;


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
