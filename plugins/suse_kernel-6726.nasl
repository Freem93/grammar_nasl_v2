#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43398);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/22 20:42:26 $");

  script_cve_id("CVE-2005-4881", "CVE-2009-2903", "CVE-2009-3080", "CVE-2009-3612", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4005", "CVE-2009-4021");

  script_name(english:"SuSE 10 Security Update : the Linux Kernel (i386) (ZYPP Patch Number 6726)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a several security issues and various bugs in the
SUSE Linux Enterprise 10 SP 2 kernel.

The following security issues were fixed: CVE-2009-3939: A sysctl
variable of the megaraid_sas driver was worldwriteable, allowing local
users to cause a denial of service or potential code execution.

  - The collect_rx_frame function in
    drivers/isdn/hisax/hfc_usb.c in the Linux kernel before
    2.6.32-rc7 allows attackers to have an unspecified
    impact via a crafted HDLC packet that arrives over ISDN
    and triggers a buffer under-read. (CVE-2009-4005)

  - A negative offset in a ioctl in the GDTH RAID driver was
    fixed. (CVE-2009-3080)

  - The fuse_direct_io function in fs/fuse/file.c in the
    fuse subsystem in the Linux kernel might allow attackers
    to cause a denial of service (invalid pointer
    dereference and OOPS) via vectors possibly related to a
    memory-consumption attack. (CVE-2009-4021)

  - The dbg_lvl file for the megaraid_sas driver in the
    Linux kernel before 2.6.27 has world-writable
    permissions, which allows local users to change the (1)
    behavior and (2) logging level of the driver by
    modifying this file. (CVE-2009-3889)

  - Memory leak in the appletalk subsystem in the Linux
    kernel when the appletalk and ipddp modules are loaded
    but the ipddp'N' device is not found, allows remote
    attackers to cause a denial of service (memory
    consumption) via IP-DDP datagrams. (CVE-2009-2903)

  - net/unix/af_unix.c in the Linux kernel allows local
    users to cause a denial of service (system hang) by
    creating an abstract-namespace AF_UNIX listening socket,
    performing a shutdown operation on this socket, and then
    performing a series of connect operations to this
    socket. (CVE-2009-3621)

  - The tcf_fill_node function in net/sched/cls_api.c in the
    netlink subsystem in the Linux kernel 2.6.x before
    2.6.32-rc5, and 2.4.37.6 and earlier, does not
    initialize a certain tcm__pad2 structure member, which
    might allow local users to obtain sensitive information
    from kernel memory via unspecified vectors. NOTE: this
    issue existed because of an incomplete fix for
    CVE-2005-4881. (CVE-2009-3612 / CVE-2005-4881)

  - The ATI Rage 128 (aka r128) driver in the Linux kernel
    does not properly verify Concurrent Command Engine (CCE)
    state initialization, which allows local users to cause
    a denial of service (NULL pointer dereference and system
    crash) or possibly gain privileges via unspecified ioctl
    calls. (CVE-2009-3620)

  - The nfs4_proc_lock function in fs/nfs/nfs4proc.c in the
    NFSv4 client in the Linux kernel allows remote NFS
    servers to cause a denial of service (NULL pointer
    dereference and panic) by sending a certain response
    containing incorrect file attributes, which trigger
    attempted use of an open file that lacks NFSv4 state.
    (CVE-2009-3726)

  - The swiotlb functionality in the r8169 driver in
    drivers/net/r8169.c in the Linux kernel allows remote
    attackers to cause a denial of service (IOMMU space
    exhaustion and system crash) by using jumbo frames for a
    large amount of network traffic, as demonstrated by a
    flood ping. (CVE-2009-3613)

The rio and sx serial multiport card drivers were disabled via a
modprobe blacklist due to severe bugs.

For a full list of changes, please read the RPM changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2005-4881.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2903.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3612.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3613.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3620.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3621.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3726.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3889.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3939.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4021.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6726.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-bigsmp-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-debug-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-default-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-kdump-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-smp-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-source-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-syms-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmi-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-vmipae-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xen-2.6.16.60-0.42.8")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"i586", reference:"kernel-xenpae-2.6.16.60-0.42.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
