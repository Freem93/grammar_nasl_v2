#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0046 and 
# CentOS Errata and Security Advisory 2010:0046 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44096);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/17 21:12:09 $");

  script_cve_id("CVE-2006-6304", "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3556", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4272");
  script_bugtraq_id(36576, 37019, 37068, 37069, 37339, 37806);
  script_osvdb_id(31466, 60311, 62058, 62122);
  script_xref(name:"RHSA", value:"2010:0046");

  script_name(english:"CentOS 5 : kernel (CESA-2010:0046)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* an array index error was found in the gdth driver. A local user
could send a specially crafted IOCTL request that would cause a denial
of service or, possibly, privilege escalation. (CVE-2009-3080,
Important)

* a flaw was found in the FUSE implementation. When a system is low on
memory, fuse_put_request() could dereference an invalid pointer,
possibly leading to a local denial of service or privilege escalation.
(CVE-2009-4021, Important)

* Tavis Ormandy discovered a deficiency in the fasync_helper()
implementation. This could allow a local, unprivileged user to
leverage a use-after-free of locked, asynchronous file descriptors to
cause a denial of service or privilege escalation. (CVE-2009-4141,
Important)

* the Parallels Virtuozzo Containers team reported the RHSA-2009:1243
update introduced two flaws in the routing implementation. If an
attacker was able to cause a large enough number of collisions in the
routing hash table (via specially crafted packets) for the emergency
route flush to trigger, a deadlock could occur. Secondly, if the
kernel routing cache was disabled, an uninitialized pointer would be
left behind after a route lookup, leading to a kernel panic.
(CVE-2009-4272, Important)

* the RHSA-2009:0225 update introduced a rewrite attack flaw in the
do_coredump() function. A local attacker able to guess the file name a
process is going to dump its core to, prior to the process crashing,
could use this flaw to append data to the dumped core file. This issue
only affects systems that have '/proc/sys/fs/suid_dumpable' set to 2
(the default value is 0). (CVE-2006-6304, Moderate)

The fix for CVE-2006-6304 changes the expected behavior: With
suid_dumpable set to 2, the core file will not be recorded if the file
already exists. For example, core files will not be overwritten on
subsequent crashes of processes whose core files map to the same name.

* an information leak was found in the Linux kernel. On AMD64 systems,
32-bit processes could access and read certain 64-bit registers by
temporarily switching themselves to 64-bit mode. (CVE-2009-2910,
Moderate)

* the RHBA-2008:0314 update introduced N_Port ID Virtualization (NPIV)
support in the qla2xxx driver, resulting in two new sysfs pseudo
files, '/sys/class/scsi_host/[a qla2xxx host]/vport_create' and
'vport_delete'. These two files were world-writable by default,
allowing a local user to change SCSI host attributes. This flaw only
affects systems using the qla2xxx driver and NPIV capable hardware.
(CVE-2009-3556, Moderate)

* permission issues were found in the megaraid_sas driver. The
'dbg_lvl' and 'poll_mode_io' files on the sysfs file system ('/sys/')
had world-writable permissions. This could allow local, unprivileged
users to change the behavior of the driver. (CVE-2009-3889,
CVE-2009-3939, Moderate)

* a NULL pointer dereference flaw was found in the firewire-ohci
driver used for OHCI compliant IEEE 1394 controllers. A local,
unprivileged user with access to /dev/fw* files could issue certain
IOCTL calls, causing a denial of service or privilege escalation. The
FireWire modules are blacklisted by default, and if enabled, only root
has access to the files noted above by default. (CVE-2009-4138,
Moderate)

* a buffer overflow flaw was found in the hfs_bnode_read() function in
the HFS file system implementation. This could lead to a denial of
service if a user browsed a specially crafted HFS file system, for
example, by running 'ls'. (CVE-2009-4020, Low)

Bug fix documentation for this update will be available shortly from
www.redhat.com/docs/en-US/errata/RHSA-2010-0046/Kernel_Security_Update
/ index.html

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016479.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66da914f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-January/016480.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bf21a6e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-164.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-164.11.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
