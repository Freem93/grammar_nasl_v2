#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0014 and 
# CentOS Errata and Security Advisory 2009:0014 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43727);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-3275", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5300", "CVE-2008-5702");
  script_bugtraq_id(30647, 32093, 32154, 32289);
  script_osvdb_id(47788);
  script_xref(name:"RHSA", value:"2009:0014");

  script_name(english:"CentOS 4 : kernel (CESA-2009:0014)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that resolve several security issues and fix
various bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update addresses the following security issues :

* the sendmsg() function in the Linux kernel did not block during UNIX
socket garbage collection. This could, potentially, lead to a local
denial of service. (CVE-2008-5300, Important)

* when fput() was called to close a socket, the __scm_destroy()
function in the Linux kernel could make indirect recursive calls to
itself. This could, potentially, lead to a local denial of service.
(CVE-2008-5029, Important)

* a deficiency was found in the Linux kernel virtual file system (VFS)
implementation. This could allow a local, unprivileged user to make a
series of file creations within deleted directories, possibly causing
a denial of service. (CVE-2008-3275, Moderate)

* a buffer underflow flaw was found in the Linux kernel IB700 SBC
watchdog timer driver. This deficiency could lead to a possible
information leak. By default, the '/dev/watchdog' device is accessible
only to the root user. (CVE-2008-5702, Low)

* the hfs and hfsplus file systems code failed to properly handle
corrupted data structures. This could, potentially, lead to a local
denial of service. (CVE-2008-4933, CVE-2008-5025, Low)

* a flaw was found in the hfsplus file system implementation. This
could, potentially, lead to a local denial of service when write
operations were performed. (CVE-2008-4934, Low)

This update also fixes the following bugs :

* when running Red Hat Enterprise Linux 4.6 and 4.7 on some systems
running Intel(r) CPUs, the cpuspeed daemon did not run, preventing the
CPU speed from being changed, such as not being reduced to an idle
state when not in use.

* mmap() could be used to gain access to beyond the first megabyte of
RAM, due to insufficient checks in the Linux kernel code. Checks have
been added to prevent this.

* attempting to turn keyboard LEDs on and off rapidly on keyboards
with slow keyboard controllers, may have caused key presses to fail.

* after migrating a hypervisor guest, the MAC address table was not
updated, causing packet loss and preventing network connections to the
guest. Now, a gratuitous ARP request is sent after migration. This
refreshes the ARP caches, minimizing network downtime.

* writing crash dumps with diskdump may have caused a kernel panic on
Non-Uniform Memory Access (NUMA) systems with certain memory
configurations.

* on big-endian systems, such as PowerPC, the getsockopt() function
incorrectly returned 0 depending on the parameters passed to it when
the time to live (TTL) value equaled 255, possibly causing memory
corruption and application crashes.

* a problem in the kernel packages provided by the RHSA-2008:0508
advisory caused the Linux kernel's built-in memory copy procedure to
return the wrong error code after recovering from a page fault on
AMD64 and Intel 64 systems. This may have caused other Linux kernel
functions to return wrong error codes.

* a divide-by-zero bug in the Linux kernel process scheduler, which
may have caused kernel panics on certain systems, has been resolved.

* the netconsole kernel module caused the Linux kernel to hang when
slave interfaces of bonded network interfaces were started, resulting
in a system hang or kernel panic when restarting the network.

* the '/proc/xen/' directory existed even if systems were not running
Red Hat Virtualization. This may have caused problems for third-party
software that checks virtualization-ability based on the existence of
'/proc/xen/'. Note: this update will remove the '/proc/xen/' directory
on systems not running Red Hat Virtualization.

All Red Hat Enterprise Linux 4 users should upgrade to these updated
packages, which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015556.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d6e2f00"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015557.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acdc3510"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-78.0.13.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.0.13.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
