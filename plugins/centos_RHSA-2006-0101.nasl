#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0101 and 
# CentOS Errata and Security Advisory 2006:0101 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21977);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2002-2185", "CVE-2004-1190", "CVE-2005-2458", "CVE-2005-2709", "CVE-2005-2800", "CVE-2005-3044", "CVE-2005-3106", "CVE-2005-3109", "CVE-2005-3276", "CVE-2005-3356", "CVE-2005-3358", "CVE-2005-3784", "CVE-2005-3806", "CVE-2005-3848", "CVE-2005-3857", "CVE-2005-3858", "CVE-2005-4605");
  script_osvdb_id(15414, 19026, 19316, 19597, 19598, 19928, 19930, 20676, 21281, 21284, 21285, 21516, 21526, 22212, 22213, 22507, 22509, 22822);
  script_xref(name:"RHSA", value:"2006:0101");

  script_name(english:"CentOS 4 : kernel (CESA-2006:0101)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in the Red
Hat Enterprise Linux 4 kernel are now available.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

  - a flaw in network IGMP processing that a allowed a
    remote user on the local network to cause a denial of
    service (disabling of multicast reports) if the system
    is running multicast applications (CVE-2002-2185,
    moderate)

  - a flaw which allowed a local user to write to firmware
    on read-only opened /dev/cdrom devices (CVE-2004-1190,
    moderate)

  - a flaw in gzip/zlib handling internal to the kernel that
    may allow a local user to cause a denial of service
    (crash) (CVE-2005-2458, low)

  - a flaw in procfs handling during unloading of modules
    that allowed a local user to cause a denial of service
    or potentially gain privileges (CVE-2005-2709, moderate)

  - a flaw in the SCSI procfs interface that allowed a local
    user to cause a denial of service (crash)
    (CVE-2005-2800, moderate)

  - a flaw in 32-bit-compat handling of the TIOCGDEV ioctl
    that allowed a local user to cause a denial of service
    (crash) (CVE-2005-3044, important)

  - a race condition when threads share memory mapping that
    allowed local users to cause a denial of service
    (deadlock) (CVE-2005-3106, important)

  - a flaw when trying to mount a non-hfsplus filesystem
    using hfsplus that allowed local users to cause a denial
    of service (crash) (CVE-2005-3109, moderate)

  - a minor info leak with the get_thread_area() syscall
    that allowed a local user to view uninitialized kernel
    stack data (CVE-2005-3276, low)

  - a flaw in mq_open system call that allowed a local user
    to cause a denial of service (crash) (CVE-2005-3356,
    important)

  - a flaw in set_mempolicy that allowed a local user on
    some 64-bit architectures to cause a denial of service
    (crash) (CVE-2005-3358, important)

  - a flaw in the auto-reap of child processes that allowed
    a local user to cause a denial of service (crash)
    (CVE-2005-3784, important)

  - a flaw in the IPv6 flowlabel code that allowed a local
    user to cause a denial of service (crash)
    (CVE-2005-3806, important)

  - a flaw in network ICMP processing that allowed a local
    user to cause a denial of service (memory exhaustion)
    (CVE-2005-3848, important)

  - a flaw in file lease time-out handling that allowed a
    local user to cause a denial of service (log file
    overflow) (CVE-2005-3857, moderate)

  - a flaw in network IPv6 xfrm handling that allowed a
    local user to cause a denial of service (memory
    exhaustion) (CVE-2005-3858, important)

  - a flaw in procfs handling that allowed a local user to
    read kernel memory (CVE-2005-4605, important)

All Red Hat Enterprise Linux 4 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012580.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0068f18c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dac73cc3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-January/012582.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0dfc54f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-22.0.2.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-22.0.2.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
