#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1392 and 
# CentOS Errata and Security Advisory 2014:1392 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79181);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/09/08 13:32:41 $");

  script_cve_id("CVE-2013-2596", "CVE-2013-4483", "CVE-2014-0181", "CVE-2014-3122", "CVE-2014-3601", "CVE-2014-4608", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-5045", "CVE-2014-5077");
  script_bugtraq_id(63445, 67034, 67162, 68162, 68164, 68214, 68862, 68881, 69489);
  script_osvdb_id(92267, 99161, 106174, 106527, 108451, 108489, 109512, 110240);
  script_xref(name:"RHSA", value:"2014:1392");

  script_name(english:"CentOS 6 : kernel (CESA-2014:1392)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, address
several hundred bugs, and add numerous enhancements are now available
as part of the ongoing support and maintenance of Red Hat Enterprise
Linux version 6. This is the sixth regular update.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A NULL pointer dereference flaw was found in the way the Linux
kernel's Stream Control Transmission Protocol (SCTP) implementation
handled simultaneous connections between the same hosts. A remote
attacker could use this flaw to crash the system. (CVE-2014-5077,
Important)

* An integer overflow flaw was found in the way the Linux kernel's
Frame Buffer device implementation mapped kernel memory to user space
via the mmap syscall. A local user able to access a frame buffer
device file (/dev/fb*) could possibly use this flaw to escalate their
privileges on the system. (CVE-2013-2596, Important)

* A flaw was found in the way the ipc_rcu_putref() function in the
Linux kernel's IPC implementation handled reference counter
decrementing. A local, unprivileged user could use this flaw to
trigger an Out of Memory (OOM) condition and, potentially, crash the
system. (CVE-2013-4483, Moderate)

* It was found that the permission checks performed by the Linux
kernel when a netlink message was received were not sufficient. A
local, unprivileged user could potentially bypass these restrictions
by passing a netlink socket as stdout or stderr to a more privileged
process and altering the output of this process. (CVE-2014-0181,
Moderate)

* It was found that the try_to_unmap_cluster() function in the Linux
kernel's Memory Managment subsystem did not properly handle page
locking in certain cases, which could potentially trigger the BUG_ON()
macro in the mlock_vma_page() function. A local, unprivileged user
could use this flaw to crash the system. (CVE-2014-3122, Moderate)

* A flaw was found in the way the Linux kernel's kvm_iommu_map_pages()
function handled IOMMU mapping failures. A privileged user in a guest
with an assigned host device could use this flaw to crash the host.
(CVE-2014-3601, Moderate)

* Multiple use-after-free flaws were found in the way the Linux
kernel's Advanced Linux Sound Architecture (ALSA) implementation
handled user controls. A local, privileged user could use either of
these flaws to crash the system. (CVE-2014-4653, CVE-2014-4654,
CVE-2014-4655, Moderate)

* A flaw was found in the way the Linux kernel's VFS subsystem handled
reference counting when performing unmount operations on symbolic
links. A local, unprivileged user could use this flaw to exhaust all
available memory on the system or, potentially, trigger a
use-after-free error, resulting in a system crash or privilege
escalation. (CVE-2014-5045, Moderate)

* An integer overflow flaw was found in the way the
lzo1x_decompress_safe() function of the Linux kernel's LZO
implementation processed Literal Runs. A local attacker could, in
extremely rare cases, use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2014-4608,
Low)

Red Hat would like to thank Vladimir Davydov of Parallels for
reporting CVE-2013-4483, Jack Morgenstein of Mellanox for reporting
CVE-2014-3601, Vasily Averin of Parallels for reporting CVE-2014-5045,
and Don A. Bailey from Lab Mouse Security for reporting CVE-2014-4608.
The security impact of the CVE-2014-3601 issue was discovered by
Michael Tsirkin of Red Hat.

This update also fixes several hundred bugs and adds numerous
enhancements. Refer to the Red Hat Enterprise Linux 6.6 Release Notes
for information on the most significant of these changes, and the
Technical Notes for further information, both linked to in the
References.

All Red Hat Enterprise Linux 6 users are advised to install these
updated packages, which correct these issues, and fix the bugs and add
the enhancements noted in the Red Hat Enterprise Linux 6.6 Release
Notes and Technical Notes. The system must be rebooted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2014-October/001221.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?528cf168"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-abi-whitelists-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-504.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-504.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
