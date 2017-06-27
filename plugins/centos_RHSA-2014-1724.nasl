#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1724 and 
# CentOS Errata and Security Advisory 2014:1724 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78702);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:05:38 $");

  script_cve_id("CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-4653", "CVE-2014-5077");
  script_osvdb_id(109512, 113731);
  script_xref(name:"RHSA", value:"2014:1724");

  script_name(english:"CentOS 7 : kernel (CESA-2014:1724)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and bugs are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* A race condition flaw was found in the way the Linux kernel's KVM
subsystem handled PIT (Programmable Interval Timer) emulation. A guest
user who has access to the PIT I/O ports could use this flaw to crash
the host. (CVE-2014-3611, Important)

* A NULL pointer dereference flaw was found in the way the Linux
kernel's Stream Control Transmission Protocol (SCTP) implementation
handled simultaneous connections between the same hosts. A remote
attacker could use this flaw to crash the system. (CVE-2014-5077,
Important)

* It was found that the Linux kernel's KVM subsystem did not handle
the VM exits gracefully for the invept (Invalidate Translations
Derived from EPT) and invvpid (Invalidate Translations Based on VPID)
instructions. On hosts with an Intel processor and invept/invppid VM
exit support, an unprivileged guest user could use these instructions
to crash the guest. (CVE-2014-3645, CVE-2014-3646, Moderate)

* A use-after-free flaw was found in the way the Linux kernel's
Advanced Linux Sound Architecture (ALSA) implementation handled user
controls. A local, privileged user could use this flaw to crash the
system. (CVE-2014-4653, Moderate)

Red Hat would like to thank Lars Bull of Google for reporting
CVE-2014-3611, and the Advanced Threat Research team at Intel Security
for reporting CVE-2014-3645 and CVE-2014-3646.

Bug fixes :

* A known issue that could prevent Chelsio adapters using the cxgb4
driver from being initialized on IBM POWER8 systems has been fixed.
These adapters can now be used on IBM POWER8 systems as expected.
(BZ#1130548)

* When bringing a hot-added CPU online, the kernel did not initialize
a CPU mask properly, which could result in a kernel panic. This update
corrects the bug by ensuring that the CPU mask is properly initialized
and the correct NUMA node selected. (BZ#1134715)

* The kernel could fail to bring a CPU online if the hardware
supported both, the acpi-cpufreq and intel_pstate modules. This update
ensures that the acpi-cpufreq module is not loaded in the intel_pstate
module is loaded. (BZ#1134716)

* Due to a bug in the time accounting of the kernel scheduler, a
divide error could occur when hot adding a CPU. To fix this problem,
the kernel scheduler time accounting has been reworked. (BZ#1134717)

* The kernel did not handle exceptions caused by an invalid floating
point control (FPC) register, resulting in a kernel oops. This problem
has been fixed by placing the label to handle these exceptions to the
correct place in the code. (BZ#1138733)

* A previous change to the kernel for the PowerPC architecture changed
implementation of the compat_sys_sendfile() function. Consequently,
the 64-bit sendfile() system call stopped working for files larger
than 2 GB on PowerPC. This update restores previous behavior of
sendfile() on PowerPC, and it again process files bigger than 2 GB as
expected. (BZ#1139126)

* Previously, the kernel scheduler could schedule a CPU topology
update even though the topology did not change. This could negatively
affect the CPU load balancing, cause degradation of the system
performance, and eventually result in a kernel oops. This problem has
been fixed by skipping the CPU topology update if the topology has not
actually changed. (BZ#1140300)

* Previously, recovery of a double-degraded RAID6 array could, under
certain circumstances, result in data corruption. This could happen
because the md driver was using an optimization that is safe to use
only for single-degraded arrays. This update ensures that this
optimization is skipped during the recovery of double-degraded RAID6
arrays. (BZ#1143850)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-October/020710.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43ebb047"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/29");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-123.9.2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
