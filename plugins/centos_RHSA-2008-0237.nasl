#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0237 and 
# CentOS Errata and Security Advisory 2008:0237 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43682);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2005-0504", "CVE-2007-6282", "CVE-2008-0007", "CVE-2008-1375", "CVE-2008-1615", "CVE-2008-1669");
  script_bugtraq_id(29003, 29076, 29081, 29086);
  script_osvdb_id(44874, 44929, 44930, 44992);
  script_xref(name:"RHSA", value:"2008:0237");

  script_name(english:"CentOS 4 : kernel (CESA-2008:0237)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix various security issues and several
bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages fix the following security issues :

* the absence of a protection mechanism when attempting to access a
critical section of code has been found in the Linux kernel open file
descriptors control mechanism, fcntl. This could allow a local
unprivileged user to simultaneously execute code, which would
otherwise be protected against parallel execution. As well, a race
condition when handling locks in the Linux kernel fcntl functionality,
may have allowed a process belonging to a local unprivileged user to
gain re-ordered access to the descriptor table. (CVE-2008-1669,
Important)

* on AMD64 architectures, the possibility of a kernel crash was
discovered by testing the Linux kernel process-trace ability. This
could allow a local unprivileged user to cause a denial of service
(kernel crash). (CVE-2008-1615, Important)

* the absence of a protection mechanism when attempting to access a
critical section of code, as well as a race condition, have been found
in the Linux kernel file system event notifier, dnotify. This could
allow a local unprivileged user to get inconsistent data, or to send
arbitrary signals to arbitrary system processes. (CVE-2008-1375,
Important)

Red Hat would like to thank Nick Piggin for responsibly disclosing the
following issue :

* when accessing kernel memory locations, certain Linux kernel drivers
registering a fault handler did not perform required range checks. A
local unprivileged user could use this flaw to gain read or write
access to arbitrary kernel memory, or possibly cause a kernel crash.
(CVE-2008-0007, Important)

* the possibility of a kernel crash was found in the Linux kernel
IPsec protocol implementation, due to improper handling of fragmented
ESP packets. When an attacker controlling an intermediate router
fragmented these packets into very small pieces, it would cause a
kernel crash on the receiving node during packet reassembly.
(CVE-2007-6282, Important)

* a flaw in the MOXA serial driver could allow a local unprivileged
user to perform privileged operations, such as replacing firmware.
(CVE-2005-0504, Important)

As well, these updated packages fix the following bugs :

* multiple buffer overflows in the neofb driver have been resolved. It
was not possible for an unprivileged user to exploit these issues, and
as such, they have not been handled as security issues.

* a kernel panic, due to inconsistent detection of AGP aperture size,
has been resolved.

* a race condition in UNIX domain sockets may have caused 'recv()' to
return zero. In clustered configurations, this may have caused
unexpected failovers.

* to prevent link storms, network link carrier events were delayed by
up to one second, causing unnecessary packet loss. Now, link carrier
events are scheduled immediately.

* a client-side race on blocking locks caused large time delays on NFS
file systems.

* in certain situations, the libATA sata_nv driver may have sent
commands with duplicate tags, which were rejected by SATA devices.
This may have caused infinite reboots.

* running the 'service network restart' command may have caused
networking to fail.

* a bug in NFS caused cached information about directories to be
stored for too long, causing wrong attributes to be read.

* on systems with a large highmem/lowmem ratio, NFS write performance
may have been very slow when using small files.

* a bug, which caused network hangs when the system clock was wrapped
around zero, has been resolved.

Red Hat Enterprise Linux 4 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014888.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014889.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014891.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 94, 119, 362, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/10");
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
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-67.0.15.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-67.0.15.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
