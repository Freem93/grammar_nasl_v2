#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0885 and 
# CentOS Errata and Security Advisory 2008:0885 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43710);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2007-6417", "CVE-2007-6716", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");
  script_bugtraq_id(27694, 30647, 31515);
  script_osvdb_id(44120, 47788);
  script_xref(name:"RHSA", value:"2008:0885");

  script_name(english:"CentOS 5 : kernel (CESA-2008:0885)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix various security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* a missing capability check was found in the Linux kernel
do_change_type routine. This could allow a local unprivileged user to
gain privileged access or cause a denial of service. (CVE-2008-2931,
Important)

* a flaw was found in the Linux kernel Direct-IO implementation. This
could allow a local unprivileged user to cause a denial of service.
(CVE-2007-6716, Important)

* Tobias Klein reported a missing check in the Linux kernel Open Sound
System (OSS) implementation. This deficiency could lead to a possible
information leak. (CVE-2008-3272, Moderate)

* a deficiency was found in the Linux kernel virtual filesystem (VFS)
implementation. This could allow a local unprivileged user to attempt
file creation within deleted directories, possibly causing a denial of
service. (CVE-2008-3275, Moderate)

* a flaw was found in the Linux kernel tmpfs implementation. This
could allow a local unprivileged user to read sensitive information
from the kernel. (CVE-2007-6417, Moderate)

Bug fixes :

* when copying a small IPoIB packet from the original skb it was
received in to a new, smaller skb, all fields in the new skb were not
initialized. This may have caused a kernel oops.

* previously, data may have been written beyond the end of an array,
causing memory corruption on certain systems, resulting in hypervisor
crashes during context switching.

* a kernel crash may have occurred on heavily-used Samba servers after
24 to 48 hours of use.

* under heavy memory pressure, pages may have been swapped out from
under the SGI Altix XPMEM driver, causing silent data corruption in
the kernel.

* the ixgbe driver is untested, but support was advertised for the
Intel 82598 network card. If this card was present when the ixgbe
driver was loaded, a NULL pointer dereference and a panic occurred.

* on certain systems, if multiple InfiniBand queue pairs
simultaneously fell into an error state, an overrun may have occurred,
stopping traffic.

* with bridging, when forward delay was set to zero, setting an
interface to the forwarding state was delayed by one or possibly two
timers, depending on whether STP was enabled. This may have caused
long delays in moving an interface to the forwarding state. This issue
caused packet loss when migrating virtual machines, preventing them
from being migrated without interrupting applications.

* on certain multinode systems, IPMI device nodes were created in
reverse order of where they physically resided.

* process hangs may have occurred while accessing application data
files via asynchronous direct I/O system calls.

* on systems with heavy lock traffic, a possible deadlock may have
caused anything requiring locks over NFS to stop, or be very slow.
Errors such as 'lockd: server [IP] not responding, timed out' were
logged on client systems.

* unexpected removals of USB devices may have caused a NULL pointer
dereference in kobject_get_path.

* on Itanium-based systems, repeatedly creating and destroying Windows
guests may have caused Dom0 to crash, due to the
'XENMEM_add_to_physmap' hypercall, used by para-virtualized drivers on
HVM, being SMP-unsafe.

* when using an MD software RAID, crashes may have occurred when
devices were removed or changed while being iterated through. Correct
locking is now used.

* break requests had no effect when using 'Serial Over Lan' with the
Intel 82571 network card. This issue may have caused log in problems.

* on Itanium-based systems, module_free() referred the first parameter
before checking it was valid. This may have caused a kernel panic when
exiting SystemTap.

Red Hat Enterprise Linux 5 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015273.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8aee81a4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-September/015274.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4031f94"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 200, 264, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/25");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-92.1.13.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-92.1.13.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
