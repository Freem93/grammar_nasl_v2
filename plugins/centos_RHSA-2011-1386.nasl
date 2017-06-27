#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1386 and 
# CentOS Errata and Security Advisory 2011:1386 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(56569);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2009-4067", "CVE-2011-1160", "CVE-2011-1585", "CVE-2011-1833", "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-2695", "CVE-2011-2699", "CVE-2011-2723", "CVE-2011-2942", "CVE-2011-3131", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3209", "CVE-2011-3347");
  script_bugtraq_id(46866, 47321, 47381, 48383, 48687, 48697, 48802, 48929, 49108, 49146, 49289, 49295, 50312, 50313);
  script_xref(name:"RHSA", value:"2011:1386");

  script_name(english:"CentOS 5 : kernel (CESA-2011:1386)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, several
bugs, and add one enhancement are now available for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* The maximum file offset handling for ext4 file systems could allow a
local, unprivileged user to cause a denial of service. (CVE-2011-2695,
Important)

* IPv6 fragment identification value generation could allow a remote
attacker to disrupt a target system's networking, preventing
legitimate users from accessing its services. (CVE-2011-2699,
Important)

* A malicious CIFS (Common Internet File System) server could send a
specially crafted response to a directory read request that would
result in a denial of service or privilege escalation on a system that
has a CIFS share mounted. (CVE-2011-3191, Important)

* A local attacker could use mount.ecryptfs_private to mount (and then
access) a directory they would otherwise not have access to. Note: To
correct this issue, the RHSA-2011:1241 ecryptfs-utils update must also
be installed. (CVE-2011-1833, Moderate)

* A flaw in the taskstats subsystem could allow a local, unprivileged
user to cause excessive CPU time and memory use. (CVE-2011-2484,
Moderate)

* Mapping expansion handling could allow a local, unprivileged user to
cause a denial of service. (CVE-2011-2496, Moderate)

* GRO (Generic Receive Offload) fields could be left in an
inconsistent state. An attacker on the local network could use this
flaw to cause a denial of service. GRO is enabled by default in all
network drivers that support it. (CVE-2011-2723, Moderate)

* RHSA-2011:1065 introduced a regression in the Ethernet bridge
implementation. If a system had an interface in a bridge, and an
attacker on the local network could send packets to that interface,
they could cause a denial of service on that system. Xen hypervisor
and KVM (Kernel-based Virtual Machine) hosts often deploy bridge
interfaces. (CVE-2011-2942, Moderate)

* A flaw in the Xen hypervisor IOMMU error handling implementation
could allow a privileged guest user, within a guest operating system
that has direct control of a PCI device, to cause performance
degradation on the host and possibly cause it to hang. (CVE-2011-3131,
Moderate)

* IPv4 and IPv6 protocol sequence number and fragment ID generation
could allow a man-in-the-middle attacker to inject packets and
possibly hijack connections. Protocol sequence number and fragment IDs
are now more random. (CVE-2011-3188, Moderate)

* A flaw in the kernel's clock implementation could allow a local,
unprivileged user to cause a denial of service. (CVE-2011-3209,
Moderate)

* Non-member VLAN (virtual LAN) packet handling for interfaces in
promiscuous mode and also using the be2net driver could allow an
attacker on the local network to cause a denial of service.
(CVE-2011-3347, Moderate)

* A flaw in the auerswald USB driver could allow a local, unprivileged
user to cause a denial of service or escalate their privileges by
inserting a specially crafted USB device. (CVE-2009-4067, Low)

* A flaw in the Trusted Platform Module (TPM) implementation could
allow a local, unprivileged user to leak information to user space.
(CVE-2011-1160, Low)

* A local, unprivileged user could possibly mount a CIFS share that
requires authentication without knowing the correct password if the
mount was already mounted by another local user. (CVE-2011-1585, Low)

Red Hat would like to thank Fernando Gont for reporting CVE-2011-2699;
Darren Lavender for reporting CVE-2011-3191; the Ubuntu Security Team
for reporting CVE-2011-1833; Vasiliy Kulikov of Openwall for reporting
CVE-2011-2484; Robert Swiecki for reporting CVE-2011-2496; Brent
Meshier for reporting CVE-2011-2723; Dan Kaminsky for reporting
CVE-2011-3188; Yasuaki Ishimatsu for reporting CVE-2011-3209; Somnath
Kotur for reporting CVE-2011-3347; Rafael Dominguez Vega for reporting
CVE-2009-4067; and Peter Huewe for reporting CVE-2011-1160. The Ubuntu
Security Team acknowledges Vasiliy Kulikov of Openwall and Dan
Rosenberg as the original reporters of CVE-2011-1833."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-October/018127.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8c70a0c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-October/018128.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ebf24022"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-274.7.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
