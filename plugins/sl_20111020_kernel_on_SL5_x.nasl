#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61162);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2009-4067", "CVE-2011-1160", "CVE-2011-1585", "CVE-2011-1833", "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-2695", "CVE-2011-2699", "CVE-2011-2723", "CVE-2011-2942", "CVE-2011-3131", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3209", "CVE-2011-3347");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

  - The maximum file offset handling for ext4 file systems
    could allow a local, unprivileged user to cause a denial
    of service. (CVE-2011-2695, Important)

  - IPv6 fragment identification value generation could
    allow a remote attacker to disrupt a target system's
    networking, preventing legitimate users from accessing
    its services. (CVE-2011-2699, Important)

  - A malicious CIFS (Common Internet File System) server
    could send a specially crafted response to a directory
    read request that would result in a denial of service or
    privilege escalation on a system that has a CIFS share
    mounted. (CVE-2011-3191, Important)

  - A local attacker could use mount.ecryptfs_private to
    mount (and then access) a directory they would otherwise
    not have access to. Note: To correct this issue, a
    ecryptfs-utils update must also be installed.
    (CVE-2011-1833, Moderate)

  - A flaw in the taskstats subsystem could allow a local,
    unprivileged user to cause excessive CPU time and memory
    use. (CVE-2011-2484, Moderate)

  - Mapping expansion handling could allow a local,
    unprivileged user to cause a denial of service.
    (CVE-2011-2496, Moderate)

  - GRO (Generic Receive Offload) fields could be left in an
    inconsistent state. An attacker on the local network
    could use this flaw to cause a denial of service. GRO is
    enabled by default in all network drivers that support
    it. (CVE-2011-2723, Moderate)

  - A previous update introduced a regression in the
    Ethernet bridge implementation. If a system had an
    interface in a bridge, and an attacker on the local
    network could send packets to that interface, they could
    cause a denial of service on that system. Xen hypervisor
    and KVM (Kernel-based Virtual Machine) hosts often
    deploy bridge interfaces. (CVE-2011-2942, Moderate)

  - A flaw in the Xen hypervisor IOMMU error handling
    implementation could allow a privileged guest user,
    within a guest operating system that has direct control
    of a PCI device, to cause performance degradation on the
    host and possibly cause it to hang. (CVE-2011-3131,
    Moderate)

  - IPv4 and IPv6 protocol sequence number and fragment ID
    generation could allow a man-in-the-middle attacker to
    inject packets and possibly hijack connections. Protocol
    sequence number and fragment IDs are now more random.
    (CVE-2011-3188, Moderate)

  - A flaw in the kernel's clock implementation could allow
    a local, unprivileged user to cause a denial of service.
    (CVE-2011-3209, Moderate)

  - Non-member VLAN (virtual LAN) packet handling for
    interfaces in promiscuous mode and also using the be2net
    driver could allow an attacker on the local network to
    cause a denial of service. (CVE-2011-3347, Moderate)

  - A flaw in the auerswald USB driver could allow a local,
    unprivileged user to cause a denial of service or
    escalate their privileges by inserting a specially
    crafted USB device. (CVE-2009-4067, Low)

  - A flaw in the Trusted Platform Module (TPM)
    implementation could allow a local, unprivileged user to
    leak information to user space. (CVE-2011-1160, Low)

  - A local, unprivileged user could possibly mount a CIFS
    share that requires authentication without knowing the
    correct password if the mount was already mounted by
    another local user. (CVE-2011-1585, Low)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1110&L=scientific-linux-errata&T=0&P=2276
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeedc209"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-274.7.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-274.7.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
