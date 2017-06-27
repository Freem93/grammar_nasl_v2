#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63183);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/12/14 11:49:00 $");

  script_cve_id("CVE-2012-2372", "CVE-2012-3552", "CVE-2012-4508", "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-5513");

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
"Security fixes :

  - A race condition in the way asynchronous I/O and
    fallocate() interacted when using ext4 could allow a
    local, unprivileged user to obtain random data from a
    deleted file. (CVE-2012-4508, Important)

  - A flaw in the way the Xen hypervisor implementation
    range checked guest provided addresses in the
    XENMEM_exchange hypercall could allow a malicious,
    para-virtualized guest administrator to crash the
    hypervisor or, potentially, escalate their privileges,
    allowing them to execute arbitrary code at the
    hypervisor level. (CVE-2012-5513, Important)

  - A flaw in the Reliable Datagram Sockets (RDS) protocol
    implementation could allow a local, unprivileged user to
    cause a denial of service. (CVE-2012-2372, Moderate)

  - A race condition in the way access to inet->opt
    ip_options was synchronized in the Linux kernel's TCP/IP
    protocol suite implementation. Depending on the network
    facing applications running on the system, a remote
    attacker could possibly trigger this flaw to cause a
    denial of service. A local, unprivileged user could use
    this flaw to cause a denial of service regardless of the
    applications the system runs. (CVE-2012-3552, Moderate)

  - The Xen hypervisor implementation did not properly
    restrict the period values used to initialize per VCPU
    periodic timers. A privileged guest user could cause an
    infinite loop on the physical CPU. If the watchdog were
    enabled, it would detect said loop and panic the host
    system. (CVE-2012-4535, Moderate)

  - A flaw in the way the Xen hypervisor implementation
    handled set_p2m_entry() error conditions could allow a
    privileged, fully-virtualized guest user to crash the
    hypervisor. (CVE-2012-4537, Moderate)

Bug fixes :

  - Previously, the interrupt handlers of the qla2xxx driver
    could clear pending interrupts right after the IRQ lines
    were attached during system start-up. Consequently, the
    kernel could miss the interrupt that reported completion
    of the link initialization, and the qla2xxx driver then
    failed to detect all attached LUNs. With this update,
    the qla2xxx driver has been modified to no longer clear
    interrupt bits after attaching the IRQ lines. The driver
    now correctly detects all attached LUNs as expected.

  - The Ethernet channel bonding driver reported the MII
    (Media Independent Interface) status of the bond
    interface in 802.3ad mode as being up even though the
    MII status of all of the slave devices was down. This
    could pose a problem if the MII status of the bond
    interface was used to determine if failover should
    occur. With this update, the agg_device_up() function
    has been added to the bonding driver, which allows the
    driver to report the link status of the bond interface
    correctly, that is, down when all of its slaves are
    down, in the 802.3ad mode.

Enhancements :

  - This update backports several changes from the latest
    upstream version of the bnx2x driver. The most important
    change, the remote-fault link detection feature, allows
    the driver to periodically scan the physical link layer
    for remote faults. If the physical link appears to be up
    and a fault is detected, the driver indicates that the
    link is down. When the fault is cleared, the driver
    indicates that the link is up again.

  - The INET socket interface has been modified to send a
    warning message when the ip_options structure is
    allocated directly by a third-party module using the
    kmalloc() function.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1212&L=scientific-linux-errata&T=0&P=308
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00576769"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-308.24.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-308.24.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
