#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60705);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-2910", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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
"This update fixes the following security issues :

  - a flaw was found in the Realtek r8169 Ethernet driver in
    the Linux kernel. pci_unmap_single() presented a memory
    leak that could lead to IOMMU space exhaustion and a
    system crash. An attacker on the local network could
    trigger this flaw by using jumbo frames for large
    amounts of network traffic. (CVE-2009-3613, Important)

  - NULL pointer dereference flaws were found in the r128
    driver in the Linux kernel. Checks to test if the
    Concurrent Command Engine state was initialized were
    missing in private IOCTL functions. An attacker could
    use these flaws to cause a local denial of service or
    escalate their privileges. (CVE-2009-3620, Important)

  - an information leak was found in the Linux kernel. On
    AMD64 systems, 32-bit processes could access and read
    certain 64-bit registers by temporarily switching
    themselves to 64-bit mode. (CVE-2009-2910, Moderate)

  - the unix_stream_connect() function in the Linux kernel
    did not check if a UNIX domain socket was in the
    shutdown state. This could lead to a deadlock. A local,
    unprivileged user could use this flaw to cause a denial
    of service. (CVE-2009-3621, Moderate)

This update also fixes the following bugs :

  - an iptables rule with the recent module and a hit count
    value greater than the ip_pkt_list_tot parameter (the
    default is 20), did not have any effect over packets, as
    the hit count could not be reached. (BZ#529306)

  - in environments that use dual-controller storage devices
    with the cciss driver, Device-Mapper Multipath maps
    could not be detected and configured, due to the cciss
    driver not exporting the bus attribute via sysfs. This
    attribute is now exported. (BZ#529309)

  - the kernel crashed with a divide error when a certain
    joystick was attached. (BZ#532027)

  - a bug in the mptctl_do_mpt_command() function in the mpt
    driver may have resulted in crashes during boot on i386
    systems with certain adapters using the mpt driver, and
    also running the hugemem kernel. (BZ#533798)

  - on certain hardware, the igb driver was unable to detect
    link statuses correctly. This may have caused problems
    for network bonding, such as failover not occurring.
    (BZ#534105)

  - the RHSA-2009:1024 update introduced a regression. After
    updating to Scientific Linux 4.8 and rebooting, network
    links often failed to be brought up for interfaces using
    the forcedeth driver. 'no link during initialization'
    messages may have been logged. (BZ#534112)

  - the RHSA-2009:1024 update introduced a second
    regression. On certain systems, PS/2 keyboards failed to
    work. (BZ#537344)

  - a bug in checksum offload calculations could have
    crashed the bnx2x firmware when the iptable_nat module
    was loaded, causing network traffic to stop. (BZ#537013)

  - a check has been added to the IPv4 code to make sure
    that the routing table data structure, rt, is not NULL,
    to help prevent future bugs in functions that call
    ip_append_data() from being exploitable. (BZ#537016)

  - possible kernel pointer dereferences on systems with
    several NFS mounts (a mixture of '-o lock' and '-o
    nolock'), which in rare cases may have caused a system
    crash, have been resolved. (BZ#537017)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0912&L=scientific-linux-errata&T=0&P=2135
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14664178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=532027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=533798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=534105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=534112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537344"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-89.0.18.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-89.0.18.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
