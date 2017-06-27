#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61083);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2010-4649", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-1182", "CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1593", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1776", "CVE-2011-1936", "CVE-2011-2213", "CVE-2011-2492");

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

This update fixes the following security issues :

  - An integer overflow flaw in ib_uverbs_poll_cq() could
    allow a local, unprivileged user to cause a denial of
    service or escalate their privileges. (CVE-2010-4649,
    Important)

  - A race condition in the way new InfiniBand connections
    were set up could allow a remote user to cause a denial
    of service. (CVE-2011-0695, Important)

  - A flaw in the Stream Control Transmission Protocol
    (SCTP) implementation could allow a remote attacker to
    cause a denial of service if the sysctl
    'net.sctp.addip_enable' variable was turned on (it is
    off by default). (CVE-2011-1573, Important)

  - Flaws in the AGPGART driver implementation when handling
    certain IOCTL commands could allow a local, unprivileged
    user to cause a denial of service or escalate their
    privileges. (CVE-2011-1745, CVE-2011-2022, Important)

  - An integer overflow flaw in agp_allocate_memory() could
    allow a local, unprivileged user to cause a denial of
    service or escalate their privileges. (CVE-2011-1746,
    Important)

  - A flaw allowed napi_reuse_skb() to be called on VLAN
    (virtual LAN) packets. An attacker on the local network
    could trigger this flaw by sending specially crafted
    packets to a target system, possibly causing a denial of
    service. (CVE-2011-1576, Moderate)

  - An integer signedness error in next_pidmap() could allow
    a local, unprivileged user to cause a denial of service.
    (CVE-2011-1593, Moderate)

  - A flaw in the way the Xen hypervisor implementation
    handled CPUID instruction emulation during virtual
    machine exits could allow an unprivileged guest user to
    crash a guest. This only affects systems that have an
    Intel x86 processor with the Intel VT-x extension
    enabled. (CVE-2011-1936, Moderate)

  - A flaw in inet_diag_bc_audit() could allow a local,
    unprivileged user to cause a denial of service (infinite
    loop). (CVE-2011-2213, Moderate)

  - A missing initialization flaw in the XFS file system
    implementation could lead to an information leak.
    (CVE-2011-0711, Low)

  - A flaw in ib_uverbs_poll_cq() could allow a local,
    unprivileged user to cause an information leak.
    (CVE-2011-1044, Low)

  - A missing validation check was found in the signals
    implementation. A local, unprivileged user could use
    this flaw to send signals via the sigqueueinfo system
    call, with the si_code set to SI_TKILL and with spoofed
    process and user IDs, to other processes. Note: This
    flaw does not allow existing permission checks to be
    bypassed; signals can only be sent if your privileges
    allow you to already do so. (CVE-2011-1182, Low)

  - A heap overflow flaw in the EFI GUID Partition Table
    (GPT) implementation could allow a local attacker to
    cause a denial of service by mounting a disk containing
    specially crafted partition tables. (CVE-2011-1776, Low)

  - Structure padding in two structures in the Bluetooth
    implementation was not initialized properly before being
    copied to user-space, possibly allowing local,
    unprivileged users to leak kernel stack memory to
    user-space. (CVE-2011-2492, Low)

This update fixes several bugs.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1107&L=scientific-linux-errata&T=0&P=1940
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3c2d1ce"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/15");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-238.19.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-238.19.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
