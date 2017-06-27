#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(62428);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-2319", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3510");

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

  - A flaw was found in the way socket buffers (skb)
    requiring TSO (TCP segment offloading) were handled by
    the sfc driver. If the skb did not fit within the
    minimum-size of the transmission queue, the network card
    could repeatedly reset itself. A remote attacker could
    use this flaw to cause a denial of service.
    (CVE-2012-3412, Important)

  - A use-after-free flaw was found in the xacct_add_tsk()
    function in the Linux kernel's taskstats subsystem. A
    local, unprivileged user could use this flaw to cause an
    information leak or a denial of service. (CVE-2012-3510,
    Moderate)

  - A buffer overflow flaw was found in the hfs_bnode_read()
    function in the HFS Plus (HFS+) file system
    implementation in the Linux kernel. A local user able to
    mount a specially crafted HFS+ file system image could
    use this flaw to cause a denial of service or escalate
    their privileges. (CVE-2012-2319, Low)

  - A flaw was found in the way the msg_namelen variable in
    the rds_recvmsg() function of the Linux kernel's
    Reliable Datagram Sockets (RDS) protocol implementation
    was initialized. A local, unprivileged user could use
    this flaw to leak kernel stack memory to user-space.
    (CVE-2012-3430, Low)

This update also fixes the following bugs :

  - The cpuid_whitelist() function, masking the Enhanced
    Intel SpeedStep (EST) flag from all guests, prevented
    the 'cpuspeed' service from working in the privileged
    Xen domain (dom0). CPU scaling was therefore not
    possible. With this update, cpuid_whitelist() is aware
    whether the domain executing CPUID is privileged or not,
    and enables the EST flag for dom0.

  - If a delayed-allocation write was performed before quota
    was enabled, the kernel displayed the following warning
    message :

    WARNING: at fs/quota/dquot.c:988
    dquot_claim_space+0x77/0x112()

This was because information about the delayed allocation was not
recorded in the quota structure. With this update, writes prior to
enabling quota are properly accounted for, and the message is not
displayed.

  - Some subsystems clear the TIF_SIGPENDING flag during
    error handling in fork() paths. Previously, if the flag
    was cleared, the ERESTARTNOINTR error code could be
    returned. The underlying source code has been modified
    so that the error code is no longer returned.

  - An unnecessary check for the RXCW.CW bit could cause the
    Intel e1000e NIC (Network Interface Controller) to not
    work properly. The check has been removed so that the
    Intel e1000e NIC works as expected.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1210&L=scientific-linux-errata&T=0&P=1097
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b64ae118"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/04");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-aufs-2.6.18-308.16.1.el5-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-aufs-2.6.18-308.16.1.el5PAE-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-aufs-2.6.18-308.16.1.el5xen-0.20090202.cvs-6.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ipw3945-2.6.18-308.16.1.el5-1.2.0-2.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ipw3945-2.6.18-308.16.1.el5PAE-1.2.0-2.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ipw3945-2.6.18-308.16.1.el5xen-1.2.0-2.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-308.16.1.el5-1.55-1.SL")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ndiswrapper-2.6.18-308.16.1.el5PAE-1.55-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-308.16.1.el5xen-1.55-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.16.1.el5-1.4.14-80.1.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-308.16.1.el5PAE-1.4.14-80.1.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-308.16.1.el5xen-1.4.14-80.1.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-xfs-2.6.18-308.16.1.el5-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-xfs-2.6.18-308.16.1.el5PAE-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-xfs-2.6.18-308.16.1.el5xen-0.4-2.sl5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-308.16.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-308.16.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
