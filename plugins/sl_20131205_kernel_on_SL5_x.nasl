#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71305);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/10 14:13:50 $");

  script_cve_id("CVE-2013-4355");

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
"  - An information leak flaw was found in the way the Xen
    hypervisor handled error conditions when reading guest
    memory during certain guest-originated operations, such
    as port or memory mapped I/O writes. A privileged user
    in a fully-virtualized guest could use this flaw to leak
    hypervisor stack memory to a guest. (CVE-2013-4355,
    Moderate)

This update also fixes the following bugs :

  - A previous fix to the kernel did not contain a memory
    barrier in the percpu_up_write() function. Consequently,
    under certain circumstances, a race condition could
    occur leading to memory corruption and a subsequent
    kernel panic. This update introduces a new memory
    barrier pair, light_mb() and heavy_mb(), for per-CPU
    basis read and write semaphores (percpu-rw- semaphores)
    ensuring that the race condition can no longer occur. In
    addition, the read path performance of
    'percpu-rw-semaphores' has been improved.

  - Due to a bug in the tg3 driver, systems that had the
    Wake-on-LAN (WOL) feature enabled on their NICs could
    not have been woken up from suspension or hibernation
    using WOL. A missing pci_wake_from_d3() function call
    has been added to the tg3 driver, which ensures that WOL
    functions properly by setting the PME_ENABLE bit.

  - Due to an incorrect test condition in the mpt2sas
    driver, the driver was unable to catch failures to map a
    SCSI scatter-gather list. The test condition has been
    corrected so that the mpt2sas driver now handles SCSI
    scatter-gather mapping failures as expected.

  - A previous patch to the kernel introduced the 'VLAN tag
    re-insertion' workaround to resolve a problem with
    incorrectly handled VLAN-tagged packets with no assigned
    VLAN group while the be2net driver was in promiscuous
    mode. However, this solution led to packet corruption
    and a subsequent kernel oops if such a processed packed
    was a GRO packet. Therefore, a patch has been applied to
    restrict VLAN tag re-insertion only to non-GRO packets.
    The be2net driver now processes VLAN-tagged packets with
    no assigned VLAN group correctly in this situation.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=1551
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8be9890e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-371.3.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-371.3.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
