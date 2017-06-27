#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61360);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/04 10:53:00 $");

  script_cve_id("CVE-2012-3375");

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

Security fix :

  - The fix for CVE-2011-1083 introduced a flaw in the way
    the Linux kernel's Event Poll (epoll) subsystem handled
    resource clean up when an ELOOP error code was returned.
    A local, unprivileged user could use this flaw to cause
    a denial of service. (CVE-2012-3375, Moderate)

Bug fixes :

  - The qla2xxx driver handled interrupts for QLogic Fibre
    Channel adapters incorrectly due to a bug in a test
    condition for MSI-X support. This update corrects the
    bug and qla2xxx now handles interrupts as expected.

  - A process scheduler did not handle RPC priority wait
    queues correctly. Consequently, the process scheduler
    failed to wake up all scheduled tasks as expected after
    RPC timeout, which caused the system to become
    unresponsive and could significantly decrease system
    performance. This update modifies the process scheduler
    to handle RPC priority wait queues as expected. All
    scheduled tasks are now properly woken up after RPC
    timeout and the system behaves as expected.

  - The kernel version 2.6.18-308.4.1.el5 contained several
    bugs which led to an overrun of the NFS server page
    array. Consequently, any attempt to connect an NFS
    client running on Scientific Linux 5.8 to the NFS server
    running on the system with this kernel caused the NFS
    server to terminate unexpectedly and the kernel to
    panic. This update corrects the bugs causing NFS page
    array overruns and the kernel no longer crashes in this
    scenario.

  - An insufficiently designed calculation in the CPU
    accelerator in the previous kernel caused an arithmetic
    overflow in the sched_clock() function when system
    uptime exceeded 208.5 days. This overflow led to a
    kernel panic on the systems using the Time Stamp Counter
    (TSC) or Virtual Machine Interface (VMI) clock source.
    This update corrects the calculation so that this
    arithmetic overflow and kernel panic can no longer occur
    under these circumstances.

Note: This advisory does not include a fix for this bug for the 32-bit
architecture.

  - Under memory pressure, memory pages that are still a
    part of a checkpointing transaction can be invalidated.
    However, when the pages were invalidated, the journal
    head was re-filed onto the transactions' 'forget' list,
    which caused the current running transaction's block to
    be modified. As a result, block accounting was not
    properly performed on that modified block because it
    appeared to have already been modified due to the
    journal head being re-filed. This could trigger an
    assertion failure in the 'journal_commit_transaction()'
    function on the system. The 'b_modified' flag is now
    cleared before the journal head is filed onto any
    transaction; assertion failures no longer occur.

  - When running more than 30 instances of the cclengine
    utility concurrently on IBM System z with IBM
    Communications Controller for Linux, the system could
    become unresponsive. This was caused by a missing
    wake_up() function call in the qeth_release_buffer()
    function in the QETH network device driver. This update
    adds the missing wake_up() function call and the system
    now responds as expected in this scenario.

  - Recent changes removing support for the Flow Director
    from the ixgbe driver introduced bugs that caused the
    RSS (Receive Side Scaling) functionality to stop working
    correctly on Intel 82599EB 10 Gigabit Ethernet network
    devices. This update corrects the return code in the
    ixgbe_cache_ring_fdir function and setting of the
    registers that control the RSS redirection table. Also,
    obsolete code related to Flow Director support has been
    removed. The RSS functionality now works as expected on
    these devices.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=4242
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d99753da"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-308.11.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
