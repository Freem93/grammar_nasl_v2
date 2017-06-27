#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1061 and 
# Oracle Linux Security Advisory ELSA-2012-1061 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68574);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:07:16 $");

  script_cve_id("CVE-2012-3375");
  script_bugtraq_id(46630, 53856, 53961, 54283);
  script_osvdb_id(83687);
  script_xref(name:"RHSA", value:"2012:1061");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2012-1061)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:1061 :

Updated kernel packages that fix one security issue and multiple bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fix :

* The fix for CVE-2011-1083 (RHSA-2012:0150) introduced a flaw in the
way the Linux kernel's Event Poll (epoll) subsystem handled resource
clean up when an ELOOP error code was returned. A local, unprivileged
user could use this flaw to cause a denial of service. (CVE-2012-3375,
Moderate)

Bug fixes :

* The qla2xxx driver handled interrupts for QLogic Fibre Channel
adapters incorrectly due to a bug in a test condition for MSI-X
support. This update corrects the bug and qla2xxx now handles
interrupts as expected. (BZ#816373)

* A process scheduler did not handle RPC priority wait queues
correctly. Consequently, the process scheduler failed to wake up all
scheduled tasks as expected after RPC timeout, which caused the system
to become unresponsive and could significantly decrease system
performance. This update modifies the process scheduler to handle RPC
priority wait queues as expected. All scheduled tasks are now properly
woken up after RPC timeout and the system behaves as expected.
(BZ#817571)

* The kernel version 2.6.18-308.4.1.el5 contained several bugs which
led to an overrun of the NFS server page array. Consequently, any
attempt to connect an NFS client running on Red Hat Enterprise Linux
5.8 to the NFS server running on the system with this kernel caused
the NFS server to terminate unexpectedly and the kernel to panic. This
update corrects the bugs causing NFS page array overruns and the
kernel no longer crashes in this scenario. (BZ#820358)

* An insufficiently designed calculation in the CPU accelerator in the
previous kernel caused an arithmetic overflow in the sched_clock()
function when system uptime exceeded 208.5 days. This overflow led to
a kernel panic on the systems using the Time Stamp Counter (TSC) or
Virtual Machine Interface (VMI) clock source. This update corrects the
calculation so that this arithmetic overflow and kernel panic can no
longer occur under these circumstances.

Note: This advisory does not include a fix for this bug for the 32-bit
architecture. (BZ#824654)

* Under memory pressure, memory pages that are still a part of a
checkpointing transaction can be invalidated. However, when the pages
were invalidated, the journal head was re-filed onto the transactions'
'forget' list, which caused the current running transaction's block to
be modified. As a result, block accounting was not properly performed
on that modified block because it appeared to have already been
modified due to the journal head being re-filed. This could trigger an
assertion failure in the 'journal_commit_transaction()' function on
the system. The 'b_modified' flag is now cleared before the journal
head is filed onto any transaction; assertion failures no longer
occur. (BZ#827205)

* When running more than 30 instances of the cclengine utility
concurrently on IBM System z with IBM Communications Controller for
Linux, the system could become unresponsive. This was caused by a
missing wake_up() function call in the qeth_release_buffer() function
in the QETH network device driver. This update adds the missing
wake_up() function call and the system now responds as expected in
this scenario. (BZ#829059)

* Recent changes removing support for the Flow Director from the ixgbe
driver introduced bugs that caused the RSS (Receive Side Scaling)
functionality to stop working correctly on Intel 82599EB 10 Gigabit
Ethernet network devices. This update corrects the return code in the
ixgbe_cache_ring_fdir function and setting of the registers that
control the RSS redirection table. Also, obsolete code related to Flow
Director support has been removed. The RSS functionality now works as
expected on these devices. (BZ#832169)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002924.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-308.11.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-308.11.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
