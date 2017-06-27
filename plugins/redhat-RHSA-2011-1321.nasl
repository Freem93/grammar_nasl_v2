#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1321. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(64003);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/02 18:01:07 $");

  script_cve_id("CVE-2011-2723");
  script_bugtraq_id(48929);
  script_osvdb_id(74138);
  script_xref(name:"RHSA", value:"2011:1321");

  script_name(english:"RHEL 5 : kernel (RHSA-2011:1321)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 5.6 Extended Update
Support.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The kernel packages contain the Linux kernel.

Security fix :

* A flaw in skb_gro_header_slow() in the Linux kernel could lead to
GRO (Generic Receive Offload) fields being left in an inconsistent
state. An attacker on the local network could use this flaw to trigger
a denial of service. (CVE-2011-2723, Moderate)

Red Hat would like to thank Brent Meshier for reporting this issue.

Bug fixes :

* When reading a file from a subdirectory in /proc/bus/pci/ while
hot-unplugging the device related to that file, the system will crash.
Now, the kernel correctly handles the simultaneous removal of a device
and access to the representation of that device in the proc file
system. (BZ#713454)

* RHSA-2011:0017 introduced a regression: Non-disk SCSI devices
(except for tape drives) such as enclosure or CD-ROM devices were
hidden when attached to a SAS based RAID controller that uses the
megaraid_sas driver. With this update, such devices are accessible, as
expected. (BZ#726487)

* The fix for CVE-2010-3432 provided in RHSA-2011:0004 introduced a
regression: Information in sctp_packet_config(), which was called
before appending data chunks to a packet, was not reset, causing
considerably poor SCTP (Stream Control Transmission Protocol)
performance. With this update, the packet information is reset after
transmission. (BZ#727591)

* Certain systems do not correctly set the ACPI FADT APIC mode bit.
They set the bit to 'cluster' mode instead of 'physical' mode which
caused these systems to boot without the TSC (Time Stamp Counter).
With this update, the ACPI FADT check has been removed due to its
unreliability. (BZ#728162)

* Performance when invalidating and rereading cached data as a glock
moves around the cluster with GFS2 is improved. (BZ#729082)

* Performance issues occurred when multiple nodes attempted to call
mmap() on the same inode at the same time on a GFS2 file system, as it
was using an exclusive glock. With this update, a shared lock is used
when 'noatime' is set on the mount, allowing mmap() operations to
occur in parallel, fixing this bug. Note that this issue only refers
to mmap() system calls, and not to subsequent page faults. (BZ#729090)

* Some of the functions in the GFS2 file system were not reserving
enough space for the resource group header in a transaction and for
resource groups bit blocks that get added when a memory allocation is
performed. That resulted in failed write and allocation operations.
With this update, GFS2 makes sure to reserve space in the described
scenario, using the new gfs2_rg_blocks() inline function. (BZ#729092)

* When GFS2 grew the file system, it never reread the rindex file
during the grow. This is necessary for large grows when the file
system is almost full, and GFS2 needs to use some of the space
allocated earlier in the grow to complete it. Now, if GFS2 fails to
reserve the necessary space and the rindex data is not up-to-date, it
rereads it. (BZ#729094)

* Previously, when the Xen hypervisor split a 2 MB page into 4 KB
pages, it linked the new page from PDE (Page Directory Entry) before
it filled entries of the page with appropriate data. Consequently,
when doing a live migration with EPT (Extended Page Tables) enabled on
a non-idle guest running with more than two virtual CPUs, the guest
often terminated unexpectedly. With this update, the Xen hypervisor
prepares the page table entry first, and then links it in. (BZ#730684)

* Changes made to TSC as a clock source for IRQs caused virtual
machines running under the VMware ESX or ESXi hypervisors to become
unresponsive during the initial kernel boot process. With this update,
the enable_tsc_timer flag enables the do_timer_tsc_timekeeping()
function to be called in the do_timer_interrupt_hook() function,
preventing a deadlock in the timer interrupt handler. (BZ#730688)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2723.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1321.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-debug-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", reference:"kernel-doc-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"kernel-headers-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-headers-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-headers-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i686", reference:"kernel-xen-devel-2.6.18-238.27.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-238.27.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
