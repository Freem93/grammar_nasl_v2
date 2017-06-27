#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1438 and 
# CentOS Errata and Security Advisory 2009:1438 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43790);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-1883", "CVE-2009-1895", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-3238");
  script_bugtraq_id(35647, 35930);
  script_osvdb_id(55807, 57264, 58234, 58235);
  script_xref(name:"RHSA", value:"2009:1438");

  script_name(english:"CentOS 4 : kernel (CESA-2009:1438)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and several
bugs are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared
when a setuid or setgid program was executed. A local, unprivileged
user could use this flaw to bypass the mmap_min_addr protection
mechanism and perform a NULL pointer dereference attack, or bypass the
Address Space Layout Randomization (ASLR) security feature.
(CVE-2009-1895, Important)

* it was discovered that, when executing a new process, the
clear_child_tid pointer in the Linux kernel is not cleared. If this
pointer points to a writable portion of the memory of the new program,
the kernel could corrupt four bytes of memory, possibly leading to a
local denial of service or privilege escalation. (CVE-2009-2848,
Important)

* Solar Designer reported a missing capability check in the z90crypt
driver in the Linux kernel. This missing check could allow a local
user with an effective user ID (euid) of 0 to bypass intended
capability restrictions. (CVE-2009-1883, Moderate)

* a flaw was found in the way the do_sigaltstack() function in the
Linux kernel copies the stack_t structure to user-space. On 64-bit
machines, this flaw could lead to a four-byte information leak.
(CVE-2009-2847, Moderate)

This update also fixes the following bugs :

* the gcc flag '-fno-delete-null-pointer-checks' was added to the
kernel build options. This prevents gcc from optimizing out NULL
pointer checks after the first use of a pointer. NULL pointer bugs are
often exploited by attackers. Keeping these checks is a safety
measure. (BZ#517964)

* the Emulex LPFC driver has been updated to version 8.0.16.47, which
fixes a memory leak that caused memory allocation failures and system
hangs. (BZ#513192)

* an error in the MPT Fusion driver makefile caused CSMI ioctls to not
work with Serial Attached SCSI devices. (BZ#516184)

* this update adds the mmap_min_addr tunable and restriction checks to
help prevent unprivileged users from creating new memory mappings
below the minimum address. This can help prevent the exploitation of
NULL pointer deference bugs. Note that mmap_min_addr is set to zero
(disabled) by default for backwards compatibility. (BZ#517904)

* time-outs resulted in I/O errors being logged to '/var/log/messages'
when running 'mt erase' on tape drives using certain LSI MegaRAID SAS
adapters, preventing the command from completing. The megaraid_sas
driver's timeout value is now set to the OS layer value. (BZ#517965)

* a locking issue caused the qla2xxx ioctl module to hang after
encountering errors. This locking issue has been corrected. This ioctl
module is used by the QLogic SAN management tools, such as SANsurfer
and scli. (BZ#519428)

* when a RAID 1 array that uses the mptscsi driver and the LSI 1030
controller became degraded, the whole array was detected as being
offline, which could cause kernel panics at boot or data loss.
(BZ#517295)

* on 32-bit architectures, if a file was held open and frequently
written for more than 25 days, it was possible that the kernel would
stop flushing those writes to storage. (BZ#515255)

* a memory allocation bug in ib_mthca prevented the driver from
loading if it was loaded with large values for the 'num_mpt=' and
'num_mtt=' options. (BZ#518707)

* with this update, get_random_int() is more random and no longer uses
a common seed value, reducing the possibility of predicting the values
returned. (BZ#519692)

* a bug in __ptrace_unlink() caused it to create deadlocked and
unkillable processes. (BZ#519446)

* previously, multiple threads using the fcntl() F_SETLK command to
synchronize file access caused a deadlock in posix_locks_deadlock().
This could cause a system hang. (BZ#519429)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016165.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e588b518"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016166.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea3ba178"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 264, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-devel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-devel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-89.0.11.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-89.0.11.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
