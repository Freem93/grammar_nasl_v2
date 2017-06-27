#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1466. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63898);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/09 14:34:06 $");

  script_cve_id("CVE-2009-2847", "CVE-2009-2848");
  script_xref(name:"RHSA", value:"2009:1466");

  script_name(english:"RHEL 5 : kernel (RHSA-2009:1466)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 5.3 Extended Update
Support.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update includes backported fixes for two security issues. These
issues only affected users of Red Hat Enterprise Linux 5.3 Extended
Update Support as they have already been addressed for users of Red
Hat Enterprise Linux 5 in the 5.4 update, RHSA-2009:1243.

In accordance with the support policy, future security updates to Red
Hat Enterprise Linux 5.3 Extended Update Support will only include
issues of critical security impact.

This update fixes the following security issues :

* it was discovered that, when executing a new process, the
clear_child_tid pointer in the Linux kernel is not cleared. If this
pointer points to a writable portion of the memory of the new program,
the kernel could corrupt four bytes of memory, possibly leading to a
local denial of service or privilege escalation. (CVE-2009-2848,
Important)

* a flaw was found in the way the do_sigaltstack() function in the
Linux kernel copies the stack_t structure to user-space. On 64-bit
machines, this flaw could lead to a four-byte information leak.
(CVE-2009-2847, Moderate)

This update also fixes the following bugs :

* a regression was found in the SCSI retry logic: SCSI mode select was
not retried when retryable errors were encountered. In Device-Mapper
Multipath environments, this could cause paths to fail, or possibly
prevent successful failover. (BZ#506905)

* the gcc flag '-fno-delete-null-pointer-checks' was added to the
kernel build options. This prevents gcc from optimizing out NULL
pointer checks after the first use of a pointer. NULL pointer bugs are
often exploited by attackers, and keeping these checks is considered a
safety measure. (BZ#515468)

* due to incorrect APIC timer calibration, a system hang could have
occurred while booting certain systems. This incorrect timer
calibration could have also caused the system time to become faster or
slower. With this update, it is still possible for APIC timer
calibration issues to occur; however, a clear warning is now provided
if they do. (BZ#521237)

* gettimeofday() experienced poor performance (which caused
performance problems for applications using gettimeofday()) when
running on hypervisors that use hardware assisted virtualization. With
this update, MFENCE/LFENCE is used instead of CPUID for gettimeofday()
serialization, which resolves this issue. (BZ#523280)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1466.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-PAE-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-PAE-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-debug-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-debug-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-debug-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-debug-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-debug-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-debug-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", reference:"kernel-doc-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"kernel-headers-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-headers-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-headers-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-kdump-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"kernel-kdump-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-xen-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-xen-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i686", reference:"kernel-xen-devel-2.6.18-128.8.1.el5")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-2.6.18-128.8.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
