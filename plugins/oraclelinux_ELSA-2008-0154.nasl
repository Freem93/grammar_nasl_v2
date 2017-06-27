#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0154 and 
# Oracle Linux Security Advisory ELSA-2008-0154 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67659);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2006-6921", "CVE-2007-5938", "CVE-2007-6063", "CVE-2007-6207", "CVE-2007-6694");
  script_bugtraq_id(26605);
  script_osvdb_id(40911, 41341, 44749);
  script_xref(name:"RHSA", value:"2008:0154");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2008-0154)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0154 :

Updated kernel packages that fix various security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages fix the following security issues :

* a flaw in the hypervisor for hosts running on Itanium architectures
allowed an Intel VTi domain to read arbitrary physical memory from
other Intel VTi domains, which could make information available to
unauthorized users. (CVE-2007-6207, Important)

* two buffer overflow flaws were found in ISDN subsystem. A local
unprivileged user could use these flaws to cause a denial of service.
(CVE-2007-5938: Important, CVE-2007-6063: Moderate)

* a possible NULL pointer dereference was found in the subsystem used
for showing CPU information, as used by CHRP systems on PowerPC
architectures. This may have allowed a local unprivileged user to
cause a denial of service (crash). (CVE-2007-6694, Moderate)

* a flaw was found in the handling of zombie processes. A local user
could create processes that would not be properly reaped, possibly
causing a denial of service. (CVE-2006-6921, Moderate)

As well, these updated packages fix the following bugs :

* a bug was found in the Linux kernel audit subsystem. When the audit
daemon was setup to log the execve system call with a large number of
arguments, the kernel could run out of memory, causing a kernel panic.

* on IBM System z architectures, using the IBM Hardware Management
Console to toggle IBM FICON channel path ids (CHPID) caused a file ID
miscompare, possibly causing data corruption.

* when running the IA-32 Execution Layer (IA-32EL) or a Java VM on
Itanium architectures, a bug in the address translation in the
hypervisor caused the wrong address to be registered, causing Dom0 to
hang.

* on Itanium architectures, frequent Corrected Platform Error errors
may have caused the hypervisor to hang.

* when enabling a CPU without hot plug support, routines for checking
the presence of the CPU were missing. The CPU tried to access its own
resources, causing a kernel panic.

* after updating to kernel-2.6.18-53.el5, a bug in the CCISS driver
caused the HP Array Configuration Utility CLI to become unstable,
possibly causing a system hang, or a kernel panic.

* a bug in NFS directory caching could have caused different hosts to
have different views of NFS directories.

* on Itanium architectures, the Corrected Machine Check Interrupt
masked hot-added CPUs as disabled.

* when running Oracle database software on the Intel 64 and AMD64
architectures, if an SGA larger than 4GB was created, and had
hugepages allocated to it, the hugepages were not freed after database
shutdown.

* in a clustered environment, when two or more NFS clients had the
same logical volume mounted, and one of them modified a file on the
volume, NULL characters may have been inserted, possibly causing data
corruption.

These updated packages resolve several severe issues in the lpfc
driver :

* a system hang after LUN discovery.

* a general fault protection, a NULL pointer dereference, or slab
corruption could occur while running a debug on the kernel.

* the inability to handle kernel paging requests in
'lpfc_get_scsi_buf'.

* erroneous structure references caused certain FC discovery routines
to reference and change 'lpfc_nodelist' structures, even after they
were freed.

* the lpfc driver failed to interpret certain fields correctly,
causing tape backup software to fail. Tape drives reported 'Illegal
Request'.

* the lpfc driver did not clear structures correctly, resulting in
SCSI I/Os being rejected by targets, and causing errors.

Red Hat Enterprise Linux 5 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-March/000535.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-53.1.14.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-53.1.14.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
