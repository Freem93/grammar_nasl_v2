#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0233 and 
# Oracle Linux Security Advisory ELSA-2008-0233 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67683);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2007-5498", "CVE-2008-0007", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1619", "CVE-2008-1669");
  script_bugtraq_id(29003, 29076);
  script_osvdb_id(44874, 44929, 44990);
  script_xref(name:"RHSA", value:"2008:0233");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2008-0233)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0233 :

Updated kernel packages that fix various security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

These updated packages fix the following security issues :

* the absence of a protection mechanism when attempting to access a
critical section of code has been found in the Linux kernel open file
descriptors control mechanism, fcntl. This could allow a local
unprivileged user to simultaneously execute code, which would
otherwise be protected against parallel execution. As well, a race
condition when handling locks in the Linux kernel fcntl functionality,
may have allowed a process belonging to a local unprivileged user to
gain re-ordered access to the descriptor table. (CVE-2008-1669,
Important)

* a possible hypervisor panic was found in the Linux kernel. A
privileged user of a fully virtualized guest could initiate a
stress-test File Transfer Protocol (FTP) transfer between the guest
and the hypervisor, possibly leading to hypervisor panic.
(CVE-2008-1619, Important)

* the absence of a protection mechanism when attempting to access a
critical section of code, as well as a race condition, have been found
in the Linux kernel file system event notifier, dnotify. This could
allow a local unprivileged user to get inconsistent data, or to send
arbitrary signals to arbitrary system processes. (CVE-2008-1375,
Important)

Red Hat would like to thank Nick Piggin for responsibly disclosing the
following issue :

* when accessing kernel memory locations, certain Linux kernel drivers
registering a fault handler did not perform required range checks. A
local unprivileged user could use this flaw to gain read or write
access to arbitrary kernel memory, or possibly cause a kernel crash.
(CVE-2008-0007, Important)

* the absence of sanity-checks was found in the hypervisor block
backend driver, when running 32-bit paravirtualized guests on a 64-bit
host. The number of blocks to be processed per one request from guest
to host, or vice-versa, was not checked for its maximum value, which
could have allowed a local privileged user of the guest operating
system to cause a denial of service. (CVE-2007-5498, Important)

* it was discovered that the Linux kernel handled string operations in
the opposite way to the GNU Compiler Collection (GCC). This could
allow a local unprivileged user to cause memory corruption.
(CVE-2008-1367, Low)

As well, these updated packages fix the following bugs :

* on IBM System z architectures, when running QIOASSIST enabled QDIO
devices in an IBM z/VM environment, the output queue stalled under
heavy load. This caused network performance to degrade, possibly
causing network hangs and outages.

* multiple buffer overflows were discovered in the neofb video driver.
It was not possible for an unprivileged user to exploit these issues,
and as such, they have not been handled as security issues.

* when running Microsoft Windows in a HVM, a bug in vmalloc/vfree
caused network performance to degrade.

* on certain architectures, a bug in the libATA sata_nv driver may
have caused infinite reboots, and an 'ata1: CPB flags CMD err flags
0x11' error.

* repeatedly hot-plugging a PCI Express card may have caused 'Bad
DLLP' errors.

* a NULL pointer dereference in NFS, which may have caused
applications to crash, has been resolved.

* when attempting to kexec reboot, either manually or via a
panic-triggered kdump, the Unisys ES7000/one hanged after rebooting in
the new kernel, after printing the 'Memory: 32839688k/33685504k
available' line.

Red Hat Enterprise Linux 5 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-May/000588.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 362, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/08");
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
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-53.1.19.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-53.1.19.0.1.el5")) flag++;


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
