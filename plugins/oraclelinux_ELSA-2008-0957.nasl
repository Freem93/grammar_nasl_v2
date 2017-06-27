#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0957 and 
# Oracle Linux Security Advisory ELSA-2008-0957 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67758);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2006-5755", "CVE-2007-5907", "CVE-2008-2372", "CVE-2008-3276", "CVE-2008-3527", "CVE-2008-3833", "CVE-2008-4210", "CVE-2008-4302");
  script_bugtraq_id(31368);
  script_osvdb_id(41346, 49898, 50248);
  script_xref(name:"RHSA", value:"2008:0957");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2008-0957)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0957 :

Updated kernel packages that resolve several security issues and fix
various bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

[Updated 12th November 2008] The original packages distributed with
this errata had a bug which prevented the Xen kernel booting on older
hardware. We have updated the packages to correct this bug.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* the Xen implementation did not prevent applications running in a
para-virtualized guest from modifying CR4 TSC. This could cause a
local denial of service. (CVE-2007-5907, Important)

* Tavis Ormandy reported missing boundary checks in the Virtual
Dynamic Shared Objects (vDSO) implementation. This could allow a local
unprivileged user to cause a denial of service or escalate privileges.
(CVE-2008-3527, Important)

* the do_truncate() and generic_file_splice_write() functions did not
clear the setuid and setgid bits. This could allow a local
unprivileged user to obtain access to privileged information.
(CVE-2008-4210, CVE-2008-3833, Important)

* a flaw was found in the Linux kernel splice implementation. This
could cause a local denial of service when there is a certain failure
in the add_to_page_cache_lru() function. (CVE-2008-4302, Important)

* a flaw was found in the Linux kernel when running on AMD64 systems.
During a context switch, EFLAGS were being neither saved nor restored.
This could allow a local unprivileged user to cause a denial of
service. (CVE-2006-5755, Low)

* a flaw was found in the Linux kernel virtual memory implementation.
This could allow a local unprivileged user to cause a denial of
service. (CVE-2008-2372, Low)

* an integer overflow was discovered in the Linux kernel Datagram
Congestion Control Protocol (DCCP) implementation. This could allow a
remote attacker to cause a denial of service. By default, remote DCCP
is blocked by SELinux. (CVE-2008-3276, Low)

In addition, these updated packages fix the following bugs :

* random32() seeding has been improved.

* in a multi-core environment, a race between the QP async
event-handler and the destro_qp() function could occur. This led to
unpredictable results during invalid memory access, which could lead
to a kernel crash.

* a format string was omitted in the call to the request_module()
function.

* a stack overflow caused by an infinite recursion bug in the
binfmt_misc kernel module was corrected.

* the ata_scsi_rbuf_get() and ata_scsi_rbuf_put() functions now check
for scatterlist usage before calling kmap_atomic().

* a sentinel NUL byte was added to the device_write() function to
ensure that lspace.name is NUL-terminated.

* in the character device driver, a range_is_allowed() check was added
to the read_mem() and write_mem() functions. It was possible for an
illegitimate application to bypass these checks, and access /dev/mem
beyond the 1M limit by calling mmap_mem() instead. Also, the
parameters of range_is_allowed() were changed to cleanly handle
greater than 32-bits of physical address on 32-bit architectures.

* some of the newer Nehalem-based systems declare their CPU DSDT
entries as type 'Alias'. During boot, this caused an 'Error attaching
device data' message to be logged.

* the evtchn event channel device lacked locks and memory barriers.
This has led to xenstore becoming unresponsive on the Itanium(r)
architecture.

* sending of gratuitous ARP packets in the Xen frontend network driver
is now delayed until the backend signals that its carrier status has
been processed by the stack.

* on forcedeth devices, whenever setting ethtool parameters for link
speed, the device could stop receiving interrupts.

* the CIFS 'forcedirectio' option did not allow text to be appended to
files.

* the gettimeofday() function returned a backwards time on Intel(r) 64.

* residual-count corrections during UNDERRUN handling were added to
the qla2xxx driver.

* the fix for a small quirk was removed for certain Adaptec
controllers for which it caused problems.

* the 'xm trigger init' command caused a domain panic if a userland
application was running on a guest on the Intel(r) 64 architecture.

Users of kernel should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-November/000785.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189, 264, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/05");
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
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-92.1.17.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-92.1.17.0.1.el5")) flag++;


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
