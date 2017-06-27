#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-2021.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68676);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/12/01 17:16:03 $");

  script_cve_id("CVE-2012-1179", "CVE-2012-2121", "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2373");
  script_bugtraq_id(52533, 53162, 53166);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2012-2021)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

* CVE-2012-2123: Privilege escalation when assigning permissions using 
fcaps.

If a process increases permissions using fcaps, all of the dangerous
personality flags which are cleared for suid apps are not cleared. This has
allowed programs that gained elevated permissions using fcaps to disable
the address space randomization of other processes.


* CVE-2012-2121: Memory leak in KVM device assignment.

KVM uses memory slots to track and map guest regions of memory.  When 
device
assignment is used, the pages backing these slots are pinned in memory 
and mapped
into the iommu.  The problem is that when a memory slot is destroyed the 
pages
for the associated memory slot are neither unpinned nor unmapped from 
the iommu.


* Memory corruption in KVM device assignment slot handling.

A race condition in the KVM device assignment slot handling caused by
missing locks around the unmapping of memory slots could cause a memory
corruption.


* CVE-2012-2136: Privilege escalation in TUN/TAP virtual device.

The length of packet fragments to be sent wasn't validated before use,
leading to heap overflow. A user having access to TUN/TAP virtual
device could use this flaw to crash the system or to potentially
escalate their privileges.


* CVE-2012-2137: Buffer overflow in KVM MSI routing entry handler.

A buffer overflow flaw was found in the setup_routing_entry() function 
in the
KVM subsystem of the Linux kernel in the way the Message Signaled 
Interrupts
(MSI) routing entry was handled. A local, unprivileged user could use 
this flaw
to cause a denial of service or, possibly, escalate their privileges.


* CVE-2012-1179 and CVE-2012-2373: Hugepage denial of service.

CVE-2012-1179: Denial of service in page mapping of the hugepage subsystem.

In some cases, the hugepage subsystem would allocate new PMDs when not
expected by the memory management subsystem. A privileged user in the
KVM guest can use this flaw to crash the host, an unprivileged local
user could use this flaw to crash the system.

CVE-2012-2373: Denial of service in PAE page tables.

On a PAE system, a non-atomic load could be corrupted by a page fault
resulting in a kernel crash, triggerable by an unprivileged user.


* Regression in handling of bind() with AF_UNSPEC family sockets.

Legacy applications used to bind() with AF_UNSPEC instead of AF_INET. Allow
them to continue doing so, but verify that the address is indeed 
INADDR_ANY.


[2.6.39-100.10.1.el6uek]
- thp: avoid atomic64_read in pmd_read_atomic for 32bit PAE (Andrea 
Arcangeli)
   [Orabug: 14217003]

[2.6.39-100.9.1.el6uek]
- mm: pmd_read_atomic: fix 32bit PAE pmd walk vs pmd_populate SMP race
   condition (Andrea Arcangeli) [Bugdb: 13966] {CVE-2012-2373}
- mm: thp: fix pmd_bad() triggering in code paths holding mmap_sem read 
mode
   (Andrea Arcangeli)  {CVE-2012-1179}
- KVM: Fix buffer overflow in kvm_set_irq() (Avi Kivity) [Bugdb: 13966]
   {CVE-2012-2137}
- net: sock: validate data_len before allocating skb in 
sock_alloc_send_pskb()
   (Jason Wang) [Bugdb: 13966] {CVE-2012-2136}
- KVM: lock slots_lock around device assignment (Alex Williamson) [Bugdb:
   13966] {CVE-2012-2121}
- KVM: unmap pages from the iommu when slots are removed (Alex Williamson)
   [Bugdb: 13966] {CVE-2012-2121}
- KVM: introduce kvm_for_each_memslot macro (Xiao Guangrong) [Bugdb: 13966]
- fcaps: clear the same personality flags as suid when fcaps are used (Eric
   Paris) [Bugdb: 13966] {CVE-2012-2123}

[2.6.39-100.8.1.el6uek]
- net: ipv4: relax AF_INET check in bind() (Eric Dumazet) [Orabug: 
14054411]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-June/002872.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-June/002873.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-June/002874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-June/002875.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/24");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.39-100.10.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.39-100.10.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.39-100.10.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.39-100.10.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.39-100.10.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.39-100.10.1.el5uek")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.39-100.10.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.39-100.10.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.39-100.10.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.39-100.10.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.39-100.10.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.39-100.10.1.el6uek")) flag++;


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
