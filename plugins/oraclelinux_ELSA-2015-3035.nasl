#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-3035.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83448);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2015/12/01 17:43:32 $");

  script_cve_id("CVE-2014-3215", "CVE-2014-8159", "CVE-2014-8171", "CVE-2014-9529", "CVE-2014-9584", "CVE-2015-2150", "CVE-2015-3331");
  script_bugtraq_id(67341, 71880, 71883, 73014, 73060, 74235, 74293);

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2015-3035)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

kernel-uek
[3.8.13-68.2.2.el7uek]

* crypto: aesni

*  fix memory usage in GCM decryption (Stephan Mueller) 
[Orabug: 21077385]  {CVE-2015-3331}

[3.8.13-68.2.1.el7uek]

* xen/pciback: Don't disable PCI_COMMAND on PCI device reset. (Konrad 
Rzeszutek Wilk)  [Orabug: 20807438]  {CVE-2015-2150}

* xen-blkfront: fix accounting of reqs when migrating (Roger Pau Monne) 
  [Orabug: 20860817]

*  Doc/cpu-hotplug: Specify race-free way to 
register CPU hotplug callbacks (Srivatsa S. Bhat)  [Orabug: 20917697]

*  
net/iucv/iucv.c: Fix CPU hotplug callback registration (Srivatsa S. 
Bhat)  [Orabug: 20917697]

*  net/core/flow.c: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  mm, vmstat: Fix 
CPU hotplug callback registration (Srivatsa S. Bhat)  [Orabug: 20917697] 

* profile: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
[Orabug: 20917697]

*  trace, ring-buffer: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  hwmon, 
via-cputemp: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
[Orabug: 20917697]

*  hwmon, coretemp: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  octeon, watchdog: 
Fix CPU hotplug callback registration (Srivatsa S. Bhat)  [Orabug: 
20917697]

*  oprofile, nmi-timer: Fix CPU hotplug callback registration 
(Srivatsa S. Bhat)  [Orabug: 20917697]

*  intel-idle: Fix CPU hotplug 
callback registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  
drivers/base/topology.c: Fix CPU hotplug callback registration (Srivatsa 
S. Bhat)  [Orabug: 20917697]

*  acpi-cpufreq: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  scsi, fcoe: Fix 
CPU hotplug callback registration (Srivatsa S. Bhat)  [Orabug: 20917697] 

* scsi, bnx2fc: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
  [Orabug: 20917697]

*  scsi, bnx2i: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  arm64, 
debug-monitors: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
  [Orabug: 20917697]

*  arm64, hw_breakpoint.c: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  x86, kvm: Fix CPU 
hotplug callback registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  
x86, oprofile, nmi: Fix CPU hotplug callback registration (Srivatsa S. 
Bhat)  [Orabug: 20917697]

*  x86, pci, amd-bus: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  x86, hpet: Fix CPU 
hotplug callback registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  
x86, intel, cacheinfo: Fix CPU hotplug callback registration (Srivatsa 
S. Bhat)  [Orabug: 20917697]

*  x86, amd, ibs: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  x86, 
therm_throt.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
  [Orabug: 20917697]

*  x86, mce: Fix CPU hotplug callback registration 
(Srivatsa S. Bhat)  [Orabug: 20917697]

*  x86, intel, uncore: Fix CPU 
hotplug callback registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  
x86, vsyscall: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
  [Orabug: 20917697]

*  x86, cpuid: Fix CPU hotplug callback registration 
(Srivatsa S. Bhat)  [Orabug: 20917697]

*  x86, msr: Fix CPU hotplug 
callback registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  powerpc, 
sysfs: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
[Orabug: 20917697]

*  sparc, sysfs: Fix CPU hotplug callback registration 
(Srivatsa S. Bhat)  [Orabug: 20917697]

*  s390, smp: Fix CPU hotplug 
callback registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  s390, 
cacheinfo: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
[Orabug: 20917697]

*  arm, hw-breakpoint: Fix CPU hotplug callback 
registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  ia64, err-inject: 
Fix CPU hotplug callback registration (Srivatsa S. Bhat)  [Orabug: 
20917697]

*  ia64, topology: Fix CPU hotplug callback registration 
(Srivatsa S. Bhat)  [Orabug: 20917697]

*  ia64, palinfo: Fix CPU hotplug 
callback registration (Srivatsa S. Bhat)  [Orabug: 20917697]

*  CPU 
hotplug, perf: Fix CPU hotplug callback registration (Srivatsa S. Bhat) 
  [Orabug: 20917697]

*  CPU hotplug: Provide lockless versions of 
callback registration functions (Srivatsa S. Bhat)  [Orabug: 20917697]

*  
isofs: Fix unchecked printing of ER records (Jan Kara)  [Orabug: 
20930551]  {CVE-2014-9584}

* KEYS: close race between key lookup and freeing (Sasha Levin) 
[Orabug: 20930548]  {CVE-2014-9529} {CVE-2014-9529}

* mm: memcg: do not allow task about to OOM kill to bypass the limit 
(Johannes Weiner)  [Orabug: 20930539]  {CVE-2014-8171}

* mm: memcg: do not declare OOM from __GFP_NOFAIL allocations (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}

* fs: buffer: move allocation failure loop into the allocator (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}

* mm: memcg: handle non-error OOM situations more gracefully (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}

* mm: memcg: do not trap chargers with full callstack on OOM (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}

* mm: memcg: rework and document OOM waiting and wakeup (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}

* mm: memcg: enable memcg OOM killer only for user faults (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}

* x86: finish user fault error path with fatal signal (Johannes Weiner) 
  [Orabug: 20930539]  {CVE-2014-8171}

* arch: mm: pass userspace fault flag to generic fault handler (Johannes 
Weiner)  [Orabug: 20930539]  {CVE-2014-8171}

* selinux: Permit bounded transitions under NO_NEW_PRIVS or NOSUID. 
(Stephen Smalley)  [Orabug: 20930501]  {CVE-2014-3215}

* IB/core: Prevent integer overflow in ib_umem_get address arithmetic 
(Shachar Raindel)  [Orabug: 20799875]  {CVE-2014-8159} {CVE-2014-8159}"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-May/005069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-May/005070.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-68.2.2.el6uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dtrace-modules-3.8.13-68.2.2.el7uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL6", cpu:"x86_64", reference:"dtrace-modules-3.8.13-68.2.2.el6uek-0.4.3-4.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-3.8.13-68.2.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-68.2.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-68.2.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-68.2.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-68.2.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-68.2.2.el6uek")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"dtrace-modules-3.8.13-68.2.2.el7uek-0.4.3-4.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-3.8.13-68.2.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-3.8.13-68.2.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-3.8.13-68.2.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-3.8.13-68.2.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-3.8.13-68.2.2.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-3.8.13") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-3.8.13-68.2.2.el7uek")) flag++;


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
