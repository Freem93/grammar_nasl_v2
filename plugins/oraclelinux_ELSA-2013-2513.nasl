#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-2513.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68850);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/01 17:25:13 $");

  script_cve_id("CVE-2013-0268", "CVE-2013-0871", "CVE-2013-0913", "CVE-2013-1773");
  script_bugtraq_id(57838, 57986, 58200, 58427);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2013-2513)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[2.6.39-400.21.1.el6uek]
- SPEC: v2.6.39-400.21.1 (Maxim Uvarov)
- xen/mmu: On early bootup, flush the TLB when changing RO->RW bits Xen 
provided pagetables. (Konrad Rzeszutek Wilk)

[2.6.39-400.20.1.el6uek]
- SPEC: v2.6.39-400.20.1 (Maxim Uvarov)
- PCI: Set device power state to PCI_D0 for device without native PM 
support (Ajaykumar Hotchandani) [Orabug: 16482495]
- sched: Fix cgroup movement of waking process (Daisuke Nishimura) 
[Orabug: 13740515]
- sched: Fix cgroup movement of newly created process (Daisuke 
Nishimura) [Orabug: 13740515]
- sched: Fix cgroup movement of forking process (Daisuke Nishimura) 
[Orabug: 13740515]

[2.6.39-400.19.1.el6uek]
- IB/core: Allow device-specific per-port sysfs files (Ralph Campbell)
- RDMA/cma: Pass QP type into rdma_create_id() (Sean Hefty)
- IB: Rename RAW_ETY to RAW_ETHERTYPE (Aleksey Senin)
- IB: Warning Resolution. (Ajaykumar Hotchandani)
- mlx4_core: fix FMR flags in free MTT range (Saeed Mahameed)
- mlx4_core/ib: sriov fmr bug fixes (Saeed Mahameed)
- mlx4_core: Change bitmap allocator to work in round-robin fashion (Saeed
   Mahameed)
- mlx4_vnic: move host admin vnics to closed state when closing the vnic.
   (Saeed Mahameed)
- mlx4_ib: make sure to flush clean_wq while closing sriov device (Saeed
   Mahameed)
- ib_sdp: fix deadlock when sdp_cma_handler is called while socket is being
   closed (Saeed Mahameed)
- ib_sdp: add unhandled events to rdma_cm_event_str (Saeed Mahameed)
- mlx4_core: use dev->sriov instead of hardcoed 127 vfs when 
initializing FMR
   MPT tables (Saeed Mahameed)
- mlx4_vnic: print vnic keep alive info in mlx4_vnic_info (Saeed Mahameed)
- rds: Congestion flag does not get cleared causing the connection to hang
   (Bang Nguyen) [Orabug: 16424692]
- dm table: set flush capability based on underlying devices (Mike Snitzer)
   [Orabug: 16392584]
- wake_up_process() should be never used to wakeup a TASK_STOPPED/TRACED 
task
   (Oleg Nesterov) [Orabug: 16405869] {CVE-2013-0871}
- ptrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL 
(Oleg
   Nesterov) [Orabug: 16405869] {CVE-2013-0871}
- ptrace: introduce signal_wake_up_state() and ptrace_signal_wake_up() (Oleg
   Nesterov) [Orabug: 16405869] {CVE-2013-0871}
- drm/i915: bounds check execbuffer relocation count (Kees Cook) [Orabug:
   16482650] {CVE-2013-0913}
- NLS: improve UTF8 -> UTF16 string conversion routine (Alan Stern) [Orabug:
   16425571] {CVE-2013-1773}
- ipmi: make kcs timeout parameters as module options (Pavel Bures) [Orabug:
   16470881]
- drm/i915/lvds: ditch ->prepare special case (Daniel Vetter) [Orabug:
   14394113]
- drm/i915: Leave LVDS registers unlocked (Keith Packard) [Orabug: 14394113]
- drm/i915: don't clobber the pipe param in sanitize_modesetting (Daniel
   Vetter) [Orabug: 14394113]
- drm/i915: Sanitize BIOS debugging bits from PIPECONF (Chris Wilson) 
[Orabug:
   14394113]

[2.6.39-400.18.1.el6uek]
- SPEC: fix doc build (Guru Anbalagane)
- floppy: Fix a crash during rmmod (Vivek Goyal) [Orabug: 16040504]
- x86: ignore changes to paravirt_lazy_mode while in an interrupt context
   (Chuck Anderson) [Orabug: 16417326]
- x86/msr: Add capabilities check (Alan Cox) [Orabug: 16405007] 
{CVE-2013-0268}
- spec: unique debuginfo (Maxim Uvarov) [Orabug: 16245366]
- xfs: Use preallocation for inodes with extsz hints (Dave Chinner) [Orabug:
   16307993]
- Add SIOCRDSGETTOS to get the current TOS for the socket (bang.nguyen)
   [Orabug: 16397197]
- Changes to connect/TOS interface (bang.nguyen) [Orabug: 16397197]
- floppy: Cleanup disk->queue before calling put_disk() if add_disk() was 
never
   called (Vivek Goyal) [Orabug: 16040504]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-April/003406.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-April/003407.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/12");
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
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.39-400.21.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.39-400.21.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.39-400.21.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.39-400.21.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.39-400.21.1.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.39-400.21.1.el5uek")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.39-400.21.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.39-400.21.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.39-400.21.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.39-400.21.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.39-400.21.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.39-400.21.1.el6uek")) flag++;


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
