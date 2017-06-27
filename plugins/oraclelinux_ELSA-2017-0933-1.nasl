#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-0933-1.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(99386);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/14 20:51:10 $");

  script_cve_id("CVE-2016-8650", "CVE-2016-9793", "CVE-2017-2618", "CVE-2017-2636");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2017-0933-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

- [3.10.0-514.16.1.0.1.el7.OL7]
- [ipc] ipc/sem.c: bugfix for semctl(,,GETZCNT) (Manfred Spraul) [orabug 
22552377]
- Oracle Linux certificates (Alexey Petrenko)
- Oracle Linux RHCK Module Signing Key was compiled into kernel 
(olkmod_signing_key.x509)(<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>alexey.petrenko at oracle.com</A>)
- Update x509.genkey [bug 24817676]

[3.10.0-514.16.1.el7]
- [tty] n_hdlc: get rid of racy n_hdlc.tbuf ('Herton R. Krzesinski') 
[1429919 1429920] {CVE-2017-2636}
- [md] dm rq: cope with DM device destruction while in 
dm_old_request_fn() (Mike Snitzer) [1430334 1412854]
- [fs] nfs: Fix inode corruption in nfs_prime_dcache() (Benjamin 
Coddington) [1429514 1416532]
- [fs] nfs: Don't let readdirplus revalidate an inode that was marked as 
stale (Benjamin Coddington) [1429514 1416532]
- [block] Copy a user iovec if it includes gaps (Jeff Moyer) [1429508 
1421263]
- [kernel] percpu-refcount: fix reference leak during percpu-atomic 
transition (Jeff Moyer) [1429507 1418333]
- [powerpc] eeh: eeh_pci_enable(): fix checking of post-request state 
(Steve Best) [1425538 1383670]
- [s390] mm: handle PTE-mapped tail pages in fast gup (Hendrik 
Brueckner) [1423438 1391532]
- [net] skbuff: Fix skb checksum partial check (Lance Richardson) 
[1422964 1411480]
- [net] skbuff: Fix skb checksum flag on skb pull (Lance Richardson) 
[1422964 1411480]
- [security] selinux: fix off-by-one in setprocattr (Paul Moore) 
[1422368 1422369] {CVE-2017-2618}
- [virtio] balloon: check the number of available pages in leak balloon 
(David Hildenbrand) [1417194 1401615]
- [infiniband] ib/rdmavt: Only put mmap_info ref if it exists (Jonathan 
Toppins) [1417191 1391299]
- [x86] kvm: x86: make lapic hrtimer pinned (Luiz Capitulino) [1416373 
1392593]
- [kernel] sched/nohz: Fix affine unpinned timers mess (Luiz Capitulino) 
[1416373 1392593]
- [kernel] nohz: Affine unpinned timers to housekeepers (Luiz 
Capitulino) [1416373 1392593]
- [kernel] tick-sched: add housekeeping_mask cpumask (Luiz Capitulino) 
[1416373 1392593]
- [x86] platform/uv/bau: Add UV4-specific functions (Frank Ramsay) 
[1414715 1386692]
- [x86] platform/uv/bau: Fix payload queue setup on UV4 hardware (Frank 
Ramsay) [1414715 1386692]
- [x86] platform/uv/bau: Disable software timeout on UV4 hardware (Frank 
Ramsay) [1414715 1386692]
- [x86] platform/uv/bau: Populate ->uvhub_version with UV4 version 
information (Frank Ramsay) [1414715 1386692]
- [x86] platform/uv/bau: Use generic function pointers (Frank Ramsay) 
[1414715 1386692]
- [x86] platform/uv/bau: Add generic function pointers (Frank Ramsay) 
[1414715 1386692]
- [x86] platform/uv/bau: Convert uv_physnodeaddr() use to 
uv_gpa_to_offset() (Frank Ramsay) [1414715 1386692]
- [x86] platform/uv/bau: Clean up pq_init() (Frank Ramsay) [1414715 1386692]
- [x86] platform/uv/bau: Clean up and update printks (Frank Ramsay) 
[1414715 1386692]
- [x86] platform/uv/bau: Clean up vertical alignment (Frank Ramsay) 
[1414715 1386692]
- [virtio] virtio-pci: alloc only resources actually used (Laurent 
Vivier) [1413093 1375153]
- [net] avoid signed overflows for SO_{SND|RCV}BUFFORCE (Sabrina 
Dubroca) [1412473 1412474] {CVE-2016-9793}
- [netdrv] sfc: clear napi_hash state when copying channels (Jarod 
Wilson) [1401461 1394304]
- [lib] mpi: Fix NULL ptr dereference in mpi_powm() (Mateusz Guzik) 
[1398457 1398458] {CVE-2016-8650}
- [scsi] lpfc: Fix eh_deadline setting for sli3 adapters (Ewan Milne) 
[1430687 1366564]
- [md] dm round robin: revert 'use percpu 'repeat_count' and 
'current_path'' (Mike Snitzer) [1430689 1422567]
- [md] dm round robin: do not use this_cpu_ptr() without having 
preemption disabled (Mike Snitzer) [1430689 1422567]
- Revert: [x86] Handle non enumerated CPU after physical hotplug (Prarit 
Bhargava) [1426633 1373738]
- Revert: [x86] smp: Don't try to poke disabled/non-existent APIC 
(Prarit Bhargava) [1426633 1373738]
- Revert: [x86] smpboot: Init apic mapping before usage (Prarit 
Bhargava) [1426633 1373738]
- Revert: [x86] revert 'perf/uncore: Disable uncore on kdump kernel' 
(Prarit Bhargava) [1426633 1373738]
- Revert: [x86] perf/x86/intel/uncore: Fix hardcoded socket 0 assumption 
in the Haswell init code (Prarit Bhargava) [1426633 1373738]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-April/006863.html"
  );
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages. Note that the updated packages
may not be immediately available from the package repository and its
mirrors.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(release:"EL7", rpm:"kernel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-abi-whitelists-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-debug-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-doc-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-doc-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-headers-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-tools-libs-devel-3.10.0") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"perf-3.10.0-514.16.1.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-perf-3.10.0-514.16.1.0.1.el7")) flag++;


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
