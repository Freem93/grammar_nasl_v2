#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2015-3004.
#

include("compat.inc");

if (description)
{
  script_id(81101);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 17:43:32 $");

  script_cve_id("CVE-2014-7841");
  script_bugtraq_id(71081);

  script_name(english:"Oracle Linux 5 / 6 : Unbreakable Enterprise kernel (ELSA-2015-3004)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[2.6.39-400.246.2.el6uek]
- net: sctp: fix NULL pointer dereference in af->from_addr_param on 
malformed packet (Daniel Borkmann)  [Orabug: 20425333]  {CVE-2014-7841}

[2.6.39-400.246.1.el6uek]
- sched: Fix possible divide by zero in avg_atom() calculation (Mateusz 
Guzik)  [Orabug: 20148169]
- include/linux/math64.h: add div64_ul() (Alex Shi)
- deadlock when two nodes are converting same lock from PR to EX and 
idletimeout closes conn (Tariq Saeed)  [Orabug: 18639535]
- bonding: Bond master should reflect slave's features. (Ashish Samant) 
  [Orabug: 20231825]
- x86, fpu: remove the logic of non-eager fpu mem allocation at the 
first usage (Annie Li)  [Orabug: 20239143]
- x86, fpu: remove cpu_has_xmm check in the fx_finit() (Suresh Siddha) 
[Orabug: 20239143]
- x86, fpu: make eagerfpu= boot param tri-state (Suresh Siddha) 
[Orabug: 20239143]
- x86, fpu: enable eagerfpu by default for xsaveopt (Suresh Siddha) 
[Orabug: 20239143]
- x86, fpu: decouple non-lazy/eager fpu restore from xsave (Suresh 
Siddha)  [Orabug: 20239143]
- x86, fpu: use non-lazy fpu restore for processors supporting xsave 
(Suresh Siddha)  [Orabug: 20239143]
- lguest, x86: handle guest TS bit for lazy/non-lazy fpu host models 
(Suresh Siddha)  [Orabug: 20239143]
- x86, fpu: always use kernel_fpu_begin/end() for in-kernel FPU usage 
(Suresh Siddha)  [Orabug: 20239143]
- x86, kvm: use kernel_fpu_begin/end() in kvm_load/put_guest_fpu() 
(Suresh Siddha)  [Orabug: 20239143]
- x86, fpu: remove unnecessary user_fpu_end() in save_xstate_sig() 
(Suresh Siddha)  [Orabug: 20239143]
- raid5: add AVX optimized RAID5 checksumming (Jim Kukunas)  [Orabug: 
20239143]
- x86, fpu: drop the fpu state during thread exit (Suresh Siddha) 
[Orabug: 20239143]
- x32: Add a thread flag for x32 processes (H. Peter Anvin)  [Orabug: 
20239143]
- x86, fpu: Unify signal handling code paths for x86 and x86_64 kernels 
(Suresh Siddha)  [Orabug: 20239143]
- x86, fpu: Consolidate inline asm routines for saving/restoring fpu 
state (Suresh Siddha)  [Orabug: 20239143]
- x86, signal: Cleanup ifdefs and is_ia32, is_x32 (Suresh Siddha) 
[Orabug: 20239143]
into exported and internal interfaces (Linus Torvalds)  [Orabug: 20239143]
- i387: Uninline the generic FP helpers that we expose to kernel modules 
(Linus Torvalds)  [Orabug: 20239143]
- i387: use 'restore_fpu_checking()' directly in task switching code 
(Linus Torvalds)  [Orabug: 20239143]
- i387: fix up some fpu_counter confusion (Linus Torvalds)  [Orabug: 
20239143]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-January/004822.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-January/004823.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/30");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-2.6.39-400.246.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-2.6.39-400.246.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-debug-devel-2.6.39-400.246.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-devel-2.6.39-400.246.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-doc-2.6.39-400.246.2.el5uek")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL5", reference:"kernel-uek-firmware-2.6.39-400.246.2.el5uek")) flag++;

if (rpm_exists(release:"EL6", rpm:"kernel-uek-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-2.6.39-400.246.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-2.6.39-400.246.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-debug-devel-2.6.39-400.246.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-devel-2.6.39-400.246.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-doc-2.6.39-400.246.2.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-2.6.39") && rpm_check(release:"EL6", reference:"kernel-uek-firmware-2.6.39-400.246.2.el6uek")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
