#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:230. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79610);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/01 00:40:59 $");

  script_cve_id("CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3690", "CVE-2014-7825", "CVE-2014-7826", "CVE-2014-7970", "CVE-2014-8369");
  script_bugtraq_id(70319, 70691, 70742, 70743, 70745, 70746, 70748, 70749, 70766, 70883, 70971, 70972);
  script_xref(name:"MDVSA", value:"2014:230");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2014:230)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in the Linux
kernel :

The WRMSR processing functionality in the KVM subsystem in the Linux
kernel through 3.17.2 does not properly handle the writing of a
non-canonical address to a model-specific register, which allows guest
OS users to cause a denial of service (host OS crash) by leveraging
guest OS privileges, related to the wrmsr_interception function in
arch/x86/kvm/svm.c and the handle_wrmsr function in arch/x86/kvm/vmx.c
(CVE-2014-3610).

Race condition in the __kvm_migrate_pit_timer function in
arch/x86/kvm/i8254.c in the KVM subsystem in the Linux kernel through
3.17.2 allows guest OS users to cause a denial of service (host OS
crash) by leveraging incorrect PIT emulation (CVE-2014-3611).

arch/x86/kvm/vmx.c in the KVM subsystem in the Linux kernel before
3.12 does not have an exit handler for the INVEPT instruction, which
allows guest OS users to cause a denial of service (guest OS crash)
via a crafted application (CVE-2014-3645).

arch/x86/kvm/vmx.c in the KVM subsystem in the Linux kernel through
3.17.2 does not have an exit handler for the INVVPID instruction,
which allows guest OS users to cause a denial of service (guest OS
crash) via a crafted application (CVE-2014-3646).

arch/x86/kvm/emulate.c in the KVM subsystem in the Linux kernel
through 3.17.2 does not properly perform RIP changes, which allows
guest OS users to cause a denial of service (guest OS crash) via a
crafted application (CVE-2014-3647).

The SCTP implementation in the Linux kernel through 3.17.2 allows
remote attackers to cause a denial of service (system crash) via a
malformed ASCONF chunk, related to net/sctp/sm_make_chunk.c and
net/sctp/sm_statefuns.c (CVE-2014-3673).

The sctp_assoc_lookup_asconf_ack function in net/sctp/associola.c in
the SCTP implementation in the Linux kernel through 3.17.2 allows
remote attackers to cause a denial of service (panic) via duplicate
ASCONF chunks that trigger an incorrect uncork within the side-effect
interpreter (CVE-2014-3687).

arch/x86/kvm/vmx.c in the KVM subsystem in the Linux kernel before
3.17.2 on Intel processors does not ensure that the value in the CR4
control register remains the same after a VM entry, which allows host
OS users to kill arbitrary processes or cause a denial of service
(system disruption) by leveraging /dev/kvm access, as demonstrated by
PR_SET_TSC prctl calls within a modified copy of QEMU (CVE-2014-3690).

kernel/trace/trace_syscalls.c in the Linux kernel through 3.17.2 does
not properly handle private syscall numbers during use of the perf
subsystem, which allows local users to cause a denial of service
(out-of-bounds read and OOPS) or bypass the ASLR protection mechanism
via a crafted application (CVE-2014-7825).

kernel/trace/trace_syscalls.c in the Linux kernel through 3.17.2 does
not properly handle private syscall numbers during use of the ftrace
subsystem, which allows local users to gain privileges or cause a
denial of service (invalid pointer dereference) via a crafted
application (CVE-2014-7826).

The pivot_root implementation in fs/namespace.c in the Linux kernel
through 3.17 does not properly interact with certain locations of a
chroot directory, which allows local users to cause a denial of
service (mount-tree loop) via . (dot) values in both arguments to the
pivot_root system call (CVE-2014-7970).

The kvm_iommu_map_pages function in virt/kvm/iommu.c in the Linux
kernel through 3.17.2 miscalculates the number of pages during the
handling of a mapping failure, which allows guest OS users to cause a
denial of service (host OS page unpinning) or possibly have
unspecified other impact by leveraging guest OS privileges. NOTE: this
vulnerability exists because of an incorrect fix for CVE-2014-3601
(CVE-2014-8369).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.104-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.104-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.104-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.104-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.104-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.104-2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.104-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.104-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.104-2.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
