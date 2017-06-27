#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:291. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(71511);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/12/23 14:11:58 $");

  script_cve_id("CVE-2013-2929", "CVE-2013-2930", "CVE-2013-4511", "CVE-2013-4512", "CVE-2013-4514", "CVE-2013-4515", "CVE-2013-4592", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6381", "CVE-2013-6383", "CVE-2013-6763");
  script_bugtraq_id(63509, 63510, 63512, 63518, 63707, 63790, 63886, 63887, 63888, 63890, 64111, 64318);
  script_xref(name:"MDVSA", value:"2013:291");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2013:291)");
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

The Linux kernel before 3.12.2 does not properly use the get_dumpable
function, which allows local users to bypass intended ptrace
restrictions or obtain sensitive information from IA64 scratch
registers via a crafted application, related to kernel/ptrace.c and
arch/ia64/include/asm/processor.h (CVE-2013-2929).

The perf_trace_event_perm function in kernel/trace/trace_event_perf.c
in the Linux kernel before 3.12.2 does not properly restrict access to
the perf subsystem, which allows local users to enable function
tracing via a crafted application (CVE-2013-2930).

Multiple integer overflows in Alchemy LCD frame-buffer drivers in the
Linux kernel before 3.12 allow local users to create a read-write
memory mapping for the entirety of kernel memory, and consequently
gain privileges, via crafted mmap operations, related to the (1)
au1100fb_fb_mmap function in drivers/video/au1100fb.c and the (2)
au1200fb_fb_mmap function in drivers/video/au1200fb.c (CVE-2013-4511).

Buffer overflow in the exitcode_proc_write function in
arch/um/kernel/exitcode.c in the Linux kernel before 3.12 allows local
users to cause a denial of service or possibly have unspecified other
impact by leveraging root privileges for a write operation
(CVE-2013-4512).

Multiple buffer overflows in drivers/staging/wlags49_h2/wl_priv.c in
the Linux kernel before 3.12 allow local users to cause a denial of
service or possibly have unspecified other impact by leveraging the
CAP_NET_ADMIN capability and providing a long station-name string,
related to the (1) wvlan_uil_put_info and (2)
wvlan_set_station_nickname functions (CVE-2013-4514).

The bcm_char_ioctl function in drivers/staging/bcm/Bcmchar.c in the
Linux kernel before 3.12 does not initialize a certain data structure,
which allows local users to obtain sensitive information from kernel
memory via an IOCTL_BCM_GET_DEVICE_DRIVER_INFO ioctl call
(CVE-2013-4515).

Memory leak in the __kvm_set_memory_region function in
virt/kvm/kvm_main.c in the Linux kernel before 3.9 allows local users
to cause a denial of service (memory consumption) by leveraging
certain device access to trigger movement of memory slots
(CVE-2013-4592).

The lbs_debugfs_write function in
drivers/net/wireless/libertas/debugfs.c in the Linux kernel through
3.12.1 allows local users to cause a denial of service (OOPS) by
leveraging root privileges for a zero-length write operation
(CVE-2013-6378).

The aac_send_raw_srb function in drivers/scsi/aacraid/commctrl.c in
the Linux kernel through 3.12.1 does not properly validate a certain
size value, which allows local users to cause a denial of service
(invalid pointer dereference) or possibly have unspecified other
impact via an FSACTL_SEND_RAW_SRB ioctl call that triggers a crafted
SRB command (CVE-2013-6380).

Buffer overflow in the qeth_snmp_command function in
drivers/s390/net/qeth_core_main.c in the Linux kernel through 3.12.1
allows local users to cause a denial of service or possibly have
unspecified other impact via an SNMP ioctl call with a length value
that is incompatible with the command-buffer size (CVE-2013-6381).

The aac_compat_ioctl function in drivers/scsi/aacraid/linit.c in the
Linux kernel before 3.11.8 does not require the CAP_SYS_RAWIO
capability, which allows local users to bypass intended access
restrictions via a crafted ioctl call (CVE-2013-6383).

The uio_mmap_physical function in drivers/uio/uio.c in the Linux
kernel before 3.12 does not validate the size of a memory block, which
allows local users to cause a denial of service (memory corruption) or
possibly gain privileges via crafted mmap operations, a different
vulnerability than CVE-2013-4511 (CVE-2013-6763).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.71-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.71-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.71-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.71-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.71-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.71-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.71-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.71-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.71-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
