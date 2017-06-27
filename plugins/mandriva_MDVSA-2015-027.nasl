#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:027. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80578);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/05 14:23:33 $");

  script_cve_id("CVE-2014-3688", "CVE-2014-6416", "CVE-2014-6417", "CVE-2014-6418", "CVE-2014-7841", "CVE-2014-7842", "CVE-2014-8133", "CVE-2014-8884", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585");
  script_bugtraq_id(69805, 70393, 70395, 70768, 71078, 71081, 71097, 71250, 71684, 71685, 71717, 71794, 71880, 71883, 71990);
  script_xref(name:"MDVSA", value:"2015:027");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2015:027)");
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

The SCTP implementation in the Linux kernel before 3.17.4 allows
remote attackers to cause a denial of service (memory consumption) by
triggering a large number of chunks in an association's output queue,
as demonstrated by ASCONF probes, related to net/sctp/inqueue.c and
net/sctp/sm_statefuns.c (CVE-2014-3688=.

Buffer overflow in net/ceph/auth_x.c in Ceph, as used in the Linux
kernel before 3.16.3, allows remote attackers to cause a denial of
service (memory corruption and panic) or possibly have unspecified
other impact via a long unencrypted auth ticket (CVE-2014-6416).

net/ceph/auth_x.c in Ceph, as used in the Linux kernel before 3.16.3,
does not properly consider the possibility of kmalloc failure, which
allows remote attackers to cause a denial of service (system crash) or
possibly have unspecified other impact via a long unencrypted auth
ticket (CVE-2014-6417).

net/ceph/auth_x.c in Ceph, as used in the Linux kernel before 3.16.3,
does not properly validate auth replies, which allows remote attackers
to cause a denial of service (system crash) or possibly have
unspecified other impact via crafted data from the IP address of a
Ceph Monitor (CVE-2014-6418).

The sctp_process_param function in net/sctp/sm_make_chunk.c in the
SCTP implementation in the Linux kernel before 3.17.4, when ASCONF is
used, allows remote attackers to cause a denial of service (NULL
pointer dereference and system crash) via a malformed INIT chunk
(CVE-2014-7841).

Race condition in arch/x86/kvm/x86.c in the Linux kernel before 3.17.4
allows guest OS users to cause a denial of service (guest OS crash)
via a crafted application that performs an MMIO transaction or a PIO
transaction to trigger a guest userspace emulation error report, a
similar issue to CVE-2010-5313 (CVE-2014-7842).

arch/x86/kernel/tls.c in the Thread Local Storage (TLS) implementation
in the Linux kernel through 3.18.1 allows local users to bypass the
espfix protection mechanism, and consequently makes it easier for
local users to bypass the ASLR protection mechanism, via a crafted
application that makes a set_thread_area system call and later reads a
16-bit value (CVE-2014-8133).

Stack-based buffer overflow in the
ttusbdecfe_dvbs_diseqc_send_master_cmd function in
drivers/media/usb/ttusb-dec/ttusbdecfe.c in the Linux kernel before
3.17.4 allows local users to cause a denial of service (system crash)
or possibly gain privileges via a large message length in an ioctl
call (CVE-2014-8884).

The do_double_fault function in arch/x86/kernel/traps.c in the Linux
kernel through 3.17.4 does not properly handle faults associated with
the Stack Segment (SS) segment register, which allows local users to
cause a denial of service (panic) via a modify_ldt system call, as
demonstrated by sigreturn_32 in the linux-clock-tests test suite
(CVE-2014-9090).

arch/x86/kernel/entry_64.S in the Linux kernel before 3.17.5 does not
properly handle faults associated with the Stack Segment (SS) segment
register, which allows local users to gain privileges by triggering an
IRET instruction that leads to access to a GS Base address from the
wrong space (CVE-2014-9322).

The __switch_to function in arch/x86/kernel/process_64.c in the Linux
kernel through 3.18.1 does not ensure that Thread Local Storage (TLS)
descriptors are loaded before proceeding with other steps, which makes
it easier for local users to bypass the ASLR protection mechanism via
a crafted application that reads a TLS base address (CVE-2014-9419).

The rock_continue function in fs/isofs/rock.c in the Linux kernel
through 3.18.1 does not restrict the number of Rock Ridge continuation
entries, which allows local users to cause a denial of service
(infinite loop, and system crash or hang) via a crafted iso9660 image
(CVE-2014-9420).

Race condition in the key_gc_unused_keys function in
security/keys/gc.c in the Linux kernel through 3.18.2 allows local
users to cause a denial of service (memory corruption or panic) or
possibly have unspecified other impact via keyctl commands that
trigger access to a key structure member during garbage collection of
a key (CVE-2014-9529).

The parse_rock_ridge_inode_internal function in fs/isofs/rock.c in the
Linux kernel before 3.18.2 does not validate a length value in the
Extensions Reference (ER) System Use Field, which allows local users
to obtain sensitive information from kernel memory via a crafted
iso9660 image (CVE-2014-9584).

The vdso_addr function in arch/x86/vdso/vma.c in the Linux kernel
through 3.18.2 does not properly choose memory locations for the vDSO
area, which makes it easier for local users to bypass the ASLR
protection mechanism by guessing a location at the end of a PMD
(CVE-2014-9585).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.105-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.105-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.105-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.105-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.105-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.105-2.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.105-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.105-2.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.105-2.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
