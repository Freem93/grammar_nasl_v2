#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:058. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81941);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/19 15:24:54 $");

  script_cve_id("CVE-2013-7421", "CVE-2014-3690", "CVE-2014-8133", "CVE-2014-8160", "CVE-2014-8989", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9428", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9644", "CVE-2014-9683", "CVE-2015-0239");
  script_xref(name:"MDVSA", value:"2015:058");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2015:058)");
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

The Crypto API in the Linux kernel before 3.18.5 allows local users to
load arbitrary kernel modules via a bind system call for an AF_ALG
socket with a module name in the salg_name field, a different
vulnerability than CVE-2014-9644 (CVE-2013-7421).

arch/x86/kvm/vmx.c in the KVM subsystem in the Linux kernel before
3.17.2 on Intel processors does not ensure that the value in the CR4
control register remains the same after a VM entry, which allows host
OS users to kill arbitrary processes or cause a denial of service
(system disruption) by leveraging /dev/kvm access, as demonstrated by
PR_SET_TSC prctl calls within a modified copy of QEMU (CVE-2014-3690).

arch/x86/kernel/tls.c in the Thread Local Storage (TLS) implementation
in the Linux kernel through 3.18.1 allows local users to bypass the
espfix protection mechanism, and consequently makes it easier for
local users to bypass the ASLR protection mechanism, via a crafted
application that makes a set_thread_area system call and later reads a
16-bit value (CVE-2014-8133).

net/netfilter/nf_conntrack_proto_generic.c in the Linux kernel before
3.18 generates incorrect conntrack entries during handling of certain
iptables rule sets for the SCTP, DCCP, GRE, and UDP-Lite protocols,
which allows remote attackers to bypass intended access restrictions
via packets with disallowed port numbers (CVE-2014-8160).

The Linux kernel through 3.17.4 does not properly restrict dropping of
supplemental group memberships in certain namespace scenarios, which
allows local users to bypass intended file permissions by leveraging a
POSIX ACL containing an entry for the group category that is more
restrictive than the entry for the other category, aka a negative
groups issue, related to kernel/groups.c, kernel/uid16.c, and
kernel/user_namespace.c (CVE-2014-8989).

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

The batadv_frag_merge_packets function in
net/batman-adv/fragmentation.c in the B.A.T.M.A.N. implementation in
the Linux kernel through 3.18.1 uses an incorrect length field during
a calculation of an amount of memory, which allows remote attackers to
cause a denial of service (mesh-node system crash) via fragmented
packets (CVE-2014-9428).

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

The Crypto API in the Linux kernel before 3.18.5 allows local users to
load arbitrary kernel modules via a bind system call for an AF_ALG
socket with a parenthesized module template expression in the
salg_name field, as demonstrated by the vfat(aes) expression, a
different vulnerability than CVE-2013-7421 (CVE-2014-9644).

Off-by-one error in the ecryptfs_decode_from_filename function in
fs/ecryptfs/crypto.c in the eCryptfs subsystem in the Linux kernel
before 3.18.2 allows local users to cause a denial of service (buffer
overflow and system crash) or possibly gain privileges via a crafted
filename (CVE-2014-9683).

The em_sysenter function in arch/x86/kvm/emulate.c in the Linux kernel
before 3.18.5, when the guest OS lacks SYSENTER MSR initialization,
allows guest OS users to gain guest OS privileges or cause a denial of
service (guest OS crash) by triggering use of a 16-bit code segment
for emulation of a SYSENTER instruction (CVE-2015-0239).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"cpupower-3.14.34-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"kernel-firmware-3.14.34-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"kernel-headers-3.14.34-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"kernel-server-3.14.34-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"kernel-server-devel-3.14.34-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"kernel-source-3.14.34-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64cpupower-devel-3.14.34-1.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64cpupower0-3.14.34-1.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
