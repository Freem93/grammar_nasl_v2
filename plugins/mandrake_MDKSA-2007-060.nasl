#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:060. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24810);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:49:26 $");

  script_cve_id("CVE-2006-4538", "CVE-2006-4814", "CVE-2006-5753", "CVE-2006-5823", "CVE-2006-6053", "CVE-2006-6056", "CVE-2007-0006", "CVE-2007-0772", "CVE-2007-0958");
  script_bugtraq_id(19702, 21663, 22316, 22625);
  script_xref(name:"MDKSA", value:"2007:060");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2007:060)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel :

The 2.6.17 kernel and earlier, when running on IA64 and SPARC
platforms would allow a local user to cause a DoS (crash) via a
malformed ELF file (CVE-2006-4538).

The mincore function in the Linux kernel did not properly lock access
to user space, which has unspecified impact and attack vectors,
possibly related to a deadlock (CVE-2006-4814).

An unspecified vulnerability in the listxattr system call, when a 'bad
inode' is present, could allow a local user to cause a DoS (data
corruption) and possibly gain privileges via unknown vectors
(CVE-2006-5753).

The zlib_inflate function allows local users to cause a crash via a
malformed filesystem that uses zlib compression that triggers memory
corruption (CVE-2006-5823).

The ext3fs_dirhash function could allow local users to cause a DoS
(crash) via an ext3 stream with malformed data structures
(CVE-2006-6053).

When SELinux hooks are enabled, the kernel could allow a local user to
cause a DoS (crash) via a malformed file stream that triggers a NULL
pointer derefernece (CVE-2006-6056).

The key serial number collision avoidance code in the key_alloc_serial
function in kernels 2.6.9 up to 2.6.20 allows local users to cause a
crash via vectors thatr trigger a null dereference (CVE-2007-0006).

The Linux kernel version 2.6.13 to 2.6.20.1 allowed a remote attacker
to cause a DoS (oops) via a crafted NFSACL2 ACCESS request that
triggered a free of an incorrect pointer (CVE-2007-0772).

A local user could read unreadable binaries by using the interpreter
(PT_INTERP) functionality and triggering a core dump; a variant of
CVE-2004-1073 (CVE-2007-0958).

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.

In addition to these security fixes, other fixes have been included
such as :

  - add PCI IDs for cciss driver (HP ML370G5 / DL360G5)

    - fixed a mssive SCSI reset on megasas (Dell PE2960)

    - increased port-reset completion delay for HP
      controllers (HP ML350)

    - NUMA rnage fixes for x86_64

    - various netfilter fixes

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-BOOT-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xbox-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.12.31mdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"kernel-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-BOOT-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-doc-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i586-up-1GB-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-smp-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-stripped-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xbox-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-xen0-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-xenU-2.6.12.31mdk-1-1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
