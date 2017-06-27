#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:111. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(18599);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2005-0109", "CVE-2005-0209", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-1263");
  script_xref(name:"MDKSA", value:"2005:111");

  script_name(english:"Mandrake Linux Security Advisory : kernel-2.4 (MDKSA-2005:111)");
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
"Multiple vulnerabilities in the Linux kernel have been discovered and
fixed in this update. The following have been fixed in the 2.4 
kernels :

Colin Percival discovered a vulnerability in Intel's Hyper-Threading
technology could allow a local user to use a malicious thread to
create covert channels, monitor the execution of other threads, and
obtain sensitive information such as cryptographic keys via a timing
attack on memory cache misses. This has been corrected by disabling HT
support in all kernels (CVE-2005-0109).

When forwarding fragmented packets, a hardware assisted checksum could
only be used once which could lead to a Denial of Service attack or
crash by remote users (CVE-2005-0209).

A flaw in the Linux PPP driver was found where on systems allowing
remote users to connect to a server via PPP, a remote client could
cause a crash, resulting in a Denial of Service (CVE-2005-0384).

An information leak in the ext2 filesystem code was found where when a
new directory is created, the ext2 block written to disk is not
initialized (CVE-2005-0400).

A signedness error in the copy_from_read_buf function in n_tty.c
allows local users to read kernel memory via a negative argument
(CVE-2005-0530).

George Guninski discovered a buffer overflow in the ATM driver where
the atm_get_addr() function does not validate its arguments
sufficiently which could allow a local attacker to overwrite large
portions of kernel memory by supplying a negative length argument.
This could potentially lead to the execution of arbitrary code
(CVE-2005-0531).

A flaw when freeing a pointer in load_elf_library was found that could
be abused by a local user to potentially crash the machine causing a
Denial of Service (CVE-2005-0749).

A problem with the Bluetooth kernel stack in kernels 2.4.6 through
2.4.30-rc1 and 2.6 through 2.6.11.5 could be used by a local attacker
to gain root access or crash the machine (CVE-2005-0750).

A race condition in the Radeon DRI driver allows a local user with DRI
privileges to execute arbitrary code as root (CVE-2005-0767).

Paul Starzetz found an integer overflow in the ELF binary format
loader's code dump function in kernels prior to and including
2.4.31-pre1 and 2.6.12-rc4. By creating and executing a specially
crafted ELF executable, a local attacker could exploit this to execute
arbitrary code with root and kernel privileges (CVE-2005-1263)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.25.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.28.0.rc1.6mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.25.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.28.0.rc1.6mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.4.28.0.rc1.6mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.4.25.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-p3-smp-64GB-2.4.25.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.25.14mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.28.0.rc1.6mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"kernel-2.4.25.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-enterprise-2.4.25.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.4.25.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-p3-smp-64GB-2.4.25.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-smp-2.4.25.14mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-source-2.4.25-14mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"kernel-2.4.28.0.rc1.6mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"kernel-enterprise-2.4.28.0.rc1.6mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"kernel-i586-up-1GB-2.4.28.0.rc1.6mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-smp-2.4.28.0.rc1.6mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kernel-source-2.4-2.4.28-0.rc1.6mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
