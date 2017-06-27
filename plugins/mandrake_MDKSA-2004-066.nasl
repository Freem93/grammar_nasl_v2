#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:066. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14165);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0495", "CVE-2004-0497", "CVE-2004-0565", "CVE-2004-0587");
  script_xref(name:"MDKSA", value:"2004:066");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2004:066)");
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
"A number of vulnerabilities were discovered in the Linux kernel that
are corrected with this update :

Multiple vulnerabilities were found by the Sparse source checker that
could allow local users to elevate privileges or gain access to kernel
memory (CVE-2004-0495).

Missing Discretionary Access Controls (DAC) checks in the chown(2)
system call could allow an attacker with a local account to change the
group ownership of arbitrary files, which could lead to root
privileges on affected systems (CVE-2004-0497).

An information leak vulnerability that affects only ia64 systems was
fixed (CVE-2004-0565).

Insecure permissions on /proc/scsi/qla2300/HbaApiNode could allow a
local user to cause a DoS on the system; this only affects
Mandrakelinux 9.2 and below (CVE-2004-0587).

A vulnerability that could crash the kernel has also been fixed. This
crash, however, can only be exploited via root (in br_if.c).

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels.

To update your kernel, please follow the directions located at :

http://www.mandrakesoft.com/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.21.0.32mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.22.36mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.25.7mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.3.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.21.0.32mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.22.36mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.25.7mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.6.3.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.4.22.36mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.4.25.7mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.6.3.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-p3-smp-64GB-2.4.22.36mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-p3-smp-64GB-2.4.25.7mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-p3-smp-64GB-2.6.3.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.21.0.32mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.22.36mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.6.3.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.21.0.32mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.22.36mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.25.7mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.3.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"kernel-2.4.25.7mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-2.6.3.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-enterprise-2.4.25.7mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-enterprise-2.6.3.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.4.25.7mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.6.3.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-p3-smp-64GB-2.4.25.7mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"kernel-p3-smp-64GB-2.6.3.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-secure-2.6.3.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-smp-2.4.25.7mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-smp-2.6.3.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-source-2.4.25-7mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"kernel-source-stripped-2.6.3-15mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-2.4.21.0.32mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-enterprise-2.4.21.0.32mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-secure-2.4.21.0.32mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-smp-2.4.21.0.32mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-source-2.4.21-0.32mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"kernel-2.4.22.36mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-enterprise-2.4.22.36mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-i686-up-4GB-2.4.22.36mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-p3-smp-64GB-2.4.22.36mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kernel-secure-2.4.22.36mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kernel-smp-2.4.22.36mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"kernel-source-2.4.22-36mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
