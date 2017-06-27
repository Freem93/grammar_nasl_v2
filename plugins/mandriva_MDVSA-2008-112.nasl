#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:112. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36852);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2006-6058", "CVE-2007-5500", "CVE-2007-5966", "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2007-6417", "CVE-2008-0001", "CVE-2008-0007", "CVE-2008-2358");
  script_xref(name:"MDVSA", value:"2008:112");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2008:112)");
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
"Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel :

The Datagram Congestion Control Protocol (DCCP) subsystem in the Linux
kernel 2.6.18, and probably other versions, does not properly check
feature lengths, which might allow remote attackers to execute
arbitrary code, related to an unspecified overflow. (CVE-2008-2358)

VFS in the Linux kernel before 2.6.22.16, and 2.6.23.x before
2.6.23.14, performs tests of access mode by using the flag variable
instead of the acc_mode variable, which might allow local users to
bypass intended permissions and remove directories. (CVE-2008-0001)

Linux kernel before 2.6.22.17, when using certain drivers that
register a fault handler that does not perform range checks, allows
local users to access kernel memory via an out-of-range offset.
(CVE-2008-0007)

Integer overflow in the hrtimer_start function in kernel/hrtimer.c in
the Linux kernel before 2.6.23.10 allows local users to execute
arbitrary code or cause a denial of service (panic) via a large
relative timeout value. NOTE: some of these details are obtained from
third-party information. (CVE-2007-5966)

The shmem_getpage function (mm/shmem.c) in Linux kernel 2.6.11 through
2.6.23 does not properly clear allocated memory in some rare
circumstances related to tmpfs, which might allow local users to read
sensitive kernel data or cause a denial of service (crash).
(CVE-2007-6417)

The isdn_ioctl function in isdn_common.c in Linux kernel 2.6.23 allows
local users to cause a denial of service via a crafted ioctl struct in
which iocts is not null terminated, which triggers a buffer overflow.
(CVE-2007-6151)

The do_coredump function in fs/exec.c in Linux kernel 2.4.x and 2.6.x
up to 2.6.24-rc3, and possibly other versions, does not change the UID
of a core dump file if it exists before a root process creates a core
dump in the same location, which might allow local users to obtain
sensitive information. (CVE-2007-6206)

Buffer overflow in the isdn_net_setcfg function in isdn_net.c in Linux
kernel 2.6.23 allows local users to have an unknown impact via a
crafted argument to the isdn_ioctl function. (CVE-2007-6063)

The wait_task_stopped function in the Linux kernel before 2.6.23.8
checks a TASK_TRACED bit instead of an exit_state value, which allows
local users to cause a denial of service (machine crash) via
unspecified vectors. NOTE: some of these details are obtained from
third-party information. (CVE-2007-5500)

The minix filesystem code in Linux kernel 2.6.x before 2.6.24,
including 2.6.18, allows local users to cause a denial of service
(hang) via a malformed minix file stream that triggers an infinite
loop in the minix_bmap function. NOTE: this issue might be due to an
integer overflow or signedness error. (CVE-2006-6058)

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 189, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.17.19mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-2.6.17.19mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.6.17.19mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-2.6.17.19mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.17.19mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6.17.19mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.17.19mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.17.19mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"kernel-2.6.17.19mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-doc-2.6.17.19mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-doc-latest-2.6.17-19mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-enterprise-2.6.17.19mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-enterprise-latest-2.6.17-19mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-latest-2.6.17-19mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-legacy-2.6.17.19mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-legacy-latest-2.6.17-19mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-2.6.17.19mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-latest-2.6.17-19mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-stripped-2.6.17.19mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-stripped-latest-2.6.17-19mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xen0-2.6.17.19mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xen0-latest-2.6.17-19mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xenU-2.6.17.19mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xenU-latest-2.6.17-19mdv", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
