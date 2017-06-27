#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:018. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20796);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2005-3527", "CVE-2005-3783", "CVE-2005-3784", "CVE-2005-3805", "CVE-2005-3806", "CVE-2005-3808");
  script_xref(name:"MDKSA", value:"2006:018");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2006:018)");
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
"A number of vulnerabilities have been corrected in the Linux kernel :

A race condition in the 2.6 kernel could allow a local user to cause a
DoS by triggering a core dump in one thread while another thread has a
pending SIGSTOP (CVE-2005-3527).

The ptrace functionality in 2.6 kernels prior to 2.6.14.2, using
CLONE_THREAD, does not use the thread group ID to check whether it is
attaching to itself, which could allow local users to cause a DoS
(CVE-2005-3783).

The auto-reap child process in 2.6 kernels prior to 2.6.15 include
processes with ptrace attached, which leads to a dangling ptrace
reference and allows local users to cause a crash (CVE-2005-3784).

A locking problem in the POSIX timer cleanup handling on exit on
kernels 2.6.10 to 2.6.14 when running on SMP systems, allows a local
user to cause a deadlock involving process CPU timers (CVE-2005-3805).

The IPv6 flowlabel handling code in 2.4 and 2.6 kernels prior to
2.4.32 and 2.6.14 modifes the wrong variable in certain circumstances,
which allows local users to corrupt kernel memory or cause a crash by
triggering a free of non-allocated memory (CVE-2005-3806).

An integer overflow in 2.6.14 and earlier could allow a local user to
cause a hang via 64-bit mmap calls that are not properly handled on a
32-bit system (CVE-2005-3808).

As well, other bugfixes are included in this update :

Fixes to swsup and HDA sound fixes (DMA buffer fixes, and fixes for
the AD1986a codec, added support for Nvidia chipsets, and new model
information for the Gigabyte K8N51).

MCP51 forcedeth support has been added."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.12.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.6.12.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.6.12.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.12.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xbox-2.6.12.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.12.15mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.12.15mdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"kernel-2.6.12.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i586-up-1GB-2.6.12.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.6.12.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-smp-2.6.12.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-2.6-2.6.12-15mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-stripped-2.6-2.6.12-15mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xbox-2.6.12.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xen0-2.6.12.15mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xenU-2.6.12.15mdk-1-1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
