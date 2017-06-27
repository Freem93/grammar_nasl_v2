#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:044. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36924);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2007-5500", "CVE-2007-5501", "CVE-2007-6206", "CVE-2008-0001", "CVE-2008-0007", "CVE-2008-0600");
  script_bugtraq_id(26474, 26477, 26701, 27280, 27686);
  script_xref(name:"MDVSA", value:"2008:044");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2008:044)");
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
"The wait_task_stopped function in the Linux kernel before 2.6.23.8
checks a TASK_TRACED bit instead of an exit_state value, which allows
local users to cause a denial of service (machine crash) via
unspecified vectors. NOTE: some of these details are obtained from
third-party information. (CVE-2007-5500)

The tcp_sacktag_write_queue function in the Linux kernel 2.6.21
through 2.6.23.7 allowed remote attackers to cause a denial of service
(crash) via crafted ACK responses that trigger a NULL pointer
dereference (CVE-2007-5501).

The do_corefump function in fs/exec.c in the Linux kernel prior to
2.6.24-rc3 did not change the UID of a core dump file if it exists
before a root process creates a core dump in the same location, which
could possibly allow local users to obtain sensitive information
(CVE-2007-6206).

VFS in the Linux kernel before 2.6.22.16 performed tests of access
mode by using the flag variable instead of the acc_mode variable,
which could possibly allow local users to bypass intended permissions
and remove directories (CVE-2008-0001).

The Linux kernel prior to 2.6.22.17, when using certain drivers that
register a fault handler that does not perform range checks, allowed
local users to access kernel memory via an out-of-range offset
(CVE-2008-0007).

A flaw in the vmsplice system call did not properly verify address
arguments passed by user-space processes, which allowed local
attackers to overwrite arbitrary kernel memory and gain root
privileges (CVE-2008-0600).

Mandriva urges all users to upgrade to these new kernels immediately
as the CVE-2008-0600 flaw is being actively exploited. This issue only
affects 2.6.17 and newer Linux kernels, so neither Corporate 3.0 nor
Corporate 4.0 are affected.

Additionally, this kernel updates the version from 2.6.22.12 to
2.6.22.18 and fixes numerous other bugs, including :

  - fix freeze when ejecting a cm40x0 PCMCIA card

    - fix crash on unloading netrom

    - fixes alsa-related sound issues on Dell XPS M1210 and
      M1330 models

    - the HZ value was increased on the laptop kernel to
      increase interactivity and reduce latency

  - netfilter ipset, psd, and ifwlog support was re-enabled

    - unionfs was reverted to a working 1.4 branch that is
      less buggy

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-devel-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-laptop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.22.18-1mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
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
if (rpm_check(release:"MDK2008.0", reference:"kernel-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-desktop-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-desktop-devel-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-desktop-devel-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-desktop-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"kernel-desktop586-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"kernel-desktop586-devel-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"kernel-desktop586-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-doc-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-laptop-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-laptop-devel-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-laptop-devel-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-laptop-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-server-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-server-devel-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-server-devel-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-server-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-source-2.6.22.18-1mdv-1-1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"kernel-source-latest-2.6.22.18-1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
