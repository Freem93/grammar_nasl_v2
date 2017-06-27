#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:195. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(27561);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2007-3105", "CVE-2007-3513", "CVE-2007-3642", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4573");
  script_bugtraq_id(24734, 25216, 25348, 25387, 25774);
  script_xref(name:"MDKSA", value:"2007:195");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2007:195)");
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

A stack-based buffer overflow in the random number generator could
allow local root users to cause a denial of service or gain privileges
by setting the default wakeup threshold to a value greater than the
output pool size (CVE-2007-3105).

The lcd_write function did not limit the amount of memory used by a
caller, which allows local users to cause a denial of service (memory
consumption) (CVE-2007-3513).

The decode_choice function allowed remote attackers to cause a denial
of service (crash) via an encoded out-of-range index value for a
choice field which triggered a NULL pointer dereference
(CVE-2007-3642).

The Linux kernel allowed local users to send arbitrary signals to a
child process that is running at higher privileges by causing a
setuid-root parent process to die which delivered an
attacker-controlled parent process death signal (PR_SET_PDEATHSIG)
(CVE-2007-3848).

The aac_cfg_openm and aac_compat_ioctl functions in the SCSI layer
ioctl patch in aacraid did not check permissions for ioctls, which
might allow local users to cause a denial of service or gain
privileges (CVE-2007-4308).

The IA32 system call emulation functionality, when running on the
x86_64 architecture, did not zero extend the eax register after the
32bit entry path to ptrace is used, which could allow local users to
gain privileges by triggering an out-of-bounds access to the system
call table using the %RAX register (CVE-2007-4573).

In addition to these security fixes, other fixes have been included
such as :

  - More NVidia PCI ids wre added

    - The 3w-9xxx module was updated to version 2.26.02.010

    - Fixed the map entry for ICH8

    - Added the TG3 5786 PCI id

    - Reduced the log verbosity of cx88-mpeg

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.17.16mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-2.6.17.16mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.6.17.16mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-2.6.17.16mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-legacy-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.17.16mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6.17.16mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.17.16mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.17.16mdv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"kernel-2.6.17.16mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-doc-2.6.17.16mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"kernel-enterprise-2.6.17.16mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"kernel-legacy-2.6.17.16mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-source-2.6.17.16mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-source-stripped-2.6.17.16mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-xen0-2.6.17.16mdv-1-1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"kernel-xenU-2.6.17.16mdv-1-1mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"kernel-2.6.17.16mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-doc-2.6.17.16mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-doc-latest-2.6.17-16mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-enterprise-2.6.17.16mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-enterprise-latest-2.6.17-16mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-latest-2.6.17-16mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-legacy-2.6.17.16mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"kernel-legacy-latest-2.6.17-16mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-2.6.17.16mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-latest-2.6.17-16mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-stripped-2.6.17.16mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-source-stripped-latest-2.6.17-16mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xen0-2.6.17.16mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xen0-latest-2.6.17-16mdv", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xenU-2.6.17.16mdv-1-1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"kernel-xenU-latest-2.6.17-16mdv", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
