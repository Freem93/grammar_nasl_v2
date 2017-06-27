#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:182. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24567);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:49:26 $");

  script_cve_id("CVE-2006-3741", "CVE-2006-4145", "CVE-2006-4535", "CVE-2006-4623");
  script_bugtraq_id(19562, 19939, 20361);
  script_xref(name:"MDKSA", value:"2006:182");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2006:182)");
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
"A number of vulnerabilities were discovered and corrected in the Linux
2.6 kernel :

Stephane Eranian discovered an issue with permon2.0 where, under
certain circumstances, the perfmonctl() system call may not correctly
manage the file descriptor reference count, resulting in the system
possibly running out of file structure (CVE-2006-3741).

Prior to and including 2.6.17, the Universal Disk Format (UDF)
filesystem driver allowed local users to cause a DoS (hang and crash)
via certain operations involving truncated files (CVE-2006-4145).

Various versions of the Linux kernel allowed local users to cause a
DoS (crash) via an SCTP socket with a certain SO_LINGER value, which
is possibly related to the patch used to correct CVE-2006-3745
(CVE-2006-4535).

The Unidirectional Lightweight Encapsulation (ULE) decapsulation
component in the dvb driver allows remote attackers to cause a DoS
(crash) via an SNDU length of 0 in a ULE packet (CVE-2006-4623).

The provided packages are patched to fix these vulnerabilities. All
users are encouraged to upgrade to these updated kernels immediately
and reboot to effect the fixes.

In addition to these security fixes, other fixes have been included
such as :

  - added support for new devices: o NetXtreme BCM5715
    gigabit ethernet o NetXtreme II BCM5708 gigabit ethernet
    - enabled the CISS driver for Xen kernels - updated ich8
    support in ata_piix - enabled support for 1078 type
    controller in megaraid_sas - multiple fixes for RSBAC
    support

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-BOOT-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i586-up-1GB-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-stripped-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xbox-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xen0-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-xenU-2.6.12.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rsbac1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rsbac1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64rsbac1-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:librsbac1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:librsbac1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:librsbac1-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rsbac-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rsbac-admin-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
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
if (rpm_check(release:"MDK2006.0", reference:"kernel-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-BOOT-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i586-up-1GB-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-i686-up-4GB-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-smp-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-source-stripped-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"kernel-xbox-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-xen0-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"kernel-xenU-2.6.12.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64rsbac1-1.2.4-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64rsbac1-devel-1.2.4-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64rsbac1-static-devel-1.2.4-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"librsbac1-1.2.4-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"librsbac1-devel-1.2.4-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"librsbac1-static-devel-1.2.4-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"rsbac-admin-1.2.4-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"rsbac-admin-doc-1.2.4-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xen-3.0.1-3.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
