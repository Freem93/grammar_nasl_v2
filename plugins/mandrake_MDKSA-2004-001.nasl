#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:001. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14101);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2003-0984", "CVE-2003-0985");
  script_xref(name:"MDKSA", value:"2004:001");

  script_name(english:"Mandrake Linux Security Advisory : kernel (MDKSA-2004:001)");
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
"A flaw in bounds checking in mremap() in the Linux kernel versions
2.4.23 and previous was discovered by Paul Starzetz. This flaw may be
used to allow a local attacker to obtain root privilege.

Another minor information leak in the RTC (real time clock) routines
was fixed as well.

All Mandrake Linux users are encouraged to upgrade to these packages
immediately. To update your kernel, please follow the directions
located at :

http://www.mandrakesecure.net/en/kernelupdate.php

Mandrake Linux 9.1 and 9.2 users should upgrade the initscripts (9.1)
and bootloader-utils (9.2) packages prior to upgrading the kernel as
they contain a fixed installkernel script that fixes instances where
the loop module was not being loaded and would cause mkinitrd to fail.

Users requiring commercial NVIDIA drivers can find drivers for
Mandrake Linux 9.2 at MandrakeClub."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bootloader-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:initscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.19.37mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.21.0.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.22.26mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.4.22.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.19.37mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.21.0.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-enterprise-2.4.22.26mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-i686-up-4GB-2.4.22.26mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-p3-smp-64GB-2.4.22.26mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.19.37mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.21.0.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.22.26mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-secure-2.4.22.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.19.37mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.21.0.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.22.26mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-smp-2.4.22.27mdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/07");
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
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-2.4.19.37mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-enterprise-2.4.19.37mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-secure-2.4.19.37mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-smp-2.4.19.37mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"kernel-source-2.4.19-37mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"initscripts-7.06-12.3.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-2.4.21.0.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-enterprise-2.4.21.0.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-secure-2.4.21.0.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-smp-2.4.21.0.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"kernel-source-2.4.21-0.27mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"bootloader-utils-1.6-3.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-2.4.22.26mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"kernel-2.4.22.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-enterprise-2.4.22.26mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-i686-up-4GB-2.4.22.26mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-p3-smp-64GB-2.4.22.26mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-secure-2.4.22.26mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"kernel-secure-2.4.22.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-smp-2.4.22.26mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"kernel-smp-2.4.22.27mdk-1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"kernel-source-2.4.22-27mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"kernel-source-2.4.22-26mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
