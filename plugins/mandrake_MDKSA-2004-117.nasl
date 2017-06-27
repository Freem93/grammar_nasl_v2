#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:117. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(15597);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:36 $");

  script_cve_id("CVE-2004-0891");
  script_xref(name:"MDKSA", value:"2004:117");

  script_name(english:"Mandrake Linux Security Advisory : gaim (MDKSA-2004:117)");
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
"A vulnerability in the MSN protocol handler in the gaim instant
messenger application was discovered. When receiving unexpected
sequences of MSNSLP messages, it is possible that an attacker could
trigger an internal buffer overflow which could lead to a crash or
even code execution as the user running gaim.

The updated packages are patched to fix this problem. This problem
does not affect Mandrakelinux 10.0 installations."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-festival");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-gevolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gaim-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gaim-remote0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gaim-remote0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgaim-remote0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgaim-remote0-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/02");
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
if (rpm_check(release:"MDK10.1", reference:"gaim-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-devel-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-festival-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-gevolution-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-perl-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"gaim-tcl-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64gaim-remote0-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64gaim-remote0-devel-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libgaim-remote0-0.82.1-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libgaim-remote0-devel-0.82.1-2.1.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
