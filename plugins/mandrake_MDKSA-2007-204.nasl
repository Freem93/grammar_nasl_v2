#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:204. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(27615);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/01 00:01:20 $");

  script_cve_id("CVE-2007-4351");
  script_xref(name:"MDKSA", value:"2007:204-1");

  script_name(english:"Mandrake Linux Security Advisory : cups (MDKSA-2007:204-1)");
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
"Alin Rad Pop of Secunia Research discovered a vulnerability in CUPS
that can be exploited by malicious individuals to execute arbitrary
code. This flaw is due to a boundary error when processing IPP
(Internet Printing Protocol) tags.

Update :

Due to incorrect build requirements/conflicts, the cups-config in
Mandriva Linux 2008.0 was displaying the full CFLAGS and libs instead
of just the libraries when 'cups-config --libs' was invoked. This
update corrects the cups-config behaviour."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cups2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcups2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"cups-1.3.0-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"cups-common-1.3.0-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"cups-serial-1.3.0-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64cups2-1.3.0-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64cups2-devel-1.3.0-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libcups2-1.3.0-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libcups2-devel-1.3.0-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"php-cups-1.3.0-3.2mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
