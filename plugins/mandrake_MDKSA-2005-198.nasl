#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:198. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20436);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-3149");
  script_xref(name:"MDKSA", value:"2005:198");

  script_name(english:"Mandrake Linux Security Advisory : uim (MDKSA-2005:198)");
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
"Masanari Yamamoto discovered that Uim uses environment variables
incorrectly. This bug causes a privilege escalation if setuid/setgid
applications are linked to libuim.

The updated packages have been patched to address this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64uim0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64uim0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libuim0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libuim0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:uim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:uim-anthy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:uim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:uim-m17nlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:uim-prime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:uim-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:uim-qtimmodule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:uim-skk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
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
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64uim0-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64uim0-devel-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libuim0-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libuim0-devel-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"uim-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"uim-anthy-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"uim-gtk-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"uim-m17nlib-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"uim-prime-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"uim-qt-0.4.6-6.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"uim-skk-0.4.6-6.1.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64uim0-0.4.8-4.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64uim0-devel-0.4.8-4.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libuim0-0.4.8-4.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libuim0-devel-0.4.8-4.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"uim-0.4.8-4.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"uim-gtk-0.4.8-4.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"uim-qt-0.4.8-4.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"uim-qtimmodule-0.4.8-4.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
