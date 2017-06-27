#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:160. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19915);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-2494");
  script_xref(name:"MDKSA", value:"2005:160");

  script_name(english:"Mandrake Linux Security Advisory : kdebase (MDKSA-2005:160)");
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
"Ilja van Sprundel from suresec.org notified the KDE security team
about a serious lock file handling error in kcheckpass that can, in
some configurations, be used to gain root access.

In order for an exploit to succeed, the directory /var/lock has to be
writeable for a user that is allowed to invoke kcheckpass.

The updated packages have been patched to correct this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20050905-1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kcontrol-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kcontrol-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdeprintfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kdm-config-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-nsplugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdebase-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kdebase4-konsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kate-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkdebase4-konsole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"kdebase-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-common-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kate-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kcontrol-data-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kcontrol-nsplugins-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kdeprintfax-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kdm-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kdm-config-file-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-kmenuedit-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-konsole-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-nsplugins-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"kdebase-progs-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-devel-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-kate-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-kate-devel-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-kmenuedit-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64kdebase4-konsole-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-devel-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-kate-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-kate-devel-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-kmenuedit-3.2.3-134.9.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libkdebase4-konsole-3.2.3-134.9.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"kdebase-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-common-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-kate-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-kcontrol-data-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-kcontrol-nsplugins-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-kdeprintfax-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-kdm-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-kdm-config-file-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-kmenuedit-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-konsole-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"kdebase-nsplugins-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"kdebase-progs-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64kdebase4-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64kdebase4-devel-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64kdebase4-kate-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64kdebase4-kate-devel-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64kdebase4-kmenuedit-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64kdebase4-konsole-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libkdebase4-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libkdebase4-devel-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libkdebase4-kate-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libkdebase4-kate-devel-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libkdebase4-kmenuedit-3.3.2-100.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libkdebase4-konsole-3.3.2-100.2.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
