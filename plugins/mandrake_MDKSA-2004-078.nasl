#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:078. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14176);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0179", "CVE-2004-0398");
  script_xref(name:"MDKSA", value:"2004:078");

  script_name(english:"Mandrake Linux Security Advisory : OpenOffice.org (MDKSA-2004:078)");
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
"The OpenOffice.org office suite contains an internal libneon library
which allows it to connect to WebDAV servers. This internal library is
subject to the same vulnerabilities that were fixed in libneon
recently. These updated packages contain fixes to libneon to correct
the several format string vulnerabilities in it, as well as a
heap-based buffer overflow vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-help-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:OpenOffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/07/29");
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
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-cs-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-de-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-en-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-es-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-eu-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-fi-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-fr-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-it-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-ja-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-ko-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-nl-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-ru-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-sk-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-sv-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-zh_CN-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-help-zh_TW-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-ar-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-ca-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-cs-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-da-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-de-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-el-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-en-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-es-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-et-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-eu-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-fi-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-fr-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-it-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-ja-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-ko-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-nl-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-pl-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-pt-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-pt_BR-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-ru-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-sk-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-sv-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-tr-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-zh_CN-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-l10n-zh_TW-1.1.2-3.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"OpenOffice.org-libs-1.1.2-3.1.100mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
