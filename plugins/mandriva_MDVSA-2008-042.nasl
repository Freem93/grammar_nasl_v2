#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:042. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(38087);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/30 13:45:23 $");

  script_cve_id("CVE-2007-5965");
  script_bugtraq_id(27112);
  script_xref(name:"MDVSA", value:"2008:042");

  script_name(english:"Mandriva Linux Security Advisory : qt4 (MDVSA-2008:042)");
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
"A potential vulnerability was discovered in Qt4 version 4.3.0 through
4.3.2 which may cause a certificate verification in SSL connections
not to be performed. As a result, code that uses QSslSocket could be
tricked into thinking that the certificate was verified correctly when
it actually failed in one or more criteria.

The updated packages have been patched to correct this issue."
  );
  # http://trolltech.com/company/newsroom/announcements/press.2007-12-21.2182567220
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24ed23d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qassistant1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtdbus4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtdesigner1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtnetwork4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtopengl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtscript4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtsql4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtsvg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qttest4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtuitools4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtxml4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqassistant1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtdbus4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtdesigner1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtnetwork4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtopengl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtscript4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtsql4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtsvg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqttest4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtuitools4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtxml4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-accessibility-plugin-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-accessibility-plugin-lib64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-codecs-plugin-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-codecs-plugin-lib64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-mysql-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-mysql-lib64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-odbc-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-odbc-lib64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-pgsql-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-pgsql-lib64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-sqlite-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-sqlite-lib64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-qtdbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-qvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-tutorial");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qassistant1-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qt3support4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qt4-devel-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtcore4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtdbus4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtdesigner1-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtgui4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtnetwork4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtopengl4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtscript4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtsql4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtsvg4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qttest4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtuitools4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64qtxml4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqassistant1-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqt3support4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqt4-devel-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtcore4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtdbus4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtdesigner1-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtgui4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtnetwork4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtopengl4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtscript4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtsql4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtsvg4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqttest4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtuitools4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libqtxml4-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"qt4-accessibility-plugin-lib-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"qt4-accessibility-plugin-lib64-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-assistant-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"qt4-codecs-plugin-lib-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"qt4-codecs-plugin-lib64-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-common-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"qt4-database-plugin-mysql-lib-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"qt4-database-plugin-mysql-lib64-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"qt4-database-plugin-odbc-lib-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"qt4-database-plugin-odbc-lib64-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"qt4-database-plugin-pgsql-lib-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"qt4-database-plugin-pgsql-lib64-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"qt4-database-plugin-sqlite-lib-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"qt4-database-plugin-sqlite-lib64-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-designer-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-doc-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-examples-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-linguist-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-qtdbus-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-qvfb-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"qt4-tutorial-4.3.1-12.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
