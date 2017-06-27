#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:225. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(40900);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/01 00:11:05 $");

  script_cve_id("CVE-2009-2700");
  script_xref(name:"MDVSA", value:"2009:225");

  script_name(english:"Mandriva Linux Security Advisory : qt4 (MDVSA-2009:225)");
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
"A vulnerability has been found and corrected in qt4 :

src/network/ssl/qsslcertificate.cpp in Nokia Trolltech Qt 4.x does not
properly handle a '&#0;' character in a domain name in the Subject
Alternative Name field of an X.509 certificate, which allows
man-in-the-middle attackers to spoof arbitrary SSL servers via a
crafted certificate issued by a legitimate Certification Authority, a
related issue to CVE-2009-2408 (CVE-2009-2700).

This update provides a solution to this vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qassistant4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtclucene4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtdbus4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtdesigner4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qthelp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtnetwork4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtopengl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtscript4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtscripttools4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtsql4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtsvg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qttest4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtwebkit4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtxml4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtxmlpatterns4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqassistant4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtclucene4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtdbus4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtdesigner4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqthelp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtnetwork4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtopengl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtscript4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtscripttools4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtsql4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtsvg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqttest4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtwebkit4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtxml4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtxmlpatterns4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-accessibility-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-database-plugin-tds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-graphicssystems-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-qdoc3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-qtconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-qtdbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-qvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-xmlpatterns");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qassistant4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qt3support4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qt4-devel-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtclucene4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtcore4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtdbus4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtdesigner4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtgui4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qthelp4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtnetwork4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtopengl4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtscript4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtscripttools4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtsql4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtsvg4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qttest4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtwebkit4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtxml4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64qtxmlpatterns4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqassistant4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqt3support4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqt4-devel-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtclucene4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtcore4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtdbus4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtdesigner4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtgui4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqthelp4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtnetwork4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtopengl4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtscript4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtscripttools4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtsql4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtsvg4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqttest4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtwebkit4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtxml4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libqtxmlpatterns4-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-accessibility-plugin-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-assistant-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-common-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-database-plugin-mysql-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-database-plugin-odbc-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-database-plugin-pgsql-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-database-plugin-sqlite-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-database-plugin-tds-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-designer-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-doc-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-examples-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-graphicssystems-plugin-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-linguist-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-qdoc3-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-qtconfig-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-qtdbus-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-qvfb-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qt4-xmlpatterns-4.5.2-1.6mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qassistant4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qt3support4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qt4-devel-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtclucene4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtcore4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtdbus4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtdesigner4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtgui4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qthelp4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtnetwork4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtopengl4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtscript4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtscripttools4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtsql4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtsvg4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qttest4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtwebkit4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtxml4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64qtxmlpatterns4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqassistant4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqt3support4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqt4-devel-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtclucene4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtcore4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtdbus4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtdesigner4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtgui4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqthelp4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtnetwork4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtopengl4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtscript4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtscripttools4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtsql4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtsvg4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqttest4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtwebkit4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtxml4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libqtxmlpatterns4-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-accessibility-plugin-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-assistant-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-common-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-database-plugin-mysql-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-database-plugin-odbc-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-database-plugin-pgsql-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-database-plugin-sqlite-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-database-plugin-tds-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-designer-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-doc-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-examples-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-graphicssystems-plugin-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-linguist-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-qdoc3-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-qtconfig-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-qtdbus-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-qvfb-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"qt4-xmlpatterns-4.5.2-1.4mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
