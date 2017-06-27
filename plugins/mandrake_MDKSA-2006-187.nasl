#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:187. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24572);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:49:26 $");

  script_cve_id("CVE-2006-4811");
  script_bugtraq_id(20599);
  script_xref(name:"MDKSA", value:"2006:187");

  script_name(english:"Mandrake Linux Security Advisory : qt (MDKSA-2006:187)");
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
"An integer overflow was discovered in the way that Qt handled pixmap
images. This flaw could be exploited by a remote attacker in a
malicious website that, when viewed by an individual using an
application that uses Qt (like Konqueror), would cause it to crash or
possibly execute arbitrary code with the privileges of the user.

Updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64designercore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64editor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qassistant1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qassistantclient1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtdesigner1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtnetwork4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtopengl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtsql4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtsvg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qttest4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtuitools4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qtxml4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdesignercore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libeditor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqassistant1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqassistantclient1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3support4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtdesigner1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtgui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtnetwork4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtopengl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtsql4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtsvg4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqttest4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtuitools4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqtxml4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-example");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-tutorial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-accessibility-plugin-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-accessibility-plugin-lib64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-assistant");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt4-tutorial");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/24");
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
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64designercore1-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64editor1-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64qassistantclient1-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64qt3-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64qt3-devel-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64qt3-mysql-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64qt3-odbc-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64qt3-psql-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64qt3-sqlite-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64qt3-static-devel-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libdesignercore1-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libeditor1-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libqassistantclient1-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libqt3-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libqt3-devel-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libqt3-mysql-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libqt3-odbc-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libqt3-psql-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libqt3-sqlite-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libqt3-static-devel-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"qt3-common-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"qt3-doc-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"qt3-example-3.3.4-23.2.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64designercore1-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64editor1-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qassistant1-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qassistantclient1-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-devel-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-mysql-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-odbc-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-psql-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-sqlite-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-static-devel-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3support4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt4-devel-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtcore4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtdesigner1-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtgui4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtnetwork4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtopengl4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtsql4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtsvg4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qttest4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtuitools4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qtxml4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libdesignercore1-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libeditor1-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqassistant1-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqassistantclient1-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-devel-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-mysql-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-odbc-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-psql-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-sqlite-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-static-devel-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3support4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt4-devel-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtcore4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtdesigner1-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtgui4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtnetwork4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtopengl4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtsql4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtsvg4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqttest4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtuitools4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqtxml4-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt3-common-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt3-doc-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt3-example-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt3-tutorial-3.3.6-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"qt4-accessibility-plugin-lib-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"qt4-accessibility-plugin-lib64-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt4-assistant-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt4-common-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"qt4-database-plugin-mysql-lib-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"qt4-database-plugin-mysql-lib64-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"qt4-database-plugin-odbc-lib-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"qt4-database-plugin-odbc-lib64-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"qt4-database-plugin-pgsql-lib-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"qt4-database-plugin-pgsql-lib64-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"qt4-database-plugin-sqlite-lib-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"qt4-database-plugin-sqlite-lib64-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt4-designer-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt4-doc-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt4-examples-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt4-linguist-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt4-tutorial-4.1.4-12.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
