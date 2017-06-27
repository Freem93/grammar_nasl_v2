#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:074. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37804);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/01 00:01:19 $");

  script_cve_id("CVE-2007-0242");
  script_xref(name:"MDKSA", value:"2007:074");

  script_name(english:"Mandrake Linux Security Advisory : qt3 (MDKSA-2007:074)");
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
"Andreas Nolden discover a bug in qt3, where the UTF8 decoder does not
reject overlong sequences, which can cause '/../' injection or (in the
case of konqueror) a '<script>' tag injection.

Updated packages have been patched to address this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64designercore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64editor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qassistantclient1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdesignercore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libeditor1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqassistantclient1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-example");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-tutorial");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64designercore1-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64editor1-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qassistantclient1-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-devel-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-mysql-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-odbc-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-psql-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-sqlite-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64qt3-static-devel-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libdesignercore1-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libeditor1-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqassistantclient1-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-devel-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-mysql-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-odbc-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-psql-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-sqlite-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libqt3-static-devel-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt3-common-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt3-doc-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt3-example-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"qt3-tutorial-3.3.6-18.2mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
