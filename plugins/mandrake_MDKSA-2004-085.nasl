#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:085. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14334);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
  script_xref(name:"MDKSA", value:"2004:085");

  script_name(english:"Mandrake Linux Security Advisory : qt3 (MDKSA-2004:085)");
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
"Chris Evans discovered a heap-based overflow in the QT library when
handling 8-bit RLE encoded BMP files. This vulnerability could allow
for the compromise of the account used to view or browse malicious BMP
files. On subsequent investigation, it was also found that the
handlers for XPM, GIF, and JPEG image types were also faulty.

These problems affect all applications that use QT to handle image
files, such as QT-based image viewers, the Konqueror web browser, and
others.

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64qt3-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libqt3-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qt3-example");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/22");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-devel-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-mysql-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-odbc-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64qt3-psql-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-devel-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-mysql-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-odbc-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libqt3-psql-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"qt3-common-3.2.3-19.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"qt3-example-3.2.3-19.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64qt3-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64qt3-devel-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64qt3-mysql-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64qt3-odbc-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64qt3-psql-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libqt3-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libqt3-devel-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libqt3-mysql-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libqt3-odbc-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libqt3-psql-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"qt3-common-3.1.2-15.4.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"qt3-example-3.1.2-15.4.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
