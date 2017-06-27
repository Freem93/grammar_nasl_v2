#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:002. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16115);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2004-1183", "CVE-2004-1307", "CVE-2004-1308");
  script_xref(name:"MDKSA", value:"2005:002");

  script_name(english:"Mandrake Linux Security Advisory : wxGTK2 (MDKSA-2005:002)");
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
"Several vulnerabilities have been discovered in the libtiff package;
wxGTK2 uses a libtiff code tree, so it may have the same
vulnerabilities :

iDefense reported the possibility of remote exploitation of an integer
overflow in libtiff that may allow for the execution of arbitrary
code.

The overflow occurs in the parsing of TIFF files set with the
STRIPOFFSETS flag.

iDefense also reported a heap-based buffer overflow vulnerability
within the LibTIFF package could allow attackers to execute arbitrary
code. (CVE-2004-1308)

The vulnerability specifically exists due to insufficient validation
of user-supplied data when calculating the size of a directory entry.

The updated packages are patched to protect against these
vulnerabilities."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wxgtk2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wxgtk2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wxgtk2.5_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wxgtk2.5_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wxgtkgl2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wxgtkgl2.5_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwxgtk2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwxgtk2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwxgtk2.5_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwxgtk2.5_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwxgtkgl2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwxgtkgl2.5_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:wxGTK2.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/07");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64wxgtk2.5-2.5.0-0.cvs20030817.1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64wxgtk2.5-devel-2.5.0-0.cvs20030817.1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64wxgtkgl2.5-2.5.0-0.cvs20030817.1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libwxgtk2.5-2.5.0-0.cvs20030817.1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libwxgtk2.5-devel-2.5.0-0.cvs20030817.1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libwxgtkgl2.5-2.5.0-0.cvs20030817.1.5.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"wxGTK2.5-2.5.0-0.cvs20030817.1.5.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64wxgtk2.5_1-2.5.1-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64wxgtk2.5_1-devel-2.5.1-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64wxgtkgl2.5_1-2.5.1-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libwxgtk2.5_1-2.5.1-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libwxgtk2.5_1-devel-2.5.1-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libwxgtkgl2.5_1-2.5.1-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"wxGTK2.5-2.5.1-5.3.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
