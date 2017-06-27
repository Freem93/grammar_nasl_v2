#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:113. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(21770);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:56:38 $");

  script_cve_id("CVE-2004-0941", "CVE-2004-0990", "CVE-2006-2906");
  script_xref(name:"MDKSA", value:"2006:113");

  script_name(english:"Mandrake Linux Security Advisory : tetex (MDKSA-2006:113)");
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
"Integer overflows were reported in the GD Graphics Library (libgd)
2.0.28, and possibly other versions. These overflows allow remote
attackers to cause a denial of service and possibly execute arbitrary
code via PNG image files with large image rows values that lead to a
heap-based buffer overflow in the gdImageCreateFromPngCtx() function.
Tetex contains an embedded copy of the GD library code.
(CVE-2004-0990)

The LZW decoding in the gdImageCreateFromGifPtr function in the Thomas
Boutell graphics draw (GD) library (aka libgd) 2.0.33 allows remote
attackers to cause a denial of service (CPU consumption) via malformed
GIF data that causes an infinite loop. Tetex contains an embedded copy
of the GD library code. (CVE-2006-2906)

Updated packages have been patched to address both issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvipdfm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-mfwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-texi2html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xmltex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/28");
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
if (rpm_check(release:"MDK10.2", reference:"jadetex-3.12-106.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-afm-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-context-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-devel-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-doc-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-dvilj-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-dvipdfm-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-dvips-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-latex-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-mfwin-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-texi2html-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"tetex-xdvi-3.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xmltex-1.9-54.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"jadetex-3.12-110.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-afm-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-context-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-devel-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-doc-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvilj-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvipdfm-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvips-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-latex-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-mfwin-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-texi2html-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-xdvi-3.0-12.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xmltex-1.9-58.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
